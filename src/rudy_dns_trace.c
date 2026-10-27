#include "rudy_dns_trace.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define RDT_MAX_PACKET (16U * 1024U * 1024U)
#define RDT_MAX_BLOCK (64U * 1024U * 1024U)
#define RDT_MAX_INTERFACES 256U
#define RDT_MAX_DNS_ITEMS 4096U
#define RDT_ACTIVE_SLOT_TOMBSTONE SIZE_MAX

static int resize_buffer(uint8_t **buffer, size_t size) {
    uint8_t *next = (uint8_t *)realloc(*buffer, size == 0U ? 1U : size);
    if (next == NULL) return 0;
    *buffer = next;
    return 1;
}

typedef struct {
    uint32_t linktype;
    uint32_t snaplen;
    double ticks_per_second;
    int64_t timestamp_offset;
} rdt_interface;

typedef struct {
    char name[RDT_NAME_MAX];
    uint16_t qtype;
    uint16_t id;
    uint16_t answers;
    uint8_t rcode;
    int is_response;
    int has_question;
    int truncated;
} rdt_dns_message;

static void set_error(char *error, size_t error_size, const char *format, ...) {
    va_list args;
    if (error == NULL || error_size == 0U) return;
    va_start(args, format);
    (void)vsnprintf(error, error_size, format, args);
    va_end(args);
}

static uint16_t read_u16(const uint8_t *p, int little) {
    uint32_t value;
    if (little) value = (uint32_t)p[0] | ((uint32_t)p[1] << 8U);
    else value = ((uint32_t)p[0] << 8U) | (uint32_t)p[1];
    return (uint16_t)value;
}

static uint32_t read_u32(const uint8_t *p, int little) {
    if (little) return (uint32_t)p[0] | ((uint32_t)p[1] << 8U) |
                        ((uint32_t)p[2] << 16U) | ((uint32_t)p[3] << 24U);
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) |
           ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

static uint64_t read_u64(const uint8_t *p, int little) {
    uint64_t a = read_u32(p, little);
    uint64_t b = read_u32(p + 4, little);
    return little ? (a | (b << 32U)) : ((a << 32U) | b);
}

static int read_fully(FILE *file, uint8_t *out, size_t count) {
    size_t got = 0U;
    while (got < count) {
        size_t n = fread(out + got, 1U, count - got, file);
        if (n == 0U) return 0;
        got += n;
    }
    return 1;
}

static int printable_name_char(unsigned char c) {
    return c >= 0x21U && c <= 0x7eU && c != (unsigned char)'.' && c != (unsigned char)'\\';
}

/* DNS compression is backward-only, bounded, and decoded without recursion. */
static int decode_name(const uint8_t *message, size_t length, size_t *cursor,
                       char *out, size_t out_size) {
    size_t pos = *cursor;
    size_t next = pos;
    size_t written = 0U;
    size_t raw_name_size = 0U;
    unsigned jumps = 0U;
    int jumped = 0;
    int first_label = 1;

    if (out_size == 0U) return 0;
    out[0] = '\0';
    for (;;) {
        uint8_t label;
        size_t i;
        if (pos >= length) return 0;
        label = message[pos];
        if ((label & 0xc0U) == 0xc0U) {
            size_t target;
            if (pos + 1U >= length) return 0;
            target = (size_t)(((uint16_t)(label & 0x3fU) << 8U) | message[pos + 1U]);
            if (target >= pos || target >= length || ++jumps > 32U) return 0;
            if (!jumped) next = pos + 2U;
            jumped = 1;
            pos = target;
            continue;
        }
        if ((label & 0xc0U) != 0U) return 0;
        ++pos;
        if (label == 0U) {
            if (!jumped) next = pos;
            if (first_label) {
                if (written + 1U >= out_size) return 0;
                out[written++] = '.';
            }
            out[written] = '\0';
            *cursor = next;
            return 1;
        }
        if ((size_t)label > length - pos || raw_name_size + (size_t)label + 1U > 255U) return 0;
        if (!first_label) {
            if (written + 1U >= out_size) return 0;
            out[written++] = '.';
        }
        first_label = 0;
        raw_name_size += (size_t)label + 1U;
        for (i = 0U; i < (size_t)label; ++i) {
            unsigned char c = message[pos + i];
            if (printable_name_char(c)) {
                if (written + 1U >= out_size) return 0;
                out[written++] = (char)tolower(c);
            } else {
                static const char hex[] = "0123456789abcdef";
                if (written + 4U >= out_size) return 0;
                out[written++] = '\\';
                out[written++] = 'x';
                out[written++] = hex[c >> 4U];
                out[written++] = hex[c & 0x0fU];
            }
        }
        if (!jumped) next = pos + (size_t)label;
        pos += (size_t)label;
    }
}

static int skip_dns_name(const uint8_t *message, size_t length, size_t *cursor) {
    char name[RDT_NAME_MAX];
    return decode_name(message, length, cursor, name, sizeof(name));
}

static int parse_dns(const uint8_t *message, size_t length, rdt_dns_message *out) {
    size_t offset = 12U;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
    uint32_t total_records;
    uint32_t i;
    uint16_t flags;

    if (length < 12U) return 0;
    memset(out, 0, sizeof(*out));
    out->id = read_u16(message, 0);
    flags = read_u16(message + 2U, 0);
    questions = read_u16(message + 4U, 0);
    answers = read_u16(message + 6U, 0);
    authority = read_u16(message + 8U, 0);
    additional = read_u16(message + 10U, 0);
    total_records = (uint32_t)answers + (uint32_t)authority + (uint32_t)additional;
    if (questions > RDT_MAX_DNS_ITEMS || total_records > RDT_MAX_DNS_ITEMS) return 0;
    out->is_response = (flags & 0x8000U) != 0U;
    out->rcode = (uint8_t)(flags & 0x000fU);
    out->truncated = (flags & 0x0200U) != 0U;
    out->answers = answers;
    for (i = 0U; i < (uint32_t)questions; ++i) {
        if (i == 0U) {
            if (!decode_name(message, length, &offset, out->name, sizeof(out->name))) return 0;
            if (offset + 4U > length) return 0;
            out->qtype = read_u16(message + offset, 0);
            out->has_question = 1;
            offset += 4U;
        } else {
            if (!skip_dns_name(message, length, &offset) || offset + 4U > length) return 0;
            offset += 4U;
        }
    }
    for (i = 0U; i < total_records; ++i) {
        uint16_t data_length;
        if (!skip_dns_name(message, length, &offset) || offset + 10U > length) return 0;
        data_length = read_u16(message + offset + 8U, 0);
        offset += 10U;
        if ((size_t)data_length > length - offset) return 0;
        offset += (size_t)data_length;
    }
    return 1;
}

static const char *type_name(uint16_t type, char *buffer, size_t size) {
    switch (type) {
        case 1U: return "A";
        case 2U: return "NS";
        case 5U: return "CNAME";
        case 6U: return "SOA";
        case 12U: return "PTR";
        case 15U: return "MX";
        case 16U: return "TXT";
        case 28U: return "AAAA";
        case 33U: return "SRV";
        case 35U: return "NAPTR";
        case 41U: return "OPT";
        case 43U: return "DS";
        case 46U: return "RRSIG";
        case 47U: return "NSEC";
        case 48U: return "DNSKEY";
        case 52U: return "TLSA";
        case 65U: return "HTTPS";
        default: (void)snprintf(buffer, size, "TYPE%u", (unsigned)type); return buffer;
    }
}

static void format_address(const uint8_t *bytes, int version, char *out, size_t size) {
    size_t used = 0U;
    unsigned i;
    if (version == 4) {
        (void)snprintf(out, size, "%u.%u.%u.%u", (unsigned)bytes[0], (unsigned)bytes[1],
                       (unsigned)bytes[2], (unsigned)bytes[3]);
        return;
    }
    for (i = 0U; i < 8U; ++i) {
        int n = snprintf(out + used, size - used, i == 0U ? "%x" : ":%x",
                         (unsigned)(((uint16_t)bytes[2U * i] << 8U) | bytes[2U * i + 1U]));
        if (n < 0 || (size_t)n >= size - used) break;
        used += (size_t)n;
    }
}

typedef struct {
    const char *client;
    const char *resolver;
    uint16_t client_port;
    uint16_t resolver_port;
    int tcp;
} rdt_flow;

static int transaction_key_equal(const rdt_transaction *tx, const rdt_flow *flow,
                                 const rdt_dns_message *dns) {
    char qtype[24];
    if (tx->id != dns->id || strcmp(tx->client, flow->client) != 0 ||
        strcmp(tx->resolver, flow->resolver) != 0 || tx->client_port != flow->client_port ||
        tx->resolver_port != flow->resolver_port || tx->tcp != flow->tcp) return 0;
    if (!dns->has_question) return 1;
    return strcmp(tx->qname, dns->name) == 0 &&
           strcmp(tx->qtype, type_name(dns->qtype, qtype, sizeof(qtype))) == 0;
}

static uint64_t hash_string(uint64_t hash, const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    while (*p != 0U) {
        hash = (hash ^ (uint64_t)*p) * UINT64_C(1099511628211);
        ++p;
    }
    return (hash ^ 0xffU) * UINT64_C(1099511628211);
}

static size_t transaction_hash(const char *client, const char *resolver,
                               const char *qname, const char *qtype, uint16_t id,
                               uint16_t client_port, uint16_t resolver_port, int tcp) {
    uint64_t hash = UINT64_C(14695981039346656037);
    hash = hash_string(hash, client);
    hash = hash_string(hash, resolver);
    hash = hash_string(hash, qname);
    hash = hash_string(hash, qtype);
    hash = (hash ^ (uint64_t)(id & 0xffU)) * UINT64_C(1099511628211);
    hash = (hash ^ (uint64_t)(id >> 8U)) * UINT64_C(1099511628211);
    hash = (hash ^ (uint64_t)client_port) * UINT64_C(1099511628211);
    hash = (hash ^ (uint64_t)resolver_port) * UINT64_C(1099511628211);
    hash = (hash ^ (uint64_t)tcp) * UINT64_C(1099511628211);
    return (size_t)hash;
}

static int ensure_active_table(rdt_report *report) {
    const size_t capacity = 1U << 17U;
    if (report->active_transaction_slots != NULL) return 1;
    report->active_transaction_slots = (size_t *)calloc(capacity, sizeof(size_t));
    if (report->active_transaction_slots == NULL) return 0;
    report->active_transaction_capacity = capacity;
    return 1;
}

static rdt_transaction *find_active_transaction(rdt_report *report, const rdt_flow *flow,
                                                 const rdt_dns_message *dns,
                                                 size_t *index_out) {
    size_t i;
    if (!dns->has_question || report->active_transaction_slots == NULL) {
        if (dns->is_response) {
            for (i = 0U; i < report->transaction_count; ++i) {
                rdt_transaction *tx = &report->transactions[i];
                if (!tx->has_response && transaction_key_equal(tx, flow, dns)) {
                    if (index_out != NULL) *index_out = i;
                    return tx;
                }
            }
        } else {
            for (i = report->transaction_count; i > 0U; --i) {
                size_t index = i - 1U;
                rdt_transaction *tx = &report->transactions[index];
                if (!tx->has_response && transaction_key_equal(tx, flow, dns)) {
                    if (index_out != NULL) *index_out = index;
                    return tx;
                }
            }
        }
        return NULL;
    }
    {
        char qtype[24];
        const char *qtype_name = type_name(dns->qtype, qtype, sizeof(qtype));
        size_t mask = report->active_transaction_capacity - 1U;
        size_t slot = transaction_hash(flow->client, flow->resolver, dns->name, qtype_name, dns->id,
                                       flow->client_port, flow->resolver_port, flow->tcp) & mask;
        size_t checked;
        for (checked = 0U; checked < report->active_transaction_capacity; ++checked) {
            size_t entry = report->active_transaction_slots[slot];
            if (entry == 0U) return NULL;
            if (entry != RDT_ACTIVE_SLOT_TOMBSTONE) {
                size_t index = entry - 1U;
                rdt_transaction *tx = &report->transactions[index];
                if (!tx->has_response && transaction_key_equal(tx, flow, dns)) {
                    if (index_out != NULL) *index_out = index;
                    return tx;
                }
            }
            slot = (slot + 1U) & mask;
        }
    }
    return NULL;
}

static int insert_active_transaction(rdt_report *report, size_t index) {
    const rdt_transaction *tx = &report->transactions[index];
    size_t mask = report->active_transaction_capacity - 1U;
    size_t slot = transaction_hash(tx->client, tx->resolver, tx->qname, tx->qtype, tx->id,
                                   tx->client_port, tx->resolver_port, tx->tcp) & mask;
    size_t first_tombstone = SIZE_MAX;
    size_t checked;
    for (checked = 0U; checked < report->active_transaction_capacity; ++checked) {
        size_t entry = report->active_transaction_slots[slot];
        if (entry == RDT_ACTIVE_SLOT_TOMBSTONE && first_tombstone == SIZE_MAX) first_tombstone = slot;
        if (entry == 0U) {
            report->active_transaction_slots[first_tombstone == SIZE_MAX ? slot : first_tombstone] = index + 1U;
            return 1;
        }
        slot = (slot + 1U) & mask;
    }
    if (first_tombstone != SIZE_MAX) {
        report->active_transaction_slots[first_tombstone] = index + 1U;
        return 1;
    }
    return 0;
}

static void remove_active_transaction(rdt_report *report, size_t index) {
    const rdt_transaction *tx = &report->transactions[index];
    size_t mask;
    size_t slot;
    size_t checked;
    if (report->active_transaction_slots == NULL) return;
    mask = report->active_transaction_capacity - 1U;
    slot = transaction_hash(tx->client, tx->resolver, tx->qname, tx->qtype, tx->id,
                            tx->client_port, tx->resolver_port, tx->tcp) & mask;
    for (checked = 0U; checked < report->active_transaction_capacity; ++checked) {
        size_t entry = report->active_transaction_slots[slot];
        if (entry == 0U) return;
        if (entry == index + 1U) {
            report->active_transaction_slots[slot] = RDT_ACTIVE_SLOT_TOMBSTONE;
            return;
        }
        slot = (slot + 1U) & mask;
    }
}

static rdt_transaction *append_transaction(rdt_report *report) {
    rdt_transaction *next;
    size_t capacity;
    if (report->transaction_count >= RDT_MAX_TRANSACTIONS) return NULL;
    if (report->transaction_count == report->transaction_capacity) {
        capacity = report->transaction_capacity == 0U ? 64U : report->transaction_capacity * 2U;
        if (capacity > RDT_MAX_TRANSACTIONS) capacity = RDT_MAX_TRANSACTIONS;
        next = (rdt_transaction *)realloc(report->transactions, capacity * sizeof(*next));
        if (next == NULL) return NULL;
        report->transactions = next;
        report->transaction_capacity = capacity;
    }
    next = &report->transactions[report->transaction_count++];
    memset(next, 0, sizeof(*next));
    return next;
}

static void record_dns(rdt_report *report, const rdt_dns_message *dns,
                       const char *source, const char *destination, uint16_t source_port,
                       uint16_t destination_port, int tcp, double timestamp, char *error,
                       size_t error_size) {
    const rdt_flow flow = {
        dns->is_response ? destination : source,
        dns->is_response ? source : destination,
        dns->is_response ? destination_port : source_port,
        dns->is_response ? source_port : destination_port,
        tcp
    };
    char qtype_buffer[24];
    const char *qtype = type_name(dns->qtype, qtype_buffer, sizeof(qtype_buffer));
    ++report->dns_messages;
    if (!dns->is_response) {
        rdt_transaction *tx = NULL;
        size_t tx_index = 0U;
        ++report->queries;
        tx = find_active_transaction(report, &flow, dns, &tx_index);
        if (tx != NULL) {
            ++tx->query_count;
            ++report->retransmissions;
            return;
        }
        if (!ensure_active_table(report)) {
            set_error(error, error_size, "out of memory building DNS transaction index");
            return;
        }
        tx = append_transaction(report);
        if (tx == NULL) {
            set_error(error, error_size, "capture exceeds the %u transaction safety limit",
                      (unsigned)RDT_MAX_TRANSACTIONS);
            return;
        }
        (void)snprintf(tx->client, sizeof(tx->client), "%s", flow.client);
        (void)snprintf(tx->resolver, sizeof(tx->resolver), "%s", flow.resolver);
        tx->client_port = flow.client_port;
        tx->resolver_port = flow.resolver_port;
        tx->tcp = flow.tcp;
        (void)snprintf(tx->qname, sizeof(tx->qname), "%s", dns->has_question ? dns->name : "<no-question>");
        (void)snprintf(tx->qtype, sizeof(tx->qtype), "%s", dns->has_question ? qtype : "-");
        tx->id = dns->id;
        tx->query_count = 1U;
        tx->query_time = timestamp;
        if (!insert_active_transaction(report, report->transaction_count - 1U))
            set_error(error, error_size, "DNS transaction index is full");
        return;
    }

    ++report->responses;
    {
        size_t tx_index = 0U;
        rdt_transaction *tx = find_active_transaction(report, &flow, dns, &tx_index);
        if (tx != NULL) {
            tx->has_response = 1;
            tx->response_time = timestamp;
            tx->latency_ms = (timestamp - tx->query_time) * 1000.0;
            if (tx->latency_ms < 0.0) tx->latency_ms = 0.0;
            tx->answer_count = dns->answers;
            tx->rcode = dns->rcode;
            tx->truncated_response = dns->truncated;
            remove_active_transaction(report, tx_index);
            return;
        }
    }
    ++report->unmatched_responses;
}

static int parse_dns_packet(rdt_report *report, const uint8_t *payload, size_t length,
                            const char *src, const char *dst, uint16_t src_port,
                            uint16_t dst_port, double timestamp, int tcp,
                            char *error, size_t error_size) {
    rdt_dns_message dns;
    size_t dns_length = length;
    const uint8_t *dns_data = payload;
    if (tcp) {
        if (length < 2U) { ++report->tcp_dns_skipped; return 1; }
        dns_length = read_u16(payload, 0);
        if (dns_length == 0U || dns_length + 2U > length) {
            ++report->tcp_dns_skipped;
            return 1;
        }
        dns_data = payload + 2U;
    }
    if (!parse_dns(dns_data, dns_length, &dns)) {
        ++report->malformed_dns;
        return 1;
    }
    record_dns(report, &dns, src, dst, src_port, dst_port, tcp, timestamp, error, error_size);
    return error == NULL || error[0] == '\0';
}

static int parse_transport(rdt_report *report, const uint8_t *packet, size_t length,
                           uint8_t protocol, const uint8_t *src_bytes,
                           const uint8_t *dst_bytes, int version, double timestamp,
                           char *error, size_t error_size) {
    char src[RDT_ADDRESS_MAX];
    char dst[RDT_ADDRESS_MAX];
    size_t header_length;
    uint16_t src_port;
    uint16_t dst_port;
    size_t payload_length;
    const uint8_t *payload;
    int tcp = protocol == 6U;
    format_address(src_bytes, version, src, sizeof(src));
    format_address(dst_bytes, version, dst, sizeof(dst));
    if (protocol == 17U) {
        uint16_t udp_length;
        if (length < 8U) { ++report->malformed_packets; return 1; }
        src_port = read_u16(packet, 0);
        dst_port = read_u16(packet + 2U, 0);
        udp_length = read_u16(packet + 4U, 0);
        if (udp_length < 8U) { ++report->malformed_packets; return 1; }
        if (udp_length > length) { ++report->truncated_packets; return 1; }
        header_length = 8U;
        payload_length = (size_t)udp_length - header_length;
    } else if (tcp) {
        if (length < 20U) { ++report->malformed_packets; return 1; }
        src_port = read_u16(packet, 0);
        dst_port = read_u16(packet + 2U, 0);
        header_length = (size_t)(packet[12] >> 4U) * 4U;
        if (header_length < 20U || header_length > length) { ++report->malformed_packets; return 1; }
        payload_length = length - header_length;
    } else {
        return 1;
    }
    if (src_port != 53U && dst_port != 53U) return 1;
    payload = packet + header_length;
    return parse_dns_packet(report, payload, payload_length, src, dst, src_port, dst_port,
                            timestamp, tcp, error, error_size);
}

static int parse_ipv4(rdt_report *report, const uint8_t *packet, size_t length,
                      double timestamp, char *error, size_t error_size) {
    size_t header_length;
    uint16_t total_length;
    uint16_t fragment;
    if (length < 20U || (packet[0] >> 4U) != 4U) { ++report->malformed_packets; return 1; }
    header_length = (size_t)(packet[0] & 0x0fU) * 4U;
    total_length = read_u16(packet + 2U, 0);
    if (header_length < 20U || header_length > length || total_length < header_length) {
        ++report->malformed_packets;
        return 1;
    }
    if ((size_t)total_length > length) { ++report->truncated_packets; return 1; }
    fragment = read_u16(packet + 6U, 0);
    if ((fragment & 0x3fffU) != 0U) { ++report->skipped_fragments; return 1; }
    return parse_transport(report, packet + header_length, (size_t)total_length - header_length,
                           packet[9], packet + 12U, packet + 16U, 4, timestamp,
                           error, error_size);
}

static int parse_ipv6(rdt_report *report, const uint8_t *packet, size_t length,
                      double timestamp, char *error, size_t error_size) {
    uint16_t payload_length;
    uint8_t next_header;
    size_t offset = 40U;
    unsigned extension_count = 0U;
    if (length < 40U || (packet[0] >> 4U) != 6U) { ++report->malformed_packets; return 1; }
    payload_length = read_u16(packet + 4U, 0);
    if ((size_t)payload_length + 40U > length) { ++report->truncated_packets; return 1; }
    next_header = packet[6];
    while (next_header == 0U || next_header == 43U || next_header == 60U || next_header == 51U) {
        size_t extension_length;
        if (++extension_count > 8U || offset + 2U > (size_t)payload_length + 40U) {
            ++report->malformed_packets;
            return 1;
        }
        if (next_header == 51U) extension_length = ((size_t)packet[offset + 1U] + 2U) * 4U;
        else extension_length = ((size_t)packet[offset + 1U] + 1U) * 8U;
        if (extension_length < 8U || offset + extension_length > (size_t)payload_length + 40U) {
            ++report->malformed_packets;
            return 1;
        }
        next_header = packet[offset];
        offset += extension_length;
    }
    if (next_header == 44U) {
        if (offset + 8U > (size_t)payload_length + 40U) { ++report->malformed_packets; return 1; }
        ++report->skipped_fragments;
        return 1;
    }
    if (next_header == 50U) return 1;
    return parse_transport(report, packet + offset, (size_t)payload_length + 40U - offset,
                           next_header, packet + 8U, packet + 24U, 6, timestamp,
                           error, error_size);
}

static int parse_frame(rdt_report *report, uint32_t linktype, const uint8_t *frame,
                       size_t length, double timestamp, char *error, size_t error_size) {
    size_t offset = 0U;
    uint16_t protocol = 0U;
    unsigned vlan_depth = 0U;
    if (linktype == 1U) { /* Ethernet */
        if (length < 14U) { ++report->malformed_packets; return 1; }
        protocol = read_u16(frame + 12U, 0);
        offset = 14U;
        while (protocol == 0x8100U || protocol == 0x88a8U || protocol == 0x9100U) {
            if (++vlan_depth > 4U || offset + 4U > length) { ++report->malformed_packets; return 1; }
            protocol = read_u16(frame + offset + 2U, 0);
            offset += 4U;
        }
    } else if (linktype == 113U) { /* Linux cooked capture v1 */
        if (length < 16U) { ++report->malformed_packets; return 1; }
        protocol = read_u16(frame + 14U, 0);
        offset = 16U;
    } else if (linktype == 276U) { /* Linux cooked capture v2 */
        if (length < 20U) { ++report->malformed_packets; return 1; }
        protocol = read_u16(frame, 0);
        offset = 20U;
    } else if (linktype == 101U || linktype == 12U) { /* raw IP */
        if (length == 0U) { ++report->malformed_packets; return 1; }
        if ((frame[0] >> 4U) == 4U) return parse_ipv4(report, frame, length, timestamp, error, error_size);
        if ((frame[0] >> 4U) == 6U) return parse_ipv6(report, frame, length, timestamp, error, error_size);
        ++report->malformed_packets;
        return 1;
    } else if (linktype == 0U) { /* BSD loopback/null */
        uint32_t family;
        if (length < 4U) { ++report->malformed_packets; return 1; }
        family = read_u32(frame, 1);
        if (family != 2U && family != 10U && family != 24U && family != 28U && family != 30U) {
            family = read_u32(frame, 0);
        }
        offset = 4U;
        if (family == 2U) return parse_ipv4(report, frame + offset, length - offset, timestamp, error, error_size);
        if (family == 10U || family == 24U || family == 28U || family == 30U)
            return parse_ipv6(report, frame + offset, length - offset, timestamp, error, error_size);
        ++report->unsupported_link_packets;
        return 1;
    } else {
        ++report->unsupported_link_packets;
        return 1;
    }
    if (protocol == 0x0800U) return parse_ipv4(report, frame + offset, length - offset, timestamp, error, error_size);
    if (protocol == 0x86ddU) return parse_ipv6(report, frame + offset, length - offset, timestamp, error, error_size);
    return 1;
}

static void process_packet(rdt_report *report, uint32_t linktype, const uint8_t *packet,
                           size_t captured, uint32_t original, double timestamp,
                           char *error, size_t error_size) {
    ++report->packets;
    if (captured < (size_t)original) ++report->truncated_packets;
    if (captured > RDT_MAX_PACKET) {
        set_error(error, error_size, "packet exceeds the %u-byte safety limit", RDT_MAX_PACKET);
        return;
    }
    (void)parse_frame(report, linktype, packet, captured, timestamp, error, error_size);
}

static int parse_classic_pcap(FILE *file, const uint8_t magic[4], rdt_report *report,
                              char *error, size_t error_size) {
    uint8_t header[20];
    uint8_t *packet = NULL;
    int little;
    double fraction_scale;
    uint16_t major;
    uint16_t minor;
    uint32_t linktype;
    uint32_t snaplen;
    if (magic[0] == 0xd4U && magic[1] == 0xc3U && magic[2] == 0xb2U && magic[3] == 0xa1U) {
        little = 1; fraction_scale = 1000000.0;
    } else if (magic[0] == 0xa1U && magic[1] == 0xb2U && magic[2] == 0xc3U && magic[3] == 0xd4U) {
        little = 0; fraction_scale = 1000000.0;
    } else if (magic[0] == 0x4dU && magic[1] == 0x3cU && magic[2] == 0xb2U && magic[3] == 0xa1U) {
        little = 1; fraction_scale = 1000000000.0;
    } else if (magic[0] == 0xa1U && magic[1] == 0xb2U && magic[2] == 0x3cU && magic[3] == 0x4dU) {
        little = 0; fraction_scale = 1000000000.0;
    } else {
        set_error(error, error_size, "unrecognized capture magic");
        return 0;
    }
    if (!read_fully(file, header, sizeof(header))) { set_error(error, error_size, "truncated classic PCAP header"); return 0; }
    major = read_u16(header, little);
    minor = read_u16(header + 2U, little);
    if (major != 2U || minor > 4U) { set_error(error, error_size, "unsupported classic PCAP version %u.%u", major, minor); return 0; }
    snaplen = read_u32(header + 12U, little);
    linktype = read_u32(header + 16U, little) & 0xffffU;
    for (;;) {
        uint8_t record[16];
        uint32_t seconds;
        uint32_t fraction;
        uint32_t captured;
        uint32_t original;
        size_t got = fread(record, 1U, sizeof(record), file);
        if (got == 0U && feof(file)) break;
        if (got != sizeof(record)) { set_error(error, error_size, "truncated classic PCAP packet header"); free(packet); return 0; }
        seconds = read_u32(record, little);
        fraction = read_u32(record + 4U, little);
        captured = read_u32(record + 8U, little);
        original = read_u32(record + 12U, little);
        if (captured > RDT_MAX_PACKET || captured > original || (snaplen != 0U && captured > snaplen)) {
            set_error(error, error_size, "invalid or oversized classic PCAP packet length"); free(packet); return 0;
        }
        if (fraction >= (uint32_t)fraction_scale) {
            set_error(error, error_size, "invalid classic PCAP timestamp fraction"); free(packet); return 0;
        }
        if (!resize_buffer(&packet, (size_t)captured)) {
            set_error(error, error_size, "out of memory reading packet"); free(packet); return 0;
        }
        if (!read_fully(file, packet, captured)) { set_error(error, error_size, "truncated classic PCAP packet data"); free(packet); return 0; }
        process_packet(report, linktype, packet, captured, original,
                       (double)seconds + (double)fraction / fraction_scale,
                       error, error_size);
        if (error != NULL && error[0] != '\0') { free(packet); return 0; }
    }
    free(packet);
    return 1;
}

static double power10(unsigned exponent) {
    double value = 1.0;
    while (exponent-- > 0U) value *= 10.0;
    return value;
}

static int parse_options(const uint8_t *block, size_t begin, size_t end, int little,
                         double *ticks_per_second, int64_t *timestamp_offset) {
    size_t offset = begin;
    while (offset + 4U <= end) {
        uint16_t code = read_u16(block + offset, little);
        uint16_t length = read_u16(block + offset + 2U, little);
        size_t padded = ((size_t)length + 3U) & ~(size_t)3U;
        offset += 4U;
        if (padded > end - offset) return 0;
        if (code == 0U) return length == 0U && offset == end;
        if (code == 9U && length == 1U && ticks_per_second != NULL) {
            uint8_t resolution = block[offset];
            unsigned exponent = (unsigned)(resolution & 0x7fU);
            if (exponent > 18U) return 0;
            *ticks_per_second = (resolution & 0x80U) != 0U ? (double)(UINT64_C(1) << exponent) : power10(exponent);
            if (*ticks_per_second == 0.0) return 0;
        }
        if (code == 14U && length == 8U && timestamp_offset != NULL)
            *timestamp_offset = (int64_t)read_u64(block + offset, little);
        offset += padded;
    }
    return offset == end;
}

static int append_interface(rdt_interface interfaces[RDT_MAX_INTERFACES], size_t *count,
                            const uint8_t *block, size_t length, int little) {
    rdt_interface *it;
    if (*count >= RDT_MAX_INTERFACES || length < 20U) return 0;
    it = &interfaces[(*count)++];
    it->linktype = read_u16(block + 8U, little);
    it->snaplen = read_u32(block + 12U, little);
    it->ticks_per_second = 1000000.0;
    it->timestamp_offset = 0;
    return parse_options(block, 16U, length - 4U, little,
                         &it->ticks_per_second, &it->timestamp_offset);
}

static int is_section_header(const uint8_t *header) {
    return header[0] == 0x0aU && header[1] == 0x0dU &&
           header[2] == 0x0dU && header[3] == 0x0aU;
}

static int parse_pcapng(FILE *file, const uint8_t first_magic[4], rdt_report *report,
                        char *error, size_t error_size) {
    uint8_t header[12];
    rdt_interface interfaces[RDT_MAX_INTERFACES];
    size_t interface_count = 0U;
    int little = 0;
    int have_section = 0;
    uint8_t *block = NULL;
    uint8_t *packet = NULL;
    memcpy(header, first_magic, 4U);
    for (;;) {
        uint32_t total_length;
        int is_shb = is_section_header(header);
        {
            size_t got = fread(header + 4U, 1U, 4U, file);
            if (got == 0U && feof(file)) break;
            if (got != 4U) { set_error(error, error_size, "truncated pcapng block header"); free(block); free(packet); return 0; }
        }
        if (is_shb) {
            uint8_t bom[4];
            if (!read_fully(file, bom, sizeof(bom))) { set_error(error, error_size, "truncated pcapng section header"); free(block); free(packet); return 0; }
            if (bom[0] == 0x4dU && bom[1] == 0x3cU && bom[2] == 0x2bU && bom[3] == 0x1aU) little = 1;
            else if (bom[0] == 0x1aU && bom[1] == 0x2bU && bom[2] == 0x3cU && bom[3] == 0x4dU) little = 0;
            else { set_error(error, error_size, "invalid pcapng byte-order magic"); free(block); free(packet); return 0; }
            total_length = read_u32(header + 4U, little);
            memcpy(header + 8U, bom, sizeof(bom));
        } else {
            if (!have_section) { set_error(error, error_size, "pcapng section header is missing"); free(block); free(packet); return 0; }
            total_length = read_u32(header + 4U, little);
        }
        if (total_length < (is_shb ? 28U : 12U) || total_length > RDT_MAX_BLOCK || (total_length & 3U) != 0U) {
            set_error(error, error_size, "invalid pcapng block length %u", total_length); free(block); free(packet); return 0;
        }
        if (!resize_buffer(&block, total_length)) {
            set_error(error, error_size, "out of memory reading pcapng block"); free(block); free(packet); return 0;
        }
        memcpy(block, header, 8U);
        if (is_shb) {
            memcpy(block + 8U, header + 8U, 4U);
            if (!read_fully(file, block + 12U, (size_t)total_length - 12U)) {
                set_error(error, error_size, "truncated pcapng section block"); free(block); free(packet); return 0;
            }
            interface_count = 0U;
            have_section = 1;
        } else {
            if (!read_fully(file, block + 8U, (size_t)total_length - 8U)) {
                set_error(error, error_size, "truncated pcapng block"); free(block); free(packet); return 0;
            }
        }
        if (read_u32(block + total_length - 4U, little) != total_length) {
            set_error(error, error_size, "pcapng block length trailer does not match"); free(block); free(packet); return 0;
        }
        if (is_shb) {
            if (read_u16(block + 12U, little) != 1U) {
                set_error(error, error_size, "unsupported pcapng major version"); free(block); free(packet); return 0;
            }
        } else {
            uint32_t type = read_u32(block, little);
            if (type == 1U) {
                if (!append_interface(interfaces, &interface_count, block, total_length, little)) {
                    set_error(error, error_size, "invalid or excessive pcapng interface description"); free(block); free(packet); return 0;
                }
            } else if (type == 6U) {
                uint32_t interface_id;
                uint32_t captured;
                uint32_t original;
                uint64_t ticks;
                size_t padded;
                rdt_interface *it;
                double timestamp;
                if (total_length < 32U) { set_error(error, error_size, "short pcapng enhanced packet block"); free(block); free(packet); return 0; }
                interface_id = read_u32(block + 8U, little);
                ticks = ((uint64_t)read_u32(block + 12U, little) << 32U) | read_u32(block + 16U, little);
                captured = read_u32(block + 20U, little);
                original = read_u32(block + 24U, little);
                padded = ((size_t)captured + 3U) & ~(size_t)3U;
                if (interface_id >= interface_count || padded > (size_t)total_length - 32U || captured > RDT_MAX_PACKET || captured > original) {
                    set_error(error, error_size, "invalid pcapng enhanced packet bounds"); free(block); free(packet); return 0;
                }
                if (!parse_options(block, 28U + padded, (size_t)total_length - 4U, little, NULL, NULL)) {
                    set_error(error, error_size, "invalid pcapng enhanced packet options"); free(block); free(packet); return 0;
                }
                it = &interfaces[interface_id];
                timestamp = (double)ticks / it->ticks_per_second + (double)it->timestamp_offset;
                if (!resize_buffer(&packet, (size_t)captured)) {
                    set_error(error, error_size, "out of memory reading pcapng packet"); free(block); free(packet); return 0;
                }
                memcpy(packet, block + 28U, captured);
                process_packet(report, it->linktype, packet, captured, original, timestamp, error, error_size);
                if (error != NULL && error[0] != '\0') { free(block); free(packet); return 0; }
            } else if (type == 3U) {
                uint32_t original;
                size_t available;
                size_t captured;
                rdt_interface *it;
                if (interface_count == 0U || total_length < 16U) { set_error(error, error_size, "invalid pcapng simple packet block"); free(block); free(packet); return 0; }
                original = read_u32(block + 8U, little);
                it = &interfaces[0];
                available = (size_t)total_length - 16U;
                captured = original;
                if (captured > available) captured = available;
                if (it->snaplen != 0U && captured > it->snaplen) captured = it->snaplen;
                if (captured > RDT_MAX_PACKET || captured > original) { set_error(error, error_size, "invalid pcapng simple packet bounds"); free(block); free(packet); return 0; }
                if (!resize_buffer(&packet, captured)) {
                    set_error(error, error_size, "out of memory reading pcapng packet"); free(block); free(packet); return 0;
                }
                memcpy(packet, block + 12U, captured);
                process_packet(report, it->linktype, packet, captured, original, 0.0, error, error_size);
                if (error != NULL && error[0] != '\0') { free(block); free(packet); return 0; }
            }
        }
        {
            size_t got = fread(header, 1U, 4U, file);
            if (got == 0U && feof(file)) break;
            if (got != 4U) { set_error(error, error_size, "truncated pcapng block type"); free(block); free(packet); return 0; }
        }
    }
    free(block);
    free(packet);
    return 1;
}

void rdt_report_init(rdt_report *report) {
    memset(report, 0, sizeof(*report));
}

void rdt_report_free(rdt_report *report) {
    if (report == NULL) return;
    free(report->transactions);
    free(report->active_transaction_slots);
    memset(report, 0, sizeof(*report));
}

int rdt_analyze_file(const char *path, rdt_report *report, char *error, size_t error_size) {
    FILE *file;
    uint8_t magic[4];
    int result;
    if (path == NULL || report == NULL || error == NULL || error_size == 0U) {
        set_error(error, error_size, "input path, report, and error buffer are required");
        return 0;
    }
    if (error != NULL && error_size > 0U) error[0] = '\0';
    file = fopen(path, "rb");
    if (file == NULL) { set_error(error, error_size, "cannot open input: %s", strerror(errno)); return 0; }
    if (!read_fully(file, magic, sizeof(magic))) {
        set_error(error, error_size, "capture is empty or its header is truncated");
        fclose(file);
        return 0;
    }
    if (is_section_header(magic)) result = parse_pcapng(file, magic, report, error, error_size);
    else result = parse_classic_pcap(file, magic, report, error, error_size);
    if (fclose(file) != 0 && result) { set_error(error, error_size, "failed to close capture file"); result = 0; }
    return result;
}

static void json_string(FILE *out, const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    fputc('"', out);
    while (*p != 0U) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc((int)*p, out); }
        else if (*p < 0x20U) (void)fprintf(out, "\\u%04x", (unsigned)*p);
        else fputc((int)*p, out);
        ++p;
    }
    fputc('"', out);
}

static const char *rcode_name(uint8_t rcode) {
    switch (rcode) {
        case 0U: return "NOERROR";
        case 1U: return "FORMERR";
        case 2U: return "SERVFAIL";
        case 3U: return "NXDOMAIN";
        case 4U: return "NOTIMP";
        case 5U: return "REFUSED";
        default: return "OTHER";
    }
}

static size_t result_limit(const rdt_report *report, size_t maximum) {
    return maximum == 0U || maximum > report->transaction_count ? report->transaction_count : maximum;
}

static void write_json(FILE *out, const rdt_report *report, int redact_ips,
                       int redact_names, size_t max_results) {
    size_t i;
    size_t count = result_limit(report, max_results);
    uint64_t answered = 0U;
    uint64_t timeouts = 0U;
    double latency_sum = 0.0;
    for (i = 0U; i < report->transaction_count; ++i) {
        if (report->transactions[i].has_response) { ++answered; latency_sum += report->transactions[i].latency_ms; }
        else ++timeouts;
    }
    fputs("{\n  \"schema\": \"rudy-dns-trace/v1\",\n  \"summary\": {", out);
    (void)fprintf(out, "\n    \"packets\": %llu,\n    \"dnsMessages\": %llu,\n    \"queries\": %llu,\n    \"responses\": %llu,\n    \"transactions\": %llu,\n    \"answered\": %llu,\n    \"unanswered\": %llu,\n    \"retransmissions\": %llu,\n    \"unmatchedResponses\": %llu,\n    \"malformedPackets\": %llu,\n    \"malformedDns\": %llu,\n    \"truncatedPackets\": %llu,\n    \"skippedFragments\": %llu,\n    \"tcpDnsSkipped\": %llu,\n    \"unsupportedLinkPackets\": %llu,\n    \"meanLatencyMs\": %.3f\n  },\n  \"transactions\": [\n",
                   (unsigned long long)report->packets, (unsigned long long)report->dns_messages,
                   (unsigned long long)report->queries, (unsigned long long)report->responses,
                   (unsigned long long)report->transaction_count, (unsigned long long)answered,
                   (unsigned long long)timeouts, (unsigned long long)report->retransmissions,
                   (unsigned long long)report->unmatched_responses, (unsigned long long)report->malformed_packets,
                   (unsigned long long)report->malformed_dns, (unsigned long long)report->truncated_packets,
                   (unsigned long long)report->skipped_fragments, (unsigned long long)report->tcp_dns_skipped,
                   (unsigned long long)report->unsupported_link_packets,
                   answered == 0U ? 0.0 : latency_sum / (double)answered);
    for (i = 0U; i < count; ++i) {
        const rdt_transaction *tx = &report->transactions[i];
        if (i != 0U) fputs(",\n", out);
        fputs("    {\"client\":", out); json_string(out, redact_ips ? "<redacted>" : tx->client);
        fputs(",\"resolver\":", out); json_string(out, redact_ips ? "<redacted>" : tx->resolver);
        fputs(",\"name\":", out); json_string(out, redact_names ? "<redacted>" : tx->qname);
        fputs(",\"type\":", out); json_string(out, tx->qtype);
        fputs(",\"status\":", out); json_string(out, tx->has_response ? "response" : "unanswered");
        fputs(",\"rcode\":", out); json_string(out, tx->has_response ? rcode_name(tx->rcode) : "-");
        (void)fprintf(out, ",\"id\":%u,\"queries\":%u,\"answers\":%u,\"latencyMs\":%.3f,\"truncated\":%s,\"clientPort\":%u,\"resolverPort\":%u,\"transport\":\"%s\"}",
                      (unsigned)tx->id, tx->query_count, tx->answer_count, tx->latency_ms,
                      tx->truncated_response ? "true" : "false", (unsigned)tx->client_port,
                      (unsigned)tx->resolver_port, tx->tcp ? "tcp" : "udp");
    }
    if (count != 0U) fputc('\n', out);
    fputs("  ],\n", out);
    (void)fprintf(out, "  \"displayedTransactions\": %llu,\n  \"transactionsOmitted\": %llu,\n  \"redacted\": {\"ips\": %s, \"names\": %s}\n}\n",
                  (unsigned long long)count,
                  (unsigned long long)(report->transaction_count - count),
                  redact_ips ? "true" : "false", redact_names ? "true" : "false");
}

static void csv_field(FILE *out, const char *value) {
    const char *p;
    fputc('"', out);
    for (p = value; *p != '\0'; ++p) {
        if (*p == '"') fputc('"', out);
        fputc(*p, out);
    }
    fputc('"', out);
}

static void csv_name(FILE *out, const char *value) {
    if (value[0] != '\0' && strchr("=+-@", value[0]) != NULL) {
        char escaped[RDT_NAME_MAX + 4U];
        /* Quoting alone does not stop spreadsheet formula interpretation. Use
           the DNS display's literal hex notation, preserving JSON evidence. */
        (void)snprintf(escaped, sizeof(escaped), "\\x%02x%s", (unsigned char)value[0], value + 1);
        csv_field(out, escaped);
    } else {
        csv_field(out, value);
    }
}

static void write_csv(FILE *out, const rdt_report *report, int redact_ips,
                      int redact_names, size_t max_results) {
    size_t i;
    size_t count = result_limit(report, max_results);
    fputs("client,resolver,name,type,status,rcode,id,queries,answers,latency_ms,truncated,client_port,resolver_port,transport\n", out);
    for (i = 0U; i < count; ++i) {
        const rdt_transaction *tx = &report->transactions[i];
        csv_field(out, redact_ips ? "<redacted>" : tx->client); fputc(',', out);
        csv_field(out, redact_ips ? "<redacted>" : tx->resolver); fputc(',', out);
        csv_name(out, redact_names ? "<redacted>" : tx->qname); fputc(',', out);
        csv_field(out, tx->qtype); fputc(',', out);
        csv_field(out, tx->has_response ? "response" : "unanswered"); fputc(',', out);
        csv_field(out, tx->has_response ? rcode_name(tx->rcode) : "-");
        (void)fprintf(out, ",%u,%u,%u,%.3f,%s,%u,%u,%s\n", (unsigned)tx->id, tx->query_count,
                      tx->answer_count, tx->latency_ms, tx->truncated_response ? "true" : "false",
                      (unsigned)tx->client_port, (unsigned)tx->resolver_port, tx->tcp ? "tcp" : "udp");
    }
}

static void write_text(FILE *out, const rdt_report *report, int redact_ips,
                       int redact_names, size_t max_results) {
    size_t i;
    size_t count = result_limit(report, max_results);
    uint64_t answered = 0U;
    uint64_t timeouts = 0U;
    for (i = 0U; i < report->transaction_count; ++i) {
        if (report->transactions[i].has_response) ++answered; else ++timeouts;
    }
    (void)fprintf(out, "Rudy DNS Trace | packets %llu | DNS %llu | queries %llu | responses %llu\n",
                  (unsigned long long)report->packets, (unsigned long long)report->dns_messages,
                  (unsigned long long)report->queries, (unsigned long long)report->responses);
    (void)fprintf(out, "Transactions %llu | answered %llu | unanswered %llu | retries %llu | unmatched replies %llu\n",
                  (unsigned long long)report->transaction_count, (unsigned long long)answered,
                  (unsigned long long)timeouts, (unsigned long long)report->retransmissions,
                  (unsigned long long)report->unmatched_responses);
    (void)fprintf(out, "Malformed packets %llu | malformed DNS %llu | truncated %llu | fragments skipped %llu | TCP DNS segments skipped %llu\n\n",
                  (unsigned long long)report->malformed_packets, (unsigned long long)report->malformed_dns,
                  (unsigned long long)report->truncated_packets, (unsigned long long)report->skipped_fragments,
                  (unsigned long long)report->tcp_dns_skipped);
    fputs("CLIENT             RESOLVER           STATUS   RCODE     MS      TYPE  NAME\n", out);
    for (i = 0U; i < count; ++i) {
        const rdt_transaction *tx = &report->transactions[i];
        (void)fprintf(out, "%-18s %-18s %-8s %-9s %7.3f %-5s %s\n",
                      redact_ips ? "<redacted>" : tx->client,
                      redact_ips ? "<redacted>" : tx->resolver,
                      tx->has_response ? "response" : "unanswered",
                      tx->has_response ? rcode_name(tx->rcode) : "-",
                      tx->latency_ms, tx->qtype,
                      redact_names ? "<redacted>" : tx->qname);
    }
    if (count < report->transaction_count)
        (void)fprintf(out, "\n... %llu transactions omitted; use --max-results 0 to show all.\n",
                      (unsigned long long)(report->transaction_count - count));
}

void rdt_write_report(FILE *out, const rdt_report *report, const char *format,
                      int redact_ips, int redact_names, size_t max_results) {
    if (strcmp(format, "json") == 0) write_json(out, report, redact_ips, redact_names, max_results);
    else if (strcmp(format, "csv") == 0) write_csv(out, report, redact_ips, redact_names, max_results);
    else write_text(out, report, redact_ips, redact_names, max_results);
}
