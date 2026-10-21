#include "rudy_dns_trace.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message) do { \
    ++checks; \
    if (!(condition)) { (void)fprintf(stderr, "check failed: %s\n", message); return 0; } \
} while (0)

static unsigned checks;

static void put_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffU); p[1] = (uint8_t)(v >> 8U);
}

static void put_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffU); p[1] = (uint8_t)((v >> 8U) & 0xffU);
    p[2] = (uint8_t)((v >> 16U) & 0xffU); p[3] = (uint8_t)(v >> 24U);
}

static size_t make_dns(uint8_t *out, int response, int answer, int compression_loop) {
    size_t n = 0U;
    memset(out, 0, 128U);
    out[n++] = 0x12U; out[n++] = 0x34U;
    out[n++] = response ? 0x81U : 0x01U;
    out[n++] = response ? 0x80U : 0x00U;
    out[n++] = 0x00U; out[n++] = 0x01U;
    out[n++] = 0x00U; out[n++] = answer ? 0x01U : 0x00U;
    out[n++] = 0x00U; out[n++] = 0x00U;
    out[n++] = 0x00U; out[n++] = 0x00U;
    if (compression_loop) {
        out[n++] = 0xc0U; out[n++] = 0x0cU;
        out[n++] = 0x00U; out[n++] = 0x01U;
        out[n++] = 0x00U; out[n++] = 0x01U;
        return n;
    }
    out[n++] = 7U; memcpy(out + n, "example", 7U); n += 7U;
    out[n++] = 3U; memcpy(out + n, "com", 3U); n += 3U;
    out[n++] = 0U;
    out[n++] = 0x00U; out[n++] = 0x01U;
    out[n++] = 0x00U; out[n++] = 0x01U;
    if (answer) {
        out[n++] = 0xc0U; out[n++] = 0x0cU;
        out[n++] = 0x00U; out[n++] = 0x01U;
        out[n++] = 0x00U; out[n++] = 0x01U;
        out[n++] = 0U; out[n++] = 0U; out[n++] = 0U; out[n++] = 60U;
        out[n++] = 0U; out[n++] = 4U;
        out[n++] = 203U; out[n++] = 0U; out[n++] = 113U; out[n++] = 5U;
    }
    return n;
}

static size_t make_ipv4_frame(uint8_t *out, const uint8_t *dns, size_t dns_length,
                              int response, int vlan) {
    size_t eth = vlan ? 18U : 14U;
    size_t ip = eth;
    size_t udp = ip + 20U;
    size_t payload = udp + 8U;
    size_t total = payload + dns_length;
    memset(out, 0, 512U);
    out[12] = vlan ? 0x81U : 0x08U;
    out[13] = vlan ? 0x00U : 0x00U;
    if (vlan) { out[14] = 0U; out[15] = 1U; out[16] = 0x08U; out[17] = 0U; }
    out[ip] = 0x45U;
    out[ip + 2U] = (uint8_t)((20U + 8U + dns_length) >> 8U);
    out[ip + 3U] = (uint8_t)(20U + 8U + dns_length);
    out[ip + 8U] = 64U;
    out[ip + 9U] = 17U;
    if (response) {
        out[ip + 12U] = 192U; out[ip + 13U] = 0U; out[ip + 14U] = 2U; out[ip + 15U] = 53U;
        out[ip + 16U] = 192U; out[ip + 17U] = 0U; out[ip + 18U] = 2U; out[ip + 19U] = 10U;
        out[udp] = 0U; out[udp + 1U] = 53U; out[udp + 2U] = 0xcfU; out[udp + 3U] = 0x08U;
    } else {
        out[ip + 12U] = 192U; out[ip + 13U] = 0U; out[ip + 14U] = 2U; out[ip + 15U] = 10U;
        out[ip + 16U] = 192U; out[ip + 17U] = 0U; out[ip + 18U] = 2U; out[ip + 19U] = 53U;
        out[udp] = 0xcfU; out[udp + 1U] = 0x08U; out[udp + 2U] = 0U; out[udp + 3U] = 53U;
    }
    out[udp + 4U] = (uint8_t)((8U + dns_length) >> 8U);
    out[udp + 5U] = (uint8_t)(8U + dns_length);
    memcpy(out + payload, dns, dns_length);
    return total;
}

static size_t make_ipv6_raw(uint8_t *out, const uint8_t *dns, size_t dns_length) {
    size_t total = 40U + 8U + dns_length;
    memset(out, 0, 256U);
    out[0] = 0x60U;
    out[4] = (uint8_t)((8U + dns_length) >> 8U);
    out[5] = (uint8_t)(8U + dns_length);
    out[6] = 17U;
    out[7] = 64U;
    out[8] = 0x20U; out[9] = 0x01U; out[10] = 0x0dU; out[11] = 0xb8U;
    out[23] = 0x10U;
    out[24] = 0x20U; out[25] = 0x01U; out[26] = 0x0dU; out[27] = 0xb8U;
    out[39] = 0x35U;
    out[40] = 0xcfU; out[41] = 0x08U; out[42] = 0U; out[43] = 53U;
    out[44] = (uint8_t)((8U + dns_length) >> 8U);
    out[45] = (uint8_t)(8U + dns_length);
    memcpy(out + 48U, dns, dns_length);
    return total;
}

static int write_classic(const char *path, uint32_t linktype,
                         const uint8_t *const *packets, const size_t *lengths,
                         const uint32_t *seconds, const uint32_t *fractions, size_t count) {
    FILE *file = fopen(path, "wb");
    size_t i;
    uint8_t header[24] = {0xd4U, 0xc3U, 0xb2U, 0xa1U};
    if (file == NULL) return 0;
    put_u16le(header + 4U, 2U); put_u16le(header + 6U, 4U);
    put_u32le(header + 16U, 65535U); put_u32le(header + 20U, linktype);
    if (fwrite(header, 1U, sizeof(header), file) != sizeof(header)) { fclose(file); return 0; }
    for (i = 0U; i < count; ++i) {
        uint8_t record[16];
        put_u32le(record, seconds[i]); put_u32le(record + 4U, fractions[i]);
        put_u32le(record + 8U, (uint32_t)lengths[i]); put_u32le(record + 12U, (uint32_t)lengths[i]);
        if (fwrite(record, 1U, sizeof(record), file) != sizeof(record) ||
            fwrite(packets[i], 1U, lengths[i], file) != lengths[i]) { fclose(file); return 0; }
    }
    return fclose(file) == 0;
}

static int write_pcapng(const char *path, const uint8_t *query, size_t query_length,
                        const uint8_t *response, size_t response_length) {
    FILE *file = fopen(path, "wb");
    uint8_t shb[28] = {0x0aU, 0x0dU, 0x0dU, 0x0aU};
    uint8_t idb[20] = {1U, 0U, 0U, 0U};
    uint8_t epb[512];
    const uint8_t *packets[2] = {query, response};
    size_t lengths[2] = {query_length, response_length};
    size_t i;
    if (file == NULL) return 0;
    put_u32le(shb + 4U, 28U); shb[8] = 0x4dU; shb[9] = 0x3cU; shb[10] = 0x2bU; shb[11] = 0x1aU;
    put_u16le(shb + 12U, 1U); put_u16le(shb + 14U, 0U);
    memset(shb + 16U, 0xff, 8U); put_u32le(shb + 24U, 28U);
    put_u32le(idb + 4U, 20U); put_u16le(idb + 8U, 1U); put_u32le(idb + 12U, 65535U); put_u32le(idb + 16U, 20U);
    if (fwrite(shb, 1U, sizeof(shb), file) != sizeof(shb) || fwrite(idb, 1U, sizeof(idb), file) != sizeof(idb)) { fclose(file); return 0; }
    for (i = 0U; i < 2U; ++i) {
        size_t padded = (lengths[i] + 3U) & ~(size_t)3U;
        size_t total = 32U + padded;
        memset(epb, 0, total);
        put_u32le(epb, 6U); put_u32le(epb + 4U, (uint32_t)total);
        put_u32le(epb + 8U, 0U); put_u32le(epb + 12U, 0U);
        put_u32le(epb + 16U, i == 0U ? 10000000U : 10025000U);
        put_u32le(epb + 20U, (uint32_t)lengths[i]); put_u32le(epb + 24U, (uint32_t)lengths[i]);
        memcpy(epb + 28U, packets[i], lengths[i]); put_u32le(epb + total - 4U, (uint32_t)total);
        if (fwrite(epb, 1U, total, file) != total) { fclose(file); return 0; }
    }
    return fclose(file) == 0;
}

static int test_classic_and_outputs(void) {
    uint8_t query_dns[128], answer_dns[128], query_frame[512], retry_frame[512], answer_frame[512];
    size_t qn = make_dns(query_dns, 0, 0, 0);
    size_t an = make_dns(answer_dns, 1, 1, 0);
    size_t qf = make_ipv4_frame(query_frame, query_dns, qn, 0, 0);
    size_t rf = make_ipv4_frame(retry_frame, query_dns, qn, 0, 1);
    size_t af = make_ipv4_frame(answer_frame, answer_dns, an, 1, 0);
    const uint8_t *packets[3] = {query_frame, retry_frame, answer_frame};
    size_t lengths[3] = {qf, rf, af};
    uint32_t seconds[3] = {10U, 10U, 10U};
    uint32_t fractions[3] = {0U, 5000U, 25000U};
    rdt_report report;
    char error[256] = {0};
    FILE *out;
    char text[4096];
    size_t read_count;

    CHECK(write_classic("rdt-test-classic.pcap", 1U, packets, lengths, seconds, fractions, 3U), "write classic PCAP fixture");
    rdt_report_init(&report);
    CHECK(rdt_analyze_file("rdt-test-classic.pcap", &report, error, sizeof(error)), error);
    CHECK(report.packets == 3U && report.dns_messages == 3U, "classic PCAP and VLAN packets decode");
    CHECK(report.queries == 2U && report.responses == 1U && report.retransmissions == 1U, "retry is correlated into one query");
    CHECK(report.transaction_count == 1U && report.transactions[0].has_response, "reply closes the transaction");
    CHECK(strcmp(report.transactions[0].qname, "example.com") == 0, "DNS name is decoded");
    CHECK(strcmp(report.transactions[0].qtype, "A") == 0, "DNS query type is decoded");
    CHECK(report.transactions[0].rcode == 0U && report.transactions[0].answer_count == 1U, "answer count and response code are reported");
    CHECK(fabs(report.transactions[0].latency_ms - 25.0) < 0.01, "transaction latency uses capture timestamps");
    CHECK(report.malformed_dns == 0U && report.malformed_packets == 0U, "valid packets produce no parse warnings");
    out = tmpfile();
    CHECK(out != NULL, "temporary report stream opens");
    rdt_write_report(out, &report, "json", 1, 1, 1U);
    rewind(out);
    read_count = fread(text, 1U, sizeof(text) - 1U, out);
    text[read_count] = '\0';
    CHECK(strstr(text, "\"client\":\"<redacted>\"") != NULL, "JSON report redacts addresses");
    CHECK(strstr(text, "\"name\":\"<redacted>\"") != NULL, "JSON report redacts names");
    fclose(out);
    rdt_report_free(&report);
    return 1;
}

static int test_pcapng(void) {
    uint8_t qdns[128], adns[128], qframe[512], aframe[512];
    size_t qn = make_dns(qdns, 0, 0, 0), an = make_dns(adns, 1, 0, 0);
    size_t qf = make_ipv4_frame(qframe, qdns, qn, 0, 0), af = make_ipv4_frame(aframe, adns, an, 1, 0);
    rdt_report report;
    char error[256] = {0};
    CHECK(write_pcapng("rdt-test-ng.pcapng", qframe, qf, aframe, af), "write PCAPNG fixture");
    rdt_report_init(&report);
    CHECK(rdt_analyze_file("rdt-test-ng.pcapng", &report, error, sizeof(error)), error);
    CHECK(report.packets == 2U && report.queries == 1U && report.responses == 1U, "PCAPNG section, interface, and packet blocks decode");
    CHECK(report.transaction_count == 1U && report.transactions[0].has_response, "PCAPNG DNS exchange correlates");
    CHECK(fabs(report.transactions[0].latency_ms - 25.0) < 0.01, "PCAPNG timestamp resolution defaults to microseconds");
    rdt_report_free(&report);
    return 1;
}

static int test_ipv6_and_malformed_dns(void) {
    uint8_t dns[128], raw[256], malformed[128], frame[512];
    size_t dns_length = make_dns(dns, 0, 0, 0);
    size_t raw_length = make_ipv6_raw(raw, dns, dns_length);
    uint32_t seconds[1] = {1U}, fractions[1] = {0U};
    const uint8_t *packets[1] = {raw};
    size_t lengths[1] = {raw_length};
    rdt_report report;
    char error[256] = {0};
    size_t malformed_dns_length = make_dns(malformed, 0, 0, 1);
    size_t malformed_frame_length = make_ipv4_frame(frame, malformed, malformed_dns_length, 0, 0);
    const uint8_t *bad_packets[1] = {frame};
    size_t bad_lengths[1] = {malformed_frame_length};

    CHECK(write_classic("rdt-test-v6.pcap", 101U, packets, lengths, seconds, fractions, 1U), "write raw IPv6 fixture");
    rdt_report_init(&report);
    CHECK(rdt_analyze_file("rdt-test-v6.pcap", &report, error, sizeof(error)), error);
    CHECK(report.queries == 1U && strcmp(report.transactions[0].client, "2001:db8:0:0:0:0:0:10") == 0, "raw IPv6 packet and address decode");
    rdt_report_free(&report);

    CHECK(write_classic("rdt-test-loop.pcap", 1U, bad_packets, bad_lengths, seconds, fractions, 1U), "write DNS compression loop fixture");
    rdt_report_init(&report);
    CHECK(rdt_analyze_file("rdt-test-loop.pcap", &report, error, sizeof(error)), error);
    CHECK(report.malformed_dns == 1U && report.transaction_count == 0U, "self-referential DNS compression pointer fails closed");
    rdt_report_free(&report);
    return 1;
}

static int test_parallel_transaction_correlation(void) {
    uint8_t packets_storage[6][512];
    uint8_t dns[128];
    const uint8_t *packets[6];
    size_t lengths[6];
    uint32_t seconds[6] = {1U, 1U, 1U, 1U, 1U, 1U};
    uint32_t fractions[6] = {0U, 1000U, 2000U, 10000U, 11000U, 12000U};
    rdt_report report;
    char error[256] = {0};
    size_t i;

    for (i = 0U; i < 3U; ++i) {
        size_t dns_length = make_dns(dns, 0, 0, 0);
        dns[0] = 0x20U;
        dns[1] = (uint8_t)i;
        dns[13] = (uint8_t)('a' + i);
        lengths[i] = make_ipv4_frame(packets_storage[i], dns, dns_length, 0, 0);
        packets[i] = packets_storage[i];
    }
    for (i = 0U; i < 3U; ++i) {
        size_t dns_length = make_dns(dns, 1, 1, 0);
        dns[0] = 0x20U;
        dns[1] = (uint8_t)i;
        dns[13] = (uint8_t)('a' + i);
        lengths[i + 3U] = make_ipv4_frame(packets_storage[i + 3U], dns, dns_length, 1, 0);
        packets[i + 3U] = packets_storage[i + 3U];
    }
    CHECK(write_classic("rdt-test-parallel.pcap", 1U, packets, lengths, seconds, fractions, 6U),
          "write parallel transaction fixture");
    rdt_report_init(&report);
    CHECK(rdt_analyze_file("rdt-test-parallel.pcap", &report, error, sizeof(error)), error);
    CHECK(report.queries == 3U && report.responses == 3U && report.transaction_count == 3U,
          "distinct in-flight DNS requests stay separate");
    CHECK(report.unmatched_responses == 0U && report.transactions[0].has_response &&
          report.transactions[1].has_response && report.transactions[2].has_response,
          "indexed replies match the correct pending transactions");
    rdt_report_free(&report);
    return 1;
}

static int test_truncated_capture(void) {
    FILE *file = fopen("rdt-test-bad.pcap", "wb");
    rdt_report report;
    char error[256] = {0};
    uint8_t partial[5] = {0xd4U, 0xc3U, 0xb2U, 0xa1U, 0x02U};
    int ok;
    if (file == NULL) return 0;
    (void)fwrite(partial, 1U, sizeof(partial), file);
    fclose(file);
    rdt_report_init(&report);
    ok = !rdt_analyze_file("rdt-test-bad.pcap", &report, error, sizeof(error)) &&
         strstr(error, "truncated") != NULL;
    rdt_report_free(&report);
    ++checks;
    if (!ok) (void)fprintf(stderr, "check failed: truncated capture is rejected\n");
    return ok;
}

int main(void) {
    if (!test_classic_and_outputs() || !test_pcapng() ||
        !test_ipv6_and_malformed_dns() || !test_parallel_transaction_correlation() ||
        !test_truncated_capture()) return 1;
    (void)printf("Rudy DNS Trace: %u checks passed\n", checks);
    return 0;
}
