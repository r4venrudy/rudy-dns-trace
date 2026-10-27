#ifndef RUDY_DNS_TRACE_H
#define RUDY_DNS_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define RDT_NAME_MAX 1024
#define RDT_ADDRESS_MAX 48
#define RDT_MAX_TRANSACTIONS 50000U

typedef struct {
    char client[RDT_ADDRESS_MAX];
    char resolver[RDT_ADDRESS_MAX];
    char qname[RDT_NAME_MAX];
    char qtype[24];
    uint16_t client_port;
    uint16_t resolver_port;
    int tcp;
    uint16_t id;
    uint32_t query_count;
    uint32_t answer_count;
    uint8_t rcode;
    double query_time;
    double response_time;
    double latency_ms;
    int has_response;
    int truncated_response;
} rdt_transaction;

typedef struct {
    uint64_t packets;
    uint64_t dns_messages;
    uint64_t queries;
    uint64_t responses;
    uint64_t retransmissions;
    uint64_t unmatched_responses;
    uint64_t malformed_packets;
    uint64_t malformed_dns;
    uint64_t truncated_packets;
    uint64_t skipped_fragments;
    uint64_t tcp_dns_skipped;
    uint64_t unsupported_link_packets;
    rdt_transaction *transactions;
    size_t transaction_count;
    size_t transaction_capacity;
    size_t *active_transaction_slots;
    size_t active_transaction_capacity;
} rdt_report;

void rdt_report_init(rdt_report *report);
void rdt_report_free(rdt_report *report);
int rdt_analyze_file(const char *path, rdt_report *report, char *error, size_t error_size);
void rdt_write_report(FILE *out, const rdt_report *report, const char *format,
                     int redact_ips, int redact_names, size_t max_results);

#endif
