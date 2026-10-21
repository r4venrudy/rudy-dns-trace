#include "rudy_dns_trace.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out) {
    fputs("Rudy DNS Trace - offline DNS analysis for PCAP and PCAPNG\n\n"
          "Usage:\n"
          "  rudy-dns-trace analyze <capture> [options]\n"
          "  rudy-dns-trace --help\n\n"
          "Options:\n"
          "  --format text|json|csv  Report format (default: text)\n"
          "  --redact-ips            Replace client and resolver addresses\n"
          "  --redact-names          Replace queried DNS names\n"
          "  --max-results N         Show first N transactions (default: 100; 0: all)\n"
          "\nReads saved captures only. It does not sniff live traffic or change the host.\n"
          "TCP DNS messages split across packets are not reassembled.\n", out);
}

static int parse_limit(const char *text, size_t *value) {
    char *end = NULL;
    unsigned long long parsed;
    if (text == NULL || *text == '\0' || *text == '-') return 0;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > (unsigned long long)SIZE_MAX) return 0;
    *value = (size_t)parsed;
    return 1;
}

int main(int argc, char **argv) {
    const char *capture = NULL;
    const char *format = "text";
    size_t max_results = 100U;
    int redact_ips = 0;
    int redact_names = 0;
    int i;
    char error[256] = {0};
    rdt_report report;

    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc < 3 || strcmp(argv[1], "analyze") != 0) {
        usage(stderr);
        return 2;
    }
    capture = argv[2];
    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--redact-ips") == 0) redact_ips = 1;
        else if (strcmp(argv[i], "--redact-names") == 0) redact_names = 1;
        else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) format = argv[++i];
        else if (strcmp(argv[i], "--max-results") == 0 && i + 1 < argc) {
            if (!parse_limit(argv[++i], &max_results)) {
                fputs("error: --max-results must be a non-negative integer\n", stderr);
                return 2;
            }
        } else {
            (void)fprintf(stderr, "error: unknown or incomplete option: %s\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }
    if (strcmp(format, "text") != 0 && strcmp(format, "json") != 0 && strcmp(format, "csv") != 0) {
        fputs("error: --format must be text, json, or csv\n", stderr);
        return 2;
    }

    rdt_report_init(&report);
    if (!rdt_analyze_file(capture, &report, error, sizeof(error))) {
        (void)fprintf(stderr, "error: %s\n", error[0] == '\0' ? "capture could not be parsed" : error);
        rdt_report_free(&report);
        return 2;
    }
    rdt_write_report(stdout, &report, format, redact_ips, redact_names, max_results);
    rdt_report_free(&report);
    if (ferror(stdout)) {
        fputs("error: failed while writing report\n", stderr);
        return 1;
    }
    return 0;
}
