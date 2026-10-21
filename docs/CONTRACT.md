# Rudy DNS Trace contract

Rudy DNS Trace reads an offline PCAP or PCAPNG file and writes a summary plus a bounded list of DNS query transactions. It never opens a capture device, sends packets, resolves names, contacts a service, or changes system configuration.

## Supported capture records

- Classic PCAP 2.x, little- or big-endian, microsecond or nanosecond timestamps.
- PCAPNG section, interface, enhanced-packet, and simple-packet blocks; interface timestamp resolution and offset are honored.
- Ethernet with up to four VLAN tags, Linux cooked capture v1/v2, raw IPv4/IPv6, and BSD null/loopback.
- IPv4 and IPv6 UDP packets carrying port 53 DNS. IPv6 hop-by-hop, routing, destination-options, and authentication extension headers are bounded and parsed.
- DNS over TCP only when a complete length-prefixed DNS message appears in one captured packet.

Unknown link types, unsupported IP protocols, encrypted DNS, fragmented IP packets, and incomplete TCP DNS messages are skipped and counted where applicable. TCP streams are not reassembled. Packets that are truncated in the capture cannot be reconstructed.

## Correlation

Transactions are matched on the DNS identifier, client and resolver addresses, and the first question name/type. A repeated matching query before a response increments its retry count. A response with no question may match by identifier and endpoint pair. If a capture begins after a query or omits packets, a response can be reported as unmatched and an unanswered query can be a capture artifact rather than a network failure.

The tool reports the answer-section record count but does not interpret arbitrary DNS resource-record data. Its output is a packet-capture summary, not a DNSSEC validation result, resolver health verdict, or proof of malicious behavior.

## Resource limits and privacy

DNS compression pointers must point backward and are bounded. DNS message section counts are capped at 4,096 records, captured packets at 16 MiB, PCAPNG blocks at 64 MiB, interfaces at 256, and retained transactions at 50,000. Inputs exceeding a hard bound fail with an error. Classic PCAP timestamps with fractions outside their declared microsecond or nanosecond range are rejected.

Transaction output includes queried names and endpoint IP addresses unless `--redact-names` and `--redact-ips` are used. Use the redaction options before sharing reports. The original capture is never modified or uploaded.
