# Security policy

Rudy DNS Trace is an offline parser for capture files. Treat capture files as untrusted input and use a current release. The parser enforces explicit packet, block, transaction, interface, and DNS section limits; CI runs AddressSanitizer and UndefinedBehaviorSanitizer on Linux.

Please report suspected vulnerabilities privately to the repository owner through GitHub's security advisory feature. Include the release or commit, the input format, and a minimized reproduction when possible. Do not include real user traffic or credentials in a public issue.

The tool does not sniff live interfaces, transmit traffic, or access external services.
