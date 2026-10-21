# Example workflow

Use a capture from your own lab or an assessment where you have permission. Avoid sharing raw captures: DNS names and client addresses can expose private activity.

```sh
rudy-dns-trace analyze lab-session.pcapng --format text
rudy-dns-trace analyze lab-session.pcapng --format json --redact-ips --redact-names > sanitized-report.json
```

The tests create a synthetic fixture with one `example.com A` query, a repeated query, and a matching reply. A representative transaction row is:

```text
CLIENT             RESOLVER           STATUS   RCODE     MS      TYPE  NAME
192.0.2.10         192.0.2.53         response NOERROR   25.000 A     example.com
```

`192.0.2.0/24` is reserved for documentation. The row above is illustrative test data, not a measurement from a real network. To inspect generated fixtures, build the project and run `ctest --test-dir build`; the test binary writes its fixtures to the build directory before parsing them.
