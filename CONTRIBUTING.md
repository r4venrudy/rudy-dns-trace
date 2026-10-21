# Contributing

Small, focused fixes and tests are welcome.

1. Build with CMake and a C11 compiler.
2. Run `ctest --test-dir build --output-on-failure`.
3. Add a regression case for parser-boundary changes, using synthetic packets rather than real traffic.
4. Keep offline-only behavior, bounded parsing, and report redaction intact.

Please do not include private packet captures, credentials, or customer data in issues or pull requests.
