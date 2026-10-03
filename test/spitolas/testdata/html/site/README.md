# Crawljax test site

Static fixtures for the spitolas crawler integration tests (`-tags=integration`,
run by `make test-browser-conformance`). The test servers in
`pkg/spitolas/internal/testutil/testserver.go` serve this tree; the tests that
use it are ports of Crawljax's own crawler tests, so their expected state and
edge counts assume these exact pages.

- Source: https://github.com/crawljax/crawljax, `core/src/test/resources/site/`
- Revision: `5771f6161c645c75f710a8cdc14e3c6898727e06` (2023-06-19)
- License: Apache License 2.0 (see `LICENSE` in this directory)

Copied unmodified apart from adding this README and the license file. Keep it
byte-identical to upstream so a test failure points at the crawler, not at a
drifted fixture.
