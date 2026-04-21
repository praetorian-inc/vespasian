# Test fixtures

## mitmproxy fixtures

| File | Source | Purpose |
|------|--------|---------|
| `sample-mitmproxy.json` | engineer-authored | JSON export format — schema reference |
| `sample-mitmproxy.mitm` | `gen_mitmproxy_native/` | Native-format fixture matching the same 3 flows as `sample-mitmproxy.json`. Used by the `import-mitmproxy-native` live test for byte-match verification. Regenerate with `go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm`. `TestMitmproxyFixture_MatchesGenerator` asserts the committed bytes match the generator output. |
| `real-mitmproxy.mitm` | [mitmproxy/mitmproxy/test/mitmproxy/data/dumpfile-7.mitm](https://github.com/mitmproxy/mitmproxy/tree/main/test/mitmproxy/data) (MIT license) | **Real** mitmproxy-produced native flow file. Vendored as-is; do not regenerate. Exercises the importer against bytes written by mitmproxy itself, protecting against schema drift between the engineer's reading of `HTTPFlow.get_state()` and what mitmproxy actually emits. Used by `TestMitmproxyImporter_Native_RealFixture`. |
