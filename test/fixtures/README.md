# Test fixtures

## mitmproxy fixtures

| File | Source | Purpose |
|------|--------|---------|
| `sample-mitmproxy.json` | engineer-authored | JSON export format — schema reference |
| `sample-mitmproxy.mitm` | `gen_mitmproxy_native/` | Native-format fixture matching the same 3 flows as `sample-mitmproxy.json`. Used by the `import-mitmproxy-native` live test for byte-match verification. Regenerate with `go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm`. `TestMitmproxyFixture_MatchesGenerator` asserts the committed bytes match the generator output. |
| `real-mitmproxy.mitm` | [mitmproxy@faeb9678 test/mitmproxy/data/dumpfile-7.mitm](https://github.com/mitmproxy/mitmproxy/blob/faeb9678f1e59dc19fc8a34d9d5bb262de4b6d63/test/mitmproxy/data/dumpfile-7.mitm) (MIT — see [LICENSE.mitmproxy](LICENSE.mitmproxy)) | **Real** mitmproxy-produced native flow file, vendored as-is from the pinned upstream commit above. Do not regenerate. Exercises the importer against bytes written by mitmproxy itself, protecting against schema drift between the engineer's reading of `HTTPFlow.get_state()` and what mitmproxy actually emits. Used by `TestMitmproxyImporter_Native_RealFixture`. |

## Vendored third-party content

Only `real-mitmproxy.mitm` is vendored from an external source. Its upstream copyright and MIT permission notice are preserved in [`LICENSE.mitmproxy`](LICENSE.mitmproxy) alongside the binary so the license terms travel with the file.
