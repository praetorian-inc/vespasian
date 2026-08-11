# Test fixtures

## mitmproxy fixtures

| File | Source | Purpose |
|------|--------|---------|
| `sample-mitmproxy.json` | engineer-authored | JSON export format — schema reference |
| `sample-mitmproxy.mitm` | `gen_mitmproxy_native/` | Native-format fixture matching the same 3 flows as `sample-mitmproxy.json`. Used by the `import-mitmproxy-native` live test for byte-match verification. Regenerate with `go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm`. `TestMitmproxyFixture_MatchesGenerator` asserts the committed bytes match the generator output. |
| `real-mitmproxy.mitm` | [mitmproxy@faeb9678 test/mitmproxy/data/dumpfile-7.mitm](https://github.com/mitmproxy/mitmproxy/blob/faeb9678f1e59dc19fc8a34d9d5bb262de4b6d63/test/mitmproxy/data/dumpfile-7.mitm) (MIT — see [LICENSE.mitmproxy](LICENSE.mitmproxy)) | **Real** mitmproxy-produced native flow file, vendored as-is from the pinned upstream commit above. Do not regenerate. Exercises the importer against bytes written by mitmproxy itself, protecting against schema drift between the engineer's reading of `HTTPFlow.get_state()` and what mitmproxy actually emits. Used by `TestMitmproxyImporter_Native_RealFixture`. |

## PGP key fixtures

| File | Source | Purpose |
|------|--------|---------|
| `google-linux-signing-key.asc` | [`https://dl.google.com/linux/linux_signing_key.pub`](https://dl.google.com/linux/linux_signing_key.pub) — vendored as-is | **Real** Google Linux package-signing key bundle, carrying primary fingerprint `EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796`. The sole input to `install-chrome-selftest.sh` cases j/j2/v/y — the trust anchor's only success-path coverage. Refreshing this file is the **same event** as changing `GOOGLE_KEY_FPR` in [`../install-chrome.sh`](../install-chrome.sh): if Google rotates its primary key, both must move together, deliberately, in one commit. Regenerate with `curl -fsSL https://dl.google.com/linux/linux_signing_key.pub -o test/fixtures/google-linux-signing-key.asc` and re-derive the fingerprint with `gpg --show-keys --with-colons --with-fingerprint <file>`. `install-chrome-selftest.sh` refuses to run cases j/j2 if the committed bytes no longer carry the pinned fingerprint, so a silent swap fails loudly rather than passing vacuously. |
| `not-google-signing-key.asc` | Ubuntu archive signing key (2012), public by definition | An arbitrary well-formed key used ONLY as a "not Google's key" sample, proving the pinned-fingerprint check rejects a key it does not expect. Carries fingerprint `790BC7277767219C42C86F933B4FE6ACC0B21F32`, which case f asserts verbatim. Contains no secret material and is trusted by nothing in this repo; any valid key would do. |

Both are PGP **public** keys. Neither carries secret material, so neither is a credential.

## Vendored third-party content

`real-mitmproxy.mitm` and `google-linux-signing-key.asc` are vendored from external sources; `not-google-signing-key.asc` is a public archive key reproduced as sample material. `real-mitmproxy.mitm`'s upstream copyright and MIT permission notice are preserved in [`LICENSE.mitmproxy`](LICENSE.mitmproxy) alongside the binary so the license terms travel with the file. The two `.asc` files are published public keys distributed for verification purposes and carry no accompanying licence text; their provenance is recorded in the table above.
