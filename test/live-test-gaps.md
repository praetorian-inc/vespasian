# Live Test Coverage Gaps

Documents what the CI live test suite covers versus known gaps.
Updated as part of LAB-4012 (live tests in GitHub Actions).

## Covered by CI

### Offline tests (no services, no Chrome)

| Target | What it validates |
|--------|-------------------|
| import-burp | Burp XML import, JSON golden-file comparison |
| import-har | HAR import, request count and URL validation |
| import-base64 | Base64-encoded Burp XML import |
| import-mitmproxy | mitmproxy JSON export import |
| import-mitmproxy-native | mitmproxy native tnetstring format import |
| import-unicode | Unicode/emoji content in Burp XML |
| import-duplicates | Duplicate headers/params in HAR |
| import-malformed | Graceful failure on truncated/invalid input |
| import-empty | Zero-entry imports produce null output |
| generate-rest | OpenAPI generation, golden-file diff |
| generate-wsdl | WSDL generation, golden-file diff |
| generate-wsdl-matrix | SOAP 1.1/1.2, RPC/doc/literal param extraction |
| generate-graphql | GraphQL SDL generation, golden-file diff |
| generate-graphql-imports | Import then generate SDL from Burp XML and HAR |
| generate-js-static | JS bundle static analysis with --analyze-js |
| generate-merge-slugs | Slug merging opt-in vs default behavior |
| crawl-unreachable | No crash/panic on unreachable host |
| classifier-edge | RSS feeds, versioned paths, mismatched content-types |
| spec-edge | UUID paths, numeric IDs, multi-param paths |

### Live tests (require services + Chrome)

| Target | What it validates |
|--------|-------------------|
| rest-api | REST crawl (both backends), OpenAPI path coverage, static asset exclusion |
| soap-service | SOAP traffic generation, WSDL operation extraction |
| graphql-server | GraphQL queries/mutations, SDL structure, introspection quality, SPA fetch capture |
| concat-spa | JS concat/plus-chain extraction, exact path count, forbidden path absence |
| edge-cases | Large responses, URL encoding, redirects, HTTP errors, binary exclusion |
| crawl-depth | Depth limiting, max-pages, infinite loop detection |
| forms-target | HTML `<form>` extraction (LAB-2109): POST form endpoints recovered via `analyze.ExtractForms`, GET form query params merged into the spec |

## Known gaps

- **Path parameterization validation**: `validate_path_coverage` treats `{param}` as a wildcard matching any segment, so parameterization regressions (e.g., literal `/users/1` instead of `/users/{id}`) are invisible to live tests. Only the offline golden-file diffs catch these.
- **SOAP body-based detection**: All SOAP test traffic includes `SOAPAction` headers; the body-based `hasSoapEnvelope` fallback (Signal 2) is never the primary classifier. See LAB-4698.
- **Pipeline `IsStaticAssetURL`**: The pipeline's static asset filter is only used in the SDK capability path, not the CLI path the live tests exercise. See LAB-4698.
- **Static extension list drift**: `internal/pipeline/static_asset.go:staticAssetExtensions` and `pkg/classify/rest.go:staticExtensions` are independent lists with no synchronization test. See LAB-4698.
- **SDK/capability path**: `pkg/sdk` is not exercised by any live test; only the CLI pipeline is tested.
- **Sourcemap fetching**: `--fetch-sourcemaps` is not exercised by any live test target.
