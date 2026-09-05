# Vespasian CLI (agent reference)

Relocated from AGENTS.md (ENG-6805).

## CLI Commands

| Command   | Purpose |
|-----------|---------|
| `scan`    | Full pipeline: crawl + classify + probe + generate. Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default true), `--merge-slugs` (default false), `--slug-threshold` (default 2), `--grpc-insecure-skip-verify` (default false; opt-in TLS trust-chain skip for gRPC reflection), `--max-requests` (default 0 = unlimited), `--interact` (default false) |
| `crawl`   | Capture traffic via headless browser → capture.json. Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default true), `--max-requests` (default 0 = unlimited), `--interact` (default false) |
| `import`  | Convert Burp XML / HAR / mitmproxy → capture.json |
| `generate` | Produce spec from capture.json (REST→OpenAPI, GraphQL→SDL, WSDL→WSDL, gRPC→`.proto`). Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default false), `--merge-slugs` (default false), `--slug-threshold` (default 2), `--grpc-insecure-skip-verify` (default false), `--header`/`-H` (repeatable auth headers forwarded to same-origin JS-replay fetches/probes), `--target-url` (override the capture-derived JS-replay origin). `grpc` must be passed explicitly; unlike the other types it is **not** fully offline — descriptors are not stored in the capture (`FileDescriptors` is `json:"-"`), so `generate grpc` re-runs the reflection probe live against the gRPC targets in the capture (needs `--probe`, on by default, and target reachability). |
| `version` | Show version information |
