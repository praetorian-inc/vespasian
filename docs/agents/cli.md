# Vespasian CLI (agent reference)

Relocated from AGENTS.md (ENG-6805).

## CLI Commands

| Command   | Purpose |
|-----------|---------|
| `scan`    | Full pipeline: crawl + classify + probe + generate. Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default true), `--merge-slugs` (default false), `--slug-threshold` (default 2), `--grpc-insecure-skip-verify` (default false; opt-in TLS trust-chain skip for gRPC reflection), `--max-requests` (default 0 = unlimited), `--interact` (default false) |
| `crawl`   | Capture traffic via headless browser → capture.json. Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default true), `--max-requests` (default 0 = unlimited), `--interact` (default false) |
| `import`  | Convert Burp XML / HAR / mitmproxy → capture.json |
| `generate` | Produce spec from capture.json (REST→OpenAPI, GraphQL→SDL, WSDL→WSDL, gRPC→`.proto`). Flags: `--analyze-js` (default true), `--fetch-sourcemaps` (default false), `--merge-slugs` (default false), `--slug-threshold` (default 2), `--grpc-insecure-skip-verify` (default false), `--header`/`-H` (repeatable auth headers forwarded to same-origin JS-replay fetches/probes), `--target-url` (trusted origin for probe gating and generated server metadata; also overrides the capture-derived JS-replay origin). `grpc` must be passed explicitly. Live `generate grpc` with `--probe` (default on) re-runs server reflection against reachable targets (`FileDescriptors` is `json:"-"` in the capture). Capture-only recovery does not need live reflection: grpc-gateway OpenAPI and gRPC-Web bindings feed `FileDescriptorsFromServices`, which synthesizes descriptors. |
| `version` | Show version information |
