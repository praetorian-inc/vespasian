# Vespasian Live Test Suite

End-to-end live tests that spin up intentionally simple target applications, run vespasian against them, and validate the generated API specifications.

## Quick Start

```bash
# 1. Setup: build binaries, resolve ports, start services
./test/setup-live-targets.sh

# 2. Run: crawl targets, generate specs, validate output
./test/run-live-tests.sh

# 3. Teardown: stop services, clean up
./test/setup-live-targets.sh --teardown
```

## Prerequisites

- **Go 1.25+** — [https://go.dev/dl/](https://go.dev/dl/)
- **Chrome/Chromium** — Required for headless crawling
- **python3** — Required for test validation scripts
- **Node.js** — Required for the graphql-server target

## Targets

| Target | Protocol | Description | Infrastructure |
|--------|----------|-------------|----------------|
| rest-api | REST | Custom API with users, products, orders endpoints | Go binary |
| soap-service | SOAP/WSDL | Custom SOAP service with GetUser, ListUsers, CreateUser | Go binary |
| graphql-server | GraphQL | Apollo Server with queries, mutations, enums, unions, nested types | Node.js |
| grpc-server | gRPC | Three reflectable gRPC services (UserService, OrderService, AccountService) | Go binary |

## What the Test Runner Does

For each target:

1. **Build** vespasian and target binaries
2. **Start** target services (with auto-resolved ports)
3. **Crawl** — `vespasian crawl <url> --dangerous-allow-private -o capture.json`
4. **Validate capture** — Check request count and expected URLs
5. **Generate** — `vespasian generate <type> capture.json -o spec.<ext>`
6. **Validate spec** — Path/operation coverage, schema structure, no static assets
7. **Print summary** — Pass/fail status with endpoint counts and durations

> **Why `--dangerous-allow-private`?** All live targets run on `localhost`, which the crawler's SSRF gate treats as a private host. The flag is required on every `vespasian crawl` invocation in this suite; running without it will exit non-zero with `seed URL rejected by frontier ...`. The flag name reflects production-risk semantics — pass it only when you intend to crawl a known-private host (e.g., this suite, or an internal-network assessment).

For the GraphQL live test (`graphql-server`):

1. **Send** real GraphQL queries to the running Apollo Server
2. **Capture** traffic as a vespasian capture file
3. **Generate** — `vespasian generate graphql capture.json --dangerous-allow-private` (with introspection probe)
4. **Validate** — SDL structure, expected operations, introspection-quality checks (schema block, non-null types, enums)

For deterministic GraphQL tests (`generate-graphql`, `generate-graphql-imports`):

1. **Generate** SDL from fixed reference capture or imported Burp/HAR files
2. **Diff** against expected SDL (byte-identical comparison)

For the JS bundle static-analysis test (`generate-js-static`, offline — no server or browser):

1. **Generate** an OpenAPI spec from `js-static/reference-capture.json` (one HTML page + one JS bundle containing a `fetch` POST with a JSON body, an `axios` GET, and a template-literal GET) with `--analyze-js --confidence 0.1 --probe=false`
2. **Assert** the recovered path count matches `js-static/expected-paths.json` and every operation carries `x-vespasian-source: js-bundle`
3. **Assert opt-out** — re-generating with `--analyze-js=false` yields zero `/api` paths and no `x-vespasian-source` extension

For the slug-merging test (`generate-merge-slugs`, offline — no server or browser):

1. **Generate** an OpenAPI spec from `fixtures/merge-slugs-capture.json` (two slug siblings `/api/posts/hello-world`, `/api/posts/my-trip` plus numeric-ID siblings `/api/users/42`, `/api/users/99`) with `--probe=false`
2. **Assert default (off)** — both `/api/posts/*` siblings survive as distinct paths (the LAB-4107 regression guard) while `/api/users/{userId}` is still ID-normalized
3. **Assert `--merge-slugs`** — the slug siblings collapse to `/api/posts/{postSlug}` and `/api/users/{userId}` normalization is unaffected

For importer tests:

1. **Import** — `vespasian import burp fixtures/sample-burp-export.xml -o imported.json`
2. **Validate** — Request count, expected URLs and methods

## Scripts

### setup-live-targets.sh

```bash
./test/setup-live-targets.sh [options]

Options:
  --targets <list>   Comma-separated targets (default: all)
                     Valid: rest-api,soap-service,graphql-server,grpc-server
  --skip-start       Only build, don't start services
  --teardown         Stop all running targets and clean up
  --sweep            With --teardown, also sweep untracked orphans by name/port
  --help             Show this help message
```

The script is resilient to repeated runs: every started PID is recorded (per
service, appended across runs), so `--teardown` kills **every** generation, not
just the most recent. Running setup again without a teardown first detects and
kills the stale processes from the previous run (logged as `Killing stale
process …`) before starting fresh, so orphans never accumulate and exhaust the
port range.

Because every generation is recorded, normal teardown never needs to guess which
processes are ours. The broad orphan sweep — killing by executable basename (Go
targets) or any `node` listening in the graphql port window — is therefore
**opt-in** via `--sweep`, and off by default: it matches purely by name/port and
could otherwise kill an unrelated process (a developer's own same-named service,
or any `node` on those ports). Reach for it only to recover a pre-existing orphan
whose pid log was lost:

```bash
make live-test-clean                        # == --teardown; kills recorded PIDs only (safe)
./test/setup-live-targets.sh --teardown --sweep   # also sweep untracked orphans (last resort)
```

A regression test (`test/setup-live-targets_test.sh`) covers the
teardown/sweep/port-exhaustion behavior with lightweight stand-ins and needs no
live services — run it directly: `./test/setup-live-targets_test.sh`.

### run-live-tests.sh

```bash
./test/run-live-tests.sh [options]

Options:
  --targets <list>      Comma-separated targets to test (default: all)
                        Valid targets:
                          Live:       rest-api, soap-service, graphql-server,
                                      grpc-server
                          Generate:   generate-rest, generate-wsdl, generate-wsdl-matrix,
                                      generate-graphql, generate-graphql-imports,
                                      generate-js-static, generate-merge-slugs
                          Import:     import-burp, import-har, import-base64,
                                      import-mitmproxy, import-mitmproxy-native,
                                      import-unicode, import-duplicates,
                                      import-malformed, import-empty
                          Crawl:      crawl-depth, crawl-unreachable
                          Edge cases: edge-cases, classifier-edge, spec-edge
  --verbose             Enable verbose vespasian output
  --no-build            Skip building vespasian and target binaries
  --no-start            Don't start/stop services (assume already running)
  --help                Show this help message
```

## Configuration

### `TEST_HOST` (optional)

`run-live-tests.sh` reaches the target services at `http://${TEST_HOST:-localhost}:<port>`. The default (`localhost`) is correct when the harness and the targets run on the same host.

Override `TEST_HOST` when the harness runs inside a devcontainer while the target services run on the Docker host. Example (Docker Desktop):

```bash
TEST_HOST=host.docker.internal ./test/run-live-tests.sh --targets rest-api
```

For Linux devcontainers without Docker Desktop, use the detected host gateway (e.g. the address of the `docker0` bridge or whatever name resolves to the host from inside the container).

`setup-live-targets.sh` does not read `TEST_HOST` — run it on the host that actually runs the target binaries.

### `.live-test-config`

The setup script writes `.live-test-config` with resolved ports:

```
REST_API_PORT=8990
SOAP_SERVICE_PORT=8991
GRAPHQL_SERVER_PORT=8992
GRPC_SERVER_PORT=50051
TARGETS_SETUP=rest-api,soap-service,graphql-server,grpc-server
```

### Default Ports

| Target | Default Port |
|--------|-------------|
| rest-api | 8990 |
| soap-service | 8991 |
| graphql-server | 8992 |
| grpc-server | 50051 |

Ports are auto-resolved if the default is in use (searches up to 20 ports ahead).

## Output

Results are saved to `test/.results/` with one subdirectory per test:

```
.results/
├── rest-api/
│   ├── capture.json        # Crawl output
│   └── spec.yaml           # Generated OpenAPI spec
├── soap-service/
│   ├── capture.json        # Crawl output
│   ├── soap-capture.json   # Direct SOAP requests
│   └── spec.xml            # Generated WSDL
├── graphql-server/
│   ├── capture.json        # Live GraphQL traffic
│   └── spec.graphql        # Generated GraphQL SDL
├── generate-rest/
│   └── spec.yaml           # OpenAPI spec from reference capture
├── generate-wsdl/
│   └── spec.xml            # WSDL from reference capture
├── generate-wsdl-matrix/
│   └── spec.xml            # WSDL param-extraction matrix (SOAP 1.1/1.2, RPC + doc/literal)
├── generate-graphql/
│   └── spec.graphql        # Deterministic SDL from reference capture
├── generate-graphql-imports/
│   ├── burp-spec.graphql   # SDL from Burp import
│   └── har-spec.graphql    # SDL from HAR import
├── generate-js-static/
│   ├── spec-on.yaml        # OpenAPI from a JS bundle (--analyze-js)
│   └── spec-off.yaml       # Same capture with --analyze-js=false (opt-out)
├── generate-merge-slugs/
│   ├── spec-default.yaml   # Slug siblings preserved (merge off, LAB-4107 default)
│   └── spec-merge.yaml     # Same capture with --merge-slugs (collapsed to {postSlug})
├── import-burp/
│   └── imported.json       # Imported from Burp XML
├── import-har/
│   └── imported.json       # Imported from HAR
├── import-base64/
│   └── imported.json       # Imported from base64-encoded Burp XML
├── import-mitmproxy/
│   └── imported.json       # Imported from mitmproxy JSON
├── import-unicode/
│   └── imported.json       # Imported from Burp XML with unicode
├── import-duplicates/
│   └── imported.json       # Imported from HAR with duplicate requests
├── import-malformed/
│   └── (empty on success)  # Validates graceful failure on bad input
├── import-empty/
│   └── imported.json       # Imported from empty Burp/HAR
├── edge-cases/
│   └── (crawl artifacts)   # Timeout, error handling, auth header tests
├── crawl-depth/
│   ├── shallow.json        # Depth-limited crawl
│   ├── limited.json        # Max-pages-limited crawl
│   └── loop.json           # Infinite loop detection
├── crawl-unreachable/
│   └── capture.json        # Crawl of unreachable host
├── classifier-edge/
│   ├── capture.json        # Synthetic edge case requests
│   └── spec.yaml           # Spec from classifier edge cases
└── spec-edge/
    ├── capture.json        # Synthetic edge case requests
    └── spec.yaml           # Spec with UUID/multi-param paths
```

## Expected Results

All 23 tests should pass. Order is non-deterministic and durations vary by machine (live crawl tests take the longest).

```
  TARGET                      STATUS    ENDPOINTS   EXPECTED   DURATION
  --------------------------  --------  ----------  ---------  --------
  classifier-edge             PASS      -           -          0s
  crawl-depth                 PASS      -           -          188s
  crawl-unreachable           PASS      0           0          39s
  edge-cases                  PASS      -           -          193s
  generate-graphql            PASS      8           8          0s
  generate-graphql-imports    PASS      2           2          0s
  generate-js-static          PASS      3           3          1s
  generate-merge-slugs        PASS      3           3          0s
  generate-rest               PASS      8           8          0s
  generate-wsdl               PASS      3           3          1s
  graphql-server              PASS      8           8          1s
  grpc-server                 PASS      3           3          1s
  import-base64               PASS      2           2          0s
  import-burp                 PASS      5           5          0s
  import-duplicates           PASS      2           2          0s
  import-empty                PASS      0           0          0s
  import-har                  PASS      3           3          1s
  import-malformed            PASS      0           0          1s
  import-mitmproxy            PASS      3           3          0s
  import-mitmproxy-native     PASS      3           3          1s
  import-unicode              PASS      3           3          0s
  rest-api                    PASS      8           8          79s
  soap-service                PASS      3           3          51s
  spec-edge                   PASS      -           -          0s

  Total: 23 passed, 0 failed, 0 skipped
```

Some tests emit warnings (`[WARN]`) for soft behavioral checks. These are informational and do not cause failures.

## Directory Structure

```
test/
├── setup-live-targets.sh    # Setup script
├── run-live-tests.sh        # Test runner
├── validate.sh              # Shared validation functions
├── README.md                # This file
├── .live-test-config        # Auto-generated (gitignored)
├── .results/                # Test output (gitignored)
│
├── rest-api/
│   ├── main.go              # REST API server
│   └── expected-paths.json  # Expected paths for validation
│
├── soap-service/
│   ├── main.go              # SOAP service server
│   ├── service.wsdl         # WSDL definition
│   └── expected-paths.json  # Expected operations for validation
│
├── graphql-server/
│   ├── server.js            # Apollo Server (GraphQL)
│   ├── package.json         # Node.js dependencies
│   ├── reference-capture.json  # Fixed capture for deterministic tests
│   ├── test-burp.xml        # Burp XML import test data
│   ├── test-traffic.har     # HAR import test data
│   ├── expected-paths.json  # Expected operations for validation
│   └── expected-spec.graphql  # Expected SDL for exact comparison
│
├── grpc-server/
│   ├── main.go              # gRPC server (UserService, OrderService, AccountService)
│   └── expected-paths.json  # Expected services/methods for validation
│
└── fixtures/
    ├── sample-burp-export.xml            # Burp XML (standard)
    ├── sample-burp-base64.xml            # Burp XML (base64-encoded bodies)
    ├── sample-burp-unicode.xml           # Burp XML (unicode content)
    ├── sample-capture.har                # HAR file (standard)
    ├── sample-har-duplicates.json        # HAR file (duplicate requests)
    ├── sample-mitmproxy.json             # mitmproxy JSON export
    ├── malformed-burp.xml                # Malformed Burp XML
    ├── malformed-har.json                # Malformed HAR file
    ├── empty-burp.xml                    # Empty Burp XML
    ├── empty-har.json                    # Empty HAR file
    ├── expected-from-burp.json           # Expected: Burp import
    ├── expected-from-har.json            # Expected: HAR import
    ├── expected-burp-capture.json        # Expected: Burp capture
    ├── expected-burp-base64-capture.json # Expected: base64 Burp capture
    ├── expected-burp-unicode-capture.json# Expected: unicode Burp capture
    ├── expected-har-capture.json         # Expected: HAR capture
    ├── expected-har-duplicates-capture.json # Expected: deduped HAR capture
    ├── expected-mitmproxy-capture.json   # Expected: mitmproxy capture
    └── expected-empty-capture.json       # Expected: empty capture
```

## Troubleshooting

### Port conflicts

If setup fails with a "Cannot find available port" error, it now prints the
processes holding the port window so you can see what to stop. Use `--teardown`
(or `make live-test-clean`) first, then retry:

```bash
./test/setup-live-targets.sh --teardown
./test/setup-live-targets.sh
```

### Chrome not found

Install Chrome or Chromium:

```bash
# Ubuntu/Debian
sudo apt install chromium-browser

# macOS
brew install --cask google-chrome
```

### Crawl produces empty capture

Ensure the target service is running and healthy. Run the check from the host that started the services (`setup-live-targets.sh` binds to localhost there):

```bash
curl http://localhost:8990/api/health
```

If you're running the harness inside a devcontainer and the targets are on the host, set `TEST_HOST` (see Configuration above) and verify connectivity from inside the container with `curl http://${TEST_HOST}:8990/api/health`. Without `TEST_HOST`, `localhost` resolves to the container's own loopback (not the Docker host), the crawler connects to nothing, and the capture is empty.

### Crawl exits with `seed URL rejected by frontier (scope, SSRF, or parse): ...`

The seed URL is a private host (`localhost`, `127.0.0.1`, RFC1918, or link-local) and `--dangerous-allow-private` was not passed. All live tests in this suite crawl localhost targets, so every `vespasian crawl` invocation in `run-live-tests.sh` already includes the flag. If you are reproducing a single test by hand, add the flag to your command line:

```bash
./bin/vespasian crawl http://localhost:8990 --dangerous-allow-private \
    -o /tmp/cap.json --depth 2 --max-pages 50
```

### Build failures

Ensure Go modules are up to date:

```bash
cd /path/to/vespasian
go mod tidy
```
