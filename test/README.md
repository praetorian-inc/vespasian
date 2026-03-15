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

- **Go 1.24+** — [https://go.dev/dl/](https://go.dev/dl/)
- **Chrome/Chromium** — Required for headless crawling
- **python3** — Required for test validation scripts

## Targets

| Target | Protocol | Description | Infrastructure |
|--------|----------|-------------|----------------|
| rest-api | REST | Custom API with users, products, orders endpoints | Go binary |
| soap-service | SOAP/WSDL | Custom SOAP service with GetUser, ListUsers, CreateUser | Go binary |

## What the Test Runner Does

For each target:

1. **Build** vespasian and target binaries
2. **Start** target services (with auto-resolved ports)
3. **Crawl** — `vespasian crawl <url> -o capture.json`
4. **Validate capture** — Check request count and expected URLs
5. **Generate** — `vespasian generate rest capture.json -o spec.yaml`
6. **Validate spec** — Path coverage, method coverage, schema presence, no static assets
7. **Print summary** — Pass/fail status with endpoint counts and durations

For importer tests:

1. **Import** — `vespasian import burp fixtures/sample-burp-export.xml -o imported.json`
2. **Validate** — Request count, expected URLs and methods

## Scripts

### setup-live-targets.sh

```bash
./test/setup-live-targets.sh [options]

Options:
  --targets <list>   Comma-separated targets (default: all)
                     Valid: rest-api,soap-service
  --skip-start       Only build, don't start services
  --teardown         Stop all running targets and clean up
  --help             Show this help message
```

### run-live-tests.sh

```bash
./test/run-live-tests.sh [options]

Options:
  --targets <list>      Comma-separated targets to test (default: all)
                        Valid: rest-api,soap-service,import-burp,import-har
  --verbose             Enable verbose vespasian output
  --no-build            Skip building vespasian and target binaries
  --no-start            Don't start/stop services (assume already running)
  --help                Show this help message
```

## Configuration

The setup script writes `.live-test-config` with resolved ports:

```
REST_API_PORT=8990
SOAP_SERVICE_PORT=8991
TARGETS_SETUP=rest-api,soap-service
```

### Default Ports

| Target | Default Port |
|--------|-------------|
| rest-api | 8990 |
| soap-service | 8991 |

Ports are auto-resolved if the default is in use (searches up to 20 ports ahead).

## Output

Results are saved to `test/.results/`:

```
.results/
├── rest-api/
│   ├── capture.json      # Crawl output
│   └── spec.yaml         # Generated OpenAPI spec
├── soap-service/
│   ├── capture.json      # Crawl output
│   ├── soap-capture.json # Direct SOAP requests
│   └── spec.xml          # Generated WSDL
├── import-burp/
│   └── imported.json     # Imported from Burp XML
└── import-har/
    └── imported.json     # Imported from HAR
```

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
└── fixtures/
    ├── sample-burp-export.xml   # Synthetic Burp XML
    ├── sample-capture.har       # Synthetic HAR file
    ├── expected-from-burp.json  # Expected import output
    └── expected-from-har.json   # Expected import output
```

## Troubleshooting

### Port conflicts

If setup fails with port errors, use `--teardown` first, then retry:

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

Ensure the target service is running and healthy:

```bash
curl http://localhost:8990/api/health
```

### Build failures

Ensure Go modules are up to date:

```bash
cd /path/to/vespasian
go mod tidy
```
