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
- **Chrome/Chromium** — Required for headless crawling (see below)
- **python3** — Required for test validation scripts
- **Node.js** — Required for the graphql-server target

### Chrome in containers

A stock Ubuntu devcontainer ships `/usr/bin/chromium-browser` as a **snap
launcher stub**, and snapd is unavailable inside the container. The stub
satisfies `command -v` and `-x` but fails the moment it runs, so `setup-live-targets.sh`
reports it as *"found … but it is not runnable"* rather than passing preflight
and failing later mid-crawl.

**In this repo's devcontainer there is nothing to do.**
[`.devcontainer/Dockerfile`](../.devcontainer/Dockerfile) runs
`test/install-chrome.sh` as an image layer, so a fresh container comes up with a
real, non-snap Chrome already installed, plus the `python3` and `yq` the guard
suites need, the Node 20 the `graphql-server` target and the spec validators
need, and the Go 1.27.0 `go.mod` requires. Go is installed by the Dockerfile
rather than inherited from the base image, which ships a release too old for
`go.mod` — under `GOTOOLCHAIN=local` every Go step in the container fails
otherwise. The four guard suites themselves need none of Go, Node or Chrome. [`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json)
sets `VESPASIAN_NO_SANDBOX=true` for you, and its `onCreateCommand` installs the
spec-validator deps the live and generator targets parse specs with.

The `devcontainer-image` CI job builds that image **through `devcontainer.json`**
(via `@devcontainers/cli`, not a hand-written `docker build`), then runs the
assertions inside it as the `vscode` user with that same environment — so the
configuration CI measures is the one you get, rather than a similar one. It
asserts the browser resolves and launches, that two of the four guard suites
(`test-runner-args.sh` and `preflight-selftest.sh`) run in the image, and that
`./test/run-live-tests.sh --group live` runs there with the rod-backed targets
reporting PASS rather than SKIP.

Outside that image — macOS, a bare Ubuntu host, your own container — install a
real, non-snap Chrome (`.deb`, amd64 or arm64) yourself:

```bash
./test/install-chrome.sh          # idempotent; if a runnable browser exists it skips the
                                  # install but still clears this script's own apt
                                  # leftovers (and, in a container, the package's
                                  # phone-home artifacts). Uses sudo.
export VESPASIAN_NO_SANDBOX=true  # containers generally cannot use the Chrome sandbox
```

The script is idempotent and exits 0 when a runnable browser is already present,
so running it inside the devcontainer anyway is harmless — it re-clears its own
apt leftovers and exits.

**How the package is trusted.** Google's apt repository is added *temporarily*,
with its signing key pinned by primary-key fingerprint. apt then verifies the
chain — Release signature → `Packages` digest → `.deb` digest — before dpkg runs
the package's maintainer scripts as root. Downloading the `.deb` directly would
leave TLS as the only control: `apt-get install ./local.deb` does **not**
authenticate a local file argument, and Google's `.deb` carries no embedded
`debsigs` signature to check instead. The fingerprint pin is what makes the
check meaningful — a key fetched over the same channel as the package, unpinned,
buys nothing against an attacker who controls that channel. If Google rotates
its primary key the script fails loudly and the constant must be updated
deliberately.

**No background egress.** The temporary repo and keyring this script itself
adds are removed once the install completes (via an `EXIT` trap, so an aborted
run cannot leave them behind). The `google-chrome-stable` package's own
permanent apt source and daily update pinger (`/etc/cron.daily/google-chrome`)
are always suppressed via `repo_add_once=false`, so the package never creates
them in the first place. Inside a throwaway image the script goes further and
also removes and verifies absent whatever the package planted anyway — that
pair is the "no phone-home from the devcontainer image" acceptance criterion,
and `.devcontainer/Dockerfile` is what makes it apply: it names
`container=docker` for the install layer, so the removal AND the
verify-absent pass both run, and a survivor fails the image build.
Outside a container (a developer's own machine), removing artifacts the
package owns is not this script's call, so they are left alone as Chrome's
normal update channel. Chrome's telemetry is separately disabled on every
browser vespasian launches (LAB-4999), and the live suite always launches
through vespasian, so it inherits those flags.

**Version policy.** The script tracks Chrome *stable* rather than pinning a
version — for a test-only layer that is the right trade, since a pinned version
goes stale and eventually 404s. The installed version is logged on success so an
image build record identifies exactly what landed.

`apt install chromium` / `chromium-browser` are **not** alternatives on Ubuntu
noble — both are transitional packages that pre-depend on snapd.

The non-privileged surface (argument handling, architecture resolution, the
pinned fingerprint) is covered by `test/install-chrome-selftest.sh`, which runs
in CI on every push. The download / apt / privileged-mutation paths are not
reachable from that suite — they need root, network, and destructive system
changes — so they are covered separately by the `install-chrome-e2e` CI job,
which runs the installer end-to-end as root inside a disposable `ubuntu:24.04`
container. That job is opt-in (`workflow_dispatch`) and also runs on every push
to `main`, rather than on every PR, because it is slow and depends on Google's
apt repo being reachable.

### Running without a browser

Browser-free work does not require a browser to be present:

```bash
./test/run-live-tests.sh --group offline   # importers, generators, fixtures — no setup run needed
./test/setup-live-targets.sh --skip-start  # build binaries only
```

The offline group talks to no service, so it needs neither `.live-test-config`
nor a browser and runs on a fresh checkout. Likewise, `setup-live-targets.sh`
treats a missing browser as fatal only when the selected targets actually drive
the headless backend — `--skip-start` and a `grpc-server`-only setup warn and
continue. Selections that do need a browser still fail loudly at preflight.

### Dynamic (integration) tests

Separate from this live suite, `pkg/crawl` carries `//go:build integration`
tests that launch a real browser to exercise `NewBrowserManager`'s launch / kill
/ close lifecycle. They are excluded from `make test` by the build tag and need
the same non-snap Chrome as above — which the devcontainer already provides, so
inside it the export is redundant:

```bash
export VESPASIAN_NO_SANDBOX=true   # already set in the devcontainer
go test -tags integration ./pkg/crawl/...
```

`TestConfigureLauncher_PinsSystemBrowser` is the exception: it only needs a
browser binary to exist on disk (it asserts go-rod's `.Bin` is pinned so no
Chromium is auto-downloaded — LAB-4999), so it runs even where Chrome cannot
launch, and skips cleanly when no browser is present at all.

## Targets

| Target | Protocol | Description | Infrastructure |
|--------|----------|-------------|----------------|
| rest-api | REST | Custom API with users, products, orders endpoints | Go binary |
| soap-service | SOAP/WSDL | Custom SOAP service with GetUser, ListUsers, CreateUser | Go binary |
| graphql-server | GraphQL | Apollo Server with queries, mutations, enums, unions, nested types | Node.js |
| grpc-server | gRPC | Three reflectable gRPC services (UserService, OrderService, AccountService) | Go binary |
| forms-target | REST (HTML forms) | Static HTML page whose POST/GET `<form>` endpoints are recovered by `analyze.ExtractForms` (LAB-2109) | Go binary |

## What the Test Runner Does

For each target:

1. **Build** vespasian and target binaries
2. **Start** target services (with auto-resolved ports)
3. **Crawl** — `vespasian crawl <url> --dangerous-allow-private -o capture.json`
4. **Validate capture** — Check request count and expected URLs
5. **Generate** — `vespasian generate <type> capture.json -o spec.<ext>`
6. **Validate spec** — Path/operation coverage, schema structure, no static assets. For `rest-api` and `scan-rest`, this additionally asserts an exact path count (the generated spec has exactly the number of paths the fixture declares — not merely "at least"), that each POST-only form action (`/api/subscribe`) carries a `post` operation and no `get` (`assert_post_get_operations`), and that each urlencoded POST form's input names (`email`, `name`) surface as request-body schema properties under that action's own endpoint (`assert_form_body_fields`) — the same operation- and body-field-level checks documented for `forms-target` below
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

For the HTML form-extraction live test (`forms-target`):

1. **Crawl** the running server (both backends) — it serves one HTML page with POST forms (`/api/login`, `/api/register`, `/api/feedback`) and a GET search form, none of the POST actions backed by a real handler or reachable via a link/fetch
2. **Generate** at the default confidence — the POST `<form>` endpoints reach the spec ONLY because `analyze.ExtractForms` (LAB-2109) parsed the captured HTML, so their presence is an end-to-end regression guard; `/api/search` is captured directly via its `<a href>` link
3. **Assert** the form-derived paths in `forms-target/expected-paths.json` are present, each POST endpoint carries a `post` operation, and each urlencoded POST form's input names (`username`, `password`, `csrf_token`, …) surface as request-body schema properties
4. **Re-generate with `--confidence 0`** and assert the GET search form's query parameters (`q`, `category`) merge onto `/api/search` — a GET form scores 0 confidence and is filtered out at the default threshold, so it needs the lower threshold to surface (multipart/form-data body-field schemas are not inferred, so `/api/feedback`'s fields are intentionally not asserted)

For the slug-merging test (`generate-merge-slugs`, offline — no server or browser):

1. **Generate** an OpenAPI spec from `fixtures/merge-slugs-capture.json` (two slug siblings `/api/posts/hello-world`, `/api/posts/my-trip` plus numeric-ID siblings `/api/users/42`, `/api/users/99`) with `--probe=false`
2. **Assert default (off)** — both `/api/posts/*` siblings survive as distinct paths (the LAB-4107 regression guard) while `/api/users/{userId}` is still ID-normalized
3. **Assert `--merge-slugs`** — the slug siblings collapse to `/api/posts/{postSlug}` and `/api/users/{userId}` normalization is unaffected

For the egress guard (`no-download`, LAB-4999 Finding 1):

1. **Isolate** a fresh, empty go-rod browser cache under a temporary HOME (not the invoking shell's `$HOME`), so the check does not depend on a clean workspace
2. **Crawl** the rest-api target headless (which must use the system Chrome)
3. **Assert** the isolated cache is still empty — any `chromium-<rev>` directory means go-rod auto-downloaded a browser from a third-party mirror, i.e. the system-Chrome pin regressed. Skips cleanly when Chrome is unavailable.

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
  --group <name>        Run a predefined target group: offline, live, or all (default: all)
  --targets <list>      Comma-separated targets to test (overrides --group)
                        Valid targets:
                          Service:    rest-api, scan-rest, soap-service, graphql-server,
                                      concat-spa, concat-spa-two-stage, forms-target
                          Config:     grpc-server (included via TARGETS_SETUP when set up)
                          Generate:   generate-rest, generate-wsdl, generate-wsdl-matrix,
                                      generate-graphql, generate-graphql-imports,
                                      generate-js-static, generate-merge-slugs
                          Import:     import-burp, import-har, import-base64,
                                      import-mitmproxy, import-mitmproxy-native,
                                      import-unicode, import-duplicates,
                                      import-malformed, import-empty, auth-capture
                          Crawl:      crawl-depth, crawl-unreachable, ssrf-rejection, no-download
                          Edge cases: edge-cases, classifier-edge, spec-edge
  --verbose             Enable verbose vespasian output
  --no-build            Skip building vespasian and target binaries
  --no-start            Don't start/stop services (assume already running)
  --dry-run             Print resolved target list and exit (no build/test)
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

### `FORMS_TARGET_BIND_HOST` (optional)

The `forms-target` server binds `127.0.0.1` by default (via its `BIND_HOST` env var), and `setup-live-targets.sh` now honours that default rather than overriding it. It is an unauthenticated HTTP app serving login / register / feedback forms, so it has no business listening on every interface of the operator's machine unless asked.

Widen it explicitly when the crawler runs inside a devcontainer and reaches the host via `TEST_HOST=host.docker.internal`:

```bash
FORMS_TARGET_BIND_HOST=0.0.0.0 ./test/setup-live-targets.sh --targets forms-target
```

Nothing else needs this variable: the other four rod-backed targets share `LIVE_TARGET_BIND_HOST` (below), and `grpc-server` hard-pins loopback in its own Go source. Every target defaults to loopback — this variable exists because `forms-target` reads its own `BIND_HOST` rather than the shared one.

### `CONFIG_FILE` (optional)

`run-live-tests.sh` reads resolved ports and `TARGETS_SETUP` from `CONFIG_FILE`, which defaults to `test/.live-test-config` (written by `setup-live-targets.sh`). Override it with the `CONFIG_FILE` environment variable — an internal test-harness knob that `test/test-runner-args.sh` uses to point `--dry-run` invocations at a throwaway stub config, so the group-resolution tests need no real setup. Only an allowlisted set of keys (the `*_PORT` values and `TARGETS_SETUP`) is honored from the file.

The config file is loaded only when a selected target actually talks to a live service, so `--group offline` runs on a fresh checkout with no config and no prior setup.

### `RESULTS_DIR` (optional)

Where per-target result files are written; defaults to `test/.results/`. Override it to keep a run's output out of the repo — `test/test-runner-args.sh` sets it to a temp dir for the one block that really executes the runner, so the guard suite leaves nothing behind.

### `LIVE_TARGET_BIND_HOST` (optional — widens an exposure)

Bind address for `rest-api`, `soap-service`, `concat-spa` and `graphql-server`. Defaults to
`127.0.0.1`.

These four targets are unauthenticated by design — they exist to give the scanner something to
discover — so they bind loopback and stay unreachable from the network. Setting this to `0.0.0.0`
exposes all four on every interface for as long as the run lasts.

The one legitimate reason to set it is the devcontainer flow, where the crawler runs inside a
container and reaches the host through `TEST_HOST` rather than loopback:

```bash
LIVE_TARGET_BIND_HOST=0.0.0.0 ./test/setup-live-targets.sh
```

`forms-target` has its own equivalent (`FORMS_TARGET_BIND_HOST`, below) and `grpc-server` hardcodes
loopback. Both halves of this seam are asserted — that `setup-live-targets.sh` passes the value, and
that each target's own source reads it — because either half alone is inert.

### `LIVE_TESTS_ALLOW_NO_EXECUTION` (optional — disables a merge gate)

Set to any non-empty value to make `run-live-tests.sh` treat a run in which **every** selected target
skipped as a success instead of a failure.

Leave it unset. The check it disables is what makes this ticket's AC3 — "rod-backed targets, including
`no-download`, execute rather than SKIP" — enforceable at all: without it a `--group live` run of three
SKIPs and zero passes exits 0, and CI stays green while proving nothing. Setting this variable in CI
therefore retires AC3's enforcement silently, which is the opposite of what a green build would imply.

The legitimate use is interactive and local: a developer deliberately running the live group on a
browserless box who wants the skips reported without a non-zero exit. Prefer running
`./test/install-chrome.sh` instead, so the targets actually execute. `--group offline` needs no browser
and is unaffected by this variable either way.

### `VESPASIAN` (optional)

Path to the `vespasian` binary under test; defaults to `bin/vespasian`. Override it to test a binary built elsewhere. Note this is **not** settable from `CONFIG_FILE`: `VESPASIAN` is deliberately absent from `load_config`'s allowlist, so a config file cannot redirect which binary the suite executes.

### `VESPASIAN_TEST_ROOT` (internal, test-only)

Read by `install-chrome.sh` to reroot every absolute system path it reads or
writes — the pinned keyring, the temporary apt source, `/etc/default/google-chrome`,
the phone-home artifacts it may remove, and the version record — under a
caller-supplied directory instead of the real filesystem. It exists solely so
`test/install-chrome-selftest.sh` can drive the installer's privileged branches
(the defaults-file rewrite, the container gate, phone-home removal and
verification) against fixtures, unprivileged. **No production caller sets
it** — `install-chrome.sh` itself, `setup-live-targets.sh`,
[`.devcontainer/Dockerfile`](../.devcontainer/Dockerfile), and the CI jobs all
leave it unset. That is not left as prose: `test/test-runner-args.sh` asserts it,
greping each of those callers for an assignment and failing if one appears — the
citation AGENTS.md's "comments that claim a state is impossible must cite a test"
convention asks for.

The script validates the value before using it — it must be an absolute,
existing directory containing only `[A-Za-z0-9._/-]`, with no `..` component,
and must not resolve to `/` or `//` — which closes the obvious ways a
caller-controlled value could redirect a root-privileged write onto the real
system. It does **not** defend against a symlink planted inside the root
*after* validation, a bind mount at the root, or the root being swapped out
from under it between validation and the write (TOCTOU): those are accepted
residuals, because the variable's whole trust model assumes its caller is
*already* privileged — either the process runs as root, or it runs
unprivileged and already holds the `sudo` rights the script would use anyway.

Because it feeds root-privileged writes, it must never be exposed through a
narrowly-scoped `sudoers` grant that also permits environment passing
(`SETENV`, `sudo -E`, or an `env_keep` entry) — default `sudoers`
(`Defaults env_reset`) already drops it, and that default must not be loosened
for this script.

### `.live-test-config`

The setup script writes `.live-test-config` with resolved ports:

```
REST_API_PORT=8990
SOAP_SERVICE_PORT=8991
GRAPHQL_SERVER_PORT=8992
GRPC_SERVER_PORT=50051
TARGETS_SETUP=rest-api,soap-service,graphql-server,grpc-server
```

> **`TARGETS_SETUP` is additive, not restrictive.** A bare `./test/run-live-tests.sh`
> resolves the full `all` group (every `OFFLINE_TARGETS` + `LIVE_TARGETS`).
> `TARGETS_SETUP` only *adds* config-only targets such as `grpc-server` to that run —
> it does **not** narrow it. To run only the targets you set up, pass
> `--targets <list>` (or use `--group offline` / `--group live`). After a partial
> `setup-live-targets.sh --targets <subset>`, the setup script prints the exact
> `--targets` command to use.

### Default Ports

| Target | Default Port |
|--------|-------------|
| rest-api | 8990 |
| soap-service | 8991 |
| graphql-server | 8992 |
| grpc-server | 50051 |
| forms-target | 8994 |

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
├── auth-capture/
│   └── imported.json       # Authorization header preserved through import (LAB-3890 A5)
├── edge-cases/
│   └── (crawl artifacts)   # Timeout, redirects, HTTP errors, encoding
├── crawl-depth/
│   ├── shallow.json        # Depth-limited crawl
│   ├── limited.json        # Max-pages-limited crawl
│   └── loop.json           # Infinite loop detection
├── crawl-unreachable/
│   └── capture.json        # Crawl of unreachable host
├── ssrf-rejection/
│   └── (no artifact)       # Asserts SSRF gate rejects a private target (LAB-3890 A4)
├── classifier-edge/
│   ├── capture.json        # Synthetic edge case requests
│   └── spec.yaml           # Spec from classifier edge cases
└── spec-edge/
    ├── capture.json        # Synthetic edge case requests
    └── spec.yaml           # Spec with UUID/multi-param paths
```

## Expected Results

All 31 tests should pass. Order is non-deterministic and durations vary by machine (live crawl tests take the longest). The sample below is a default `--group all` run (21 offline + 10 live targets); the config-only `grpc-server` target runs additionally only when `TARGETS_SETUP` is configured.

```text
  TARGET                      STATUS    ENDPOINTS   EXPECTED   DURATION
  --------------------------  --------  ----------  ---------  --------
  auth-capture                PASS      1           1          0s
  classifier-edge             PASS      -           -          0s
  concat-spa                  PASS      2           2          90s
  concat-spa-two-stage        PASS      2           2          92s
  crawl-depth                 PASS      -           -          188s
  crawl-unreachable           PASS      0           0          39s
  edge-cases                  PASS      -           -          193s
  forms-target                PASS      4           4          55s
  generate-graphql            PASS      8           8          0s
  generate-graphql-imports    PASS      2           2          0s
  generate-js-static          PASS      3           3          1s
  generate-merge-slugs        PASS      3           3          0s
  generate-rest               PASS      10          10         0s
  generate-wsdl               PASS      3           3          1s
  generate-wsdl-matrix        PASS      3           3          1s
  graphql-server              PASS      8           8          1s
  import-base64               PASS      2           2          0s
  import-burp                 PASS      5           5          0s
  import-duplicates           PASS      2           2          0s
  import-empty                PASS      0           0          0s
  import-har                  PASS      3           3          1s
  import-malformed            PASS      0           0          1s
  import-mitmproxy            PASS      3           3          0s
  import-mitmproxy-native     PASS      3           3          1s
  import-unicode              PASS      3           3          0s
  no-download                 PASS      -           -          80s
  rest-api                    PASS      11          11         79s
  scan-rest                   PASS      11          11         84s
  soap-service                PASS      3           3          51s
  spec-edge                   PASS      -           -          0s
  ssrf-rejection              PASS      -           -          0s

  Total: 31 passed, 0 failed, 0 skipped
```

Some tests emit warnings (`[WARN]`) for soft behavioral checks. These are informational and do not cause failures.

## Directory Structure

```
test/
├── setup-live-targets.sh    # Setup script
├── run-live-tests.sh        # Test runner
├── install-chrome.sh        # Provisions a real non-snap Chrome (see "Chrome in containers")
├── common.sh                # Shared logging + Chrome detection (detect_chrome_binary)
├── validate.sh              # Shared validation functions
├── README.md                # This file
├── .live-test-config        # Auto-generated (gitignored)
├── .results/                # Test output (gitignored)
│
│   # Guard suites — CI-run regression nets, no Go/Node/Chrome needed
├── preflight-selftest.sh        # Chrome/Chromium detection (LAB-3893)
├── install-chrome-selftest.sh   # install-chrome.sh's non-privileged surface
├── setup-live-targets_test.sh   # Teardown / orphan-PID hardening (LAB-2893)
├── test-runner-args.sh          # Target-group vs dispatch drift, CI step lists
├── validate_test.sh             # Spec validators still reject malformed specs
│
├── internal/
│   └── target/              # Shared bind-host + server-timeout helper for the Go targets
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
├── forms-target/
│   ├── main.go              # HTML forms server (POST/GET <form> endpoints)
│   └── expected-paths.json  # Expected form-derived paths + query params for validation
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
# Ubuntu/Debian — installs a real, non-snap Chrome (see "Chrome in containers" above).
# Do NOT use `apt install chromium-browser`: on recent Ubuntu that package is the
# snap stub described below, which installs cleanly and then fails at runtime.
./test/install-chrome.sh

# macOS
brew install --cask google-chrome
```

**Found but not runnable:** this is the snap-stub case described under
[Chrome in containers](#chrome-in-containers) above — the same cause, seen from the
troubleshooting side. `setup-live-targets.sh` probes each candidate binary with
`--version` before accepting it, so it fails preflight with `Found <path> but it is
not runnable` instead of failing later during `vespasian crawl`. Fix with
`./test/install-chrome.sh`, `snap install chromium`, or install `google-chrome`
directly.

**macOS note:** the runnability probe uses `timeout` (falling back to
`gtimeout` from Homebrew coreutils) to guard against a hanging binary. Stock
macOS ships neither, so on an unpatched macOS install the probe runs without a
timeout — a binary that hangs on `--version` would block preflight rather
than failing fast.

**Slow hosts:** the probe gives each candidate 2 seconds to answer
`--version`. On a cold or throttled container mount a healthy browser's first
exec can take longer, which surfaces as a spurious `Found <path> but it is not
runnable`. Set `CHROME_PROBE_TIMEOUT` (seconds, fractions allowed) to widen
the budget: `CHROME_PROBE_TIMEOUT=10 ./test/setup-live-targets.sh`.

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
