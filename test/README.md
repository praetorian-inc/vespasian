# Vespasian Live Test Suite

End-to-end live tests that spin up intentionally simple target applications, run vespasian against them, and validate the generated API specifications.

## Quick Start

```bash
# 0. One-time: install the OpenAPI/GraphQL spec validators
(cd test/spec-validators && npm ci --ignore-scripts)

# 1. Setup: build binaries, resolve ports, start services
./test/setup-live-targets.sh

# 2. Run: crawl targets, generate specs, validate output
./test/run-live-tests.sh

# 3. Teardown: stop services, clean up
./test/setup-live-targets.sh --teardown
```

## Prerequisites

- **Go 1.27.0+** — [https://go.dev/dl/](https://go.dev/dl/)
- **Chrome/Chromium** — Required for headless crawling (see below)
- **python3** — Required for test validation scripts
- **Node.js** — Required for the graphql-server target, and for the parser-backed spec validators in `test/spec-validators/` (LAB-3890 T1) that the spec-producing targets validate through. `setup-live-targets.sh` installs the graphql-server dependencies but **not** the validator dependencies — run `(cd test/spec-validators && npm ci --ignore-scripts)` once, or `validate_openapi_structure` fails with `spec-validators deps missing or incomplete`.

Optional, feature-gated at runtime:

- **protoc** (plus `protoc-gen-go` and `protoc-gen-go-grpc`) — only needed to regenerate `grpc-server/labpb/` via its `make proto` target. The AC4 compile check does **not** need it: it compiles the emitted `.proto` in-process (see "No `protoc` required." below), so a host without `protoc` still runs that assertion rather than skipping it.
- **grpcurl** — used by the preflight reachability check for `grpc-server` (`grpcurl -plaintext <host>:<port> list`); probed with `command -v` and skipped when missing.

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
| rest-api | REST | Custom API with users, products, orders endpoints, two JS-`fetch` form POSTs (`/api/login`, `/api/upload`), and one static `<form>` action (`/api/subscribe`) | Go binary |
| soap-service | SOAP/WSDL | Custom SOAP service with GetUser, ListUsers, CreateUser | Go binary |
| graphql-server | GraphQL | Apollo Server with queries, mutations, enums, unions, nested types | Node.js |
| grpc-server | gRPC | Three reflectable gRPC services (UserService, OrderService, AccountService) | Go binary |
| concat-spa | REST | SPA whose two API paths exist only as JS string concatenations in an external bundle, recoverable only by the concat extractor rather than by link-following (LAB-1368). Backs both the `concat-spa` and `concat-spa-two-stage` test targets | Go binary |
| forms-target | REST (HTML forms) | Static HTML page whose POST/GET `<form>` endpoints are recovered by `analyze.ExtractForms` (LAB-2109) | Go binary |

## What the Test Runner Does

For each target:

1. **Build** vespasian and target binaries
2. **Start** target services (with auto-resolved ports)
3. **Crawl** — `vespasian crawl <url> --dangerous-allow-private -o capture.json`
4. **Validate capture** — Check request count and expected URLs
5. **Generate** — `vespasian generate <type> capture.json -o spec.<ext>`
6. **Validate spec** — Path/operation coverage, schema structure, no static assets. For `rest-api` and `scan-rest`, this additionally asserts an exact path count (the generated spec has exactly the number of paths the fixture declares — not merely "at least"), that each POST-only form action (`/api/subscribe`) carries a `post` operation and no `get` (`assert_post_get_operations`), and that each urlencoded POST form's input names (`email`, `name`) surface as request-body schema properties under that action's own endpoint (`assert_form_body_fields`) — the same operation- and body-field-level checks documented for `forms-target` below. Both targets additionally pin each declared path's method list, asserting its {get,post} membership against the generated spec (`assert_path_methods`), which is what makes the deliberate two-stage versus scan divergence on `/api/login` and `/api/upload` a tested invariant rather than a documented claim
7. **Print summary** — Pass/fail status with endpoint counts and durations

> **Why `--dangerous-allow-private`?** All live targets run on `localhost`, which the crawler's SSRF gate treats as a private host. The flag is required on every `vespasian crawl` invocation in this suite; running without it will exit non-zero with `seed URL rejected by frontier ...`. The flag name reflects production-risk semantics — pass it only when you intend to crawl a known-private host (e.g., this suite, or an internal-network assessment).

Steps 3 and 5 describe the two-stage shape most targets use. `concat-spa` and `no-download` deviate — see their sections below. `scan-rest` deviates too, running single-stage `scan` in place of steps 3 and 5; the REST-counts note further down covers what that changes.

For the GraphQL live test (`graphql-server`):

1. **Send** real GraphQL queries to the running Apollo Server
2. **Capture** traffic as a vespasian capture file
3. **Generate** — `vespasian generate graphql capture.json --dangerous-allow-private` (with introspection probe)
4. **Validate** — SDL structure, expected operations, introspection-quality checks (schema block, non-null types, enums)

For the gRPC live test (`grpc-server`):

1. **Synthesize** a minimal capture so the classifier tags the request as gRPC and the reflection probe dials the right host:port
2. **Generate** — `vespasian generate grpc capture.json --dangerous-allow-private -o spec.proto` (via Server Reflection)
3. **Validate services** — expected services and methods are present, each RPC scoped to its own `service` body, and server-streaming methods keep their `stream` return marker
4. **Compile the emitted `.proto`** — `test/proto-validate` compiles the generated file and fails the target on any syntax, duplicate-tag, or unresolved-reference error (AC4 of LAB-2778)

> **No `protoc` required.** The compile check runs in-process via `bufbuild/protocompile`
> rather than shelling out. It used to call `protoc` behind `command -v protoc`, which
> meant the assertion proving the emitted spec compiles passed by never running: `protoc`
> ships on no GitHub-hosted `ubuntu-24.04` image, and `live-tests.yml` runs under
> `disable-sudo: true`, so it could not be installed from a later step either. Removing
> the external dependency — rather than provisioning it — makes the check behave
> identically on CI and on a developer machine (LAB-5549). `grpcurl` remains optional:
> the reachability probe uses it when present for a stronger signal (reflection answers,
> not just an open port) and falls back to a TCP connect otherwise.

For deterministic GraphQL tests (`generate-graphql`, `generate-graphql-imports`):

1. **Generate** SDL from fixed reference capture or imported Burp/HAR files
2. **Diff** against expected SDL (byte-identical comparison)

For the JS bundle static-analysis test (`generate-js-static`, offline — no server or browser):

1. **Generate** an OpenAPI spec from `js-static/reference-capture.json` (one HTML page + one JS bundle containing a `fetch` POST with a JSON body, an `axios` GET, and a template-literal GET) with `--analyze-js --confidence 0.1 --probe=false`
2. **Assert** the recovered path count matches `js-static/expected-paths.json` and every operation carries `x-vespasian-source: js-bundle`
3. **Assert opt-out** — re-generating with `--analyze-js=false` yields zero `/api` paths and no `x-vespasian-source` extension

For the concatenated-URL SPA tests (`concat-spa`, `concat-spa-two-stage`):

Both drive the same `concat-spa` server, whose two API endpoints (`/api/users/{id}/orders`, `/api/products/{id}/reviews`) appear only as `String.prototype.concat` / `+`-string expressions with non-literal operands inside an external `app.js`. Neither full path is ever an `<a href>` or a plain string literal, so link-following alone cannot reach them: the concat extractor (Strategy 5) reconstructs them from the bundle text, and `scan` / `generate` additionally probe the reconstructions. Both targets share one fixture (`concat-spa/expected-paths.json`, `total_paths: 2`) and one validation battery (`validate_concat_spec`).

1. **`concat-spa`** — single-stage `vespasian scan`, which runs crawl, JS-replay, and generate in one process. Writes `spec.yaml` only; no capture file is produced.
2. **`concat-spa-two-stage`** — `vespasian crawl` followed by `vespasian generate rest`. The crawl records the index page and `app.js`, and statically reconstructs both paths (`--analyze-js` defaults on); `generate`'s post-crawl JS-replay step (`crawl.ReplayJSExtracted`, gated on `--probe && --analyze-js`, both default true) re-fetches the bundle from the capture's recorded origin and probes those reconstructions, which is what drops the 404 control. This target exists to prove the two-stage workflow reaches parity with `scan` (LAB-3892).
3. **Both assert** exactly `total_paths` (2) paths survive, and that three paths are absent: the bare receiver literals `/api/users` and `/api/products`, plus the `/api/missing/` subtree. The control path `/api/missing/0/gone` is referenced in `app.js` exactly like the two real ones (`fetch("/api/missing/".concat(x, "/gone"))`), so the extractor *does* reconstruct and probe it — it is dropped because the server answers it 404. Its absence is what proves the 404 filter still works; a regression that kept it would fail the exact-count assertion and `validate_paths_absent` together.

Plain `vespasian crawl` does reconstruct these paths statically — `--analyze-js` defaults on, so the concat extractor runs and the paths enter the capture tagged `static:js-concat`. What `crawl` alone does not do is probe them, so the `/api/missing/0/gone` control survives and the counts will not match the fixture. Reproducing either target by hand therefore needs `scan`, or `crawl` followed by `generate`.

For the HTML form-extraction live test (`forms-target`):

1. **Crawl** the running server (both backends) — it serves one HTML page with POST forms (`/api/login`, `/api/register`, `/api/feedback`) and a GET search form, none of the POST actions backed by a real handler or reachable via a link/fetch
2. **Generate** at the default confidence — the POST `<form>` endpoints reach the spec ONLY because `analyze.ExtractForms` (LAB-2109) parsed the captured HTML, so their presence is an end-to-end regression guard; `/api/search` is captured directly via its `<a href>` link
3. **Assert** the form-derived paths in `forms-target/expected-paths.json` are present, each POST endpoint carries a `post` operation, and each urlencoded POST form's input names (`username`, `password`, `csrf_token`, …) surface as request-body schema properties
4. **Re-generate with `--confidence 0`** into `spec-fields.yaml` and assert the GET search form's query parameters (`q`, `category`) merge onto `/api/search` — a GET form scores 0 confidence and is filtered out at the default threshold, so it needs the lower threshold to surface (multipart/form-data body-field schemas are not inferred, so `/api/feedback`'s fields are intentionally not asserted)
5. **Assert value-blanking** — the hidden-field sentinels seeded in `forms-target/main.go` (`live-test-csrf`, `live-test-token`) must appear in neither generated spec: `ExtractForms` keeps hidden/password/CSRF field *names* and blanks their *values*

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
                     Valid: rest-api,soap-service,graphql-server,grpc-server,concat-spa,forms-target
  --skip-start       Only build, don't start services
  --teardown         Stop all running targets and clean up
  --sweep            With --teardown, also sweep untracked orphans by
                     name/port (off by default; can match unrelated processes)
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
                                      grpc-server, concat-spa, concat-spa-two-stage,
                                      forms-target
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

> **Accepted values.** `run-live-tests.sh` validates `TEST_HOST` before it runs anything and
> **refuses to start** on a value outside the grammar, with
> `refusing to run: TEST_HOST is not a plain hostname, IPv4, or bracketed IPv6 literal`.
> Accepted: a plain hostname (`localhost`, `host.docker.internal`), an IPv4 literal, or a
> **bracketed** IPv6 literal (`[::1]`). The brackets are required because `curl` and `grpcurl`
> take a `host:port` authority and need them to disambiguate the colons; the gRPC preflight
> strips them again for `nc` and bash's `/dev/tcp`, which take a bare host. Anything carrying a
> leading dash, whitespace, or a shell metacharacter is rejected — those values reach a URL, a
> command operand and a `bash -c` argv, so they are screened once here rather than at each sink.
>
> The same check applies to an environment-supplied `GRPC_SERVER_PORT`, which must be 1-65535.
> (Ports read from `.live-test-config` were already validated; this closes the environment path.)

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
# Auto-generated by setup-live-targets.sh on <timestamp>
# Source this or let run-live-tests.sh read it automatically.
REST_API_PORT=8990
SOAP_SERVICE_PORT=8991
GRAPHQL_SERVER_PORT=8992
GRPC_SERVER_PORT=50051
CONCAT_SPA_PORT=8993
FORMS_TARGET_PORT=8994
TARGETS_SETUP=rest-api,soap-service,graphql-server,grpc-server,concat-spa,concat-spa-two-stage,forms-target
```

That is what a **default** `./test/setup-live-targets.sh` writes: all six port keys, every member of the setup script's `ALL_TARGETS`, and `concat-spa-two-stage` appended after `concat-spa`. That last entry is not an `ALL_TARGETS` member and is never built or started on its own: it is a test that reuses the `concat-spa` server, so the setup script appends it to the run-list it writes here while leaving the server single-instance. A partial run (`--targets <subset>`) writes an empty value for each port it did not configure, which is why `load_config` skips empty values rather than treating them as invalid.

> **`TARGETS_SETUP` is additive, not restrictive.** A bare `./test/run-live-tests.sh`
> resolves the full `all` group (every `OFFLINE_TARGETS` + `LIVE_TARGETS`).
> `TARGETS_SETUP` only *adds* targets to that run — it does **not** narrow it.
> Every shipped target is in `OFFLINE_TARGETS` or `LIVE_TARGETS`, so a default run
> already covers all of them and `TARGETS_SETUP` is only a hook for out-of-tree
> additions. To run only the targets you set up, pass
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
| concat-spa | 8993 |
| forms-target | 8994 |

Ports are auto-resolved if the default is in use (searches up to 20 ports ahead).

## Output

Results are saved to `test/.results/` with one subdirectory per test:

```
.results/
├── rest-api/
│   ├── capture-false.json  # net/http backend crawl (the capture spec generation uses)
│   ├── capture-true.json   # rod/Chrome backend crawl (parity check; absent if Chrome is unavailable)
│   ├── capture.json        # copy of capture-false.json
│   └── spec.yaml           # Generated OpenAPI spec
├── scan-rest/
│   └── spec.yaml           # Single-stage `scan` of the same server (no capture file)
├── soap-service/
│   ├── capture-false.json  # net/http backend crawl
│   ├── capture-true.json   # rod/Chrome backend crawl
│   ├── capture.json        # copy of capture-false.json
│   ├── soap-capture.json   # Direct SOAP requests
│   └── spec.xml            # Generated WSDL
├── graphql-server/
│   ├── capture.json        # Live GraphQL traffic
│   ├── capture-rod.json    # rod/Chrome capture backing the SPA-fetch assertion
│   └── spec.graphql        # Generated GraphQL SDL
├── grpc-server/
│   ├── capture.json        # Synthetic capture seeding the reflection probe
│   └── spec.proto          # Generated proto3 from server reflection
├── concat-spa/
│   └── spec.yaml           # Single-stage `scan`; 2 concat-derived paths, no capture file
├── concat-spa-two-stage/
│   ├── capture.json        # Passive crawl (index page + app.js reference only)
│   └── spec.yaml           # Same 2 paths, recovered by generate's JS-replay
├── forms-target/
│   ├── capture-false.json  # net/http backend crawl
│   ├── capture-true.json   # rod/Chrome backend crawl
│   ├── capture.json        # copy of capture-false.json
│   ├── spec.yaml           # Default confidence (POST form endpoints)
│   └── spec-fields.yaml    # --confidence 0 (GET form query params)
├── generate-rest/
│   └── spec.yaml           # OpenAPI spec from reference capture
├── generate-wsdl/
│   └── spec.xml            # WSDL from reference capture
├── generate-wsdl-matrix/
│   └── spec.xml            # WSDL param-extraction matrix (SOAP 1.1/1.2, RPC + doc/literal)
├── generate-graphql/
│   └── spec.graphql        # Deterministic SDL from reference capture
├── generate-graphql-imports/
│   ├── burp-imported.json  # Intermediate capture from Burp XML
│   ├── har-imported.json   # Intermediate capture from HAR
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
├── import-mitmproxy-native/
│   └── imported.json       # Imported from mitmproxy's native tnetstring .mitm
├── import-unicode/
│   └── imported.json       # Imported from Burp XML with unicode
├── import-duplicates/
│   └── imported.json       # Imported from HAR with duplicate requests
├── import-malformed/
│   ├── truncated-burp.xml  # Generated input: truncated XML
│   ├── invalid-burp.xml    # Generated input: not XML
│   └── invalid-har.json    # Generated input: broken JSON
│                           # Imports write to /dev/null — only the inputs remain
├── import-empty/
│   ├── empty-burp.json     # Imported from empty Burp XML
│   └── empty-har.json      # Imported from empty HAR
├── auth-capture/
│   └── imported.json       # Authorization header preserved through import (LAB-3890 A5)
├── edge-cases/
│   ├── capture.json        # Timeout, redirects, HTTP errors, encoding
│   └── spec.yaml           # Spec from the edge-case capture
├── crawl-depth/
│   ├── shallow.json        # Depth-limited crawl
│   ├── limited.json        # Max-pages-limited crawl
│   └── loop.json           # Infinite loop detection
├── crawl-unreachable/
│   └── capture.json        # Crawl of unreachable host
├── no-download/
│   ├── home/               # Isolated HOME; must contain no chromium-<rev> dir
│   ├── capture.json        # Crawl performed under that HOME
│   └── crawl.log           # Crawl output, kept for diagnosis
├── classifier-edge/
│   ├── capture.json        # Synthetic edge case requests
│   └── spec.yaml           # Spec from classifier edge cases
└── spec-edge/
    ├── capture.json        # Synthetic edge case requests
    └── spec.yaml           # Spec with UUID/multi-param paths
```

`ssrf-rejection` writes nothing and creates no directory — it asserts that `vespasian crawl` rejects `http://127.0.0.1:9` without `--dangerous-allow-private`, with output sent to `/dev/null` (LAB-3890 A4).

Every `capture-true.json` and `capture-rod.json` above is a rod/Chrome capture. `rest-api`, `soap-service`, and `forms-target` crawl with both backends and skip the rod leg with a `[WARN]` when Chrome is unavailable or unlaunchable, so those files are absent on a machine without a usable Chrome. Spec generation always uses the net/http capture, so the targets still pass.

## Expected Results

All 32 tests should pass. Order is non-deterministic and durations vary by machine (live crawl tests take the longest). The sample below is a default `--group all` run (21 offline + 11 live targets). `grpc-server` is part of the live group as of LAB-5549 — it runs on a bare `--group live` with no `TARGETS_SETUP` or `--targets` override, so CI exercises it on every PR.

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
  no-download                 PASS      -           -          80s
  rest-api                    PASS      11          11         79s
  scan-rest                   PASS      11          11         84s
  soap-service                PASS      3           3          51s
  spec-edge                   PASS      -           -          0s
  ssrf-rejection              PASS      -           -          0s

  Total: 32 passed, 0 failed, 0 skipped
```

> **Why the three REST targets report different counts.** `generate-rest` is offline: it reads the fixed `rest-api/reference-capture.json` and byte-compares against `rest-api/expected-spec.yaml`, which holds **10** paths, with `/api/login` and `/api/upload` as real POSTs carrying form request bodies (`application/x-www-form-urlencoded` and `multipart/form-data`, added by LAB-2106 form-body parsing and LAB-2109 HTML-form extraction). The two live targets crawl the running server and pick up an eleventh path, `/api/subscribe`, which exists only as a static `<form method="post">` on the index page and reaches the spec through `analyze.ExtractForms` (LAB-3890 T2) — hence **11** for both `rest-api` and `scan-rest`. Those two agree on the path set and on `total_paths`, and deliberately disagree on the *methods* for `/api/login` and `/api/upload`: `rest-api` runs two-stage `crawl` + `generate --probe=false`, so no JavaScript executes and the inline `fetch(…, {method:'POST'})` literals are recovered statically as GET candidates; `scan-rest` runs single-stage `scan` with probing on, observes the JS-fired POSTs, and records both paths as GET+POST. `_assert_fixture_parity` in `test/validate_test.sh` pins `rest-api/expected-paths.json` and `rest-api/scan-expected-paths.json` in lockstep on the path set, `total_paths`, `post_form_paths`, and `post_form_body_fields_by_path` — but not on the method lists. The method lists are enforced separately by `assert_path_methods` in `test/form-spec-asserts.sh`, which both live REST targets run, so a regression that flipped either path's classification fails the suite.

Some tests emit warnings (`[WARN]`) for soft behavioral checks. These are informational and do not cause failures.

## Directory Structure

```
test/
├── setup-live-targets.sh    # Setup script
├── run-live-tests.sh        # Test runner
├── install-chrome.sh        # Provisions a real non-snap Chrome (see "Chrome in containers")
├── common.sh                # Shared logging + Chrome detection (detect_chrome_binary)
├── validate.sh              # Shared validation functions
├── form-spec-asserts.sh     # Form operation/body-field assertions
├── check-docs.py            # Community-health docs guard (LAB-5870)
├── README.md                # This file
├── live-test-gaps.md        # Known coverage gaps
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
├── spec-validators/         # Node parser-backed validators (LAB-3890 T1; npm ci)
│   ├── package.json
│   ├── package-lock.json
│   ├── validate-openapi.mjs # Real OpenAPI validation (@apidevtools/swagger-parser)
│   └── validate-graphql.mjs # Real GraphQL SDL validation (graphql-js)
│
├── rest-api/
│   ├── main.go              # REST API server
│   ├── reference-capture.json    # Fixed capture for generate-rest
│   ├── expected-spec.yaml        # Expected OpenAPI for generate-rest (byte comparison)
│   ├── expected-paths.json       # Expected paths for the two-stage rest-api target
│   └── scan-expected-paths.json  # Expected paths for the single-stage scan-rest target
│
├── soap-service/
│   ├── main.go              # SOAP service server
│   ├── service.wsdl         # WSDL definition
│   ├── reference-capture.json      # Fixed capture for generate-wsdl
│   ├── expected-spec.xml           # Expected WSDL for generate-wsdl
│   ├── matrix-capture.json         # Param-extraction matrix capture (SOAP 1.1/1.2, RPC + doc/literal)
│   ├── matrix-expected-paths.json  # Expected ops for generate-wsdl-matrix
│   ├── matrix-expected-spec.xml    # Expected WSDL for generate-wsdl-matrix
│   └── expected-paths.json         # Expected operations for validation
│
├── graphql-server/
│   ├── server.js            # Apollo Server (GraphQL)
│   ├── package.json         # Node.js dependencies
│   ├── package-lock.json
│   ├── reference-capture.json  # Fixed capture for deterministic tests
│   ├── test-burp.xml        # Burp XML import test data
│   ├── test-traffic.har     # HAR import test data
│   ├── expected-paths.json  # Expected operations for validation
│   └── expected-spec.graphql  # Expected SDL for exact comparison
│
├── grpc-server/
│   ├── main.go              # gRPC server (UserService, OrderService, AccountService)
│   ├── doc.go               # Package documentation
│   ├── Makefile             # run/build/clean plus `proto` codegen for labpb/
│   ├── README.md            # What the target registers and how to regenerate
│   ├── labpb/               # Generated protobuf/gRPC stubs
│   └── expected-paths.json  # Expected services/methods for validation
│
├── proto-validate/          # NESTED MODULE (own go.mod, no workspace) — keeps
│   │                        # protocompile out of the shipped module's requires
│   ├── go.mod               # Its own module; root `go test ./...` does NOT reach it
│   ├── go.sum
│   ├── doc.go               # Package docs + the exit-code contract run-live-tests.sh consumes
│   ├── main.go              # Compiles a generated .proto in-process (protocompile); AC4 check
│   └── main_test.go         # Reject cases + the exit-code contract
│
├── concat-spa/
│   ├── main.go              # SPA whose API paths exist only as JS string concatenations (LAB-1368)
│   └── expected-paths.json  # Expected concat-derived paths (shared by both concat targets)
│
├── forms-target/
│   ├── main.go              # HTML forms server (POST/GET <form> endpoints)
│   └── expected-paths.json  # Expected form-derived paths + query params for validation
│
├── js-static/
│   ├── reference-capture.json  # HTML page + JS bundle for offline generate-js-static
│   └── expected-paths.json     # Expected JS-bundle-derived paths
│
└── fixtures/
    ├── README.md                         # Fixture provenance and licensing
    ├── LICENSE.mitmproxy                 # Upstream MIT notice for real-mitmproxy.mitm
    ├── gen_mitmproxy_native/main.go      # Generator for sample-mitmproxy.mitm
    ├── sample-burp-export.xml            # Burp XML (standard)
    ├── sample-burp-base64.xml            # Burp XML (base64-encoded bodies)
    ├── sample-burp-unicode.xml           # Burp XML (unicode content)
    ├── sample-capture.har                # HAR file (standard)
    ├── sample-auth.har                   # HAR with an Authorization header (auth-capture)
    ├── sample-har-duplicates.json        # HAR file (duplicate requests)
    ├── sample-mitmproxy.json             # mitmproxy JSON export
    ├── sample-mitmproxy.mitm             # mitmproxy native tnetstring stream
    ├── real-mitmproxy.mitm               # Vendored from mitmproxy upstream (MIT); bytes written by mitmproxy itself
    ├── merge-slugs-capture.json          # Slug + numeric-ID siblings (generate-merge-slugs)
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

> **Reading the `expected-*-capture.json` fixtures:** the `query_params` field is multi-value (`map[string][]string`) from LAB-2110 onward, so every value is a JSON array — e.g. `"sort": ["price", "name"]`, and single-value params as `"category": ["electronics"]`. Capture files produced before LAB-2110 used the old single-value `map[string]string` shape and are not comparable byte-for-byte.

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
`./test/install-chrome.sh` or install `google-chrome` directly. `snap install
chromium` is **not** a fix for the container case described here — snapd is
unavailable inside the container (see [Chrome in containers](#chrome-in-containers)),
which is what produced the stub in the first place; it only applies on a host
where snapd is actually running.

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

### `spec-validators deps missing or incomplete`

The Node validators in `test/spec-validators/` are not installed, or an interrupted `npm ci` left `node_modules` present but unusable. `setup-live-targets.sh` does not install them — do it directly:

```bash
(cd test/spec-validators && npm ci --ignore-scripts)
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

### `concat-spa` recovers no endpoints by hand

`vespasian crawl` alone does not run JS-replay, so the concat-derived paths enter the capture unprobed and the 404 control is never filtered out. Reproduce with `scan`, or with `crawl` followed by `generate` (whose JS-replay step probes them):

```bash
./bin/vespasian scan http://localhost:8993 --api-type rest \
    --dangerous-allow-private -o /tmp/spec.yaml
```

### Build failures

Ensure Go modules are up to date:

```bash
cd /path/to/vespasian
go mod tidy
```
