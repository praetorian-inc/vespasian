# vespasian

Canonical agent instruction file for this repository; every coding agent that
works here loads it. `CLAUDE.md` is a one-line pointer to this file and
`.gemini/settings.json` lists it as a context file. Edit this file, never the
pointers.

Vespasian captures HTTP traffic (headless crawl or Burp/HAR/mitmproxy import),
classifies API type, probes endpoints, and emits OpenAPI 3.0, GraphQL SDL, WSDL,
or `.proto`. gRPC is opt-in (`--api-type grpc`); it is never auto-detected.

The tree documents itself; this file carries only what it does not.

- `docs/agents/architecture.md` — pipeline, packages, capture format
- `docs/agents/cli.md` — `scan` / `crawl` / `import` / `generate` flags
- `docs/agents/testing.md` — live targets, nested module, spec validators
- `docs/agents/ci.md` — workflow jobs and gates
- `README.md`, `docs/crawler.md`, `docs/grpc.md`, `test/README.md`

## Build and Test Commands

```bash
make build              # binary under bin/
make test               # go test -race ./... AND test/proto-validate
make test-integration   # go test -race -tags=integration ./... (needs Chrome)
make lint               # golangci-lint here AND in test/proto-validate
make lint-comments      # unreachability claims on files changed vs origin/main
make fmt
make gosec              # go run gosec at the version security.yml pins
make check              # fmt vet lint lint-comments gosec test check-docs
make check-docs
make coverage
make coverage-gate      # fails below 85%
make deps
make clean
make live-test-clean    # teardown recorded live-test PIDs
go test ./pkg/classify/...
```

`make test` is two invocations, not one. `test/proto-validate` is a nested
module (`test/proto-validate/go.mod`); a root `./...` pattern stops at the
module boundary, and there is deliberately no workspace file (gitignored) so
the helper stays out of the shipped module's require list. `make test`,
`make vet`, `make lint`, and `make deps` each enter it with `cd`. Adding
another nested module means wiring every consumer those two greps name:
`grep -rn 'cd test/proto-validate' Makefile` and
`grep -rln 'working-directory: test/proto-validate' .github/workflows/`.

`make test-integration` needs a real Chrome. Without one, rod tests skip
unless `VESPASIAN_REQUIRE_CHROME=1` (CI sets this; a skip then becomes a
failure). Headless crawl pins a local Chrome; if none is found it errors
unless `VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true`.

Spec validators: `(cd test/spec-validators && npm ci --ignore-scripts)` once,
then `test/validate.sh`. `test/validate_test.sh` locks reject behaviour.

## Code Conventions

### Comments that claim a state is impossible must cite a test

If a comment guarantees something cannot happen, is unreachable, or can never
occur, it must name the test that would fail if it did. `make lint-comments`
enforces this on files changed against origin/main; `make lint-comments-all`
sweeps the whole tree advisorily. It is part of `make check`.

This is not a rule against long comments. Soften the claim or write the test;
do not delete the explanation. Read the code, not the comment — where a trace
and a comment disagree, the trace is the finding.

### Comments do not cite review-round ids

`TEST-003`, `SEC-BE-014`, `QUAL-007`, and the short `N-2`/`C4`/`D1` forms
resolve to nothing outside the round that produced them. Name the reason.
Linear and GitHub references stay. Clear on touch, not as a repo-wide sweep.

- Go files: lowercase_with_underscores (`rest_classifier.go`). Tests match
  (`foo.go` → `foo_test.go`). `gofmt -s` via `make fmt`. Package docs in
  `doc.go`.
- Gosec suppressions are `#nosec <RULE> -- <reason>`, never `//nolint:gosec`.
  `make lint` honors `//nolint`; `.github/workflows/security.yml` honors only
  `#nosec`.
- `generate grpc` is not offline: descriptors are `json:"-"` so reflection
  re-runs live (`--probe`, default on). There is no standalone `probe`
  command.
- Capture `query_params` is `map[string][]string`. Files from LAB-2110 and
  earlier (`map[string]string`) are incompatible — recapture. Pre-LAB-4992
  `crawl`/`scan` captures stay readable but miss `static:js-concat`; recapture.
  `import` captures are unaffected.
- `--interact` is headless-only, off by default, and can submit forms.

## Development Workflow

- After a feature or fix, `make check`.
- If a public API or package purpose changes, update that package's `doc.go`.
- Keep `README.md` and this file accurate; `CLAUDE.md` is only the pointer.
