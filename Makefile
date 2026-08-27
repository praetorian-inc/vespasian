BINARY := vespasian
MODULE := github.com/praetorian-inc/vespasian
BUILD_DIR := bin
# Must match gosec-version in .github/workflows/security.yml; that job fails on
# findings, so a local run at another version can disagree with CI.
GOSEC_VERSION ?= v2.28.0
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

# Minimum total statement coverage (%) enforced by `make coverage-gate` (see ci.yml).
# The gate was introduced against an 86.4% baseline (LAB-5331); 85 leaves headroom for
# minor run-to-run/refactor noise while still failing a build on a real regression.
COVERAGE_THRESHOLD ?= 85
# Exported (rather than passed via `awk -v`) so the gate reads it from ENVIRON: make
# places the value straight into the recipe's environment, where it never transits an
# `sh -c` word-split, so a value like `100' 'BEGIN{exit 0}` cannot smuggle a second
# program argument into awk. See coverage-gate-check below.
export COVERAGE_THRESHOLD

# Coverage profile path, and the command that emits the `go tool cover -func` report
# the gate parses. Both are seams. COVERAGE_PROFILE lets `coverage`/`coverage-gate`
# target an alternate profile; COVERAGE_FUNC lets scripts/coverage-gate_test.sh drive
# the real `coverage-gate-check` target against a fixture (COVERAGE_FUNC='cat fixture')
# with no Go build, so the test can assert make's own exit code.
COVERAGE_PROFILE ?= coverage.out
COVERAGE_FUNC ?= go tool cover -func=$(COVERAGE_PROFILE)

.PHONY: build test test-integration lint lint-comments lint-comments-selftest lint-comments-all fmt vet gosec check check-docs coverage coverage-gate coverage-gate-check clean deps live-test-clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/vespasian

# ./... does NOT reach test/proto-validate: it is a separate module (so that
# protocompile stays out of the shipped module's require list) and a package
# pattern stops at the module boundary. There is deliberately NO go.work -- a
# workspace would couple the product's dependency resolution to a live-test
# helper's manifest -- so the module is entered with `cd` rather than named by a
# root-relative path, which is the only form that works without one. The second
# line is load-bearing: without it the AC4 helper's tests simply do not run.
# CI covers the same ground in ci.yml's proto-validate-tests job.
test:
	go test -race ./...
	cd test/proto-validate && go test -race ./...

# Integration-tagged tests. Separate from `test` because these need a real Chrome,
# so a developer without one can still run `make test`/`make check`. That is why
# the build tag exists rather than a testing.Short() guard.
#
# CI runs this via the integration-tests job in .github/workflows/live-tests.yml.
# Before that job existed nothing passed the tag anywhere, so 24 tests never
# executed — including TestCrawlerContract_ScopeConfinement and _DepthLimit, the
# only end-to-end assertions of two containment controls, and the LAB-4678 tests
# that pin the exact --max-pages cap and the --interact destructive-control gate
# (LAB-4678 review).
test-integration:
	go test -race -tags=integration ./...

# golangci-lint resolves one module per invocation, so the nested
# test/proto-validate module needs its own run from inside its directory.
lint:
	golangci-lint run
	cd test/proto-validate && golangci-lint run

# Fails when a comment guarantees a state cannot occur without naming the test that
# pins it. Scoped to comment BLOCKS whose lines changed against BASE_REF (default
# origin/main), so it genuinely ratchets: new and modified code must comply, and a
# pre-existing claim in a file you edited elsewhere does not block the merge. It was
# file-scoped first, which broke that promise the moment a branch merged main — seven
# other authors' claims came into scope and failed the build. See the script header
# for the three LAB-4678 defects that motivated the check itself.
lint-comments: lint-comments-selftest
	./scripts/check-unreachability-claims.sh --changed

# Regression test for the checker itself, run before it so a broken checker is
# reported as such rather than as claim violations. Cheap (about a second, no Go
# build). NOTE: a green run here bounds this platform only — the checker is written
# on macOS and the BSD/GNU userlands diverge in both directions, so CI running this
# on ubuntu is what actually covers it.
lint-comments-selftest:
	./scripts/check-unreachability-claims_test.sh

# Whole-tree sweep. Advisory: run it to see the remaining backlog, not as a gate.
lint-comments-all:
	./scripts/check-unreachability-claims.sh --all

fmt:
	gofmt -s -w .

# Same reason as `test`: a separate module, entered with `cd` because there is no
# workspace to make a root-relative pattern reach it.
vet:
	go vet ./...
	cd test/proto-validate && go vet ./...

# The scan the `security / Gosec` job runs, so a finding can be reproduced locally;
# that job no longer passes -no-fail. Run through `go run @$(GOSEC_VERSION)` rather
# than a PATH binary because a go-installed gosec reports its version as "dev", so
# there is no way to check that an already-installed one matches CI. Text output
# instead of the workflow's SARIF, which exists for the upload step.
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -exclude-generated ./...

check: fmt vet lint lint-comments gosec test check-docs

# Community-health docs: presence, link/anchor resolution, CODEOWNERS-vs-GOVERNANCE
# roster equality. Also runs as its own CI job, because ci.yml's paths filter means a
# docs-only PR never reaches this Makefile.
check-docs:
	python3 test/check-docs.py

coverage:
	go test -race -coverprofile=$(COVERAGE_PROFILE) $$(go list ./... | grep -v '/test/')
	go tool cover -func=$(COVERAGE_PROFILE)

# CI gate (LAB-5331): rebuild the profile via `coverage`, then enforce the threshold.
# The enforcement lives in `coverage-gate-check` so it can run against an existing
# profile without a rebuild -- that seam is what lets scripts/coverage-gate_test.sh
# invoke the real target and assert make's exit code, closing three regressions the
# awk-fragment test cannot see: a `-` recipe prefix that would make `make` swallow a
# FAIL, a dropped `+ 0` that turns the numeric compare lexicographic, and a zeroed
# default threshold.
coverage-gate: coverage coverage-gate-check

# Enforce COVERAGE_THRESHOLD against an already-built profile (COVERAGE_FUNC emits the
# `go tool cover -func` report). Fails (exit 1) if total statement coverage is below
# the threshold; fails closed (exit 2) if the `total:` line is ever absent.
#
# COVERAGE_THRESHOLD is validated in BEGIN before any comparison and read from ENVIRON
# (see the `export` above) rather than interpolated into the awk command, so an
# untrusted value cannot inject a second program argument. awk's `threshold + 0` would
# silently coerce a non-numeric value to 0, letting ANY coverage pass a gate that still
# prints a reassuring PASS -- the one failure mode a coverage gate must not have -- so
# the regex admits only digits with an optional decimal part (rejecting negatives by
# construction) and the second check bounds the top end. `exit` in BEGIN still runs
# END, hence the `bad` flag so END does not overwrite the status with its own.
# scripts/coverage-gate_test.sh pins each of these exit codes, including via the real
# target through the COVERAGE_FUNC seam.
coverage-gate-check:
	@$(COVERAGE_FUNC) | awk 'BEGIN { threshold = ENVIRON["COVERAGE_THRESHOLD"]; seen = 0; bad = 0; if (threshold !~ /^[0-9]+(\.[0-9]+)?$$/) { printf "ERROR: COVERAGE_THRESHOLD \"%s\" is not a number\n", threshold; bad = 2; exit 2 } if (threshold + 0 > 100) { printf "ERROR: COVERAGE_THRESHOLD %s is outside 0..100\n", threshold; bad = 2; exit 2 } } /^total:/ { pct = $$NF; sub(/%/, "", pct); seen = 1; printf "total coverage %.1f%% (threshold %.1f%%)\n", pct, threshold; if (pct + 0 < threshold + 0) { printf "FAIL: coverage %.1f%% is below the %.1f%% threshold\n", pct, threshold; exit 1 } print "PASS: coverage meets the threshold" } END { if (bad) exit bad; if (!seen) { print "ERROR: no total: line in go tool cover output"; exit 2 } }'

deps:
	go mod download
	go mod tidy
	cd test/proto-validate && go mod tidy

clean:
	rm -rf $(BUILD_DIR) dist $(COVERAGE_PROFILE)

# Escape hatch for orphaned live-test services: stops every recorded generation
# (kills recorded PIDs only, which is safe). For untracked orphans whose pid log
# was lost, run ./test/setup-live-targets.sh --teardown --sweep directly.
live-test-clean:
	./test/setup-live-targets.sh --teardown
