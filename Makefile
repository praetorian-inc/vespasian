BINARY := vespasian
MODULE := github.com/praetorian-inc/vespasian
BUILD_DIR := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test test-integration lint lint-comments lint-comments-selftest lint-comments-all fmt vet check check-docs coverage clean deps live-test-clean

# GOWORK=off for the same reason .goreleaser.yml sets it: the shipped binary must
# resolve from the root go.mod/go.sum alone. go.work pulls the test-only
# test/proto-validate module into MVS, so without this a bump in a live-test
# helper's manifest could move the product's dependency set -- and dependabot now
# opens PRs against that manifest weekly. Verified byte-identical either way today;
# this keeps it that way by construction rather than by coincidence.
build:
	GOWORK=off go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/vespasian

# ./... does NOT reach test/proto-validate: it is a separate module (so that
# protocompile stays out of the shipped module's require list) and a root
# package pattern stops at the module boundary even inside a workspace. The
# second path is therefore load-bearing, not belt-and-braces — without it the
# AC4 helper's tests are simply not run. CI covers the same ground in ci.yml's
# proto-validate-tests job, since the reusable workflow it delegates to cannot
# be told about a second module.
test:
	go test -race ./...
	go test -race ./test/proto-validate/...

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
# test/proto-validate module needs its own run from inside its directory —
# ./... from the root does not reach it.
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

# Second path for the same reason as `test`: test/proto-validate is a separate
# module and ./... stops at the module boundary.
vet:
	go vet ./...
	go vet ./test/proto-validate/...

check: fmt vet lint lint-comments test check-docs

# Community-health docs: presence, link/anchor resolution, CODEOWNERS-vs-GOVERNANCE
# roster equality. Also runs as its own CI job, because ci.yml's paths filter means a
# docs-only PR never reaches this Makefile.
check-docs:
	python3 test/check-docs.py

coverage:
	go test -race -coverprofile=coverage.out $$(go list ./... | grep -v '/test/')
	go tool cover -func=coverage.out

deps:
	go mod download
	go mod tidy
	cd test/proto-validate && go mod tidy

clean:
	rm -rf $(BUILD_DIR) dist coverage.out

# Escape hatch for orphaned live-test services: stops every recorded generation
# (kills recorded PIDs only, which is safe). For untracked orphans whose pid log
# was lost, run ./test/setup-live-targets.sh --teardown --sweep directly.
live-test-clean:
	./test/setup-live-targets.sh --teardown
