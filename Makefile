BINARY := vespasian
MODULE := github.com/praetorian-inc/vespasian
BUILD_DIR := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test test-integration lint lint-comments lint-comments-all fmt vet check coverage clean deps live-test-clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/vespasian

test:
	go test -race ./...

# Integration-tagged tests. Separate from `test` because these need a real Chrome,
# so a developer without one can still run `make test`/`make check`. That is why
# the build tag exists rather than a testing.Short() guard.
#
# CI runs this via the integration-tests job in .github/workflows/live-tests.yml.
# Before that job existed nothing passed the tag anywhere, so 24 tests never
# executed — including TestCrawlerContract_ScopeConfinement and _DepthLimit, the
# only end-to-end assertions of two containment controls, and the LAB-4678 tests
# that pin the exact --max-pages cap and the --interact destructive-control gate
# (LAB-4678 review, TEST-005/REQ-002).
test-integration:
	go test -race -tags=integration ./...

lint:
	golangci-lint run

# Fails when a comment guarantees a state cannot occur without naming the test that
# pins it. Scoped to files changed against BASE_REF (default origin/main) so it
# ratchets: new and modified code must comply, pre-existing claims do not block a
# merge. See the script header for the three LAB-4678 defects that motivated it.
lint-comments:
	./scripts/check-unreachability-claims.sh --changed

# Whole-tree sweep. Advisory: run it to see the remaining backlog, not as a gate.
lint-comments-all:
	./scripts/check-unreachability-claims.sh --all

fmt:
	gofmt -s -w .

vet:
	go vet ./...

check: fmt vet lint lint-comments test

coverage:
	go test -race -coverprofile=coverage.out $$(go list ./... | grep -v '/test/')
	go tool cover -func=coverage.out

deps:
	go mod download
	go mod tidy

clean:
	rm -rf $(BUILD_DIR) dist coverage.out

# Escape hatch for orphaned live-test services: stops every recorded generation
# (kills recorded PIDs only, which is safe). For untracked orphans whose pid log
# was lost, run ./test/setup-live-targets.sh --teardown --sweep directly.
live-test-clean:
	./test/setup-live-targets.sh --teardown
