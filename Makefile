BINARY := vespasian
MODULE := github.com/praetorian-inc/vespasian
BUILD_DIR := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

# Minimum total statement coverage (%) enforced by `make coverage-gate` (see ci.yml).
# The gate was introduced against an 86.4% baseline (LAB-5331); 85 leaves headroom for
# minor run-to-run/refactor noise while still failing a build on a real regression.
COVERAGE_THRESHOLD ?= 85

.PHONY: build test lint fmt vet check check-docs coverage coverage-gate clean deps live-test-clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/vespasian

test:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -s -w .

vet:
	go vet ./...

check: fmt vet lint test check-docs

# Community-health docs: presence, link/anchor resolution, CODEOWNERS-vs-GOVERNANCE
# roster equality. Also runs as its own CI job, because ci.yml's paths filter means a
# docs-only PR never reaches this Makefile.
check-docs:
	python3 test/check-docs.py

coverage:
	go test -race -coverprofile=coverage.out $$(go list ./... | grep -v '/test/')
	go tool cover -func=coverage.out

# CI gate (LAB-5331): rebuild the profile via `coverage`, then fail if total statement
# coverage is below COVERAGE_THRESHOLD. Parses the `total:` line from `go tool cover
# -func`; fails closed (exit 2) if that line is ever absent.
coverage-gate: coverage
	@go tool cover -func=coverage.out | awk -v threshold=$(COVERAGE_THRESHOLD) 'BEGIN { seen = 0 } /^total:/ { pct = $$NF; sub(/%/, "", pct); seen = 1; printf "total coverage %.1f%% (threshold %d%%)\n", pct, threshold; if (pct + 0 < threshold + 0) { printf "FAIL: coverage %.1f%% is below the %d%% threshold\n", pct, threshold; exit 1 } print "PASS: coverage meets the threshold" } END { if (!seen) { print "ERROR: no total: line in go tool cover output"; exit 2 } }'

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
