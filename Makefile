BINARY := vespasian
MODULE := github.com/praetorian-inc/vespasian
BUILD_DIR := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test lint fmt vet check coverage clean deps

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

check: fmt vet lint test

coverage:
	go test -race -coverprofile=coverage.out $$(go list ./... | grep -v '/test/')
	go tool cover -func=coverage.out

deps:
	go mod download
	go mod tidy

clean:
	rm -rf $(BUILD_DIR) dist coverage.out
