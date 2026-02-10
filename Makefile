BINARY := vespasian
MODULE := github.com/praetorian-inc/vespasian
BUILD_DIR := bin

.PHONY: build test lint fmt vet check clean cato

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/vespasian

cato:
	go build -o $(BUILD_DIR)/cato ./cmd/cato

test:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

vet:
	go vet ./...

check: fmt vet lint test

clean:
	rm -rf $(BUILD_DIR) dist
