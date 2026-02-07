# Vespasian

[![CI](https://github.com/praetorian-inc/vespasian/actions/workflows/ci.yml/badge.svg)](https://github.com/praetorian-inc/vespasian/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/vespasian)](https://goreportcard.com/report/github.com/praetorian-inc/vespasian)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> API discovery tool for security assessments — crawls web applications, imports proxy traffic, and generates API specifications.

## Overview

Vespasian maps the API attack surface of applications during authorized security assessments. It captures HTTP traffic from multiple sources (headless browser crawling, Burp Suite/HAR imports, mitmproxy imports), classifies API calls, and generates specification files in the native format for each API type.

Modern applications make API calls dynamically — SPAs via JavaScript at runtime, mobile apps via native HTTP clients. Static analysis is insufficient. Vespasian observes actual HTTP traffic at the wire level and generates usable API specs from those observations.

### Two-stage architecture

```
vespasian crawl <url> -o capture.json             # Capture traffic (headless browser)
vespasian import <format> <file> -o capture.json   # Or import from proxy tools
vespasian generate rest capture.json -o api.yaml   # Generate spec (cheap, repeatable)
vespasian scan <url>                               # Sugar: crawl + generate rest
```

## Installation

### From source

```bash
go install github.com/praetorian-inc/vespasian/cmd/vespasian@latest
```

### From releases

Download the latest binary from the [Releases](https://github.com/praetorian-inc/vespasian/releases) page.

## Usage

```bash
# Crawl a web application and generate an OpenAPI spec
vespasian scan https://app.example.com -H "Authorization: Bearer <token>" -o api.yaml

# Stage 1: Capture traffic
vespasian crawl https://app.example.com -o capture.json

# Stage 1 (alternative): Import from Burp Suite
vespasian import burp traffic.xml -o capture.json

# Stage 2: Generate OpenAPI spec from capture
vespasian generate rest capture.json -o api.yaml
```

## Development

### Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [golangci-lint](https://golangci-lint.run/welcome/install/)

### Getting started

```bash
git clone https://github.com/praetorian-inc/vespasian.git
cd vespasian
make build
```

### Common commands

```bash
make build       # Build the binary
make test        # Run tests
make lint        # Run linters
make fmt         # Format code
make check       # Run all checks (fmt, lint, test)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure all CI checks pass before requesting review.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## About Praetorian

[Praetorian](https://www.praetorian.com/) is a leading cybersecurity company that helps organizations secure their most critical assets.
