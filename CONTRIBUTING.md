# Contributing to Vespasian

Contributions to Vespasian are welcome. Follow the steps below to get started.

## Development Setup

### Prerequisites

- Go 1.24+
- golangci-lint

### Build and Test

```bash
git clone https://github.com/praetorian-inc/vespasian.git
cd vespasian
make build       # Build the binary to bin/vespasian
make test        # Run tests with race detection
make lint        # Run golangci-lint (gocritic, misspell, revive)
make check       # Run all checks (fmt, vet, lint, test)
make coverage    # Generate coverage report
make deps        # Download and tidy modules
make clean       # Remove build artifacts
```

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure all CI checks pass before requesting review.
