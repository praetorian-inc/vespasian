// Package sdklive holds opt-in live/integration tests for the Chariot SDK
// pipeline (pkg/sdk), gated behind the "live" build tag. This file is
// intentionally untagged so the package is always buildable; the tests live in
// build-tagged files (see parity_test.go) and only run with `-tags live`.
package sdklive
