// Command proto-validate compiles a .proto file and exits non-zero if it does
// not compile, printing the compiler diagnostics.
//
// It exists because the live-test suite's AC4 assertion (LAB-2778) — "the
// emitted .proto actually compiles" — was gated on `command -v protoc` and so
// silently skipped everywhere it mattered: protoc ships on no GitHub-hosted
// ubuntu-24.04 image, and live-tests.yml runs under `disable-sudo: true`, which
// rules out `apt-get install protobuf-compiler` (the same constraint that
// forced LAB-3890 to drop `xmllint --schema`). A marketplace action such as
// arduino/setup-protoc would need the praetorian-inc enterprise allowlist —
// exactly what blocked LAB-4747. Compiling in-process with protocompile removes
// the external dependency instead of provisioning it, so the check runs
// unconditionally on every runner and developer machine (LAB-5549).
//
// protocompile is deliberately a DIFFERENT implementation from the
// jhump/protoreflect protoprint that writes the spec, so this stays an
// independent check rather than a printer agreeing with itself.
//
// Exit codes are the contract run-live-tests.sh consumes: 0 the spec compiles,
// 1 it does not (diagnostic on stderr), 2 the arguments were wrong.
package main
