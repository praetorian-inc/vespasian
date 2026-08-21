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
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bufbuild/protocompile"
)

// compile compiles the .proto at path, returning the compiler's diagnostic on
// failure. Split out from main so the reject cases have a unit test: this helper
// is what stands between a malformed emitted spec and a green live-test run, and
// a regression that made it always succeed would otherwise only show up as the
// gRPC target quietly passing.
func compile(path string) error {
	dir, file := filepath.Split(path)
	if dir == "" {
		dir = "."
	}

	// WithStandardImports resolves google/protobuf/*.proto from the embedded
	// registry, so a spec importing a well-known type compiles without the
	// include path a protoc invocation would need.
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			ImportPaths: []string{dir},
		}),
		SourceInfoMode: protocompile.SourceInfoNone,
	}

	_, err := compiler.Compile(context.Background(), file)
	return err
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: proto-validate <file.proto>")
		os.Exit(2)
	}
	path := os.Args[1]

	if err := compile(path); err != nil {
		fmt.Fprintf(os.Stderr, "proto compile failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: %s compiles\n", path)
}
