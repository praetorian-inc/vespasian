package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bufbuild/protocompile"
)

// compileTimeout bounds the in-process compile. The input is generated from a
// remote server's reflection data rather than from a fixture in the repo, so a
// pathological spec (deep nesting, a pathological import graph) would otherwise
// turn a one-second check into a hang whose only backstop is live-tests.yml's
// 30-minute job ceiling — with no diagnostic. The companion preflight in
// run-live-tests.sh takes the same position: a check that hangs is strictly
// worse than one that fails with a reason you can read.
const compileTimeout = 60 * time.Second

// compile compiles the .proto at path, returning the compiler's diagnostic on
// failure. Split out from main so the reject cases have a unit test: this helper
// is what stands between a malformed emitted spec and a green live-test run, and
// a regression that made it always succeed would otherwise only show up as the
// gRPC target quietly passing.
func compile(ctx context.Context, path string) error {
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

	_, err := compiler.Compile(ctx, file)
	return err
}

// run is the whole command, minus the process exit. It returns the exit code
// rather than calling os.Exit, and writes through the io.Writers it is handed
// rather than to the process streams, so the contract run-live-tests.sh actually
// depends on — exit 0 compiles, non-zero does not, diagnostics on stderr — is
// unit-testable. The timeout is a PARAMETER rather than a read of the package
// const: that is what makes the timeout branch reachable from a test without
// mutable package state or a clock interface -- a function that accepts its
// inputs is testable by construction. main() passes compileTimeout.
// main() consumed only the exit status, so a regression that
// returned bare instead of exiting non-zero, or that wrote the diagnostic to
// stdout, would have left every compile() subtest green while the gRPC target
// reported PASS on a malformed spec: the same silent pass the `command -v protoc`
// gate produced, relocated one level up. TestRun pins each return.
func run(args []string, stdout, stderr io.Writer, timeout time.Duration) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: proto-validate <file.proto>")
		return 2
	}
	path := args[1]

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := compile(ctx, path); err != nil {
		// Name the timeout as its own outcome so a pathological spec is
		// distinguishable from a malformed one rather than reading as a stuck
		// runner.
		if ctx.Err() != nil {
			fmt.Fprintf(stderr, "proto compile timed out after %s: %v\n", timeout, err)
			return 1
		}
		fmt.Fprintf(stderr, "proto compile failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "OK: %s compiles\n", path)
	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr, compileTimeout))
}
