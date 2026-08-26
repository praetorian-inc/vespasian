package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The gRPC live target's AC4 assertion is only as good as compile's ability to
// REJECT. A regression that made it always return nil would leave the target
// reporting PASS on a malformed spec — the same silent-pass failure the protoc
// `command -v` gate produced, just relocated. These cases run in `go test ./...`
// on every PR, which the live suite does not.
func TestCompile(t *testing.T) {
	tests := []struct {
		name    string
		proto   string
		wantErr string // substring of the expected diagnostic; "" means must compile
	}{
		{
			name: "valid proto3 with service and streaming rpc",
			proto: `syntax = "proto3";
package lab.v1;
message GetUserRequest { string id = 1; }
message User { string id = 1; string name = 2; }
service UserService {
  rpc GetUser ( GetUserRequest ) returns ( User );
  rpc ListUsers ( GetUserRequest ) returns ( stream User );
}`,
		},
		{
			name: "well-known import resolves without an include path",
			proto: `syntax = "proto3";
import "google/protobuf/timestamp.proto";
message Event { google.protobuf.Timestamp at = 1; }`,
		},
		{
			name:    "syntax error",
			proto:   "syntax = \"proto3\";\nmessage Bad { string id = ; }\n",
			wantErr: "syntax error",
		},
		{
			name:    "duplicate field tag",
			proto:   "syntax = \"proto3\";\nmessage Dup { string a = 1; string b = 1; }\n",
			wantErr: "same tag",
		},
		{
			name:    "unresolved request type",
			proto:   "syntax = \"proto3\";\nservice S { rpc M ( Missing ) returns ( Missing ); }\n",
			wantErr: "unknown request type",
		},
		{
			name:    "unresolved field type",
			proto:   "syntax = \"proto3\";\nmessage M { NoSuchType f = 1; }\n",
			wantErr: "unknown type",
		},
		{
			name:    "missing import",
			proto:   "syntax = \"proto3\";\nimport \"nope/absent.proto\";\n",
			wantErr: "absent.proto",
		},
		{
			// An empty spec COMPILES. That is not a defect in compile() but it is
			// the documented limit of this check: a truncated emission passes it.
			// Detecting missing content is the python service/method validation's
			// job in run-live-tests.sh, immediately above the compile call — this
			// case exists so that division of labour is recorded rather than
			// rediscovered if that validation is ever refactored away.
			name:  "empty spec compiles (content coverage is the python validation's job)",
			proto: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "spec.proto")
			if err := os.WriteFile(path, []byte(tt.proto), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			err := compile(context.Background(), path)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("compile() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("compile() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("compile() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A generate step that produced no file at all reaches compile() as a
// nonexistent path, and the shell reports that as "emitted .proto failed to
// compile" — misattributing an upstream failure to the spec. Pin that the
// diagnostic at least names the file, so the misattribution is diagnosable from
// the message rather than looking like a syntax problem.
func TestCompileNonexistentPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.proto")

	err := compile(context.Background(), path)
	if err == nil {
		t.Fatal("compile(nonexistent) = nil, want an error")
	}
	if !strings.Contains(err.Error(), "never-written.proto") {
		t.Errorf("compile() error = %q, want it to name the missing file", err)
	}
}

// compile is handed an absolute path by run-live-tests.sh but a bare filename is
// the easy thing to type by hand, and the dir=="." fallback exists only for that
// case. Without a test it could be deleted as dead code.
//
// t.Chdir (Go 1.24+) rather than a hand-rolled Getwd/Chdir/Cleanup trio: it
// restores the directory automatically AND panics if this test or a parent ever
// calls t.Parallel(), which a manual restore cannot do. Without that interlock,
// adding t.Parallel() anywhere in this package would let this chdir race against
// siblings reading relative paths, and the only symptom would be an intermittent
// failure in the suite whose whole job is to be the deterministic guard the live
// suite is not.
func TestCompileBareFilename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bare.proto"), []byte("syntax = \"proto3\";\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	t.Chdir(dir)

	if err := compile(context.Background(), "bare.proto"); err != nil {
		t.Fatalf("compile(bare filename) = %v, want nil", err)
	}
}

// run-live-tests.sh consumes this command purely through its exit status, so the
// contract that actually gates AC4 is: 0 when the spec compiles, non-zero when it
// does not, diagnostics on STDERR. TestCompile covers compile() thoroughly but
// none of that — a regression returning bare instead of non-zero, or printing the
// diagnostic to stdout, would leave every subtest above green while the gRPC
// target reported PASS on a malformed spec.
func TestRun(t *testing.T) {
	writeSpec := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "spec.proto")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return path
	}

	t.Run("wrong argument count exits 2 with usage on stderr", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		if got := run([]string{"proto-validate"}, &stdout, &stderr, compileTimeout); got != 2 {
			t.Errorf("run(no args) = %d, want 2", got)
		}
		if !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("stderr = %q, want it to contain the usage line", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want empty", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		if got := run([]string{"proto-validate", "a.proto", "b.proto"}, &stdout, &stderr, compileTimeout); got != 2 {
			t.Errorf("run(two specs) = %d, want 2", got)
		}
	})

	t.Run("malformed spec exits 1 with the diagnostic on stderr", func(t *testing.T) {
		path := writeSpec(t, "syntax = \"proto3\";\nmessage Dup { string a = 1; string b = 1; }\n")
		var stdout, stderr bytes.Buffer

		if got := run([]string{"proto-validate", path}, &stdout, &stderr, compileTimeout); got != 1 {
			t.Errorf("run(malformed) = %d, want 1", got)
		}
		if !strings.Contains(stderr.String(), "proto compile failed") {
			t.Errorf("stderr = %q, want it to report the compile failure", stderr.String())
		}
		// The shell prints stderr on failure and nothing else; a diagnostic that
		// leaked to stdout would be invisible in the live-test output.
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want the diagnostic on stderr only", stdout.String())
		}
	})

	t.Run("compile timeout is reported as a timeout, not a compile failure", func(t *testing.T) {
		// The timeout branch is the one path a malformed spec never reaches, so
		// without this it was the only uncovered branch in run(). It matters
		// because the two failures need different responses: "your spec is
		// broken" versus "the compile did not finish". A regression collapsing
		// them would send whoever reads the live-test log after the wrong thing.
		//
		// An already-expired budget is what makes this deterministic -- no
		// sleep, no pathological fixture, no dependence on how fast the host
		// compiles.
		path := writeSpec(t, "syntax = \"proto3\";\nmessage M { string a = 1; }\n")
		var stdout, stderr bytes.Buffer

		if got := run([]string{"proto-validate", path}, &stdout, &stderr, 1*time.Nanosecond); got != 1 {
			t.Errorf("run(expired budget) = %d, want 1", got)
		}
		if !strings.Contains(stderr.String(), "timed out") {
			t.Errorf("stderr = %q, want it to report a timeout distinctly from a compile failure", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want empty", stdout.String())
		}
	})

	t.Run("valid spec exits 0 with the OK line on stdout", func(t *testing.T) {
		path := writeSpec(t, "syntax = \"proto3\";\nmessage M { string a = 1; }\n")
		var stdout, stderr bytes.Buffer

		if got := run([]string{"proto-validate", path}, &stdout, &stderr, compileTimeout); got != 0 {
			t.Errorf("run(valid) = %d, want 0; stderr=%q", got, stderr.String())
		}
		if !strings.Contains(stdout.String(), "OK:") {
			t.Errorf("stdout = %q, want it to contain the OK line", stdout.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("stderr = %q, want empty on success", stderr.String())
		}
	})
}
