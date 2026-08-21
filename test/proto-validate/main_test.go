package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "spec.proto")
			if err := os.WriteFile(path, []byte(tt.proto), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			err := compile(path)

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

// compile is handed an absolute path by run-live-tests.sh but a bare filename is
// the easy thing to type by hand, and the dir=="." fallback exists only for that
// case. Without a test it could be deleted as dead code.
func TestCompileBareFilename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bare.proto"), []byte("syntax = \"proto3\";\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := compile("bare.proto"); err != nil {
		t.Fatalf("compile(bare filename) = %v, want nil", err)
	}
}
