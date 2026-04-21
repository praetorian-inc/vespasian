// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package importer

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoRoot walks up from the test file until it finds a go.mod, locating the
// module root so fixture paths work regardless of where `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod")
		}
		dir = parent
	}
}

// TestMitmproxyFixture_MatchesGenerator asserts the committed binary fixture
// matches what the generator currently produces. Without this, the committed
// file can silently drift from `gen_mitmproxy_native/main.go` and tests keep
// passing against stale bytes. Regression for round-1 TEST-003.
//
// The test intentionally runs under -short mode too: drift protection is the
// whole point of this test, and `go run` compilation is fast enough (~100ms
// after Go's build cache warms) that the cost is negligible compared to the
// cost of shipping a silently-stale fixture.
//
// If this test fails after intentional generator changes, regenerate:
//
//	go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm
func TestMitmproxyFixture_MatchesGenerator(t *testing.T) {
	root := repoRoot(t)
	fixturePath := filepath.Join(root, "test", "fixtures", "sample-mitmproxy.mitm")
	committed, err := os.ReadFile(fixturePath) //nolint:gosec // test-time fixture read, path derived from repo root
	require.NoError(t, err, "sample-mitmproxy.mitm missing")

	cmd := exec.Command("go", "run", "./test/fixtures/gen_mitmproxy_native")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "generator failed: %s", stderr.String())

	if !bytes.Equal(committed, stdout.Bytes()) {
		t.Fatalf("test/fixtures/sample-mitmproxy.mitm is stale (%d bytes committed, %d bytes generated).\n"+
			"Regenerate with:\n  go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm",
			len(committed), stdout.Len())
	}
}

// TestMitmproxyImporter_Native_RealFixture imports a flow file that was
// actually produced by mitmproxy (vendored from mitmproxy's own test data:
// test/mitmproxy/data/dumpfile-7.mitm, MIT license).
//
// Assertions pin specific fields rather than only checking shape, so schema
// drift in mitmproxy's HTTPFlow.get_state() that silently dropped or renamed
// a field would surface here. Regression for round-1 TEST-002 and round-2
// TEST-R2-002.
//
// Expected contents:
//
//	flow 0: GET http://example.com/     → 200, Content-Type text/html; charset=UTF-8
//	flow 1: GET https://example.com/    → 200, no Content-Type header
//
// If upstream mitmproxy's dumpfile-7.mitm changes, regenerate the expected
// values by running: `./bin/vespasian import mitmproxy test/fixtures/real-mitmproxy.mitm`.
func TestMitmproxyImporter_Native_RealFixture(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "test", "fixtures", "real-mitmproxy.mitm")
	data, err := os.ReadFile(path) //nolint:gosec // test-time fixture read, path derived from repo root
	require.NoError(t, err)

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(data))
	require.NoError(t, err, "import of real mitmproxy-produced flow file failed")

	require.Len(t, requests, 2, "dumpfile-7.mitm is known to contain exactly 2 HTTP flows")

	// Flow 0: unencrypted request via HTTP proxy.
	flow0 := requests[0]
	assert.Equal(t, "GET", flow0.Method)
	assert.Equal(t, "http://example.com/", flow0.URL)
	assert.Equal(t, 200, flow0.Response.StatusCode)
	assert.Equal(t, "text/html; charset=UTF-8", flow0.Response.ContentType)
	assert.Equal(t, "import:mitmproxy", flow0.Source)
	// Proxy-Connection header is characteristic of explicit-proxy captures;
	// its presence validates that headers from real mitmproxy output survive
	// the encode→decode→convert path.
	assert.Contains(t, flow0.Headers, "Proxy-Connection")
	assert.Contains(t, flow0.Headers, "Host")
	assert.Contains(t, flow0.Headers, "User-Agent")
	assert.NotEmpty(t, flow0.Response.Body, "response body should be populated")

	// Flow 1: HTTPS, captured via transparent proxy. Headers are lowercased
	// on the wire (curl HTTP/2-style); mitmproxy preserves wire case.
	flow1 := requests[1]
	assert.Equal(t, "GET", flow1.Method)
	assert.Equal(t, "https://example.com/", flow1.URL)
	assert.Equal(t, 200, flow1.Response.StatusCode)
	assert.Equal(t, "import:mitmproxy", flow1.Source)
	// Preserve wire-case header names exactly. The fixture was produced by
	// a curl client, so these are lowercase.
	assert.Contains(t, flow1.Headers, "user-agent")
	assert.Contains(t, flow1.Headers, "accept")
	assert.Equal(t, "curl/7.58.0", flow1.Headers["user-agent"])

	// Response body is the canonical example.com HTML (~1.2KB) — pin length
	// rather than the full body to keep the test readable.
	assert.NotEmpty(t, flow1.Response.Body, "flow 1 response body should be populated")
	assert.Contains(t, string(flow1.Response.Body), "Example Domain",
		"example.com response body should contain the title")

	// Response headers: pin a representative selection. Wire-case again.
	assert.Contains(t, flow1.Response.Headers, "content-type")
	assert.Equal(t, "text/html; charset=UTF-8", flow1.Response.Headers["content-type"])

	// Characterize a pre-existing header-lookup quirk: ObservedResponse's
	// ContentType convenience field is populated from a case-sensitive
	// "Content-Type" lookup in convertMitmproxyHeaders, so lowercase wire
	// headers leave it empty. This is existing behavior, not introduced by
	// LAB-2309; pin it here so a future lookup change surfaces deliberately.
	assert.Empty(t, flow1.Response.ContentType,
		"ContentType shortcut is case-sensitive; HTTP/2 lowercase leaves it empty (pre-existing behavior)")
}
