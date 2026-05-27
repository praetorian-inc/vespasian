//go:build live

// Package sdklive holds opt-in live/integration tests for the Chariot SDK
// pipeline (pkg/sdk). They are gated behind the "live" build tag so the default
// CI run (go test -race ./...) skips them.
//
//	go test -tags live ./test/sdk/...
//
// The parity tests reuse the fixed reference captures and expected specs that
// the shell suite's deterministic generate-{rest,wsdl,graphql} tests validate
// (test/<target>/reference-capture.json + expected-spec.*), so the SDK pipeline
// is held to the same ground truth as the CLI.
package sdklive

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/sdk"
)

var portRe = regexp.MustCompile(`localhost:[0-9]+`)

func normalizePorts(s string) string { return portRe.ReplaceAllString(s, "localhost:PORT") }

func loadCapture(t *testing.T, path string) []crawl.ObservedRequest {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "read capture %s", path)
	var reqs []crawl.ObservedRequest
	require.NoError(t, json.Unmarshal(data, &reqs), "parse capture %s", path)
	require.NotEmpty(t, reqs, "capture %s has no requests", path)
	return reqs
}

// TestClassifyProbeGenerate_SpecParity asserts the SDK pipeline wrapper produces
// the same spec as the CLI generate path for each protocol. Parameters mirror
// run-live-tests.sh (confidence 0.5, probe=false; dedup true except GraphQL).
func TestClassifyProbeGenerate_SpecParity(t *testing.T) {
	cases := []struct {
		name        string
		capture     string
		expected    string
		apiType     string
		deduplicate bool
		normalize   bool
	}{
		{"rest", "../rest-api/reference-capture.json", "../rest-api/expected-spec.yaml", "rest", true, true},
		{"wsdl", "../soap-service/reference-capture.json", "../soap-service/expected-spec.xml", "wsdl", true, true},
		{"graphql", "../graphql-server/reference-capture.json", "../graphql-server/expected-spec.graphql", "graphql", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs := loadCapture(t, tc.capture)

			spec, warns, err := sdk.ClassifyProbeGenerate(
				context.Background(), reqs, tc.apiType, 0.5, tc.deduplicate, false /*probe*/)
			require.NoError(t, err)
			require.NotEmpty(t, spec, "SDK produced an empty spec")

			expected, err := os.ReadFile(tc.expected)
			require.NoError(t, err, "read expected spec %s", tc.expected)

			got, want := string(spec), string(expected)
			if tc.normalize {
				got, want = normalizePorts(got), normalizePorts(want)
			}
			assert.Equal(t, want, got,
				"sdk.ClassifyProbeGenerate(%s) diverged from the CLI expected spec (%d probe warnings)",
				tc.apiType, len(warns))
		})
	}
}

// TestInvoke_RejectsPrivateSeed pins the trust boundary: Match accepts a private
// seed (trusted-seed model) but Invoke's headless crawl frontier rejects it.
func TestInvoke_RejectsPrivateSeed(t *testing.T) {
	c := &sdk.Capability{}
	input := capmodel.WebApplication{PrimaryURL: "http://127.0.0.1:1/"}

	require.NoError(t, c.Match(capability.ExecutionContext{}, input),
		"Match should accept a private/loopback seed under the trusted-seed model")

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "timeout", Value: "30"},
		},
	}
	err := c.Invoke(ctx, input, capability.EmitterFunc(func(...any) error { return nil }))
	require.Error(t, err, "Invoke should refuse to crawl a private/loopback seed")

	if strings.Contains(err.Error(), "launch browser") || strings.Contains(err.Error(), "browser binary") {
		t.Skipf("no usable browser in this environment; cannot reach the frontier SSRF gate: %v", err)
	}
	assert.Contains(t, err.Error(), "rejected by frontier",
		"private seed should be rejected by the crawl frontier SSRF gate")
}
