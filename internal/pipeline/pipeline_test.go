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

package pipeline_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ---------------------------------------------------------------------------
// TEST-003: Options.Status writer — pin the io.Writer seam
// ---------------------------------------------------------------------------

// restRequests returns a minimal slice of REST-like requests suitable for
// feeding ClassifyProbeGenerate in REST mode.
func restRequests() []crawl.ObservedRequest {
	return []crawl.ObservedRequest{
		{
			Method:  "GET",
			URL:     "https://x.com/api/v1/users",
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`[{"id":1}]`),
			},
		},
	}
}

func TestClassifyProbeGenerate_StatusWriterNil(t *testing.T) {
	// Status=nil must not panic and must produce no unexpected output.
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:    pipeline.APITypeREST,
		Confidence: 0.5,
		Probe:      false,
		Status:     nil,
	})
	require.NoError(t, err)
}

func TestClassifyProbeGenerate_StatusWriterCaptures(t *testing.T) {
	// Status=&bytes.Buffer{} must capture the "classified N API requests" line.
	var buf bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:    pipeline.APITypeREST,
		Confidence: 0.5,
		Probe:      false,
		Status:     &buf,
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "classified")
	assert.Contains(t, buf.String(), "API requests")
}

// ---------------------------------------------------------------------------
// TEST-004: happy-path test for ClassifyProbeGenerate
// ---------------------------------------------------------------------------

func TestClassifyProbeGenerate_RESTHappyPath(t *testing.T) {
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:     pipeline.APITypeREST,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, spec, "expected non-empty OpenAPI spec for REST requests")
}

func TestClassifyProbeGenerate_EmptyRequestsReturnsSpec(t *testing.T) {
	// An empty requests slice is not an error; the generator produces a minimal
	// (possibly empty) spec.
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), nil, pipeline.Options{
		APIType:    pipeline.APITypeREST,
		Confidence: 0.5,
	})
	// ClassifyProbeGenerate should not error on empty input for known api types.
	require.NoError(t, err)
	// spec may be empty but the call must not panic.
	_ = spec
}

func TestClassifyProbeGenerate_UnknownTypeErrors(t *testing.T) {
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:    "unknown",
		Confidence: 0.5,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported API type")
}

// ---------------------------------------------------------------------------
// TEST-002: Probe-enabled path — pin that the AllowPrivate http.Client
// construction and strategies execution run end-to-end without error and
// still produce a spec. OptionsProbe and SchemaProbe swallow individual
// request failures internally and never surface to probeErrs, so the
// "probe warning:" forwarding loop in pipeline.go is unreachable for REST
// mode and is intentionally not exercised here.
// ---------------------------------------------------------------------------

func TestClassifyProbeGenerate_ProbeEnabledEmitsSpec(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)

	requests := []crawl.ObservedRequest{
		{
			Method:  "GET",
			URL:     ts.URL + "/api/v1/users",
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`[{"id":1}]`),
			},
		},
	}
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, spec, "expected non-empty OpenAPI spec when Probe=true")
}

// slugRequests returns two REST requests to sibling slug paths under the same
// collection (/api/posts/a and /api/posts/b), enough distinct values to trip
// slug merging at threshold 2.
func slugRequests() []crawl.ObservedRequest {
	req := func(url string) crawl.ObservedRequest {
		return crawl.ObservedRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`{"id":1}`),
			},
		}
	}
	return []crawl.ObservedRequest{
		req("https://x.com/api/posts/a"),
		req("https://x.com/api/posts/b"),
	}
}

// TestClassifyProbeGenerate_MergeSlugsPassThrough pins that Options.MergeSlugs
// and Options.SlugThreshold reach generate.GetWithOptions: with MergeSlugs set,
// two sibling slug paths collapse into one templated path in the emitted spec,
// whereas leaving MergeSlugs unset keeps them literal. Without this, a regressed
// pass-through at this layer would go undetected (it is otherwise only exercised
// via the CLI and pkg/generate).
func TestClassifyProbeGenerate_MergeSlugsPassThrough(t *testing.T) {
	merged, err := pipeline.ClassifyProbeGenerate(context.Background(), slugRequests(), pipeline.Options{
		APIType:       pipeline.APITypeREST,
		Confidence:    0.5,
		Probe:         false,
		Deduplicate:   true,
		MergeSlugs:    true,
		SlugThreshold: 2,
	})
	require.NoError(t, err)
	assert.Contains(t, string(merged), "/api/posts/{postSlug}", "MergeSlugs=true must collapse siblings into a templated path")
	assert.NotContains(t, string(merged), "/api/posts/a", "merged spec must not retain the literal slug path")

	// Control: without MergeSlugs the same input keeps the literal paths, proving
	// the collapse above is driven by the flag pass-through, not the fixture.
	literal, err := pipeline.ClassifyProbeGenerate(context.Background(), slugRequests(), pipeline.Options{
		APIType:     pipeline.APITypeREST,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	require.NoError(t, err)
	assert.Contains(t, string(literal), "/api/posts/a", "MergeSlugs unset must keep the literal slug path")
	assert.NotContains(t, string(literal), "{postSlug}", "MergeSlugs unset must not template the slug position")
}
