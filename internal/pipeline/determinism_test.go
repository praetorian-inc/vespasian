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
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// determinismRuns is how many times each pipeline is executed. Go randomizes map
// iteration order per range statement, so repeating in-process is what surfaces
// order-dependence — it is not redundant repetition of one deterministic path.
// Ten is enough to make a map-order dependence overwhelmingly likely to show while
// keeping the test in the millisecond range.
const determinismRuns = 10

// determinismCapture builds a capture shaped to exercise every ordering-sensitive
// path LAB-4678 Phases 1-3 touched, so an order-dependence regression in any of them
// shows up here:
//
//   - the SAME endpoint observed more than once with DIFFERENT response shapes, so
//     response-schema union order matters (Phase 3),
//   - a top-level JSON ARRAY response, the union path that used to be unreachable,
//   - two DIFFERENT HOSTS serving the same path, so the host component of the dedup
//     key matters (Phase 1),
//   - several requests with MULTIPLE HEADERS, so header-key ordering matters,
//   - multi-valued query parameters, so query merge order matters,
//   - synthesized static-analysis entries alongside dynamic ones, so the synthesized
//     comparator's total order matters (Phase 2),
//   - a GraphQL request in a REST-dominant capture, so the API-type tiebreaker is
//     exercised rather than being a walkover (Phase 3).
//
// It also returns the count of DYNAMIC entries, i.e. the index where the synthesized
// static-analysis entries begin. Tests need that boundary because "synthesized entries
// come last" is a load-bearing pipeline invariant, not an incidental layout: pkg/analyze
// and pkg/analyze/jsstatic append after the dynamic slice specifically so
// classify.Deduplicate keeps dynamic observations on ties. Returning it beats
// hardcoding an index that silently drifts when a request is added above.
func determinismCapture() (reqs []crawl.ObservedRequest, dynamicCount int) {
	hdr := func(extra ...string) map[string]string {
		h := map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
			"User-Agent":   "vespasian-test",
			"X-Request-Id": "fixed",
			"X-Trace":      "fixed",
		}
		for i := 0; i+1 < len(extra); i += 2 {
			h[extra[i]] = extra[i+1]
		}
		return h
	}
	jsonResp := func(body string) crawl.ObservedResponse {
		return crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Headers:     map[string]string{"Content-Type": "application/json", "X-Served-By": "a"},
			Body:        []byte(body),
		}
	}

	reqs = []crawl.ObservedRequest{
		// Same endpoint, two observations with disjoint fields: the response schema
		// must union to a stable field set regardless of visit order.
		{Method: "GET", URL: "https://a.example.com/api/users", Headers: hdr(),
			Response: jsonResp(`{"id":1,"name":"a"}`)},
		{Method: "GET", URL: "https://a.example.com/api/users", Headers: hdr(),
			Response: jsonResp(`{"id":2,"email":"b@x"}`)},

		// Top-level array, twice with disjoint item fields: the array union path.
		{Method: "GET", URL: "https://a.example.com/api/orders", Headers: hdr(),
			Response: jsonResp(`[{"id":1,"total":5}]`)},
		{Method: "GET", URL: "https://a.example.com/api/orders", Headers: hdr(),
			Response: jsonResp(`[{"id":2,"currency":"usd"}]`)},

		// A SECOND HOST serving the same path. Without the host in the dedup key
		// these collapse, and which one survives depends on iteration order.
		{Method: "GET", URL: "https://b.example.com/api/users", Headers: hdr("X-Host", "b"),
			Response: jsonResp(`{"id":9,"tenant":"b"}`)},

		// Multi-valued query parameters, merged across observations.
		{Method: "GET", URL: "https://a.example.com/api/search?q=one&tag=x&tag=y", Headers: hdr(),
			Response: jsonResp(`{"hits":0}`)},
		{Method: "GET", URL: "https://a.example.com/api/search?q=two&tag=z", Headers: hdr(),
			Response: jsonResp(`{"hits":1}`)},

		// Non-GET methods on a shared path, so operation ordering within a path matters.
		{Method: "POST", URL: "https://a.example.com/api/users", Headers: hdr(),
			Response: jsonResp(`{"id":3}`)},
		{Method: "DELETE", URL: "https://a.example.com/api/users/1", Headers: hdr(),
			Response: jsonResp(`{"deleted":true}`)},

		// A GraphQL request inside a REST-dominant capture. Exercises the
		// exclusive-assignment vote and the challenger margin rather than letting
		// REST win by walkover.
		{Method: "POST", URL: "https://a.example.com/graphql", Headers: hdr(),
			Body:     []byte(`{"query":"{ user { id } }"}`),
			Response: jsonResp(`{"data":{"user":{"id":"1"}}}`)},
	}

	dynamicCount = len(reqs)

	// Synthesized static-analysis entries, appended after the dynamic ones exactly
	// as the real augmentation stages do. Several share a URL prefix so the
	// synthesized comparator has to break ties on more than the URL.
	for i, src := range []string{"static:js", "static:html", "static:js-sourcemap"} {
		reqs = append(reqs, crawl.ObservedRequest{
			Method:  "GET",
			URL:     fmt.Sprintf("https://a.example.com/api/static/%d", i),
			Source:  src,
			Headers: hdr(),
		})
		// Same URL from a different source: a tie the comparator must order totally.
		reqs = append(reqs, crawl.ObservedRequest{
			Method:  "GET",
			URL:     "https://a.example.com/api/shared",
			Source:  src,
			Headers: hdr(),
		})
	}
	return reqs, dynamicCount
}

// endpointSet renders the emitted endpoint set as a sorted, comparable list. This is
// the artifact the LAB-4678 headline criterion is about — "identical input yields the
// same endpoint set every run" — so it is asserted directly rather than only as a
// side effect of the spec bytes matching.
//
// The identity is METHOD + scheme://host + PATH, which is what Deduplicate keys on
// (query and fragment stripped). Rendering the raw URL instead would make this
// sensitive to which of several observations of one endpoint was retained as the
// representative — /api/search?q=one versus ?q=two are the SAME endpoint, their query
// parameters are unioned, and which sample URL survives is not part of the endpoint
// set. Asserting on the raw URL measured representative choice rather than the
// property under test.
func endpointSet(t *testing.T, requests []crawl.ObservedRequest, apiType string) []string {
	t.Helper()
	classified := classify.RunClassifiers(pipeline.ClassifiersForType(apiType), requests, 0.5)
	deduped := classify.Deduplicate(classified)

	out := make([]string, 0, len(deduped))
	for _, c := range deduped {
		u, err := url.Parse(c.URL)
		if err != nil {
			t.Fatalf("parse emitted URL %q: %v", c.URL, err)
		}
		out = append(out, fmt.Sprintf("%s %s://%s%s", c.Method, u.Scheme, u.Host, u.Path))
	}
	sort.Strings(out)
	return out
}

// TestPipeline_DeterministicAcrossRepeatedRuns is the executing assertion for the
// LAB-4678 headline criterion: identical input must yield the same endpoint set and
// the same API-type verdict every run.
//
// SCOPE, stated precisely, because the ticket's wording does not distinguish two
// different claims. This pins determinism for a FIXED CAPTURE — identical input means
// identical capture.json. It does NOT and cannot assert run-to-run identity against a
// LIVE target: that additionally requires the capture itself to be identical, which
// network timing does not guarantee, and this repo already documents that at
// test/run-live-tests.sh ("the live crawl is non-deterministic, so the generated spec
// varies between runs"). Phase 1's network-idle wait reduces that variance; it cannot
// eliminate it. Determinism given a fixed capture is what Phases 1-3 actually
// delivered (synthesized ordering, headerKey stability, per-page capture order,
// tiebreaker totality, ClassifyDetail purity), and it is what this test locks.
//
// Before this test the determinism mechanisms were only covered per-stage. Nothing
// asserted the COMPOSED property end to end, which is what the ticket is buying
// (LAB-4678 review, REQ-001).
//
// Probe is off and TargetURL is empty, so this is fully offline and safe for CI.
func TestPipeline_DeterministicAcrossRepeatedRuns(t *testing.T) {
	capture, _ := determinismCapture()

	opts := pipeline.ScanOptions{
		Confidence:  0.5,
		Probe:       false, // offline: no network, no WSDL probe
		Deduplicate: true,
	}

	var (
		firstSpec     string
		firstAPIType  string
		firstEndpoint []string
	)

	for run := range determinismRuns {
		spec, apiType, foundWSDL, augmented, err := pipeline.ResolveAndGenerate(
			context.Background(), capture, opts)
		if err != nil {
			t.Fatalf("run %d: ResolveAndGenerate: %v", run, err)
		}
		if foundWSDL {
			t.Fatalf("run %d: unexpected WSDL discovery with Probe=false", run)
		}
		endpoints := endpointSet(t, augmented, apiType)

		if run == 0 {
			firstSpec, firstAPIType, firstEndpoint = string(spec), apiType, endpoints
			if len(firstEndpoint) == 0 {
				t.Fatal("run 0 emitted zero endpoints; the fixture is not exercising the pipeline")
			}
			// Pin the verdict itself, not just agreement between runs. Without this,
			// a stubbed DetectAPIType returning a constant would satisfy the whole
			// test — the same defect TEST-002 flagged in the apitype tests.
			if apiType != pipeline.APITypeREST {
				t.Fatalf("API type = %q, want %q: the fixture is REST-dominant, and a "+
					"changed verdict here means the tiebreaker moved", apiType, pipeline.APITypeREST)
			}
			continue
		}

		if apiType != firstAPIType {
			t.Errorf("run %d: API type = %q, want %q — the verdict must not vary across "+
				"runs on identical input", run, apiType, firstAPIType)
		}
		if !equalStrings(endpoints, firstEndpoint) {
			t.Errorf("run %d: emitted endpoint set differs from run 0\n run 0: %v\n run %d: %v",
				run, firstEndpoint, run, endpoints)
		}
		if string(spec) != firstSpec {
			t.Errorf("run %d: generated spec is not byte-identical to run 0.\n%s",
				run, firstSpecDiff(firstSpec, string(spec)))
		}
	}
}

// TestPipeline_DeterministicUnderInputReordering is the stronger half. Repeating the
// same input catches map-order dependence; it cannot catch dependence on the ORDER OF
// THE CAPTURE ITSELF. A real crawl's request order varies run to run — concurrent
// workers finish in whatever order the scheduler and the network produce — so a
// pipeline stable in-process but sensitive to capture order would still yield
// different specs on a live target, which is exactly what the ticket is about.
//
// Two guarantees, deliberately different in strength, because measurement showed they
// ARE different:
//
//  1. Permuting the DYNAMIC entries, which is what a real crawl actually varies,
//     produces a BYTE-IDENTICAL spec. This is the strongest form of the criterion that
//     holds, and it holds.
//
//  2. Permuting the whole capture so synthesized entries land BEFORE dynamic ones
//     preserves the endpoint set and the API-type verdict, but NOT the spec bytes.
//     That is not a defect: "synthesized last" is a documented pipeline invariant that
//     the augmentation stages enforce (they append so Deduplicate keeps dynamic
//     observations on ties), so this ordering cannot occur in the real pipeline.
//     Measured difference is 3 bytes, from which observation of one endpoint is
//     retained as the representative. It is asserted at the weaker level rather than
//     skipped, so a regression that changed the endpoint SET under this input would
//     still be caught.
//
// Permutations are deterministic — rotations and a reversal, no shuffling — so a
// failure is reproducible.
func TestPipeline_DeterministicUnderInputReordering(t *testing.T) {
	base, dynamicCount := determinismCapture()
	opts := pipeline.ScanOptions{Confidence: 0.5, Probe: false, Deduplicate: true}

	run := func(reqs []crawl.ObservedRequest) (spec string, apiType string, endpoints []string) {
		raw, apiType, _, augmented, err := pipeline.ResolveAndGenerate(context.Background(), reqs, opts)
		if err != nil {
			t.Fatalf("ResolveAndGenerate: %v", err)
		}
		if len(raw) == 0 {
			t.Fatal("empty spec")
		}
		return string(raw), apiType, endpointSet(t, augmented, apiType)
	}

	wantSpec, wantType, wantEndpoints := run(base)

	// (1) Rotate only the dynamic prefix, leaving synthesized entries last.
	for _, offset := range []int{1, 3, 5, 7} {
		off := offset % dynamicCount
		permuted := make([]crawl.ObservedRequest, 0, len(base))
		permuted = append(permuted, base[off:dynamicCount]...)
		permuted = append(permuted, base[:off]...)
		permuted = append(permuted, base[dynamicCount:]...)

		spec, apiType, endpoints := run(permuted)
		if apiType != wantType {
			t.Errorf("dynamic rotation by %d changed the API type: got %q, want %q", off, apiType, wantType)
		}
		if !equalStrings(endpoints, wantEndpoints) {
			t.Errorf("dynamic rotation by %d changed the emitted endpoint set\n want: %v\n got:  %v",
				off, wantEndpoints, endpoints)
		}
		if spec != wantSpec {
			t.Errorf("dynamic rotation by %d changed the generated spec; a real crawl varies "+
				"this order every run, so the spec must not depend on it.\n%s",
				off, firstSpecDiff(wantSpec, spec))
		}
	}

	// (2) Full reversal, which violates the synthesized-last invariant. Endpoint set
	// and verdict must hold; spec bytes are not required to.
	reversed := make([]crawl.ObservedRequest, len(base))
	for i, r := range base {
		reversed[len(base)-1-i] = r
	}
	_, apiType, endpoints := run(reversed)
	if apiType != wantType {
		t.Errorf("reversing the capture changed the API type: got %q, want %q", apiType, wantType)
	}
	if !equalStrings(endpoints, wantEndpoints) {
		t.Errorf("reversing the capture changed the emitted endpoint set\n want: %v\n got:  %v",
			wantEndpoints, endpoints)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// firstSpecDiff reports the first differing line, so a failure names the divergence
// instead of dumping two whole specs.
func firstSpecDiff(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) && i < len(g); i++ {
		if w[i] != g[i] {
			return fmt.Sprintf("first difference at line %d:\n  run 0: %q\n  this run: %q", i+1, w[i], g[i])
		}
	}
	return fmt.Sprintf("specs differ in length: run 0 has %d lines, this run has %d", len(w), len(g))
}
