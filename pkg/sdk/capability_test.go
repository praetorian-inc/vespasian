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

package sdk

import (
	"context"
	"errors"
	"testing"

	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func emptyCtx() capability.ExecutionContext {
	return capability.ExecutionContext{}
}

// ctxWithParams builds an ExecutionContext from alternating key/value strings.
// e.g. ctxWithParams("mode", "crawl", "scope", "same-domain")
func ctxWithParams(kvs ...string) capability.ExecutionContext {
	if len(kvs)%2 != 0 {
		panic("ctxWithParams requires even number of args")
	}
	params := make(capability.Parameters, 0, len(kvs)/2)
	for i := 0; i+1 < len(kvs); i += 2 {
		params = append(params, capability.String(kvs[i], "").WithDefault(kvs[i+1]))
	}
	return capability.ExecutionContext{Parameters: params}
}

func seedApp(rawURL string) capmodel.WebApplication {
	return capmodel.WebApplication{PrimaryURL: rawURL, Name: rawURL, Seed: true}
}

// stubCrawl replaces crawlFunc and registers Cleanup to restore it.
func stubCrawl(t *testing.T, requests []crawl.ObservedRequest, err error) {
	t.Helper()
	orig := crawlFunc
	crawlFunc = func(_ context.Context, _ crawl.CrawlerOptions, _ string) ([]crawl.ObservedRequest, error) {
		return requests, err
	}
	t.Cleanup(func() { crawlFunc = orig })
}

func collect(t *testing.T, c *Capability, ctx capability.ExecutionContext, input capmodel.WebApplication) (webpages []capmodel.Webpage, webApps []capmodel.WebApplication, err error) {
	t.Helper()
	emitter := capability.EmitterFunc(func(models ...any) error {
		for _, m := range models {
			switch v := m.(type) {
			case capmodel.Webpage:
				webpages = append(webpages, v)
			case capmodel.WebApplication:
				webApps = append(webApps, v)
			}
		}
		return nil
	})
	err = c.Invoke(ctx, input, emitter)
	return
}

// ---------------------------------------------------------------------------
// 1. Interface satisfaction
// ---------------------------------------------------------------------------

// The compile-time check already lives in capability.go; no duplicate needed.
// Keeping this comment as evidence we verified it at line 37.

// ---------------------------------------------------------------------------
// 2. Match behavior
// ---------------------------------------------------------------------------

func TestMatch_RejectsEmptyURL(t *testing.T) {
	c := &Capability{}
	err := c.Match(emptyCtx(), capmodel.WebApplication{Seed: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "primary_url")
}

func TestMatch_RejectsNonHTTP(t *testing.T) {
	c := &Capability{}
	err := c.Match(emptyCtx(), capmodel.WebApplication{PrimaryURL: "ftp://x.com", Seed: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP/HTTPS")
}

func TestMatch_RejectsNonSeed(t *testing.T) {
	c := &Capability{}
	err := c.Match(emptyCtx(), capmodel.WebApplication{PrimaryURL: "https://x.com", Seed: false})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "seed")
}

func TestMatch_AcceptsHTTPSSeed(t *testing.T) {
	c := &Capability{}
	err := c.Match(emptyCtx(), seedApp("https://example.com"))
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// 3. Invoke crawl mode
// ---------------------------------------------------------------------------

func TestInvoke_CrawlMode_EmitsWebpagesFiltersStaticAssets(t *testing.T) {
	stubCrawl(t, []crawl.ObservedRequest{
		{Method: "GET", URL: "https://x.com/api", Response: crawl.ObservedResponse{StatusCode: 200}},
		{Method: "GET", URL: "https://x.com/style.css", Response: crawl.ObservedResponse{StatusCode: 200}},
		{Method: "GET", URL: "https://x.com/logo.png", Response: crawl.ObservedResponse{StatusCode: 200}},
	}, nil)

	c := &Capability{}
	ctx := ctxWithParams("mode", "crawl")
	webpages, webApps, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.NoError(t, err)
	assert.Len(t, webpages, 1, "only the non-static URL should be emitted")
	assert.Equal(t, "https://x.com/api", webpages[0].URL)
	assert.Empty(t, webApps, "crawl mode must not emit WebApplication")
}

func TestInvoke_CrawlMode_NoTrafficEmitsNothing(t *testing.T) {
	stubCrawl(t, nil, nil)

	c := &Capability{}
	ctx := ctxWithParams("mode", "crawl")
	webpages, webApps, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.NoError(t, err)
	assert.Empty(t, webpages)
	assert.Empty(t, webApps)
}

func TestInvoke_CrawlMode_ErrorPropagation(t *testing.T) {
	stubCrawl(t, nil, errors.New("connection refused"))

	c := &Capability{}
	ctx := ctxWithParams("mode", "crawl")
	_, _, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "crawl failed")
	assert.Contains(t, err.Error(), "connection refused")
}

// ---------------------------------------------------------------------------
// 4. Invoke scan mode
// ---------------------------------------------------------------------------

func TestInvoke_ScanMode_RESTTrafficEmitsOpenAPISpec(t *testing.T) {
	stubCrawl(t, []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://x.com/api/v1/users",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`[{"id":1}]`),
				Headers:     map[string]string{"Content-Type": "application/json"},
			},
		},
	}, nil)

	c := &Capability{}
	ctx := ctxWithParams("mode", "scan", "api_type", "rest", "probe", "false")
	_, webApps, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.NoError(t, err)
	require.Len(t, webApps, 1)
	assert.NotEmpty(t, webApps[0].Spec)
	assert.Equal(t, capmodel.SpecFormatOpenAPI, webApps[0].SpecFormat)
}

func TestInvoke_ScanMode_NoTrafficEmitsNoWebApplication(t *testing.T) {
	stubCrawl(t, nil, nil)

	c := &Capability{}
	ctx := ctxWithParams("mode", "scan", "api_type", "rest", "probe", "false")
	webpages, webApps, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.NoError(t, err)
	assert.Empty(t, webApps)
	assert.Empty(t, webpages)
}

func TestInvoke_ScanMode_ExplicitGraphQLTypeEmitsGraphQLSpec(t *testing.T) {
	stubCrawl(t, []crawl.ObservedRequest{
		{
			Method: "POST",
			URL:    "https://x.com/graphql",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: []byte(`{"query":"{ user(id: 1) { id name email } }"}`),
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`{"data":{"user":{"id":"1","name":"Alice","email":"alice@example.com"}}}`),
			},
		},
	}, nil)

	c := &Capability{}
	ctx := ctxWithParams("mode", "scan", "api_type", "graphql", "probe", "false")
	_, webApps, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.NoError(t, err)
	require.Len(t, webApps, 1)
	assert.NotEmpty(t, webApps[0].Spec)
	assert.Equal(t, capmodel.SpecFormatGraphQL, webApps[0].SpecFormat)
}

func TestInvoke_ScanMode_InvalidScopeReturnsError(t *testing.T) {
	// crawlFunc is replaced so we don't need a real stub — the scope error
	// fires before any crawl happens.
	stubCrawl(t, nil, nil)

	c := &Capability{}
	ctx := ctxWithParams("mode", "scan", "scope", "all-domains")
	_, _, err := collect(t, c, ctx, seedApp("https://x.com"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope")
}

// ---------------------------------------------------------------------------
// 7. Parameters declaration
// ---------------------------------------------------------------------------

// TestCapability_Parameters pins the public parameter contract so that an
// accidental rename (e.g. "api_type" -> "apitype") or default change
// (e.g. "scan" -> "") would be caught immediately. Parameters() was at 0.0%
// coverage before this test, meaning such a drift would ship silently.
func TestCapability_Parameters(t *testing.T) {
	c := &Capability{}
	params := c.Parameters()

	// Exactly 9 declared parameters.
	require.Len(t, params, 9)

	// Build a name -> Parameter map for convenient field assertions.
	byName := make(map[string]capability.Parameter, len(params))
	for _, p := range params {
		byName[p.Name] = p
	}

	// All expected names must be present.
	for _, name := range []string{
		"mode", "api_type", "timeout", "max_pages", "depth",
		"scope", "headers", "confidence", "probe",
	} {
		assert.Contains(t, byName, name, "missing parameter %q", name)
	}

	// Documented default values.
	assert.Equal(t, "scan", byName["mode"].Default)
	assert.Equal(t, "auto", byName["api_type"].Default)
	assert.Equal(t, "same-origin", byName["scope"].Default)
	assert.Equal(t, "0.5", byName["confidence"].Default)
	assert.Equal(t, "true", byName["probe"].Default)

	// WithOptions enum sets for the parameters that have them.
	assert.ElementsMatch(t, []string{"scan", "crawl"}, byName["mode"].Options)
	assert.ElementsMatch(t, []string{"auto", "rest", "graphql", "wsdl"}, byName["api_type"].Options)
	assert.ElementsMatch(t, []string{"same-origin", "same-domain"}, byName["scope"].Options)
}

// TestCapability_Metadata pins the trivial getter surface (Name, Description,
// Input, Full, Timeout) that were at 0.0% coverage. Each is a single-statement
// function; covering them here contributes to the 80% threshold.
func TestCapability_Metadata(t *testing.T) {
	c := &Capability{}

	assert.Equal(t, "vespasian", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Equal(t, capmodel.WebApplication{}, c.Input())
	assert.Equal(t, 5*24*time.Hour, c.Full())
	assert.Equal(t, 30, c.Timeout())
}

// ---------------------------------------------------------------------------
// 5. parseHeaders
// ---------------------------------------------------------------------------

func TestParseHeaders_Empty(t *testing.T) {
	assert.Nil(t, parseHeaders(""))
}

func TestParseHeaders_Single(t *testing.T) {
	got := parseHeaders("Authorization: Bearer tok")
	require.NotNil(t, got)
	assert.Equal(t, "Bearer tok", got["Authorization"])
}

func TestParseHeaders_Multiple(t *testing.T) {
	got := parseHeaders("Authorization: Bearer tok, X-Custom: val")
	require.NotNil(t, got)
	assert.Equal(t, "Bearer tok", got["Authorization"])
	assert.Equal(t, "val", got["X-Custom"])
}

// ---------------------------------------------------------------------------
// 8. parseConfidence and specFormatForType (internal helpers)
// ---------------------------------------------------------------------------

func TestParseConfidence_ParseFailReturnsDefault(t *testing.T) {
	// "notanumber" cannot be parsed as float — should fall back to 0.5.
	params := capability.Parameters{capability.String("confidence", "").WithDefault("notanumber")}
	got := parseConfidence(params)
	assert.Equal(t, 0.5, got)
}

func TestParseConfidence_OutOfRangeReturnsDefault(t *testing.T) {
	// Value > 1 is out of [0,1] — should fall back to 0.5.
	params := capability.Parameters{capability.String("confidence", "").WithDefault("1.5")}
	got := parseConfidence(params)
	assert.Equal(t, 0.5, got)
}

func TestSpecFormatForType_WSDL(t *testing.T) {
	assert.Equal(t, capmodel.SpecFormatWSDL, specFormatForType("wsdl"))
}

// ---------------------------------------------------------------------------
// 6. isStaticAssetURL (optional)
// ---------------------------------------------------------------------------

func TestIsStaticAssetURL_CSS(t *testing.T) {
	assert.True(t, pipeline.IsStaticAssetURL("https://example.com/styles/main.css"))
}

func TestIsStaticAssetURL_HTML(t *testing.T) {
	assert.False(t, pipeline.IsStaticAssetURL("https://example.com/index.html"))
}

func TestIsStaticAssetURL_QueryStringDoesNotMatch(t *testing.T) {
	// Path is "/api" — the .js appears only in the query string, not the path.
	assert.False(t, pipeline.IsStaticAssetURL("https://example.com/api?cb=x.js"))
}
