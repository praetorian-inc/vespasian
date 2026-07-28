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

package jsstatic

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestNextRouteFromChunkURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantPath string
		wantKind nextRouteKind
	}{
		{
			// The exact URL observed in the LAB-4677 run-013 capture. This is the
			// case the original "not achievable" finding missed.
			name:     "real capture URL with percent-encoded dynamic segment",
			url:      "https://app.example.io/_next/static/chunks/app/vaults/%5BvaultId%5D/page-8ca1aac6111f15fc.js",
			wantPath: "/vaults/{vaultId}",
			wantKind: nextRoutePage,
		},
		{
			name:     "literal brackets (unencoded)",
			url:      "https://x.test/_next/static/chunks/app/vaults/[vaultId]/page-abc123.js",
			wantPath: "/vaults/{vaultId}",
			wantKind: nextRoutePage,
		},
		{
			name:     "static page route",
			url:      "https://x.test/_next/static/chunks/app/dashboard/page-deadbeef.js",
			wantPath: "/dashboard",
			wantKind: nextRoutePage,
		},
		{
			name:     "nested static page route",
			url:      "https://x.test/_next/static/chunks/app/settings/profile/page-0f0f0f.js",
			wantPath: "/settings/profile",
			wantKind: nextRoutePage,
		},
		{
			name:     "root page route",
			url:      "https://x.test/_next/static/chunks/app/page-abc.js",
			wantPath: "/",
			wantKind: nextRoutePage,
		},
		{
			name:     "route handler is an API endpoint",
			url:      "https://x.test/_next/static/chunks/app/api/files/route-99aa88.js",
			wantPath: "/api/files",
			wantKind: nextRouteHandler,
		},
		{
			name:     "route handler with dynamic segment",
			url:      "https://x.test/_next/static/chunks/app/api/vaults/%5Bid%5D/route-1a2b3c.js",
			wantPath: "/api/vaults/{id}",
			wantKind: nextRouteHandler,
		},
		{
			name:     "catch-all segment names one parameter",
			url:      "https://x.test/_next/static/chunks/app/docs/%5B...slug%5D/page-abc.js",
			wantPath: "/docs/{slug}",
			wantKind: nextRoutePage,
		},
		{
			name:     "optional catch-all segment",
			url:      "https://x.test/_next/static/chunks/app/docs/%5B%5B...slug%5D%5D/page-abc.js",
			wantPath: "/docs/{slug}",
			wantKind: nextRoutePage,
		},
		{
			// Route groups organize files but never appear in the URL.
			name:     "route group is dropped",
			url:      "https://x.test/_next/static/chunks/app/(marketing)/pricing/page-abc.js",
			wantPath: "/pricing",
			wantKind: nextRoutePage,
		},
		{
			name:     "parallel route slot is dropped",
			url:      "https://x.test/_next/static/chunks/app/dashboard/@modal/settings/page-abc.js",
			wantPath: "/dashboard/settings",
			wantKind: nextRoutePage,
		},
		{
			name:     "intercepting prefix is stripped from its segment",
			url:      "https://x.test/_next/static/chunks/app/feed/(..)photo/page-abc.js",
			wantPath: "/feed/photo",
			wantKind: nextRoutePage,
		},
		{
			name:     "query string does not defeat the match",
			url:      "https://x.test/_next/static/chunks/app/dashboard/page-abc.js?v=2",
			wantPath: "/dashboard",
			wantKind: nextRoutePage,
		},

		// Non-matches: everything outside the App Router chunk shape.
		{name: "framework runtime chunk", url: "https://x.test/_next/static/chunks/webpack-8658fd.js", wantKind: nextRouteNone},
		{name: "shared numeric chunk", url: "https://x.test/_next/static/chunks/117-369b9f.js", wantKind: nextRouteNone},
		{name: "main-app chunk", url: "https://x.test/_next/static/chunks/main-app-6fca15.js", wantKind: nextRouteNone},
		{name: "css asset", url: "https://x.test/_next/static/css/b2932f.css", wantKind: nextRouteNone},
		{name: "layout chunk is not a route", url: "https://x.test/_next/static/chunks/app/dashboard/layout-abc.js", wantKind: nextRouteNone},
		{name: "unrelated bundle", url: "https://x.test/assets/app.js", wantKind: nextRouteNone},
		{name: "lookalike path outside _next", url: "https://x.test/chunks/app/dashboard/page-abc.js", wantKind: nextRouteNone},
		{name: "empty", url: "", wantKind: nextRouteNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotKind := nextRouteFromChunkURL(tt.url)
			assert.Equal(t, tt.wantKind, gotKind, "kind")
			if tt.wantKind != nextRouteNone {
				assert.Equal(t, tt.wantPath, gotPath, "path")
			}
		})
	}
}

// TestExtractNextRoute_SourceTags pins that the two chunk kinds carry different
// provenance, which is what lets the classifier treat a route handler as an API
// endpoint while leaving a page route as navigation.
func TestExtractNextRoute_SourceTags(t *testing.T) {
	page := extractNextRoute("https://x.test/_next/static/chunks/app/dashboard/page-abc.js", "https://x.test/")
	require.NotNil(t, page)
	assert.Equal(t, crawl.SourceNextPageRoute, page.SourceTag)
	assert.Equal(t, "GET", page.Method)

	handler := extractNextRoute("https://x.test/_next/static/chunks/app/api/files/route-abc.js", "https://x.test/")
	require.NotNil(t, handler)
	assert.Equal(t, crawl.SourceNextRouteHandler, handler.SourceTag)

	assert.Nil(t, extractNextRoute("https://x.test/_next/static/chunks/webpack-abc.js", "https://x.test/"))
}

// TestAnalyze_RecoversNextRouteFromBundleURL is the end-to-end assertion for
// LAB-4678 audit item 7: a Next.js bundle whose BODY contains no API path
// literal — the RSC case the original root-cause analysis measured — still
// yields its route, because the route is carried by the chunk URL.
func TestAnalyze_RecoversNextRouteFromBundleURL(t *testing.T) {
	// Body deliberately contains no extractable path literal, mirroring the RSC
	// bundles in the LAB-4677 capture.
	body := []byte(`(self.webpackChunk=self.webpackChunk||[]).push([[974],{123:(e,t,n)=>{n.r(t);var r=n(456);function a(){return r.jsx("div",{})}}}]);`)

	captured := []crawl.ObservedRequest{
		{
			Method:  "GET",
			URL:     "https://app.example.io/_next/static/chunks/app/vaults/%5BvaultId%5D/page-8ca1aac6111f15fc.js",
			PageURL: "https://app.example.io/vaults/1",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        body,
			},
		},
		{
			Method:  "GET",
			URL:     "https://app.example.io/_next/static/chunks/app/api/files/route-99aa88.js",
			PageURL: "https://app.example.io/dashboard",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        body,
			},
		},
	}

	res, err := Analyze(context.Background(), captured, Options{FetchSourcemaps: false})
	require.NoError(t, err)

	// Key by the DECODED path, which is what pkg/generate/rest consumes: it
	// reads url.Parse(endpoint.URL).Path. toRequests resolves the route against
	// the page origin via url.ResolveReference, which percent-encodes the braces
	// of a {param} segment, so the stored URL carries %7B...%7D and decodes back
	// to {param}. That round-trip is pre-existing behavior shared by every
	// parameterized endpoint this package synthesizes.
	got := map[string]string{} // decoded path -> Source
	for _, r := range res.Requests {
		if r.Source == "" {
			continue
		}
		parsed, err := url.Parse(r.URL)
		require.NoError(t, err)
		assert.Equal(t, "app.example.io", parsed.Host, "route must resolve against the app origin")
		got[parsed.Path] = r.Source
	}

	assert.Equal(t, crawl.SourceNextPageRoute, got["/vaults/{vaultId}"],
		"page chunk URL must yield its route, tagged as a page route")
	assert.Equal(t, crawl.SourceNextRouteHandler, got["/api/files"],
		"route-handler chunk URL must yield its route, tagged as a route handler")
}

// TestAnalyze_NextRouteSurvivesFailedBodyExtraction pins the ordering decision
// in analyzeOne: route recovery reads the URL, so it must run BEFORE body
// extraction and still contribute its route when that extraction fails. A
// panicking jsluice parse makes analyzeOne return early via the BundlesSkipped
// path; the route must already have been recorded by then.
func TestAnalyze_NextRouteSurvivesFailedBodyExtraction(t *testing.T) {
	testInjectPanic = func(loc string) {
		if loc == "bundle" {
			panic("forced bundle-extraction panic for nextroute ordering test")
		}
	}
	defer func() { testInjectPanic = nil }()

	captured := []crawl.ObservedRequest{{
		Method:  "GET",
		URL:     "https://app.example.io/_next/static/chunks/app/api/files/route-99aa88.js",
		PageURL: "https://app.example.io/dashboard",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        []byte(`fetch("/api/never-reached")`),
		},
	}}

	res, err := Analyze(context.Background(), captured, Options{FetchSourcemaps: false, Concurrency: 1})
	require.NoError(t, err)
	require.Equal(t, 1, res.Stats.BundlesSkipped, "the panicking bundle must be counted as skipped")

	var found bool
	for _, r := range res.Requests {
		if r.Source == crawl.SourceNextRouteHandler {
			found = true
		}
	}
	assert.True(t, found, "route must survive a failed body extraction — it comes from the URL")
}
