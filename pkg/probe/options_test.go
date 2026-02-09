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

package probe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

func TestOptionsProbe_Name(t *testing.T) {
	p := probe.NewOptionsProbe(probe.DefaultConfig())
	if p.Name() != "options" {
		t.Errorf("Name() = %q, want %q", p.Name(), "options")
	}
}

func TestOptionsProbe_ParsesAllowHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			t.Errorf("expected OPTIONS, got %s", r.Method)
		}
		w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := probe.Config{
		Client:  srv.Client(),
		Timeout: 5 * time.Second,
	}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    srv.URL + "/api/users",
			},
			IsAPI: true,
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(result))
	}

	want := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	if len(result[0].AllowedMethods) != len(want) {
		t.Errorf("AllowedMethods: got %v, want %v", result[0].AllowedMethods, want)
	}
}

func TestOptionsProbe_EmptyAllowHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: srv.URL + "/api/users"}, IsAPI: true},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if len(result[0].AllowedMethods) != 0 {
		t.Errorf("expected empty AllowedMethods for missing header, got %v", result[0].AllowedMethods)
	}
}

func TestOptionsProbe_InjectsAuthHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := probe.Config{
		Client:      srv.Client(),
		Timeout:     5 * time.Second,
		AuthHeaders: map[string]string{"Authorization": "Bearer test-token"},
	}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: srv.URL + "/api/users"}, IsAPI: true},
	}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if gotAuth != "Bearer test-token" {
		t.Errorf("auth header: got %q, want %q", gotAuth, "Bearer test-token")
	}
}

func TestOptionsProbe_DeduplicatesByURL(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: srv.URL + "/api/users"}, IsAPI: true},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/api/users"}, IsAPI: true},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 OPTIONS request (deduplicated), got %d", requestCount)
	}

	for i, ep := range result {
		if len(ep.AllowedMethods) != 2 {
			t.Errorf("endpoint[%d].AllowedMethods: got %v, want [GET POST]", i, ep.AllowedMethods)
		}
	}
}

func TestOptionsProbe_PerRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := probe.Config{
		Client:  srv.Client(),
		Timeout: 100 * time.Millisecond,
	}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: srv.URL + "/api/users"}, IsAPI: true},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() should not return error on timeout, got: %v", err)
	}

	if len(result[0].AllowedMethods) != 0 {
		t.Errorf("expected empty AllowedMethods on timeout, got %v", result[0].AllowedMethods)
	}
}
