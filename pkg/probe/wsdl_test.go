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
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

func TestWSDLProbe_Name(t *testing.T) {
	p := probe.NewWSDLProbe(probe.DefaultConfig())
	if p.Name() != "wsdl" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wsdl")
	}
}

func TestWSDLProbe_ValidWSDL(t *testing.T) {
	wsdlDoc := `<?xml version="1.0"?>
<definitions name="TestService" xmlns="http://schemas.xmlsoap.org/wsdl/">
  <message name="GetUserRequest"><part name="parameters" element="tns:GetUser"/></message>
  <portType name="TestPortType">
    <operation name="GetUser"/>
  </portType>
</definitions>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "wsdl" {
			w.Header().Set("Content-Type", "text/xml")
			w.Write([]byte(wsdlDoc))
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    srv.URL + "/service",
		},
		IsAPI:   true,
		APIType: "wsdl",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if result[0].WSDLDocument == nil {
		t.Fatal("WSDLDocument should not be nil")
	}
	if string(result[0].WSDLDocument) != wsdlDoc {
		t.Errorf("WSDLDocument mismatch")
	}
}

func TestWSDLProbe_404OnWSDL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/service"},
		IsAPI:           true,
		APIType:         "wsdl",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if result[0].WSDLDocument != nil {
		t.Errorf("expected nil WSDLDocument for 404, got %d bytes", len(result[0].WSDLDocument))
	}
}

func TestWSDLProbe_NoDoubleAppendWSDL(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.URL.RawQuery == "wsdl" {
			w.Header().Set("Content-Type", "text/xml")
			w.Write([]byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="PT"/></definitions>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	// URL already has ?wsdl -- should not double-append
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: srv.URL + "/service?wsdl"},
		IsAPI:           true,
		APIType:         "wsdl",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if result[0].WSDLDocument == nil {
		t.Fatal("WSDLDocument should not be nil")
	}
	// Should have made exactly 1 request, not 2
	if requestCount.Load() != 1 {
		t.Errorf("expected 1 request, got %d", requestCount.Load())
	}
}

func TestWSDLProbe_SkipsNonSOAP(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: srv.URL + "/api/users"},
		IsAPI:           true,
		APIType:         "rest",
	}}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() != 0 {
		t.Errorf("expected 0 requests for non-SOAP endpoint, got %d", requestCount.Load())
	}
}

func TestWSDLProbe_MaxEndpointsRespected(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="PT"/></definitions>`))
	}))
	defer srv.Close()

	cfg := probe.Config{
		Client:       srv.Client(),
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		MaxEndpoints: 2,
	}
	p := probe.NewWSDLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/svc1"}, IsAPI: true, APIType: "wsdl"},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/svc2"}, IsAPI: true, APIType: "wsdl"},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/svc3"}, IsAPI: true, APIType: "wsdl"},
	}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() > 2 {
		t.Errorf("expected at most 2 requests (MaxEndpoints=2), got %d", requestCount.Load())
	}
}

func TestWSDLProbe_DeduplicatesByBaseURL(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="PT"/></definitions>`))
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     srv.URL + "/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
			IsAPI: true, APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     srv.URL + "/service",
				Headers: map[string]string{"SOAPAction": `"urn:DeleteUser"`},
			},
			IsAPI: true, APIType: "wsdl",
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() != 1 {
		t.Errorf("expected 1 request (deduplicated by base URL), got %d", requestCount.Load())
	}
	if result[0].WSDLDocument == nil {
		t.Error("result[0].WSDLDocument should not be nil")
	}
	if result[1].WSDLDocument == nil {
		t.Error("result[1].WSDLDocument should not be nil")
	}
}

func TestWSDLProbe_RejectsNonWSDLXML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<html><body>Not a WSDL</body></html>`))
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/service"},
		IsAPI: true, APIType: "wsdl",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	if result[0].WSDLDocument != nil {
		t.Error("expected nil WSDLDocument for non-WSDL response")
	}
}

func TestWSDLProbe_DoesNotMutateInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="PT"/></definitions>`))
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewWSDLProbe(cfg)

	original := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/service"},
		IsAPI: true, APIType: "wsdl",
	}}

	result, err := p.Probe(context.Background(), original)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	if original[0].WSDLDocument != nil {
		t.Error("original slice should not be mutated")
	}
	if result[0].WSDLDocument == nil {
		t.Error("result slice should have WSDL")
	}
}
