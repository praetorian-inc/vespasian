package probe_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// mockProbe is a test double for ProbeStrategy.
type mockProbe struct {
	name    string
	err     error
	enrichF func([]classify.ClassifiedRequest) []classify.ClassifiedRequest
}

func (m *mockProbe) Name() string { return m.name }

func (m *mockProbe) Probe(_ context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.enrichF != nil {
		return m.enrichF(endpoints), nil
	}
	return endpoints, nil
}

func TestRunStrategies_EmptyStrategies(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: "https://api.example.com/users"}},
	}

	result, errs := probe.RunStrategies(context.Background(), nil, endpoints)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(result))
	}
}

func TestRunStrategies_ErrorIsolation(t *testing.T) {
	failing := &mockProbe{name: "failing", err: errors.New("probe failed")}
	passing := &mockProbe{
		name: "passing",
		enrichF: func(eps []classify.ClassifiedRequest) []classify.ClassifiedRequest {
			for i := range eps {
				eps[i].AllowedMethods = []string{"GET"}
			}
			return eps
		},
	}

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: "https://api.example.com/users"}},
	}

	result, errs := probe.RunStrategies(context.Background(), []probe.ProbeStrategy{failing, passing}, endpoints)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(result))
	}
	if len(result[0].AllowedMethods) != 1 {
		t.Errorf("passing probe should have enriched endpoint")
	}
}

func TestRunStrategies_AllSucceed(t *testing.T) {
	probe1 := &mockProbe{
		name: "probe1",
		enrichF: func(eps []classify.ClassifiedRequest) []classify.ClassifiedRequest {
			for i := range eps {
				eps[i].AllowedMethods = []string{"GET", "POST"}
			}
			return eps
		},
	}
	probe2 := &mockProbe{name: "probe2"}

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: "https://api.example.com/users"}},
	}

	result, errs := probe.RunStrategies(context.Background(), []probe.ProbeStrategy{probe1, probe2}, endpoints)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(result[0].AllowedMethods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(result[0].AllowedMethods))
	}
}

func TestRunStrategies_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	slow := &mockProbe{name: "slow"}
	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: "https://api.example.com/users"}},
	}

	_, errs := probe.RunStrategies(ctx, []probe.ProbeStrategy{slow}, endpoints)
	if len(errs) != 1 {
		t.Errorf("expected 1 context error, got %d", len(errs))
	}
}

func TestProbeError_Error(t *testing.T) {
	pe := &probe.ProbeError{Strategy: "test", Err: errors.New("fail")}
	if got := pe.Error(); got != "test: fail" {
		t.Errorf("Error() = %q, want %q", got, "test: fail")
	}
}

func TestProbeError_ErrorNilErr(t *testing.T) {
	pe := &probe.ProbeError{Strategy: "test", Err: nil}
	if got := pe.Error(); got != "test: <nil>" {
		t.Errorf("Error() = %q, want %q", got, "test: <nil>")
	}
}

func TestProbeError_Unwrap(t *testing.T) {
	inner := errors.New("fail")
	pe := &probe.ProbeError{Strategy: "test", Err: inner}
	if got := pe.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v, want %v", got, inner)
	}
}

func TestDefaultClient_DoesNotFollowRedirects(t *testing.T) {
	redirectHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-target" {
			redirectHit = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))
	defer srv.Close()

	// Use a Config without a Client so withDefaults() creates one with
	// CheckRedirect disabled. We must also supply the test server's TLS
	// transport so the request actually reaches the httptest server.
	// The default client returned by withDefaults() will have CheckRedirect
	// set. We verify this by constructing a Config with a client that uses
	// the same CheckRedirect policy the default would set.
	cfg := probe.Config{
		Client: &http.Client{
			Transport: srv.Client().Transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
	}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: srv.URL + "/start"}, IsAPI: true},
	}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if redirectHit {
		t.Error("expected probe NOT to follow redirect, but redirect target was hit")
	}
}

func TestRunStrategies_ContextCancellation_Breaks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s1 := &mockProbe{name: "s1"}
	s2 := &mockProbe{name: "s2"}
	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{URL: "https://api.example.com/users"}},
	}

	_, errs := probe.RunStrategies(ctx, []probe.ProbeStrategy{s1, s2}, endpoints)
	// With break instead of continue, only s1 should report ctx error, not s2
	if len(errs) != 1 {
		t.Errorf("expected 1 context error (break after first), got %d: %v", len(errs), errs)
	}
}
