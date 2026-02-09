package probe_test

import (
	"context"
	"errors"
	"testing"

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
