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

package pipeline

import (
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/analyze"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// seedGRPCHostEndpoints returns classified plus one synthetic grpc-typed
// ClassifiedRequest per distinct host (scheme://host[:port]) observed in
// requests that is not already represented among classified grpc endpoints.
// Hosts are deduped, sorted for deterministic output, and capped at maxHosts.
// The synthetic endpoints give the reflection and grpc-gateway probes targets
// even when classification never marked the (REST/JSON) gateway traffic grpc.
// SSRF protection is unaffected: seeding only constructs URLs; the probes still
// run URLValidator/Dialer.
func seedGRPCHostEndpoints(requests []crawl.ObservedRequest, classified []classify.ClassifiedRequest, maxHosts int) []classify.ClassifiedRequest {
	// Hosts already represented among classified grpc endpoints are not re-seeded.
	existing := map[string]bool{}
	for i := range classified {
		if classified[i].APIType != APITypeGRPC {
			continue
		}
		if host := grpcHostKey(classified[i].URL); host != "" {
			existing[host] = true
		}
	}

	seen := map[string]bool{}
	var hosts []string
	for _, req := range requests {
		host := grpcHostKey(req.URL)
		if host == "" || existing[host] || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}

	sort.Strings(hosts)
	if maxHosts > 0 && len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	for _, host := range hosts {
		classified = append(classified, classify.ClassifiedRequest{
			ObservedRequest: crawl.ObservedRequest{URL: host},
			APIType:         APITypeGRPC,
		})
	}
	return classified
}

// grpcHostKey returns the scheme://host[:port] key for a request URL, or ""
// when the URL cannot be parsed or carries no host. The original scheme is
// preserved; the probes themselves map grpc/grpcs↔http/https as needed.
func grpcHostKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.Host
}

// enrichGRPCFromBindings recovers gRPC services from gRPC-Web JS bundles in the
// full augmented capture and applies them with the lowest precedence in the
// reflection > gateway > bindings chain. It never overwrites an endpoint that
// already carries usable descriptors (reflection or gateway). When no grpc
// endpoint exists at all — common for a pure gRPC-Web SPA where only JS was
// captured — a single synthetic grpc endpoint is appended so the generator has
// something to render.
//
// Bindings recovery reads JS bodies from the capture rather than the network,
// so it is not a ProbeStrategy: the classified/deduped endpoints handed to
// probes are API endpoints, not the JS bundles (which are filtered out before
// probing). Only the pipeline's request slice holds the full capture this
// needs.
func enrichGRPCFromBindings(requests []crawl.ObservedRequest, enriched []classify.ClassifiedRequest, status io.Writer) []classify.ClassifiedRequest {
	services := analyze.ExtractGRPCWebBindings(requests)
	if len(services) == 0 {
		return enriched
	}

	// Dedupe bindings services against every service already recovered across
	// all endpoints (by any technique). Reflection > gateway > bindings: a FQN
	// already recovered by a higher-precedence technique is not re-attached.
	filtered := filterUncoveredServices(services, enriched)
	if len(filtered) == 0 {
		return enriched
	}

	writeStatus(status, "recovered %d service(s) from gRPC-Web bundles\n", len(filtered))

	// Store recovered service names only. Descriptor synthesis is centralized
	// in the generator. ReflectionEnabled is false: JS bindings are not a
	// reflection response.
	schema := func() *classify.GRPCReflectionResult {
		return &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services:          filtered,
		}
	}

	// "Covered" for bindings purposes means the endpoint already carries usable
	// descriptors or recovered service names (reflection or gateway).
	hasCoverage := func(s *classify.GRPCReflectionResult) bool {
		return s != nil && (len(s.FileDescriptors) > 0 || len(s.Services) > 0)
	}

	attached := false
	for i := range enriched {
		if enriched[i].APIType != APITypeGRPC {
			continue
		}
		if hasCoverage(enriched[i].GRPCSchema) {
			continue
		}
		enriched[i].GRPCSchema = schema()
		attached = true
	}

	// Append a synthetic grpc endpoint carrying the recovered services when they
	// were not attached to any existing bare endpoint — either no grpc endpoint
	// exists (pure gRPC-Web SPA), OR all existing grpc endpoints are already
	// covered by a higher-precedence technique (single-host gateway+bindings,
	// where bindings-only services like streaming RPCs the gateway can't
	// transcode would otherwise be dropped). `filtered` is already deduped
	// against all coverage, so this never duplicates a higher-precedence service.
	if !attached {
		enriched = append(enriched, classify.ClassifiedRequest{
			APIType:    APITypeGRPC,
			GRPCSchema: schema(),
		})
	}

	return enriched
}

// filterUncoveredServices returns the subset of services whose FQN is not
// already recovered (in GRPCSchema.Services) by any endpoint in enriched.
// Leading dots are stripped before comparison so ".pkg.S" and "pkg.S" match.
func filterUncoveredServices(services []classify.GRPCService, enriched []classify.ClassifiedRequest) []classify.GRPCService {
	covered := map[string]bool{}
	for i := range enriched {
		if s := enriched[i].GRPCSchema; s != nil {
			for _, svc := range s.Services {
				covered[strings.TrimPrefix(svc.Name, ".")] = true
			}
		}
	}
	filtered := services[:0:0]
	for _, svc := range services {
		if covered[strings.TrimPrefix(svc.Name, ".")] {
			continue
		}
		filtered = append(filtered, svc)
	}
	return filtered
}
