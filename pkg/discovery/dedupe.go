package discovery

import (
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

// DedupeEndpoints removes duplicate endpoints across all probe results.
// Deduplication is based on path+method (case-insensitive for paths).
// Results are modified in-place to remove duplicate endpoints.
func DedupeEndpoints(results []probes.ProbeResult) []probes.ProbeResult {
	if len(results) == 0 {
		return results
	}

	// Track seen endpoints across all results
	seen := make(map[string]bool)

	// Create deduplicated results
	deduped := make([]probes.ProbeResult, len(results))

	for i, result := range results {
		// Copy result structure
		deduped[i] = probes.ProbeResult{
			ProbeCategory: result.ProbeCategory,
			Success:       result.Success,
			Error:         result.Error,
		}

		// If unsuccessful or no endpoints, keep as-is
		if !result.Success || len(result.Endpoints) == 0 {
			deduped[i].Endpoints = result.Endpoints
			continue
		}

		// Deduplicate endpoints for this result
		uniqueEndpoints := make([]probes.APIEndpoint, 0)
		for _, endpoint := range result.Endpoints {
			key := endpointKey(endpoint)
			if !seen[key] {
				seen[key] = true
				uniqueEndpoints = append(uniqueEndpoints, endpoint)
			}
		}

		deduped[i].Endpoints = uniqueEndpoints
	}

	return deduped
}

// endpointKey creates a unique key for an endpoint (method:path, case-insensitive path).
func endpointKey(endpoint probes.APIEndpoint) string {
	return endpoint.Method + ":" + strings.ToLower(endpoint.Path)
}
