package discovery

import (
	"context"
	"sort"
	"sync"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

// Orchestrator coordinates probe execution for API surface discovery.
type Orchestrator struct {
	probes []probes.Probe
}

// NewOrchestrator creates a new discovery orchestrator with the given probes.
func NewOrchestrator(probeList []probes.Probe) *Orchestrator {
	return &Orchestrator{
		probes: probeList,
	}
}

// Discover runs all applicable probes against the target concurrently.
// Probes are sorted by priority (higher = earlier) and run using goroutines.
// Results are collected and returned after all probes complete.
func (o *Orchestrator) Discover(ctx context.Context, target probes.Target) ([]probes.ProbeResult, error) {
	// Sort probes by priority (descending)
	sortedProbes := o.sortProbesByPriority()

	// Filter probes that accept the target
	acceptingProbes := make([]probes.Probe, 0)
	for _, probe := range sortedProbes {
		if probe.Accepts(target) {
			acceptingProbes = append(acceptingProbes, probe)
		}
	}

	// Run probes concurrently
	results := make([]probes.ProbeResult, len(acceptingProbes))
	var wg sync.WaitGroup

	for i, probe := range acceptingProbes {
		wg.Add(1)
		go func(idx int, p probes.Probe) {
			defer wg.Done()

			// Run probe with default options
			opts := probes.ProbeOptions{
				Timeout: 30, // 30 second timeout
			}

			result, err := p.Run(ctx, target, opts)
			if err != nil {
				// Store error result
				results[idx] = probes.ProbeResult{
					ProbeCategory: p.Category(),
					Success:       false,
					Error:         err,
				}
				return
			}

			// Store successful result
			results[idx] = *result
		}(i, probe)
	}

	// Wait for all probes to complete
	wg.Wait()

	return results, nil
}

// sortProbesByPriority returns probes sorted by priority (descending).
func (o *Orchestrator) sortProbesByPriority() []probes.Probe {
	sorted := make([]probes.Probe, len(o.probes))
	copy(sorted, o.probes)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority() > sorted[j].Priority()
	})

	return sorted
}
