package output

import (
	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/vespasian/pkg/probes"
)

// ToFindings converts probe results to SDK findings.
// Each APIEndpoint becomes a Finding with type=asset, severity=info.
// Failed probes (Success=false) are reported as error findings.
func ToFindings(results []probes.ProbeResult) []capability.Finding {
	var findings []capability.Finding

	for _, result := range results {
		// Handle successful probes: convert each endpoint to a finding
		if result.Success {
			for _, endpoint := range result.Endpoints {
				finding := capability.Finding{
					Type:     capability.FindingAsset,
					Severity: capability.SeverityInfo,
					Data: map[string]any{
						"type":           "api_endpoint",
						"method":         endpoint.Method,
						"path":           endpoint.Path,
						"probe_category": result.ProbeCategory.String(),
					},
				}
				findings = append(findings, finding)
			}
		}

		// Handle failed probes: create error finding
		if !result.Success && result.Error != nil {
			finding := capability.Finding{
				Type:     capability.FindingAttribute,
				Severity: capability.SeverityInfo,
				Data: map[string]any{
					"type":           "probe_error",
					"probe_category": result.ProbeCategory.String(),
					"error":          result.Error.Error(),
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

