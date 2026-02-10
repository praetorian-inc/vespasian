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

// Package report provides scan report generation and formatting.
package report

import (
	"time"

	"github.com/praetorian-inc/vespasian/pkg/types"
)

// ScanConfig contains scan configuration (excludes auth credentials for security).
type ScanConfig struct {
	Target       string
	Plugins      []string
	AllowedHosts []string
	DenyPaths    []string
	MaxRequests  int
	MaxRPS       float64
	Timeout      time.Duration
	OutputFormat string
}

// ScanReport contains the complete scan results and metadata.
type ScanReport struct {
	Target      string
	StartedAt   time.Time
	CompletedAt time.Time
	Findings    []types.Finding
	Summary     ScanSummary
	Steps       []types.AttackStep
	Plan        *types.AttackPlan
	Rejections  []types.Rejection
	Config      *ScanConfig // Scanner configuration (excludes auth tokens)
}

// ScanSummary provides aggregated statistics about the scan.
type ScanSummary struct {
	Total        int
	BySeverity   map[string]int
	ByPlugin     map[string]int
	ByTier       map[int]int
	StepsRun     int
	StepsFailed  int
	StepsSkipped int
}

// BuildSummary creates a scan summary from findings and step results.
func BuildSummary(findings []types.Finding, results []types.StepResult) ScanSummary {
	summary := ScanSummary{
		Total:      len(findings),
		BySeverity: make(map[string]int),
		ByPlugin:   make(map[string]int),
		ByTier:     make(map[int]int),
	}

	// Aggregate findings by severity, plugin, and tier
	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		summary.ByPlugin[finding.Plugin]++
		summary.ByTier[finding.Tier]++
	}

	// Count step results by status
	for _, result := range results {
		switch result.Status {
		case types.Success:
			summary.StepsRun++
		case types.Failed:
			summary.StepsFailed++
		case types.Skipped:
			summary.StepsSkipped++
		}
	}

	return summary
}
