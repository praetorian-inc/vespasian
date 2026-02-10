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
	"encoding/json"
	"fmt"
	"io"
)

// SARIFReport represents a SARIF 2.1.0 format report.
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single scan run in SARIF format.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the scanning tool information.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver information.
type SARIFDriver struct {
	Name            string `json:"name"`
	InformationURI  string `json:"informationUri"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
}

// SARIFResult represents a single finding in SARIF format.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage represents a result message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents where a finding was discovered.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents the physical location of a finding.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents the artifact (file/URI) location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a region within an artifact.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// WriteSARIF writes the scan report in SARIF 2.1.0 format for CI/CD integration.
func WriteSARIF(w io.Writer, report *ScanReport) error {
	// Map severity to SARIF level
	severityToLevel := func(severity string) string {
		switch severity {
		case "critical", "high":
			return "error"
		case "medium":
			return "warning"
		case "low", "info":
			return "note"
		default:
			return "warning"
		}
	}

	// Convert findings to SARIF results
	results := make([]SARIFResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		result := SARIFResult{
			RuleID: fmt.Sprintf("%s.%s", finding.Plugin, finding.Endpoint.Method),
			Level:  severityToLevel(finding.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s injection found in parameter %s at %s %s (confidence: %.2f)",
					finding.Plugin,
					finding.Parameter,
					finding.Endpoint.Method,
					finding.Endpoint.Path,
					finding.Confidence),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: fmt.Sprintf("%s%s", report.Target, finding.Endpoint.Path),
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	// Create SARIF report structure
	sarifReport := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            "Cato",
						InformationURI:  "https://github.com/praetorian-inc/vespasian",
						Version:         "dev",
						SemanticVersion: "0.1.0",
					},
				},
				Results: results,
			},
		},
	}

	// Write JSON with indentation
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(sarifReport); err != nil {
		return fmt.Errorf("failed to encode SARIF: %w", err)
	}

	return nil
}
