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

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSummary(t *testing.T) {
	findings := []types.Finding{
		{Plugin: "sqli", Severity: "high", Tier: 1},
		{Plugin: "xss", Severity: "medium", Tier: 2},
		{Plugin: "sqli", Severity: "high", Tier: 1},
		{Plugin: "xss", Severity: "low", Tier: 3},
	}

	results := []types.StepResult{
		{Status: types.Success},
		{Status: types.Success},
		{Status: types.Failed},
		{Status: types.Skipped},
	}

	summary := BuildSummary(findings, results)

	assert.Equal(t, 4, summary.Total)
	assert.Equal(t, 2, summary.BySeverity["high"])
	assert.Equal(t, 1, summary.BySeverity["medium"])
	assert.Equal(t, 1, summary.BySeverity["low"])
	assert.Equal(t, 2, summary.ByPlugin["sqli"])
	assert.Equal(t, 2, summary.ByPlugin["xss"])
	assert.Equal(t, 2, summary.ByTier[1])
	assert.Equal(t, 1, summary.ByTier[2])
	assert.Equal(t, 1, summary.ByTier[3])
	assert.Equal(t, 2, summary.StepsRun)
	assert.Equal(t, 1, summary.StepsFailed)
	assert.Equal(t, 1, summary.StepsSkipped)
}

func TestBuildSummaryEmpty(t *testing.T) {
	summary := BuildSummary([]types.Finding{}, []types.StepResult{})

	assert.Equal(t, 0, summary.Total)
	assert.Empty(t, summary.BySeverity)
	assert.Empty(t, summary.ByPlugin)
	assert.Empty(t, summary.ByTier)
	assert.Equal(t, 0, summary.StepsRun)
	assert.Equal(t, 0, summary.StepsFailed)
	assert.Equal(t, 0, summary.StepsSkipped)
}

func TestWriteJSON(t *testing.T) {
	report := &ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 1, 1, 12, 5, 0, 0, time.UTC),
		Findings: []types.Finding{
			{
				Plugin:     "sqli",
				Endpoint:   types.EndpointRef{Method: "POST", Path: "/api/users"},
				Parameter:  "username",
				Severity:   "high",
				Confidence: 0.95,
			},
		},
		Summary: ScanSummary{
			Total:      1,
			BySeverity: map[string]int{"high": 1},
			ByPlugin:   map[string]int{"sqli": 1},
			ByTier:     map[int]int{1: 1},
			StepsRun:   5,
		},
		Config: &ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
			MaxRPS:      10.0,
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, report)
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	// Verify key fields
	assert.Equal(t, "https://api.example.com", parsed["Target"])
	assert.NotNil(t, parsed["Findings"])
	assert.NotNil(t, parsed["Summary"])
}

func TestWriteTable(t *testing.T) {
	report := &ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 1, 1, 12, 5, 0, 0, time.UTC),
		Findings: []types.Finding{
			{
				Plugin:     "sqli",
				Endpoint:   types.EndpointRef{Method: "POST", Path: "/api/users"},
				Parameter:  "username",
				Severity:   "high",
				Confidence: 0.95,
				Evidence:   "SQL error: syntax error",
			},
		},
		Summary: ScanSummary{
			Total:      1,
			BySeverity: map[string]int{"high": 1},
			ByPlugin:   map[string]int{"sqli": 1},
			StepsRun:   5,
		},
		Config: &ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
			MaxRPS:      10.0,
		},
	}

	var buf bytes.Buffer
	err := WriteTable(&buf, report)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Cato Scan Report")
	assert.Contains(t, output, "https://api.example.com")
	assert.Contains(t, output, "Total Findings:   1")
	assert.Contains(t, output, "sqli")
	assert.Contains(t, output, "POST /api/users")
	assert.Contains(t, output, "username")
}

func TestWriteSARIF(t *testing.T) {
	report := &ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 1, 1, 12, 5, 0, 0, time.UTC),
		Findings: []types.Finding{
			{
				Plugin:     "sqli",
				Endpoint:   types.EndpointRef{Method: "POST", Path: "/api/users"},
				Parameter:  "username",
				Severity:   "high",
				Confidence: 0.95,
			},
		},
		Summary: ScanSummary{Total: 1},
		Config: &ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
			MaxRPS:      10.0,
		},
	}

	var buf bytes.Buffer
	err := WriteSARIF(&buf, report)
	require.NoError(t, err)

	// Verify it's valid JSON
	var sarif SARIFReport
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	// Verify SARIF structure
	assert.Equal(t, "2.1.0", sarif.Version)
	assert.Len(t, sarif.Runs, 1)
	assert.Equal(t, "Cato", sarif.Runs[0].Tool.Driver.Name)
	assert.Len(t, sarif.Runs[0].Results, 1)

	result := sarif.Runs[0].Results[0]
	assert.Equal(t, "sqli.POST", result.RuleID)
	assert.Equal(t, "error", result.Level)
	assert.Contains(t, result.Message.Text, "sqli")
	assert.Contains(t, result.Message.Text, "username")
}

func TestWriteSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected string
	}{
		{"critical maps to error", "critical", "error"},
		{"high maps to error", "high", "error"},
		{"medium maps to warning", "medium", "warning"},
		{"low maps to note", "low", "note"},
		{"info maps to note", "info", "note"},
		{"unknown maps to warning", "unknown", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ScanReport{
				Target: "https://api.example.com",
				Findings: []types.Finding{
					{
						Plugin:   "test",
						Severity: tt.severity,
						Endpoint: types.EndpointRef{Method: "GET", Path: "/"},
					},
				},
				Config: &ScanConfig{
					Target:      "https://api.example.com",
					MaxRequests: 1000,
					MaxRPS:      10.0,
				},
			}

			var buf bytes.Buffer
			err := WriteSARIF(&buf, report)
			require.NoError(t, err)

			var sarif SARIFReport
			err = json.Unmarshal(buf.Bytes(), &sarif)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, sarif.Runs[0].Results[0].Level)
		})
	}
}

func TestWriteTableLongEvidence(t *testing.T) {
	longEvidence := strings.Repeat("x", 150)

	report := &ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Findings: []types.Finding{
			{
				Plugin:     "test",
				Endpoint:   types.EndpointRef{Method: "GET", Path: "/"},
				Parameter:  "test",
				Severity:   "low",
				Confidence: 0.5,
				Evidence:   longEvidence,
			},
		},
		Summary: ScanSummary{Total: 1},
		Config: &ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
			MaxRPS:      10.0,
		},
	}

	var buf bytes.Buffer
	err := WriteTable(&buf, report)
	require.NoError(t, err)

	output := buf.String()
	// Evidence should be truncated
	assert.Contains(t, output, "...")
	assert.NotContains(t, output, strings.Repeat("x", 150))
}
