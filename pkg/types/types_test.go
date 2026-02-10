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

package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInjectionTypeString(t *testing.T) {
	tests := []struct {
		name     string
		injType  InjectionType
		expected string
	}{
		{"SQLi", SQLi, "SQLi"},
		{"XSS", XSS, "XSS"},
		{"SSTI", SSTI, "SSTI"},
		{"SSRF", SSRF, "SSRF"},
		{"XXE", XXE, "XXE"},
		{"CMDi", CMDi, "CMDi"},
		{"Invalid", InjectionType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.injType.String())
		})
	}
}

func TestParameterLocationString(t *testing.T) {
	tests := []struct {
		name     string
		location ParameterLocation
		expected string
	}{
		{"Query", Query, "Query"},
		{"Body", Body, "Body"},
		{"Header", Header, "Header"},
		{"Path", Path, "Path"},
		{"Cookie", Cookie, "Cookie"},
		{"Invalid", ParameterLocation(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.location.String())
		})
	}
}

func TestRuleTypeString(t *testing.T) {
	tests := []struct {
		name     string
		ruleType RuleType
		expected string
	}{
		{"Regex", Regex, "Regex"},
		{"StatusCode", StatusCode, "StatusCode"},
		{"Timing", Timing, "Timing"},
		{"OOB", OOB, "OOB"},
		{"Invalid", RuleType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ruleType.String())
		})
	}
}

func TestDependencySourceString(t *testing.T) {
	tests := []struct {
		name     string
		source   DependencySource
		expected string
	}{
		{"ResponseBody", ResponseBody, "ResponseBody"},
		{"ResponseHeader", ResponseHeader, "ResponseHeader"},
		{"PathParam", PathParam, "PathParam"},
		{"Invalid", DependencySource(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.String())
		})
	}
}

func TestStepStatusString(t *testing.T) {
	tests := []struct {
		name     string
		status   StepStatus
		expected string
	}{
		{"Success", Success, "Success"},
		{"Failed", Failed, "Failed"},
		{"Skipped", Skipped, "Skipped"},
		{"Timeout", Timeout, "Timeout"},
		{"Invalid", StepStatus(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestParameterContextJSONRoundtrip(t *testing.T) {
	original := ParameterContext{
		Name:     "userId",
		Type:     "string",
		Location: Query,
		Format:   "uuid",
		Required: true,
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded ParameterContext
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Location, decoded.Location)
	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.Required, decoded.Required)
}

func TestPayloadJSONRoundtrip(t *testing.T) {
	original := Payload{
		Value:       "' OR 1=1--",
		Description: "Basic SQL injection",
		Blind:       false,
		OOB:         false,
		Tags:        []string{"sqli", "basic"},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded Payload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Value, decoded.Value)
	assert.Equal(t, original.Description, decoded.Description)
	assert.Equal(t, original.Blind, decoded.Blind)
	assert.Equal(t, original.OOB, decoded.OOB)
	assert.ElementsMatch(t, original.Tags, decoded.Tags)
}

func TestDetectionRuleJSONRoundtrip(t *testing.T) {
	original := DetectionRule{
		Type:      Regex,
		Pattern:   "error.*sql",
		Threshold: 0.95,
		Severity:  "high",
		Evidence:  "SQL error in response",
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded DetectionRule
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Pattern, decoded.Pattern)
	assert.Equal(t, original.Threshold, decoded.Threshold)
	assert.Equal(t, original.Severity, decoded.Severity)
	assert.Equal(t, original.Evidence, decoded.Evidence)
}

func TestFindingJSONRoundtrip(t *testing.T) {
	original := Finding{
		Plugin:     "sqli-basic",
		Endpoint:   EndpointRef{Method: "GET", Path: "/api/users"},
		Parameter:  "id",
		Payload:    "' OR 1=1--",
		Severity:   "high",
		Evidence:   "SQL error detected",
		Tier:       1,
		Confidence: 0.95,
		Steps: []AttackStep{
			{
				ID:        "step1",
				Endpoint:  EndpointRef{Method: "GET", Path: "/api/users"},
				Parameter: "id",
				Payload:   "' OR 1=1--",
				Plugin:    "sqli-basic",
				OOB:       false,
				Detect:    DetectionMethod{Primary: Regex, Fallback: false},
			},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded Finding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Plugin, decoded.Plugin)
	assert.Equal(t, original.Endpoint, decoded.Endpoint)
	assert.Equal(t, original.Parameter, decoded.Parameter)
	assert.Equal(t, original.Payload, decoded.Payload)
	assert.Equal(t, original.Severity, decoded.Severity)
	assert.Equal(t, original.Evidence, decoded.Evidence)
	assert.Equal(t, original.Tier, decoded.Tier)
	assert.Equal(t, original.Confidence, decoded.Confidence)
	assert.Len(t, decoded.Steps, 1)
}

func TestScanReportJSONRoundtrip(t *testing.T) {
	now := time.Now().Truncate(time.Second) // Truncate for JSON precision

	original := ScanReport{
		Target:      "https://example.com",
		StartedAt:   now,
		CompletedAt: now.Add(5 * time.Minute),
		Findings: []Finding{
			{
				Plugin:     "sqli-basic",
				Endpoint:   EndpointRef{Method: "GET", Path: "/api/users"},
				Parameter:  "id",
				Payload:    "' OR 1=1--",
				Severity:   "high",
				Tier:       1,
				Confidence: 0.95,
			},
		},
		Summary: ScanSummary{
			Total:        1,
			BySeverity:   map[string]int{"high": 1},
			ByPlugin:     map[string]int{"sqli-basic": 1},
			ByTier:       map[int]int{1: 1},
			StepsRun:     5,
			StepsFailed:  0,
			StepsSkipped: 0,
		},
		Plan: AttackPlan{
			Steps: []AttackStep{
				{
					ID:        "step1",
					Endpoint:  EndpointRef{Method: "GET", Path: "/api/users"},
					Parameter: "id",
					Payload:   "' OR 1=1--",
					Plugin:    "sqli-basic",
					OOB:       false,
					Detect:    DetectionMethod{Primary: Regex, Fallback: false},
				},
			},
		},
		Config: ValidatorConfig{
			AllowedHosts:   []string{"example.com"},
			AllowedMethods: []string{"GET", "POST"},
			MaxRequests:    1000,
			MaxRPS:         10.0,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded ScanReport
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify key fields match
	assert.Equal(t, original.Target, decoded.Target)
	assert.Equal(t, original.StartedAt.Unix(), decoded.StartedAt.Unix())
	assert.Equal(t, original.CompletedAt.Unix(), decoded.CompletedAt.Unix())
	assert.Len(t, decoded.Findings, 1)
	assert.Equal(t, original.Summary.Total, decoded.Summary.Total)
	assert.Len(t, decoded.Plan.Steps, 1)
}

func TestAuthConfig_CredentialExclusionFromJSON(t *testing.T) {
	// Create AuthConfig with sensitive credentials
	auth := AuthConfig{
		Type:  "bearer",
		Token: "secret-token-12345",
		Headers: map[string]string{
			"Authorization": "Bearer secret-header-token",
			"X-API-Key":     "api-key-67890",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(auth)
	require.NoError(t, err)

	jsonStr := string(data)

	// Verify token is NOT in JSON output
	assert.NotContains(t, jsonStr, "secret-token-12345", "Token should not appear in JSON")

	// Verify headers are NOT in JSON output
	assert.NotContains(t, jsonStr, "Authorization", "Headers should not appear in JSON")
	assert.NotContains(t, jsonStr, "secret-header-token", "Header values should not appear in JSON")
	assert.NotContains(t, jsonStr, "api-key-67890", "Header values should not appear in JSON")

	// Verify type IS in JSON output
	assert.Contains(t, jsonStr, "bearer", "Type should appear in JSON")
}
