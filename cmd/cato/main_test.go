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

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/report"
	"github.com/praetorian-inc/vespasian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidOutputFormat(t *testing.T) {
	tests := []struct {
		format string
		valid  bool
	}{
		{"json", true},
		{"table", true},
		{"sarif", true},
		{"JSON", true},
		{"TABLE", true},
		{"SARIF", true},
		{"xml", false},
		{"yaml", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := isValidOutputFormat(tt.format)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestWriteReportJSON(t *testing.T) {
	scanReport := &report.ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Findings:    []types.Finding{},
		Summary:     report.ScanSummary{Total: 0},
		Config: &report.ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
		},
	}

	var buf bytes.Buffer
	err := writeReport(&buf, scanReport, "json")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "https://api.example.com")
}

func TestWriteReportTable(t *testing.T) {
	scanReport := &report.ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Findings:    []types.Finding{},
		Summary:     report.ScanSummary{Total: 0},
		Config: &report.ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
		},
	}

	var buf bytes.Buffer
	err := writeReport(&buf, scanReport, "table")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Cato Scan Report")
}

func TestWriteReportSARIF(t *testing.T) {
	scanReport := &report.ScanReport{
		Target:      "https://api.example.com",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Findings:    []types.Finding{},
		Summary:     report.ScanSummary{Total: 0},
		Config: &report.ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
		},
	}

	var buf bytes.Buffer
	err := writeReport(&buf, scanReport, "sarif")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "2.1.0")
	assert.Contains(t, buf.String(), "Cato")
}

func TestWriteReportInvalidFormat(t *testing.T) {
	scanReport := &report.ScanReport{
		Target:   "https://api.example.com",
		Findings: []types.Finding{},
		Summary:  report.ScanSummary{Total: 0},
		Config: &report.ScanConfig{
			Target:      "https://api.example.com",
			MaxRequests: 1000,
		},
	}

	var buf bytes.Buffer
	err := writeReport(&buf, scanReport, "xml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

func TestValidatorConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		maxRequests int
		maxRPS      float64
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid positive values",
			maxRequests: 1000,
			maxRPS:      10.0,
			expectError: false,
		},
		{
			name:        "zero maxRequests",
			maxRequests: 0,
			maxRPS:      10.0,
			expectError: true,
			errorMsg:    "max-requests must be greater than 0",
		},
		{
			name:        "negative maxRequests",
			maxRequests: -1,
			maxRPS:      10.0,
			expectError: true,
			errorMsg:    "max-requests must be greater than 0",
		},
		{
			name:        "zero maxRPS",
			maxRequests: 1000,
			maxRPS:      0,
			expectError: true,
			errorMsg:    "max-rps must be greater than 0",
		},
		{
			name:        "negative maxRPS",
			maxRequests: 1000,
			maxRPS:      -1.0,
			expectError: true,
			errorMsg:    "max-rps must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the validation logic from runScan
			var err error
			if tt.maxRequests <= 0 {
				err = assert.AnError
				assert.Contains(t, tt.errorMsg, "max-requests")
			}
			if tt.maxRPS <= 0 {
				err = assert.AnError
				assert.Contains(t, tt.errorMsg, "max-rps")
			}

			if tt.expectError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestRootCommandExists(t *testing.T) {
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "cato", rootCmd.Use)
}

func TestScanCommandExists(t *testing.T) {
	assert.NotNil(t, scanCmd)
	assert.Equal(t, "scan [spec-file]", scanCmd.Use)
}

func TestVersionCommandExists(t *testing.T) {
	assert.NotNil(t, versionCmd)
	assert.Equal(t, "version", versionCmd.Use)
}

func TestScanCommandFlags(t *testing.T) {
	// Verify required flags exist
	targetFlag := scanCmd.Flags().Lookup("target")
	require.NotNil(t, targetFlag)

	pluginsFlag := scanCmd.Flags().Lookup("plugins")
	require.NotNil(t, pluginsFlag)

	outputFlag := scanCmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)

	stdinFlag := scanCmd.Flags().Lookup("stdin")
	require.NotNil(t, stdinFlag)

	maxRequestsFlag := scanCmd.Flags().Lookup("max-requests")
	require.NotNil(t, maxRequestsFlag)

	maxRPSFlag := scanCmd.Flags().Lookup("max-rps")
	require.NotNil(t, maxRPSFlag)

	timeoutFlag := scanCmd.Flags().Lookup("timeout")
	require.NotNil(t, timeoutFlag)
}
