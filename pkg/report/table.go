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
	"fmt"
	"io"
	"strings"
)

// WriteTable writes a human-readable table format of the scan report.
func WriteTable(w io.Writer, report *ScanReport) error {
	// Header
	_, err := fmt.Fprintf(w, "Cato Scan Report\n")
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	_, err = fmt.Fprintf(w, "================\n\n")
	if err != nil {
		return fmt.Errorf("failed to write separator: %w", err)
	}

	// Target and timing
	duration := report.CompletedAt.Sub(report.StartedAt)
	_, err = fmt.Fprintf(w, "Target:       %s\n", report.Target)
	if err != nil {
		return fmt.Errorf("failed to write target: %w", err)
	}
	_, err = fmt.Fprintf(w, "Started:      %s\n", report.StartedAt.Format("2006-01-02 15:04:05"))
	if err != nil {
		return fmt.Errorf("failed to write start time: %w", err)
	}
	_, err = fmt.Fprintf(w, "Completed:    %s\n", report.CompletedAt.Format("2006-01-02 15:04:05"))
	if err != nil {
		return fmt.Errorf("failed to write completion time: %w", err)
	}
	_, err = fmt.Fprintf(w, "Duration:     %s\n\n", duration)
	if err != nil {
		return fmt.Errorf("failed to write duration: %w", err)
	}

	// Summary
	_, err = fmt.Fprintf(w, "Summary\n")
	if err != nil {
		return fmt.Errorf("failed to write summary header: %w", err)
	}
	_, err = fmt.Fprintf(w, "-------\n")
	if err != nil {
		return fmt.Errorf("failed to write summary separator: %w", err)
	}
	_, err = fmt.Fprintf(w, "Total Findings:   %d\n", report.Summary.Total)
	if err != nil {
		return fmt.Errorf("failed to write total findings: %w", err)
	}
	_, err = fmt.Fprintf(w, "Steps Run:        %d\n", report.Summary.StepsRun)
	if err != nil {
		return fmt.Errorf("failed to write steps run: %w", err)
	}
	_, err = fmt.Fprintf(w, "Steps Failed:     %d\n", report.Summary.StepsFailed)
	if err != nil {
		return fmt.Errorf("failed to write steps failed: %w", err)
	}
	_, err = fmt.Fprintf(w, "Steps Skipped:    %d\n\n", report.Summary.StepsSkipped)
	if err != nil {
		return fmt.Errorf("failed to write steps skipped: %w", err)
	}

	// By severity
	if len(report.Summary.BySeverity) > 0 {
		_, err = fmt.Fprintf(w, "By Severity:\n")
		if err != nil {
			return fmt.Errorf("failed to write severity header: %w", err)
		}
		for severity, count := range report.Summary.BySeverity {
			_, err = fmt.Fprintf(w, "  %s: %d\n", severity, count)
			if err != nil {
				return fmt.Errorf("failed to write severity count: %w", err)
			}
		}
		_, err = fmt.Fprintf(w, "\n")
		if err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	// By plugin
	if len(report.Summary.ByPlugin) > 0 {
		_, err = fmt.Fprintf(w, "By Plugin:\n")
		if err != nil {
			return fmt.Errorf("failed to write plugin header: %w", err)
		}
		for plugin, count := range report.Summary.ByPlugin {
			_, err = fmt.Fprintf(w, "  %s: %d\n", plugin, count)
			if err != nil {
				return fmt.Errorf("failed to write plugin count: %w", err)
			}
		}
		_, err = fmt.Fprintf(w, "\n")
		if err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	// Findings details
	if len(report.Findings) > 0 {
		_, err = fmt.Fprintf(w, "Findings\n")
		if err != nil {
			return fmt.Errorf("failed to write findings header: %w", err)
		}
		_, err = fmt.Fprintf(w, "--------\n")
		if err != nil {
			return fmt.Errorf("failed to write findings separator: %w", err)
		}
		for i, finding := range report.Findings {
			_, err = fmt.Fprintf(w, "%d. [%s] %s %s\n",
				i+1,
				finding.Severity,
				finding.Endpoint.Method,
				finding.Endpoint.Path)
			if err != nil {
				return fmt.Errorf("failed to write finding: %w", err)
			}
			_, err = fmt.Fprintf(w, "   Plugin: %s\n", finding.Plugin)
			if err != nil {
				return fmt.Errorf("failed to write plugin: %w", err)
			}
			_, err = fmt.Fprintf(w, "   Parameter: %s\n", finding.Parameter)
			if err != nil {
				return fmt.Errorf("failed to write parameter: %w", err)
			}
			_, err = fmt.Fprintf(w, "   Confidence: %.2f\n", finding.Confidence)
			if err != nil {
				return fmt.Errorf("failed to write confidence: %w", err)
			}
			if finding.Evidence != "" {
				// Truncate evidence if too long
				evidence := finding.Evidence
				if len(evidence) > 100 {
					evidence = evidence[:97] + "..."
				}
				_, err = fmt.Fprintf(w, "   Evidence: %s\n", strings.TrimSpace(evidence))
				if err != nil {
					return fmt.Errorf("failed to write evidence: %w", err)
				}
			}
			_, err = fmt.Fprintf(w, "\n")
			if err != nil {
				return fmt.Errorf("failed to write newline: %w", err)
			}
		}
	}

	return nil
}
