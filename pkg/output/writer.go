package output

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
)

// Writer wraps the SDK formatter for simplified output writing.
type Writer struct {
	formatter formatter.Formatter
	toolInfo  formatter.ToolInfo
}

// NewWriter creates a new output writer with the specified format.
// Supported formats: terminal, json, ndjson, markdown, sarif
func NewWriter(format string, w io.Writer) (*Writer, error) {
	// Create formatter config
	cfg := formatter.Config{
		Format: formatter.Format(format),
		Writer: w,
		ToolInfo: formatter.ToolInfo{
			Name:        "vespasian",
			Version:     "0.1.0",
			Description: "API surface enumeration tool",
			URL:         "https://github.com/praetorian-inc/vespasian",
		},
	}

	// Create formatter
	f, err := formatter.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create formatter: %w", err)
	}

	return &Writer{
		formatter: f,
		toolInfo:  cfg.ToolInfo,
	}, nil
}

// WriteFindings writes findings to the output.
// Automatically handles Initialize, Format, and Complete lifecycle.
// Converts capability.Finding to formatter.Finding for output.
func (w *Writer) WriteFindings(ctx context.Context, findings []capability.Finding) error {
	// Initialize formatter
	if err := w.formatter.Initialize(ctx, w.toolInfo); err != nil {
		return fmt.Errorf("failed to initialize formatter: %w", err)
	}

	// Convert and write each finding
	for _, capFinding := range findings {
		formatterFinding := convertToFormatterFinding(capFinding)
		if err := w.formatter.Format(ctx, formatterFinding); err != nil {
			return fmt.Errorf("failed to format finding: %w", err)
		}
	}

	// Complete with summary
	summary := formatter.Summary{
		TotalFindings: len(findings),
		InfoCount:     countBySeverity(findings, capability.SeverityInfo),
		LowCount:      countBySeverity(findings, capability.SeverityLow),
		MediumCount:   countBySeverity(findings, capability.SeverityMedium),
		HighCount:     countBySeverity(findings, capability.SeverityHigh),
		CriticalCount: countBySeverity(findings, capability.SeverityCritical),
	}

	if err := w.formatter.Complete(ctx, summary); err != nil {
		return fmt.Errorf("failed to complete formatter: %w", err)
	}

	return nil
}

// Close closes the writer and releases resources.
func (w *Writer) Close() error {
	return w.formatter.Close()
}

// convertToFormatterFinding converts a capability.Finding to formatter.Finding.
func convertToFormatterFinding(f capability.Finding) formatter.Finding {
	// Map capability severity to formatter severity
	var severity formatter.Severity
	switch f.Severity {
	case capability.SeverityInfo:
		severity = formatter.SeverityInfo
	case capability.SeverityLow:
		severity = formatter.SeverityLow
	case capability.SeverityMedium:
		severity = formatter.SeverityMedium
	case capability.SeverityHigh:
		severity = formatter.SeverityHigh
	case capability.SeverityCritical:
		severity = formatter.SeverityCritical
	default:
		severity = formatter.SeverityInfo
	}

	// Build formatter finding
	formatterFinding := formatter.Finding{
		Severity:  severity,
		Source:    "vespasian",
		Timestamp: time.Now(),
		Metadata:  f.Data,
	}

	// Set type-specific fields
	switch f.Type {
	case capability.FindingAsset:
		// API endpoint finding
		if f.Data["type"] == "api_endpoint" {
			formatterFinding.RuleID = "api-surface-enum"
			if method, ok := f.Data["method"].(string); ok {
				if path, ok := f.Data["path"].(string); ok {
					formatterFinding.Title = fmt.Sprintf("API Endpoint: %s %s", method, path)
					formatterFinding.Description = fmt.Sprintf("Discovered API endpoint: %s %s", method, path)
					formatterFinding.Location = formatter.Location{
						URL: path,
					}
					if category, ok := f.Data["probe_category"].(string); ok {
						formatterFinding.Location.Protocol = category
					}
				}
			}
		}
	case capability.FindingAttribute:
		// Error finding
		if f.Data["type"] == "probe_error" {
			formatterFinding.RuleID = "probe-error"
			if category, ok := f.Data["probe_category"].(string); ok {
				formatterFinding.Title = fmt.Sprintf("Probe Error: %s", category)
			} else {
				formatterFinding.Title = "Probe Error"
			}
			if errMsg, ok := f.Data["error"].(string); ok {
				formatterFinding.Description = fmt.Sprintf("Probe failed: %s", errMsg)
			}
		}
	}

	return formatterFinding
}

// countBySeverity counts findings with the specified severity.
func countBySeverity(findings []capability.Finding, severity capability.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}
