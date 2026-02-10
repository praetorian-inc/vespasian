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

// Package main is the entry point for the cato CLI.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/report"
	"github.com/praetorian-inc/vespasian/pkg/types"
	"github.com/spf13/cobra"
)

const (
	// maxSpecSize is the maximum size allowed for OpenAPI spec input (50MB)
	maxSpecSize = 50 * 1024 * 1024
)

var (
	// Global flags
	target       string
	plugins      []string
	allowedHosts []string
	denyPaths    []string
	maxRequests  int
	maxRPS       float64
	timeout      time.Duration
	outputFormat string
	authToken    string
	authHeader   string
	stdin        bool
	outputFile   string
)

var rootCmd = &cobra.Command{
	Use:   "cato",
	Short: "Cato injection vulnerability scanner",
	Long:  `Cato is an automated injection vulnerability scanner for API specifications.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [spec-file]",
	Short: "Run full injection vulnerability scan pipeline",
	Long: `Scan runs the complete Cato pipeline:
  1. Parse OpenAPI specification
  2. Analyze endpoint dependencies
  3. Generate attack plan
  4. Validate plan against safety rules
  5. Execute attack steps
  6. Analyze results for vulnerabilities
  7. Generate report`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("cato version dev")
	},
}

func init() {
	// Scan command flags
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "Target API base URL (required)")
	scanCmd.Flags().StringSliceVarP(&plugins, "plugins", "p", []string{}, "Comma-separated plugin names to enable (default: all)")
	scanCmd.Flags().StringSliceVar(&allowedHosts, "allowed-hosts", []string{}, "Host allowlist for Validator")
	scanCmd.Flags().StringSliceVar(&denyPaths, "deny-paths", []string{}, "Paths to exclude from testing")
	scanCmd.Flags().IntVar(&maxRequests, "max-requests", 1000, "Request budget")
	scanCmd.Flags().Float64Var(&maxRPS, "max-rps", 10.0, "Rate limit (requests per second)")
	scanCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Per-request timeout")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format: json, table, sarif")
	scanCmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token for target API")
	scanCmd.Flags().StringVar(&authHeader, "auth-header", "", "Custom auth header (format: 'Name: Value')")
	scanCmd.Flags().BoolVar(&stdin, "stdin", false, "Accept OpenAPI spec from stdin")
	scanCmd.Flags().StringVarP(&outputFile, "file", "f", "", "Write output to file instead of stdout")

	if err := scanCmd.MarkFlagRequired("target"); err != nil {
		panic(fmt.Sprintf("failed to mark target flag as required: %v", err))
	}

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Create context with signal handling for graceful shutdown (SIGINT and SIGTERM)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Read OpenAPI spec
	var specData []byte
	var err error

	if stdin {
		// Limit stdin reads to maxSpecSize
		limitedReader := io.LimitReader(os.Stdin, maxSpecSize+1)
		specData, err = io.ReadAll(limitedReader)
		if err != nil {
			return fmt.Errorf("failed to read spec from stdin: %w", err)
		}
		if len(specData) > maxSpecSize {
			return fmt.Errorf("spec input exceeds maximum size of %d bytes", maxSpecSize)
		}
	} else {
		if len(args) == 0 {
			return fmt.Errorf("spec file required (or use --stdin)")
		}
		// Clean the spec file path
		specPath := filepath.Clean(args[0])

		// Check file size before reading
		fileInfo, err := os.Stat(specPath)
		if err != nil {
			return fmt.Errorf("failed to stat spec file: %w", err)
		}
		if fileInfo.Size() > maxSpecSize {
			return fmt.Errorf("spec file exceeds maximum size of %d bytes", maxSpecSize)
		}

		specData, err = os.ReadFile(specPath)
		if err != nil {
			return fmt.Errorf("failed to read spec file: %w", err)
		}
	}

	// Normalize and validate output format
	outputFormat = strings.ToLower(outputFormat)
	if !isValidOutputFormat(outputFormat) {
		return fmt.Errorf("invalid output format: %s (must be json, table, or sarif)", outputFormat)
	}

	// Validate safety bounds
	if maxRequests <= 0 {
		return fmt.Errorf("max-requests must be greater than 0, got %d", maxRequests)
	}
	if maxRPS <= 0 {
		return fmt.Errorf("max-rps must be greater than 0, got %f", maxRPS)
	}

	// Build validator config
	validatorConfig := types.ValidatorConfig{
		AllowedHosts:   allowedHosts,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		MaxRequests:    maxRequests,
		MaxRPS:         maxRPS,
		DenyPaths:      denyPaths,
	}

	// Run pipeline with auth parameters (not yet wired, but parameters in place)
	scanReport, exitCode, err := runPipeline(ctx, specData, target, plugins, validatorConfig, authToken, authHeader)
	if err != nil {
		return err
	}

	// Write output with proper file close handling
	return writeOutput(scanReport, outputFormat, exitCode)
}

// writeOutput handles writing the scan report and ensures deferred closes complete
func writeOutput(scanReport *report.ScanReport, format string, exitCode int) (returnErr error) {
	var writer io.Writer
	var closeFunc func() error

	if outputFile != "" {
		// Clean the output file path
		outPath := filepath.Clean(outputFile)

		file, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		writer = file
		closeFunc = file.Close
		defer func() {
			if err := closeFunc(); err != nil && returnErr == nil {
				returnErr = fmt.Errorf("failed to close output file: %w", err)
			}
		}()
	} else {
		writer = os.Stdout
	}

	if err := writeReport(writer, scanReport, format); err != nil {
		return err
	}

	// Exit with appropriate code after defers complete
	os.Exit(exitCode)
	return nil
}

func runPipeline(ctx context.Context, specData []byte, target string, plugins []string, config types.ValidatorConfig, authToken, authHeader string) (*report.ScanReport, int, error) {
	// TODO: Implement pipeline stages
	// authToken and authHeader parameters are ready for when pipeline implementation needs them
	_ = authToken
	_ = authHeader
	// For now, return a placeholder error indicating pipeline is not yet implemented
	return nil, 2, fmt.Errorf("pipeline stages not yet implemented")
}

func writeReport(w io.Writer, scanReport *report.ScanReport, format string) error {
	// Format is already normalized to lowercase in runScan
	switch format {
	case "json":
		return report.WriteJSON(w, scanReport)
	case "table":
		return report.WriteTable(w, scanReport)
	case "sarif":
		return report.WriteSARIF(w, scanReport)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func isValidOutputFormat(format string) bool {
	format = strings.ToLower(format)
	return format == "json" || format == "table" || format == "sarif"
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
