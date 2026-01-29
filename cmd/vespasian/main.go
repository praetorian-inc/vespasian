// Package main is the entry point for the Vespasian CLI.
package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	// Import probe packages to trigger init() registration
	_ "github.com/praetorian-inc/vespasian/pkg/crawler"
	_ "github.com/praetorian-inc/vespasian/pkg/protocols/grpc"
	_ "github.com/praetorian-inc/vespasian/pkg/protocols/websocket"
	_ "github.com/praetorian-inc/vespasian/pkg/spec/graphql"
	_ "github.com/praetorian-inc/vespasian/pkg/spec/openapi"
	_ "github.com/praetorian-inc/vespasian/pkg/spec/wsdl"
	"github.com/praetorian-inc/vespasian/pkg/probes"
)

// CLI defines the command-line interface structure.
type CLI struct {
	Scan    ScanCmd    `cmd:"" help:"Scan targets for API surfaces"`
	List    ListCmd    `cmd:"" help:"List available probes"`
	Version VersionCmd `cmd:"" help:"Show version information"`
}

// ScanCmd handles the scan subcommand.
type ScanCmd struct {
	Config  string   `arg:"" type:"path" help:"Path to configuration file"`
	Targets []string `arg:"" optional:"" help:"Additional targets to scan"`
	Format  string   `short:"f" default:"terminal" enum:"terminal,json,ndjson,markdown,sarif" help:"Output format (terminal, json, ndjson, markdown, sarif)"`
}

// Run executes the scan command.
func (c *ScanCmd) Run() error {
	fmt.Printf("Scanning with config: %s\n", c.Config)
	if len(c.Targets) > 0 {
		fmt.Printf("Additional targets: %v\n", c.Targets)
	}
	fmt.Printf("Output format: %s\n", c.Format)
	return nil
}

// ListCmd handles the list subcommand.
type ListCmd struct{}

// Run executes the list command.
func (c *ListCmd) Run() error {
	fmt.Println("Available probes:")
	for _, name := range probes.Registry.List() {
		fmt.Printf("  - %s\n", name)
	}
	return nil
}

// VersionCmd handles the version subcommand.
type VersionCmd struct{}

// Run executes the version command.
func (c *VersionCmd) Run() error {
	fmt.Println("vespasian version 0.1.0")
	return nil
}

func main() {
	cli := &CLI{}
	ctx := kong.Parse(cli,
		kong.Name("vespasian"),
		kong.Description("Comprehensive API surface enumeration tool"),
		kong.UsageOnError(),
	)

	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
