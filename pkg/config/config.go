// Package config handles configuration loading for Vespasian.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProbeConfig represents configuration for a single probe.
type ProbeConfig struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
}

// TargetConfig represents a scan target configuration.
type TargetConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// Config represents the complete Vespasian configuration.
type Config struct {
	Probes      []ProbeConfig  `yaml:"probes"`
	Targets     []TargetConfig `yaml:"targets"`
	Timeout     int            `yaml:"timeout"`
	Concurrency int            `yaml:"concurrency"`
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &cfg, nil
}
