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

// Package types defines shared type definitions for the Cato injection scanner.
package types

// EndpointRef represents a reference to an API endpoint targeted by an attack step.
type EndpointRef struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

// AttackStep represents a single step in an attack plan, including the target
// endpoint, payload, and description of what the step attempts to accomplish.
type AttackStep struct {
	Endpoint    EndpointRef `json:"endpoint"`
	Payload     string      `json:"payload"`
	Description string      `json:"description"`
}

// AttackPlan represents a complete attack plan consisting of ordered steps.
type AttackPlan struct {
	Steps []AttackStep `json:"steps"`
}

// ValidatorConfig defines the safety constraints enforced by the validator.
// It controls which hosts and HTTP methods are permitted, the maximum number
// of requests allowed, rate limiting, and paths that must never be touched.
type ValidatorConfig struct {
	AllowedHosts   []string `json:"allowed_hosts"`   // Only these hosts can be targeted. "*" = all.
	AllowedMethods []string `json:"allowed_methods"` // Permitted HTTP methods. "*" = all.
	MaxRequests    int      `json:"max_requests"`    // Total request budget (0 = unlimited). Truncate plan if exceeded.
	MaxRPS         int      `json:"max_rps"`         // Rate limit passed through to Executor (0 = unlimited).
	DenyPaths      []string `json:"deny_paths"`      // Paths to never touch (prefix match).
}
