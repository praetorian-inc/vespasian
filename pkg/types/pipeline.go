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

// Package types provides shared types for the Cato injection vulnerability scanner.
package types

import "context"

// Plugin represents an injection detection plugin.
type Plugin interface {
	Name() string
	Type() InjectionType
	Payloads(ParameterContext) []Payload
	DetectionRules() []DetectionRule
}

// Endpoint represents an API endpoint discovered from the OpenAPI spec.
type Endpoint struct {
	Method      string
	Path        string
	OperationID string
	Parameters  []ParameterContext
	ContentType string
}

// Dependency represents a data dependency between endpoints.
type Dependency struct {
	Producer EndpointRef
	Consumer EndpointRef
	Field    string
}

// DependencyGraph represents the dependency relationships between endpoints.
type DependencyGraph struct {
	Nodes []Endpoint
	Edges []Dependency
}

// Parser parses an OpenAPI specification into endpoints.
type Parser interface {
	Parse(ctx context.Context, specData []byte) ([]Endpoint, error)
}

// DependencyAnalyzer analyzes dependencies between endpoints.
type DependencyAnalyzer interface {
	Analyze(ctx context.Context, endpoints []Endpoint) (*DependencyGraph, error)
}

// Planner creates an attack plan from endpoints and plugins.
type Planner interface {
	Plan(ctx context.Context, endpoints []Endpoint, deps *DependencyGraph, plugins []Plugin) (*AttackPlan, error)
}

// Validator validates and filters an attack plan for safety.
type Validator interface {
	Validate(plan *AttackPlan, config ValidatorConfig) (*AttackPlan, []Rejection, error)
}

// Executor executes an attack plan and collects results.
type Executor interface {
	Execute(ctx context.Context, plan *AttackPlan) ([]StepResult, error)
}

// Analyzer analyzes step results to identify vulnerabilities.
type Analyzer interface {
	Analyze(ctx context.Context, steps []AttackStep, results []StepResult, plugins []Plugin) ([]Finding, error)
}
