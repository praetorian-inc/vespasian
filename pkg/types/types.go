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

import "time"

// InjectionType represents the type of injection vulnerability.
type InjectionType int

// Supported injection vulnerability types.
const (
	SQLi InjectionType = iota // SQLi represents SQL injection vulnerabilities
	XSS                       // XSS represents cross-site scripting vulnerabilities
	SSTI                      // SSTI represents server-side template injection vulnerabilities
	SSRF                      // SSRF represents server-side request forgery vulnerabilities
	XXE                       // XXE represents XML external entity vulnerabilities
	CMDi                      // CMDi represents command injection vulnerabilities
)

// String returns the string representation of InjectionType.
func (i InjectionType) String() string {
	switch i {
	case SQLi:
		return "SQLi"
	case XSS:
		return "XSS"
	case SSTI:
		return "SSTI"
	case SSRF:
		return "SSRF"
	case XXE:
		return "XXE"
	case CMDi:
		return "CMDi"
	default:
		return "Unknown"
	}
}

// ParameterLocation represents where a parameter is located in an HTTP request.
type ParameterLocation int

// Supported parameter locations in HTTP requests.
const (
	Query  ParameterLocation = iota // Query represents URL query parameters
	Body                            // Body represents request body parameters
	Header                          // Header represents HTTP headers
	Path                            // Path represents URL path parameters
	Cookie                          // Cookie represents HTTP cookies
)

// String returns the string representation of ParameterLocation.
func (p ParameterLocation) String() string {
	switch p {
	case Query:
		return "Query"
	case Body:
		return "Body"
	case Header:
		return "Header"
	case Path:
		return "Path"
	case Cookie:
		return "Cookie"
	default:
		return "Unknown"
	}
}

// RuleType represents the type of detection rule.
type RuleType int

// Supported detection rule types for identifying vulnerabilities.
const (
	Regex      RuleType = iota // Regex represents pattern-based detection rules
	StatusCode                 // StatusCode represents HTTP status code-based detection
	Timing                     // Timing represents time-based detection rules
	OOB                        // OOB represents out-of-band detection rules
)

// String returns the string representation of RuleType.
func (r RuleType) String() string {
	switch r {
	case Regex:
		return "Regex"
	case StatusCode:
		return "StatusCode"
	case Timing:
		return "Timing"
	case OOB:
		return "OOB"
	default:
		return "Unknown"
	}
}

// StepStatus represents the execution status of an attack step.
type StepStatus int

// Supported execution statuses for attack steps.
const (
	Success StepStatus = iota // Success indicates the step executed successfully
	Failed                    // Failed indicates the step failed to execute
	Skipped                   // Skipped indicates the step was skipped
	Timeout                   // Timeout indicates the step timed out
)

// String returns the string representation of StepStatus.
func (s StepStatus) String() string {
	switch s {
	case Success:
		return "Success"
	case Failed:
		return "Failed"
	case Skipped:
		return "Skipped"
	case Timeout:
		return "Timeout"
	default:
		return "Unknown"
	}
}

// ParameterContext describes a parameter in an API endpoint.
type ParameterContext struct {
	Name     string
	Type     string
	Location ParameterLocation
	Format   string
	Required bool
}

// Payload represents an injection payload with metadata.
type Payload struct {
	Value       string
	Description string
	Blind       bool
	OOB         bool
	Tags        []string
}

// DetectionRule defines how to detect if a payload succeeded.
type DetectionRule struct {
	Type      RuleType
	Pattern   string
	Threshold float64
	Severity  string
	Evidence  string
}

// EndpointRef uniquely identifies an API endpoint.
type EndpointRef struct {
	Method string
	Path   string
}

// DetectionMethod defines the detection approach for an attack step.
type DetectionMethod struct {
	Primary  RuleType
	Fallback bool
}

// AttackStep represents a single step in an attack plan.
type AttackStep struct {
	ID        string
	Endpoint  EndpointRef
	Parameter string
	Payload   string
	Plugin    string
	OOB       bool
	DependsOn []string
	Extract   map[string]string
	Detect    DetectionMethod
}

// AttackPlan contains the complete sequence of attack steps.
type AttackPlan struct {
	Steps []AttackStep
}

// HTTPResponse captures the response from an HTTP request.
type HTTPResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Timing     time.Duration
}

// StepResult captures the result of executing an attack step.
type StepResult struct {
	StepID   string
	Status   StepStatus
	Response *HTTPResponse
	Error    string
	Duration time.Duration
}

// Finding represents a discovered vulnerability.
type Finding struct {
	Plugin     string
	Endpoint   EndpointRef
	Parameter  string
	Payload    string
	Severity   string
	Evidence   string
	Tier       int
	Confidence float64
	Steps      []AttackStep
}

// Rejection represents a step that was rejected by the validator.
type Rejection struct {
	Step   AttackStep
	Reason string
}

// ValidatorConfig configures request validation and safety checks.
type ValidatorConfig struct {
	AllowedHosts   []string
	AllowedMethods []string
	MaxRequests    int
	MaxRPS         float64
	DenyPaths      []string
}
