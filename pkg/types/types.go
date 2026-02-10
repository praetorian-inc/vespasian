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

import "time"

// InjectionType represents the type of injection vulnerability.
type InjectionType int

const (
	// SQLi represents SQL injection vulnerabilities.
	SQLi InjectionType = iota
	// XSS represents cross-site scripting vulnerabilities.
	XSS
	// SSTI represents server-side template injection vulnerabilities.
	SSTI
	// SSRF represents server-side request forgery vulnerabilities.
	SSRF
	// XXE represents XML external entity vulnerabilities.
	XXE
	// CMDi represents command injection vulnerabilities.
	CMDi
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

// ParameterLocation represents where a parameter is located in a request.
type ParameterLocation int

const (
	// Query represents a query parameter.
	Query ParameterLocation = iota
	// Body represents a body parameter.
	Body
	// Header represents a header parameter.
	Header
	// Path represents a path parameter.
	Path
	// Cookie represents a cookie parameter.
	Cookie
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

const (
	// Regex represents a regular expression-based detection rule.
	Regex RuleType = iota
	// StatusCode represents a status code-based detection rule.
	StatusCode
	// Timing represents a timing-based detection rule.
	Timing
	// OOB represents an out-of-band detection rule.
	OOB
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

// DependencySource represents where dependency data comes from.
type DependencySource int

const (
	// ResponseBody represents data from a response body.
	ResponseBody DependencySource = iota
	// ResponseHeader represents data from a response header.
	ResponseHeader
	// PathParam represents data from a path parameter.
	PathParam
)

// String returns the string representation of DependencySource.
func (d DependencySource) String() string {
	switch d {
	case ResponseBody:
		return "ResponseBody"
	case ResponseHeader:
		return "ResponseHeader"
	case PathParam:
		return "PathParam"
	default:
		return "Unknown"
	}
}

// StepStatus represents the execution status of an attack step.
type StepStatus int

const (
	// Success represents a successfully executed step.
	Success StepStatus = iota
	// Failed represents a failed step.
	Failed
	// Skipped represents a skipped step.
	Skipped
	// Timeout represents a timed out step.
	Timeout
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

// ParameterContext holds metadata about a request parameter.
type ParameterContext struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Location ParameterLocation `json:"location"`
	Format   string            `json:"format,omitempty"`
	Required bool              `json:"required"`
}

// Payload represents an attack payload.
type Payload struct {
	Value       string   `json:"value"`
	Description string   `json:"description,omitempty"`
	Blind       bool     `json:"blind"`
	OOB         bool     `json:"oob"`
	Tags        []string `json:"tags,omitempty"`
}

// DetectionRule defines how to detect a successful attack.
type DetectionRule struct {
	Type      RuleType `json:"type"`
	Pattern   string   `json:"pattern,omitempty"`
	Threshold float64  `json:"threshold,omitempty"`
	Severity  string   `json:"severity"`
	Evidence  string   `json:"evidence,omitempty"`
}

// EndpointRef references an API endpoint.
type EndpointRef struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// DetectionMethod defines detection strategy.
type DetectionMethod struct {
	Primary  RuleType `json:"primary"`
	Fallback bool     `json:"fallback"`
}

// AttackStep represents a single step in an attack sequence.
type AttackStep struct {
	ID        string            `json:"id"`
	Endpoint  EndpointRef       `json:"endpoint"`
	Parameter string            `json:"parameter"`
	Payload   string            `json:"payload"`
	Plugin    string            `json:"plugin"`
	OOB       bool              `json:"oob"`
	DependsOn []string          `json:"depends_on,omitempty"`
	Extract   map[string]string `json:"extract,omitempty"`
	Detect    DetectionMethod   `json:"detect"`
}

// AttackPlan is a sequence of attack steps.
type AttackPlan struct {
	Steps []AttackStep `json:"steps"`
}

// HTTPResponse represents an HTTP response.
type HTTPResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       []byte              `json:"body,omitempty"`
	Timing     time.Duration       `json:"timing"`
}

// StepResult represents the result of executing an attack step.
type StepResult struct {
	StepID   string        `json:"step_id"`
	Status   StepStatus    `json:"status"`
	Response *HTTPResponse `json:"response,omitempty"`
	Error    error         `json:"-"`
	Duration time.Duration `json:"duration"`
}

// Finding represents a discovered vulnerability.
type Finding struct {
	Plugin     string       `json:"plugin"`
	Endpoint   EndpointRef  `json:"endpoint"`
	Parameter  string       `json:"parameter"`
	Payload    string       `json:"payload"`
	Severity   string       `json:"severity"`
	Evidence   string       `json:"evidence,omitempty"`
	Tier       int          `json:"tier"`
	Confidence float64      `json:"confidence"`
	Steps      []AttackStep `json:"steps,omitempty"`
}

// ValidatorConfig configures attack validation.
type ValidatorConfig struct {
	AllowedHosts   []string `json:"allowed_hosts,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	MaxRequests    int      `json:"max_requests"`
	MaxRPS         float64  `json:"max_rps"`
	DenyPaths      []string `json:"deny_paths,omitempty"`
}

// AuthConfig holds authentication configuration.
// Token and Headers are excluded from JSON serialization to prevent credential leakage.
type AuthConfig struct {
	Type    string            `json:"type"`
	Token   string            `json:"-"`
	Headers map[string]string `json:"-"`
}

// ExecutorConfig configures attack execution.
type ExecutorConfig struct {
	BaseURL        string        `json:"base_url"`
	Auth           AuthConfig    `json:"auth,omitempty"`
	RequestTimeout time.Duration `json:"request_timeout"`
	RPS            float64       `json:"rps"`
}

// ScanSummary provides statistics about a scan.
type ScanSummary struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity,omitempty"`
	ByPlugin     map[string]int `json:"by_plugin,omitempty"`
	ByTier       map[int]int    `json:"by_tier,omitempty"`
	StepsRun     int            `json:"steps_run"`
	StepsFailed  int            `json:"steps_failed"`
	StepsSkipped int            `json:"steps_skipped"`
}

// ScanReport is the complete output of a scan.
type ScanReport struct {
	Target      string          `json:"target"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	Findings    []Finding       `json:"findings,omitempty"`
	Summary     ScanSummary     `json:"summary"`
	Steps       []StepResult    `json:"steps,omitempty"`
	Plan        AttackPlan      `json:"plan"`
	Config      ValidatorConfig `json:"config"`
}

// Dependency represents a data dependency between endpoints.
type Dependency struct {
	Producer EndpointRef      `json:"producer"`
	Consumer EndpointRef      `json:"consumer"`
	Field    string           `json:"field"`
	Source   DependencySource `json:"source"`
}

// DependencyGraph represents the dependency structure between endpoints.
type DependencyGraph struct {
	Nodes []EndpointRef `json:"nodes"`
	Edges []Dependency  `json:"edges,omitempty"`
}
