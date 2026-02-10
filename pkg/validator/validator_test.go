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

package validator

import (
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/types"
)

func TestValidate_HostFiltering(t *testing.T) {
	tests := []struct {
		name          string
		plan          types.AttackPlan
		config        types.ValidatorConfig
		wantSteps     int
		wantRejected  int
		rejectReasons []string
	}{
		{
			name: "allows steps targeting allowed hosts",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    2,
			wantRejected: 0,
		},
		{
			name: "rejects steps targeting disallowed hosts",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "evil.com", Method: "GET", Path: "/attack"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:     2,
			wantRejected:  1,
			rejectReasons: []string{"host not in allowed list"},
		},
		{
			name: "wildcard host allows all hosts",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "other.com", Method: "GET", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    2,
			wantRejected: 0,
		},
		{
			name: "empty allowed hosts rejects all",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{},
				AllowedMethods: []string{"*"},
			},
			wantSteps:     0,
			wantRejected:  1,
			rejectReasons: []string{"host not in allowed list"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}

			for i, reason := range tt.rejectReasons {
				if i >= len(rejected) {
					t.Errorf("Validate() missing rejection %d", i)
					continue
				}
				if rejected[i].Reason != reason {
					t.Errorf("Validate() rejection[%d].Reason = %q, want %q", i, rejected[i].Reason, reason)
				}
			}
		})
	}
}

func TestValidate_MethodFiltering(t *testing.T) {
	tests := []struct {
		name          string
		plan          types.AttackPlan
		config        types.ValidatorConfig
		wantSteps     int
		wantRejected  int
		rejectReasons []string
	}{
		{
			name: "allows steps using allowed methods",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"GET", "POST"},
			},
			wantSteps:    2,
			wantRejected: 0,
		},
		{
			name: "rejects steps using disallowed methods",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "DELETE", Path: "/user/1"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"GET", "POST"},
			},
			wantSteps:     2,
			wantRejected:  1,
			rejectReasons: []string{"method not in allowed list"},
		},
		{
			name: "wildcard method allows all methods",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "DELETE", Path: "/user/1"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "PATCH", Path: "/user/1"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    3,
			wantRejected: 0,
		},
		{
			name: "empty allowed methods rejects all",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{},
			},
			wantSteps:     0,
			wantRejected:  1,
			rejectReasons: []string{"method not in allowed list"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}

			for i, reason := range tt.rejectReasons {
				if i >= len(rejected) {
					t.Errorf("Validate() missing rejection %d", i)
					continue
				}
				if rejected[i].Reason != reason {
					t.Errorf("Validate() rejection[%d].Reason = %q, want %q", i, rejected[i].Reason, reason)
				}
			}
		})
	}
}

func TestValidate_DenyPathFiltering(t *testing.T) {
	tests := []struct {
		name          string
		plan          types.AttackPlan
		config        types.ValidatorConfig
		wantSteps     int
		wantRejected  int
		rejectReasons []string
	}{
		{
			name: "rejects steps targeting denied paths",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "DELETE", Path: "/admin/delete"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin"},
			},
			wantSteps:     2,
			wantRejected:  1,
			rejectReasons: []string{"path matches deny list"},
		},
		{
			name: "deny path prefix matching",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin/delete"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin/users/1"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin"},
			},
			wantSteps:     1,
			wantRejected:  3,
			rejectReasons: []string{"path matches deny list", "path matches deny list", "path matches deny list"},
		},
		{
			name: "multiple deny paths",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin/delete"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/internal/config"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin", "/internal"},
			},
			wantSteps:     2,
			wantRejected:  2,
			rejectReasons: []string{"path matches deny list", "path matches deny list"},
		},
		{
			name: "empty deny paths allows all",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{},
			},
			wantSteps:    2,
			wantRejected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}

			for i, reason := range tt.rejectReasons {
				if i >= len(rejected) {
					t.Errorf("Validate() missing rejection %d", i)
					continue
				}
				if rejected[i].Reason != reason {
					t.Errorf("Validate() rejection[%d].Reason = %q, want %q", i, rejected[i].Reason, reason)
				}
			}
		})
	}
}

func TestValidate_MaxRequestsBudget(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
	}{
		{
			name: "truncates plan when exceeding MaxRequests",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/1"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/2"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/3"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/4"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/5"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				MaxRequests:    3,
			},
			wantSteps:    3,
			wantRejected: 2, // Now tracks truncated steps (4 and 5)
		},
		{
			name: "MaxRequests zero means unlimited",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/1"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/2"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/3"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/4"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/5"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				MaxRequests:    0,
			},
			wantSteps:    5,
			wantRejected: 0,
		},
		{
			name: "MaxRequests applied after filtering",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/1"}},
					{Endpoint: types.EndpointRef{Host: "evil.com", Method: "GET", Path: "/2"}}, // rejected
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/3"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/4"}},
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/5"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
				MaxRequests:    2,
			},
			wantSteps:    2, // First 2 valid steps
			wantRejected: 3, // 1 rejected for host + 2 truncated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}
		})
	}
}

func TestValidate_EmptyPlan(t *testing.T) {
	plan := types.AttackPlan{Steps: []types.AttackStep{}}
	config := types.ValidatorConfig{
		AllowedHosts:   []string{"*"},
		AllowedMethods: []string{"*"},
	}

	validated, rejected := Validate(plan, config)

	if len(validated.Steps) != 0 {
		t.Errorf("Validate() validated steps = %d, want 0", len(validated.Steps))
	}

	if len(rejected) != 0 {
		t.Errorf("Validate() rejected steps = %d, want 0", len(rejected))
	}
}

func TestValidate_AllStepsRejected(t *testing.T) {
	plan := types.AttackPlan{
		Steps: []types.AttackStep{
			{Endpoint: types.EndpointRef{Host: "evil.com", Method: "GET", Path: "/attack"}},
			{Endpoint: types.EndpointRef{Host: "bad.com", Method: "GET", Path: "/attack"}},
		},
	}
	config := types.ValidatorConfig{
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"*"},
	}

	validated, rejected := Validate(plan, config)

	if len(validated.Steps) != 0 {
		t.Errorf("Validate() validated steps = %d, want 0", len(validated.Steps))
	}

	if len(rejected) != 2 {
		t.Errorf("Validate() rejected steps = %d, want 2", len(rejected))
	}
}

func TestValidate_CombinedFiltering(t *testing.T) {
	// Test that validation rules are applied in order and combine correctly
	plan := types.AttackPlan{
		Steps: []types.AttackStep{
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},    // OK
			{Endpoint: types.EndpointRef{Host: "evil.com", Method: "GET", Path: "/users"}},           // Bad host
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "DELETE", Path: "/users"}}, // Bad method
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin"}},    // Bad path
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "POST", Path: "/data"}},    // OK
		},
	}
	config := types.ValidatorConfig{
		AllowedHosts:   []string{"api.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		DenyPaths:      []string{"/admin"},
	}

	validated, rejected := Validate(plan, config)

	if len(validated.Steps) != 2 {
		t.Errorf("Validate() validated steps = %d, want 2", len(validated.Steps))
	}

	if len(rejected) != 3 {
		t.Errorf("Validate() rejected steps = %d, want 3", len(rejected))
	}

	// Verify rejection reasons
	expectedReasons := []string{
		"host not in allowed list",
		"method not in allowed list",
		"path matches deny list",
	}

	for i, want := range expectedReasons {
		if i >= len(rejected) {
			t.Errorf("Validate() missing rejection %d", i)
			continue
		}
		if rejected[i].Reason != want {
			t.Errorf("Validate() rejection[%d].Reason = %q, want %q", i, rejected[i].Reason, want)
		}
	}
}

// H-1: Case-sensitive host matching bypass tests
func TestValidate_CaseInsensitiveHost(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
	}{
		{
			name: "uppercase host should match lowercase allowed host",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "API.EXAMPLE.COM", Method: "GET", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    1,
			wantRejected: 0,
		},
		{
			name: "mixed case host should match lowercase allowed host",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "Api.Example.Com", Method: "GET", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    1,
			wantRejected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}
		})
	}
}

// H-2: Case-sensitive method matching bypass tests
func TestValidate_CaseInsensitiveMethod(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
	}{
		{
			name: "lowercase method should match uppercase allowed method",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "get", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"GET"},
			},
			wantSteps:    1,
			wantRejected: 0,
		},
		{
			name: "mixed case method should match uppercase allowed method",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "Get", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"GET"},
			},
			wantSteps:    1,
			wantRejected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}
		})
	}
}

// H-3: URL encoding bypass tests for deny paths
func TestValidate_URLEncodedPathBypass(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
	}{
		{
			name: "URL-encoded path should be caught by deny list",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/%61dmin"}}, // /admin encoded
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin"},
			},
			wantSteps:    0,
			wantRejected: 1,
		},
		{
			name: "partially encoded path should be caught",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/ad%6Din"}}, // /admin encoded
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin"},
			},
			wantSteps:    0,
			wantRejected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}
		})
	}
}

// M-4: Path traversal bypass tests
func TestValidate_PathTraversalBypass(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
	}{
		{
			name: "path traversal to admin should be caught",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/safe/../admin/delete"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin"},
			},
			wantSteps:    0,
			wantRejected: 1,
		},
		{
			name: "double dot traversal should be caught",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/public/../../admin"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
				DenyPaths:      []string{"/admin"},
			},
			wantSteps:    0,
			wantRejected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}
		})
	}
}

// H-4: URL field validation tests
func TestValidate_URLHostMismatch(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
		wantReason   string
	}{
		{
			name: "URL host mismatch should be rejected",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{
						Host:   "safe.com",
						Method: "GET",
						Path:   "/users",
						URL:    "https://evil.com/attack",
					}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"safe.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    0,
			wantRejected: 1,
			wantReason:   "URL does not match host/path fields",
		},
		{
			name: "URL path mismatch should be rejected",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{
						Host:   "api.example.com",
						Method: "GET",
						Path:   "/users",
						URL:    "https://api.example.com/admin/delete",
					}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    0,
			wantRejected: 1,
			wantReason:   "URL does not match host/path fields",
		},
		{
			name: "matching URL should be accepted",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{
						Host:   "api.example.com",
						Method: "GET",
						Path:   "/users",
						URL:    "https://api.example.com/users",
					}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"api.example.com"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    1,
			wantRejected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}

			if tt.wantReason != "" && len(rejected) > 0 {
				if rejected[0].Reason != tt.wantReason {
					t.Errorf("Validate() rejection reason = %q, want %q", rejected[0].Reason, tt.wantReason)
				}
			}
		})
	}
}

// M-1: Empty string validation tests
func TestValidate_EmptyStringInputs(t *testing.T) {
	tests := []struct {
		name         string
		plan         types.AttackPlan
		config       types.ValidatorConfig
		wantSteps    int
		wantRejected int
		wantReason   string
	}{
		{
			name: "empty host should be rejected",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "", Method: "GET", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    0,
			wantRejected: 1,
			wantReason:   "host cannot be empty",
		},
		{
			name: "empty method should be rejected",
			plan: types.AttackPlan{
				Steps: []types.AttackStep{
					{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "", Path: "/users"}},
				},
			},
			config: types.ValidatorConfig{
				AllowedHosts:   []string{"*"},
				AllowedMethods: []string{"*"},
			},
			wantSteps:    0,
			wantRejected: 1,
			wantReason:   "method cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, rejected := Validate(tt.plan, tt.config)

			if len(validated.Steps) != tt.wantSteps {
				t.Errorf("Validate() validated steps = %d, want %d", len(validated.Steps), tt.wantSteps)
			}

			if len(rejected) != tt.wantRejected {
				t.Errorf("Validate() rejected steps = %d, want %d", len(rejected), tt.wantRejected)
			}

			if tt.wantReason != "" && len(rejected) > 0 {
				if rejected[0].Reason != tt.wantReason {
					t.Errorf("Validate() rejection reason = %q, want %q", rejected[0].Reason, tt.wantReason)
				}
			}
		})
	}
}

// M-2: Truncated steps tracking tests
func TestValidate_TruncatedStepsTracking(t *testing.T) {
	plan := types.AttackPlan{
		Steps: []types.AttackStep{
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/1"}},
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/2"}},
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/3"}},
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/4"}},
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/5"}},
		},
	}
	config := types.ValidatorConfig{
		AllowedHosts:   []string{"*"},
		AllowedMethods: []string{"*"},
		MaxRequests:    2,
	}

	validated, rejected := Validate(plan, config)

	if len(validated.Steps) != 2 {
		t.Errorf("Validate() validated steps = %d, want 2", len(validated.Steps))
	}

	// Should have 3 rejections for truncated steps
	if len(rejected) != 3 {
		t.Errorf("Validate() rejected steps = %d, want 3 (for truncated steps)", len(rejected))
	}

	// All truncated rejections should have the same reason
	for i, r := range rejected {
		if r.Reason != "exceeded max requests budget" {
			t.Errorf("rejection[%d].Reason = %q, want %q", i, r.Reason, "exceeded max requests budget")
		}
	}
}

// M-3: Empty deny path handling tests
func TestValidate_EmptyDenyPath(t *testing.T) {
	plan := types.AttackPlan{
		Steps: []types.AttackStep{
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/users"}},
			{Endpoint: types.EndpointRef{Host: "api.example.com", Method: "GET", Path: "/admin"}},
		},
	}
	config := types.ValidatorConfig{
		AllowedHosts:   []string{"*"},
		AllowedMethods: []string{"*"},
		DenyPaths:      []string{"", "/admin"}, // Empty string should be ignored
	}

	validated, rejected := Validate(plan, config)

	// Only /admin should be rejected, not /users (empty string shouldn't match everything)
	if len(validated.Steps) != 1 {
		t.Errorf("Validate() validated steps = %d, want 1", len(validated.Steps))
	}

	if len(rejected) != 1 {
		t.Errorf("Validate() rejected steps = %d, want 1", len(rejected))
	}
}

// Nil steps handling test
func TestValidate_NilSteps(t *testing.T) {
	plan := types.AttackPlan{Steps: nil}
	config := types.ValidatorConfig{
		AllowedHosts:   []string{"*"},
		AllowedMethods: []string{"*"},
	}

	validated, rejected := Validate(plan, config)

	if len(validated.Steps) != 0 {
		t.Errorf("Validate() validated steps = %d, want 0", len(validated.Steps))
	}

	if len(rejected) != 0 {
		t.Errorf("Validate() rejected steps = %d, want 0", len(rejected))
	}
}
