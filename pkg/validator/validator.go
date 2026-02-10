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

// Package validator enforces safety constraints on attack plans.
package validator

import (
	"net/url"
	"path"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/types"
)

// Rejection represents a step that was rejected during validation,
// along with the reason for rejection.
type Rejection struct {
	Step   types.AttackStep
	Reason string
}

// Validate enforces safety constraints on an attack plan, returning a filtered
// plan containing only valid steps and a list of rejected steps with reasons.
//
// Validation rules are applied in order:
//  0. Empty field check: Host and Method must not be empty
//  1. URL consistency check: If URL is provided, it must match Host and Path fields
//  2. Host check: Step's endpoint host must be in AllowedHosts (unless AllowedHosts contains "*")
//  3. Method check: Step's endpoint method must be in AllowedMethods (unless AllowedMethods contains "*")
//  4. Deny path check: Step's endpoint path must NOT have any DenyPaths entry as a prefix
//  5. MaxRequests budget: After filtering, truncate remaining steps to MaxRequests (if MaxRequests > 0)
func Validate(plan types.AttackPlan, config types.ValidatorConfig) (types.AttackPlan, []Rejection) {
	var validSteps []types.AttackStep
	var rejections []Rejection

	// Apply validation rules to each step
	for _, step := range plan.Steps {
		rejected := false
		var reason string

		// Rule 0: Empty field validation
		if step.Endpoint.Host == "" {
			rejected = true
			reason = "host cannot be empty"
		}

		if !rejected && step.Endpoint.Method == "" {
			rejected = true
			reason = "method cannot be empty"
		}

		// Rule 1: URL consistency check
		if !rejected && step.Endpoint.URL != "" {
			if !isURLConsistent(step.Endpoint.URL, step.Endpoint.Host, step.Endpoint.Path) {
				rejected = true
				reason = "URL does not match host/path fields"
			}
		}

		// Rule 2: Host check
		if !rejected && !isHostAllowed(step.Endpoint.Host, config.AllowedHosts) {
			rejected = true
			reason = "host not in allowed list"
		}

		// Rule 3: Method check (only if not already rejected)
		if !rejected && !isMethodAllowed(step.Endpoint.Method, config.AllowedMethods) {
			rejected = true
			reason = "method not in allowed list"
		}

		// Rule 4: Deny path check (only if not already rejected)
		if !rejected && isDeniedPath(step.Endpoint.Path, config.DenyPaths) {
			rejected = true
			reason = "path matches deny list"
		}

		if rejected {
			rejections = append(rejections, Rejection{
				Step:   step,
				Reason: reason,
			})
		} else {
			validSteps = append(validSteps, step)
		}
	}

	// Rule 5: MaxRequests budget - truncate if needed and track truncated steps
	if config.MaxRequests > 0 && len(validSteps) > config.MaxRequests {
		// Add rejections for truncated steps
		for _, step := range validSteps[config.MaxRequests:] {
			rejections = append(rejections, Rejection{
				Step:   step,
				Reason: "exceeded max requests budget",
			})
		}
		validSteps = validSteps[:config.MaxRequests]
	}

	return types.AttackPlan{Steps: validSteps}, rejections
}

// isURLConsistent checks if the provided URL matches the Host and Path fields.
// Returns true if URL is consistent with Host and Path, false otherwise.
func isURLConsistent(urlStr, host, path string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Normalize host comparison (case-insensitive)
	urlHost := strings.ToLower(parsedURL.Host)
	expectedHost := strings.ToLower(host)

	if urlHost != expectedHost {
		return false
	}

	// Path must match exactly
	if parsedURL.Path != path {
		return false
	}

	return true
}

// isHostAllowed checks if a host is in the allowed list (case-insensitive).
// Returns true if AllowedHosts contains "*" (wildcard) or the specific host.
// Returns false if AllowedHosts is empty or doesn't contain the host.
func isHostAllowed(host string, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return false
	}

	// Normalize host to lowercase for case-insensitive comparison
	normalizedHost := strings.ToLower(host)

	for _, allowed := range allowedHosts {
		if allowed == "*" {
			return true
		}
		// Case-insensitive comparison
		if strings.ToLower(allowed) == normalizedHost {
			return true
		}
	}

	return false
}

// isMethodAllowed checks if an HTTP method is in the allowed list (case-insensitive).
// Returns true if AllowedMethods contains "*" (wildcard) or the specific method.
// Returns false if AllowedMethods is empty or doesn't contain the method.
func isMethodAllowed(method string, allowedMethods []string) bool {
	if len(allowedMethods) == 0 {
		return false
	}

	// Normalize method to uppercase for case-insensitive comparison
	normalizedMethod := strings.ToUpper(method)

	for _, allowed := range allowedMethods {
		if allowed == "*" {
			return true
		}
		// Case-insensitive comparison
		if strings.ToUpper(allowed) == normalizedMethod {
			return true
		}
	}

	return false
}

// isDeniedPath checks if a path matches any entry in the deny list (prefix match).
// Returns true if the path starts with any DenyPaths entry.
// Returns false if DenyPaths is empty or no prefix matches.
// Handles URL encoding and path traversal by normalizing paths before comparison.
func isDeniedPath(pathStr string, denyPaths []string) bool {
	// Decode URL encoding
	decodedPath, err := url.PathUnescape(pathStr)
	if err != nil {
		// If decoding fails, use original path
		decodedPath = pathStr
	}

	// Clean path to resolve .. and . segments (path traversal prevention)
	cleanedPath := path.Clean(decodedPath)

	for _, denied := range denyPaths {
		// Skip empty deny paths (would match everything)
		if denied == "" {
			continue
		}

		if strings.HasPrefix(cleanedPath, denied) {
			return true
		}
	}

	return false
}
