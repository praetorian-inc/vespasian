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

// Package probe provides strategies for enriching discovered API endpoints.
package probe

import (
	"context"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// ProbeStrategy enriches classified requests with additional information.
//
//nolint:revive // ProbeStrategy name is intentional per specification
type ProbeStrategy interface {
	// Name returns the strategy name (e.g., "options", "schema").
	Name() string

	// Probe enriches the classified requests with additional data.
	Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error)
}

// ProbeError records a failed probe strategy.
//
//nolint:revive // ProbeError name is intentional per specification
type ProbeError struct {
	Strategy string
	Err      error
}

// Error returns a formatted error string.
func (e *ProbeError) Error() string {
	return e.Strategy + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ProbeError) Unwrap() error {
	return e.Err
}

// RunStrategies applies all probe strategies sequentially to the endpoints.
// Failed strategies are isolated — errors are collected but do not prevent
// subsequent strategies from executing. Returns the enriched endpoints and
// any errors encountered.
func RunStrategies(ctx context.Context, strategies []ProbeStrategy, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, []error) {
	result := endpoints
	var errs []error

	for _, strategy := range strategies {
		if err := ctx.Err(); err != nil {
			errs = append(errs, &ProbeError{Strategy: strategy.Name(), Err: err})
			continue
		}

		enriched, err := strategy.Probe(ctx, result)
		if err != nil {
			errs = append(errs, &ProbeError{Strategy: strategy.Name(), Err: err})
			continue
		}
		result = enriched
	}

	return result, errs
}
