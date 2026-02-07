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

// RunStrategies applies all probe strategies sequentially to the endpoints.
func RunStrategies(ctx context.Context, strategies []ProbeStrategy, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	result := endpoints

	for _, strategy := range strategies {
		enriched, err := strategy.Probe(ctx, result)
		if err != nil {
			return nil, err
		}
		result = enriched
	}

	return result, nil
}
