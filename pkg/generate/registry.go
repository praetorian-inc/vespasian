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

package generate

import (
	"fmt"

	"github.com/praetorian-inc/vespasian/pkg/generate/graphql"
	"github.com/praetorian-inc/vespasian/pkg/generate/rest"
	"github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
)

// Options configures spec generation. Only the REST/OpenAPI generator
// consumes these today; wsdl and graphql ignore them.
type Options struct {
	// MergeSlugs enables observation-based slug merging in REST path normalization.
	MergeSlugs bool
	// SlugThreshold is the minimum distinct values at a path position before
	// merging; clamped to >=2 downstream. Ignored unless MergeSlugs is set.
	SlugThreshold int
}

// Get returns a SpecGenerator for the given API type using default options.
func Get(apiType string) (SpecGenerator, error) {
	return GetWithOptions(apiType, Options{})
}

// GetWithOptions returns a SpecGenerator for the given API type configured
// with the supplied options.
func GetWithOptions(apiType string, opts Options) (SpecGenerator, error) {
	switch apiType {
	case "rest":
		return &rest.OpenAPIGenerator{MergeSlugs: opts.MergeSlugs, SlugThreshold: opts.SlugThreshold}, nil
	case "wsdl":
		return &wsdl.Generator{}, nil
	case "graphql":
		return &graphql.Generator{}, nil
	default:
		return nil, fmt.Errorf("unsupported API type: %q (supported: rest, wsdl, graphql)", apiType)
	}
}
