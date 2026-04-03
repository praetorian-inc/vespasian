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
	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// SpecGenerator generates API specifications from classified requests.
type SpecGenerator interface {
	// APIType returns the API type this generator supports (e.g., "rest", "graphql").
	APIType() string

	// Generate produces an API specification from the endpoints.
	Generate(endpoints []classify.ClassifiedRequest) ([]byte, error)

	// DefaultExtension returns the default file extension for the generated spec.
	DefaultExtension() string
}
