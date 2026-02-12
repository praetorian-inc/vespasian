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

	"github.com/praetorian-inc/vespasian/pkg/generate/rest"
)

// Get returns a SpecGenerator for the given API type.
func Get(apiType string) (SpecGenerator, error) {
	switch apiType {
	case "rest":
		return &rest.OpenAPIGenerator{}, nil
	default:
		return nil, fmt.Errorf("unsupported API type: %q (supported: rest)", apiType)
	}
}
