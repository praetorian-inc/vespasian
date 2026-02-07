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

package probe

import (
	"context"
	"errors"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// SchemaProbe attempts to discover schema information from endpoints.
type SchemaProbe struct{}

// Name returns the probe name.
func (p *SchemaProbe) Name() string {
	return "schema"
}

// Probe enriches endpoints with schema information.
func (p *SchemaProbe) Probe(_ context.Context, _ []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	return nil, errors.New("schema probe: not implemented")
}
