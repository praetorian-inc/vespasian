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

// OptionsProbe sends OPTIONS requests to discover supported HTTP methods.
type OptionsProbe struct{}

// Name returns the probe name.
func (p *OptionsProbe) Name() string {
	return "options"
}

// Probe enriches endpoints by sending OPTIONS requests.
func (p *OptionsProbe) Probe(_ context.Context, _ []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	return nil, errors.New("options probe: not implemented")
}
