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

package importer

import (
	"errors"
	"io"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// HARImporter converts HAR (HTTP Archive) files to ObservedRequest format.
type HARImporter struct{}

// Name returns the importer name.
func (i *HARImporter) Name() string {
	return "har"
}

// Import reads HAR JSON and converts to ObservedRequest format.
func (i *HARImporter) Import(_ io.Reader) ([]crawl.ObservedRequest, error) {
	return nil, errors.New("har import: not implemented")
}
