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

import "fmt"

// Registry maps format names to their importers for CLI lookup.
var Registry = map[string]TrafficImporter{
	"burp":      &BurpImporter{},
	"har":       &HARImporter{},
	"mitmproxy": &MitmproxyImporter{},
}

// Get returns the importer for the given format name.
// Returns an error if the format is not supported.
func Get(format string) (TrafficImporter, error) {
	imp, ok := Registry[format]
	if !ok {
		return nil, fmt.Errorf("unsupported import format: %s (supported: burp, har, mitmproxy)", format)
	}
	return imp, nil
}

// SupportedFormats returns a list of all supported format names.
func SupportedFormats() []string {
	formats := make([]string, 0, len(Registry))
	for name := range Registry {
		formats = append(formats, name)
	}
	return formats
}
