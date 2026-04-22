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

import "net/url"

// maxPreviewLen caps how many bytes of an attacker-controlled string we embed
// into an error message, shared by the mitmproxy importer's previewString
// (for method/scheme) and the tnetstring decoder's payloadPreview (for
// element payloads). Without the bound, a crafted `.mitm` file could write
// up to 64 MB into the operator's terminal or CI log before the importer
// aborts. The two helpers keep separate signatures (string vs []byte) but
// both use %q quoting so control bytes are Go-escaped rather than rendered
// verbatim — a crafted ANSI sequence in method/scheme cannot recolor output
// or clear the screen when the error string is printed.
const maxPreviewLen = 64

// extractQueryParams parses query parameters from a URL string.
// Returns nil if the URL has no query parameters or is invalid.
// For duplicate keys, only the first value is returned.
//
// Note: Validates URL has scheme and host (absolute URL requirement per B3).
// url.Parse is lenient and accepts relative paths like "not a url" without error.
// We require absolute URLs for traffic imports since they represent real requests.
func extractQueryParams(urlStr string) map[string]string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	// Validate absolute URL: must have scheme and host (B3 fix)
	// url.Parse accepts "not a url" as a relative path without error
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}

	queryValues := parsed.Query()
	if len(queryValues) == 0 {
		return nil
	}

	params := make(map[string]string)
	for key, values := range queryValues {
		if len(values) > 0 {
			params[key] = values[0] // Take first value for duplicate keys
		}
	}

	return params
}
