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
	"fmt"
	"net/url"
)

// maxPreviewLen caps how many bytes of an attacker-controlled string we embed
// into an error message, shared by the mitmproxy importer's previewString
// (for method/scheme) and the tnetstring decoder's payloadPreview (for
// element payloads) — both of which delegate to previewBytes below. Without
// the bound, a crafted `.mitm` file could write up to 64 MB into the
// operator's terminal or CI log before the importer aborts.
const maxPreviewLen = 64

// previewBytes is the single source of truth for attacker-payload preview
// formatting. It renders up to maxPreviewLen bytes of payload using %q
// quoting; longer inputs are truncated and annotated with the original byte
// length so operators still see "this was enormous" without pasting megabytes
// into a log. %q quoting escapes control bytes (ANSI escapes, NUL, etc.) so
// crafted method/scheme/payload content cannot clear the operator's terminal,
// recolor output, or poison log parsers when the error string is rendered.
// previewString and payloadPreview are type-convenience wrappers; modify the
// format here and they both track automatically.
func previewBytes(payload []byte) string {
	if len(payload) <= maxPreviewLen {
		return fmt.Sprintf("%q", payload)
	}
	return fmt.Sprintf("%q... (%d bytes total)", payload[:maxPreviewLen], len(payload))
}

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
