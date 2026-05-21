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

	"github.com/praetorian-inc/vespasian/pkg/crawl"
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
// Returns nil if the URL is invalid or not absolute.
// All values for a key are preserved (multi-value query params).
//
// The Scheme+Host check below is required because url.Parse is intentionally
// lenient: it accepts relative paths (e.g. "not a url") without error, setting
// Scheme and Host to "". Traffic imports represent real captured requests and
// must have absolute URLs, so we reject anything without both fields.
func extractQueryParams(urlStr string) map[string][]string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	queryValues := crawl.CapQueryValues(parsed.Query())
	if len(queryValues) == 0 {
		return nil
	}
	return queryValues
}
