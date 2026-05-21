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

package crawl

import (
	"encoding/json"
	"io"
	"net/url"
	"sort"
)

// MaxCaptureFileSize is the maximum allowed capture file size for deserialization (100 MB).
const MaxCaptureFileSize = 100 * 1024 * 1024

// MaxQueryParamValues caps the number of distinct values retained per
// query-parameter key. Defends against ?k=v1&k=v2&...&k=vN expansion
// attacks in untrusted capture files (Burp/HAR/mitmproxy imports). Mirrors
// the pkg/analyze/forms.go maxFormsPerBody/maxFieldsPerForm pattern.
const MaxQueryParamValues = 256

// MaxQueryParamKeys caps the number of distinct query-parameter keys retained
// per observation. Defends against ?k1=v&k2=v&...&kN=v expansion attacks in
// untrusted capture files. When the cap is exceeded, keys are kept in
// lexicographic order to keep the result deterministic across runs. Mirrors
// the pkg/analyze/forms.go maxFormsPerBody=1000 precedent.
const MaxQueryParamKeys = 512

// CapQueryValues truncates each per-key value slice in q to at most
// MaxQueryParamValues entries and drops excess keys beyond MaxQueryParamKeys,
// mutating q in place. Returns q for call-site convenience.
//
// When the cap is exceeded, the lex-smallest MaxQueryParamKeys keys are
// retained (deterministic across runs); the lex-largest excess keys are
// dropped. Excess values are also dropped silently.
func CapQueryValues(q url.Values) url.Values {
	// Truncate values within each key first.
	for k, vs := range q {
		if len(vs) > MaxQueryParamValues {
			q[k] = vs[:MaxQueryParamValues]
		}
	}
	// Then cap the number of distinct keys deterministically.
	if len(q) > MaxQueryParamKeys {
		// Sort key names lexicographically and drop everything past the cap.
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[MaxQueryParamKeys:] {
			delete(q, k)
		}
	}
	return q
}

// WriteCapture writes observed requests to a writer in JSON format.
func WriteCapture(w io.Writer, requests []ObservedRequest) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(requests)
}

// ReadCapture reads observed requests from a reader in JSON format.
func ReadCapture(r io.Reader) ([]ObservedRequest, error) {
	var requests []ObservedRequest
	decoder := json.NewDecoder(io.LimitReader(r, MaxCaptureFileSize))
	if err := decoder.Decode(&requests); err != nil {
		return nil, err
	}
	return requests, nil
}
