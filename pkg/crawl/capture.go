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

// MaxCaptureFileSize caps capture-file deserialization.
const MaxCaptureFileSize = 100 * 1024 * 1024

// MaxQueryParamValues bounds ?k=v1&k=v2&...&k=vN expansion in untrusted imports.
// Unmeasured.
const MaxQueryParamValues = 256

// MaxQueryParamKeys bounds ?k1=v&k2=v&...&kN=v expansion. The lex-smallest keys
// are retained, so the result is deterministic across runs. Unmeasured.
const MaxQueryParamKeys = 512

// CapQueryValues truncates values and drops excess keys in place, keeping the
// lex-smallest. Returns q for convenience. Excess is dropped silently.
func CapQueryValues(q url.Values) url.Values {
	for k, vs := range q {
		if len(vs) > MaxQueryParamValues {
			q[k] = vs[:MaxQueryParamValues]
		}
	}
	if len(q) > MaxQueryParamKeys {
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

// WriteCapture writes requests as indented JSON.
func WriteCapture(w io.Writer, requests []ObservedRequest) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(requests)
}

// ReadCapture reads requests from JSON, bounded by MaxCaptureFileSize.
func ReadCapture(r io.Reader) ([]ObservedRequest, error) {
	var requests []ObservedRequest
	decoder := json.NewDecoder(io.LimitReader(r, MaxCaptureFileSize))
	if err := decoder.Decode(&requests); err != nil {
		return nil, err
	}
	return requests, nil
}
