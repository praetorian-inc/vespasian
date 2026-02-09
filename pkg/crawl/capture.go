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
)

const MaxCaptureFileSize = 100 * 1024 * 1024 // 100 MB

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
