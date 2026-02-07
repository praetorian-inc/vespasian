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

// Package classify provides API classification for observed HTTP requests.
package classify

import (
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ClassifiedRequest extends ObservedRequest with classification metadata.
type ClassifiedRequest struct {
	crawl.ObservedRequest
	IsAPI      bool    `json:"is_api"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	APIType    string  `json:"api_type"`
}
