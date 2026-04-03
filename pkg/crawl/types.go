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

// ObservedRequest represents a captured HTTP request and its response.
type ObservedRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Body        []byte            `json:"body,omitempty"`
	Response    ObservedResponse  `json:"response"`
	Source      string            `json:"source"`
	Tag         string            `json:"tag,omitempty"`
	Attribute   string            `json:"attribute,omitempty"`
	PageURL     string            `json:"page_url,omitempty"`
}

// ObservedResponse represents a captured HTTP response.
type ObservedResponse struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Body        []byte            `json:"body,omitempty"`
}
