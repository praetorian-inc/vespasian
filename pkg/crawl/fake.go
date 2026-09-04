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

import "context"

// FakeCrawler is a [Crawler] test double: it returns Requests verbatim, records
// the invocation, and never touches the network.
type FakeCrawler struct {
	Requests []ObservedRequest
	Err      error
	Called   bool
	LastURL  string // targetURL from the most recent Crawl
}

// Crawl records the invocation and returns Requests and Err.
func (f *FakeCrawler) Crawl(_ context.Context, targetURL string) ([]ObservedRequest, error) {
	f.Called = true
	f.LastURL = targetURL
	return f.Requests, f.Err
}
