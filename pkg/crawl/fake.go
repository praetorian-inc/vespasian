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

// FakeCrawler is a test double for [Crawler]. It returns a pre-configured list
// of requests and records invocation details so callers can verify the
// interaction. No network activity occurs.
//
// Usage:
//
//	fake := &FakeCrawler{Requests: []ObservedRequest{{URL: "https://example.com"}}}
//	got, err := fake.Crawl(ctx, "https://example.com/seed")
type FakeCrawler struct {
	// Requests is returned verbatim by every Crawl call.
	Requests []ObservedRequest
	// Err is returned verbatim by every Crawl call.
	Err error
	// Called is set to true after the first Crawl call.
	Called bool
	// LastURL is the targetURL passed to the most recent Crawl call.
	LastURL string
}

// Crawl records the invocation and returns the pre-configured Requests and Err.
func (f *FakeCrawler) Crawl(_ context.Context, targetURL string) ([]ObservedRequest, error) {
	f.Called = true
	f.LastURL = targetURL
	return f.Requests, f.Err
}
