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
	"context"
	"errors"
	"strings"
	"testing"
)

// TestRodCrawler_NegativeDepthRejected exercises the validateCrawlInputs path
// in RodCrawler.Crawl with a negative Depth value. No Chrome is launched
// because the validation error is returned before the browser-launch code.
func TestRodCrawler_NegativeDepthRejected(t *testing.T) {
	c := &RodCrawler{opts: CrawlerOptions{Depth: -1}}
	_, err := c.Crawl(context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("expected error for negative depth, got nil")
	}
	if !strings.Contains(err.Error(), "depth must be non-negative") {
		t.Errorf("error = %q, want 'depth must be non-negative'", err.Error())
	}
}

// TestRodCrawler_MalformedURLRejected exercises the validateCrawlInputs path
// for a malformed target URL. No Chrome is launched.
func TestRodCrawler_MalformedURLRejected(t *testing.T) {
	malformed := []string{
		"",
		"not-a-url",
		"ftp://example.com",
		"file:///etc/passwd",
	}
	for _, u := range malformed {
		t.Run(u, func(t *testing.T) {
			c := &RodCrawler{opts: CrawlerOptions{}}
			_, err := c.Crawl(context.Background(), u)
			if err == nil {
				t.Fatalf("expected error for URL %q, got nil", u)
			}
			if !strings.Contains(err.Error(), "invalid target URL") {
				t.Errorf("error = %q, want 'invalid target URL'", err.Error())
			}
		})
	}
}

// TestRodCrawler_CanceledContextReturnedEarly verifies that a pre-canceled
// context causes RodCrawler.Crawl to return ctx.Err() (context.Canceled)
// before launching a browser. No Chrome is launched.
func TestRodCrawler_CanceledContextReturnedEarly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled

	c := &RodCrawler{opts: CrawlerOptions{}}
	_, err := c.Crawl(ctx, "https://example.com")
	if err == nil {
		t.Fatal("expected error for already-canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}
