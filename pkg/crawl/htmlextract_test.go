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
	"strings"
	"testing"
)

func TestExtractFromHTML_UsesLinkSelectors(t *testing.T) {
	body := []byte(`<html><body>
      <a href="/page1">x</a>
      <form action="/submit"></form>
      <iframe src="/frame"></iframe>
      <a href="/bundle.js">js</a>
      <a href="https://other.example/x">off</a>
    </body></html>`)
	got := extractFromHTML(body, "https://e.com/")
	want := map[string]bool{
		"https://e.com/page1":      true,
		"https://e.com/submit":     true,
		"https://e.com/frame":      true,
		"https://other.example/x": true, // scope is enforced by frontier, not here
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected/duplicate link: %s", u)
		}
		delete(want, u)
	}
	if len(want) != 0 {
		t.Errorf("missing links: %v", want)
	}
	for _, u := range got {
		if strings.HasSuffix(u, ".js") {
			t.Errorf(".js bundle not filtered: %s", u)
		}
	}
}

func TestExtractInlineScripts_RunsJsluice(t *testing.T) {
	body := []byte(`<html><script>fetch("/api/inline")</script><script src="/x.js"></script></html>`)
	got := extractInlineScripts(body)
	found := false
	for _, e := range got {
		if strings.Contains(e.URL, "/api/inline") {
			found = true
		}
	}
	if !found {
		t.Errorf("inline jsluice URL not found in %v", got)
	}
}
