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

import "testing"

func TestIsJSStaticSource(t *testing.T) {
	t.Parallel()
	cases := []struct {
		source string
		want   bool
	}{
		{SourceStaticJS, true},
		{SourceStaticJSSourcemap, true},
		{SourceStaticJSConcat, true},
		{"static:html", false},
		{"katana", false},
		{"", false},
		{"static:js-extra", false},
	}
	for _, tc := range cases {
		if got := IsJSStaticSource(tc.source); got != tc.want {
			t.Errorf("IsJSStaticSource(%q) = %v; want %v", tc.source, got, tc.want)
		}
	}
}

func TestAnyStaticSource(t *testing.T) {
	t.Parallel()

	empty := []ObservedRequest{}
	if AnyStaticSource(empty) {
		t.Error("AnyStaticSource(empty) = true; want false")
	}

	noneStatic := []ObservedRequest{
		{Source: "katana"},
		{Source: "static:html"},
	}
	if AnyStaticSource(noneStatic) {
		t.Error("AnyStaticSource(noneStatic) = true; want false")
	}

	withJS := []ObservedRequest{
		{Source: "katana"},
		{Source: SourceStaticJS},
	}
	if !AnyStaticSource(withJS) {
		t.Error("AnyStaticSource(withJS) = false; want true")
	}

	withSourcemap := []ObservedRequest{
		{Source: SourceStaticJSSourcemap},
	}
	if !AnyStaticSource(withSourcemap) {
		t.Error("AnyStaticSource(withSourcemap) = false; want true")
	}

	withConcat := []ObservedRequest{
		{Source: SourceStaticJSConcat},
	}
	if !AnyStaticSource(withConcat) {
		t.Error("AnyStaticSource(withConcat) = false; want true")
	}
}
