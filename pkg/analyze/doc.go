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

// Package analyze runs after traffic capture and before classification. It
// performs static analysis of captured response bodies to surface additional
// API endpoints and parameters that were not exercised by the capture itself.
//
// The current analyzer, ExtractForms, parses HTML response bodies with the
// golang.org/x/net/html tokenizer and emits one synthetic ObservedRequest per
// <form> element found. This complements pkg/crawl's DOM-based extractor
// (Source="form") which runs only during live headless crawling: static
// analysis also benefits traffic imported from Burp, HAR, or mitmproxy.
//
// Synthetic requests are tagged with Source="static:html" so downstream
// consumers can distinguish them from live captures.
package analyze
