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

// Package crawl drives a headless Chrome browser via [Katana] to capture HTTP
// traffic from web applications. It intercepts all outbound requests—including
// XHR, fetch, and dynamically constructed calls from JavaScript—and records
// them as [ObservedRequest] values.
//
// The package also defines the capture file format: a JSON array of
// ObservedRequest structs that serves as the interchange format between the
// capture stage (crawl or import) and the generation stage.
//
// Key types:
//   - [Crawler] orchestrates a headless browser crawl with configurable depth,
//     page limits, timeouts, and scope restrictions.
//   - [BrowserManager] manages Chrome process lifecycle, including proxy
//     configuration and graceful shutdown.
//   - [ObservedRequest] and [ObservedResponse] represent captured HTTP traffic.
//
// [Katana]: https://github.com/projectdiscovery/katana
package crawl
