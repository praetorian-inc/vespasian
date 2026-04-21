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

// Package importer converts traffic captures from external tools into the
// vespasian [crawl.ObservedRequest] format. Each importer implements the
// [TrafficImporter] interface.
//
// Supported formats:
//   - Burp Suite XML: exported proxy history from Burp Suite.
//   - HAR 1.2: HTTP Archive files from browser dev tools or other proxies.
//   - mitmproxy: both the JSON export and the native tnetstring-based flow
//     dump produced by mitmproxy's "save flows" (`w`) command.
//
// Use [Get] to retrieve an importer by format name, and [SupportedFormats]
// to list all registered importers.
//
// Safety limits:
//
//   - File size: 500 MB hard cap (all formats).
//   - Entry count: each importer enforces a format-specific cap on the
//     number of records it will parse, to bound CPU on pathological inputs.
//     See the package-private caps (e.g. maxNativeFlows for the native
//     mitmproxy path) for current values. Pass [ImportOptions.MaxEntries]
//     through [ImportWithOptions] to apply a tighter caller-specified limit.
//   - Per-element size (native mitmproxy only): any single tnetstring
//     element is capped at 64 MB. This applies to request/response BODIES
//     as well as the flow dict itself. Captures containing a single
//     response body larger than 64 MB will be rejected even when the total
//     file is below the 500 MB cap. The error message surfaces this limit
//     so operators can tell the difference from the file-size cap.
//   - Callers can also apply a scope filter via [ImportOptions.Scope].
package importer
