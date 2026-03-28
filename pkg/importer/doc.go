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
//   - mitmproxy: flow dumps from mitmproxy's JSON export.
//
// Use [Get] to retrieve an importer by format name, and [SupportedFormats]
// to list all registered importers.
//
// Safety limits: files larger than 500 MB or containing more than 100,000
// entries are rejected to prevent resource exhaustion.
package importer
