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

// Package mediatype provides shared helpers for parsing HTTP headers. Both
// pkg/classify and pkg/generate/rest need the same media-type canonicalization
// and case-insensitive header lookup, and they cannot import each other
// directly (generate/rest importing classify would be fine, but the reverse
// would create a cycle), so the helpers live in their own leaf package.
//
// Base canonicalizes a Content-Type value to its lowercased media type with any
// charset/parameter suffix stripped. Header performs a deterministic,
// case-insensitive lookup of a named header, tolerating the casing differences
// between browser-captured (lowercased) and Burp/HAR-imported (title-cased)
// headers.
package mediatype
