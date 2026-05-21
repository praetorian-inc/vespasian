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

// Package tnetenc is a minimal tnetstring encoder used only by tests and the
// fixture-generator utility. It mirrors the subset of the format that
// mitmproxy uses in HTTPFlow serialization so the importer's decoder can be
// round-trip tested and live-test fixtures can be regenerated from source.
//
// This is NOT a general-purpose tnetstring library. It lives under the
// module's internal/ tree so it is only available to vespasian packages
// (importer tests, the fixture generator under test/fixtures).
package tnetenc
