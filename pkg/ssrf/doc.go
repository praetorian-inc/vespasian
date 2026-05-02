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

// Package ssrf provides URL validation and SSRF-safe dialing primitives.
//
// It rejects requests to private/loopback/link-local IP ranges and includes
// a connect-time validator that defeats DNS rebinding by re-resolving the
// hostname when the dial happens.
//
// The package is intentionally a leaf — it depends only on the standard
// library — so it can be imported by any other Vespasian package that
// needs to make outbound HTTP requests without creating an import cycle.
//
// Key entry points:
//   - [ValidateURL] checks a URL up-front and returns a descriptive error
//     when it should not be probed.
//   - [SafeDialContext] is a net.Dialer-compatible DialContext that runs the
//     blocklist check at connect time so transports get protection without
//     additional plumbing.
package ssrf
