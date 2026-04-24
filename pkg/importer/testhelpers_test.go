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

package importer

import (
	"strconv"
	"testing"
)

// buildElement builds a raw tnetstring element "<len>:<payload><marker>" by
// explicit byte concatenation — never via fmt.Sprintf("%d:%s,", len, payload),
// because %s on []byte re-interprets percent signs in the payload as format
// directives, silently corrupting binary bodies. The shared production
// encoder (tnetenc.encodeWithMarker) uses the same safe pattern.
//
// Why this is deliberately duplicated from tnetenc.encodeWithMarker:
// tnetenc.Encode selects the marker automatically based on Go type and only
// emits the four production markers (','/']'/'}'/'#'/'!'/'~'). Tests here
// need to craft edge-case elements — including malformed markers like ';'
// used for UTF-8-string typing, type-marker mismatches, and markers the
// encoder's type switch does not produce. Exporting encodeWithMarker would
// leak a test-only primitive into the production API surface; duplicating
// it in the test package keeps the production surface minimal while still
// sharing the %-unsafe byte-concat discipline. If you change the wire
// format (length-prefix syntax, marker position), update both locations.
func buildElement(payload []byte, marker byte) []byte {
	lenStr := strconv.Itoa(len(payload))
	out := make([]byte, 0, len(lenStr)+1+len(payload)+1)
	out = append(out, lenStr...)
	out = append(out, ':')
	out = append(out, payload...)
	out = append(out, marker)
	return out
}

// tnetBytesElement builds a raw tnetstring bytes element ("N:payload,").
// Unlike the shared encodeTnet helper, the result is deterministic and
// inspectable — length prefix + raw payload + marker byte, nothing else.
func tnetBytesElement(payload string) []byte {
	return buildElement([]byte(payload), ',')
}

// tnetStringElement builds a raw tnetstring UTF-8-string element ("N:payload;").
// The shared encoder emits everything as bytes (`,`); this helper is the only
// way to exercise the decoder's `;` path in integration tests.
func tnetStringElement(payload string) []byte {
	return buildElement([]byte(payload), ';')
}

// tnetListElement wraps already-encoded tnetstring elements into a list
// payload ("N:<elements>]"). Pass raw helper output in order.
func tnetListElement(elements ...[]byte) []byte {
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	return buildElement(body, ']')
}

// tnetDictElement wraps alternating key and value elements into a dict
// payload ("N:<k><v><k><v>...}"). Caller passes keys/values already encoded.
func tnetDictElement(keysAndValues ...[]byte) []byte {
	if len(keysAndValues)%2 != 0 {
		panic("tnetDictElement: odd number of key/value pieces")
	}
	var body []byte
	for _, e := range keysAndValues {
		body = append(body, e...)
	}
	return buildElement(body, '}')
}

// withTempCap temporarily sets *target to newValue and registers a Cleanup
// to restore it. Used by tests that need to exercise a rejection path of a
// package-private cap (e.g. maxTnetstringElements, maxNativeFlows) without
// constructing millions of elements.
//
// NOT PARALLEL-SAFE. These caps are package-private ints, not atomics.
// Any test that calls withTempCap MUST NOT call t.Parallel(), and no two
// callers may overlap. Today no test anywhere in the repo uses t.Parallel();
// if that ever changes, either promote these caps to sync/atomic values or
// gate the cap tests behind a serial subtest group.
func withTempCap(t *testing.T, target *int, newValue int) {
	t.Helper()
	orig := *target
	*target = newValue
	t.Cleanup(func() { *target = orig })
}
