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
	"fmt"
	"testing"
)

// tnetBytesElement builds a raw tnetstring bytes element ("N:payload,").
// Unlike the shared encodeTnet helper, the result is deterministic and
// inspectable — length prefix + raw payload + marker byte, nothing else.
func tnetBytesElement(payload string) []byte {
	return []byte(fmt.Sprintf("%d:%s,", len(payload), payload))
}

// tnetStringElement builds a raw tnetstring UTF-8-string element ("N:payload;").
// The shared encoder emits everything as bytes (`,`); this helper is the only
// way to exercise the decoder's `;` path in integration tests.
func tnetStringElement(payload string) []byte {
	return []byte(fmt.Sprintf("%d:%s;", len(payload), payload))
}

// tnetListElement wraps already-encoded tnetstring elements into a list
// payload ("N:<elements>]"). Pass raw helper output in order.
func tnetListElement(elements ...[]byte) []byte {
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	return []byte(fmt.Sprintf("%d:%s]", len(body), body))
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
	return []byte(fmt.Sprintf("%d:%s}", len(body), body))
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
