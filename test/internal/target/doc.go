// Package target holds the listener setup shared by the live-test target servers.
//
// QUAL-007: rest-api, soap-service, concat-spa and forms-target each carried a
// byte-identical copy of the BIND_HOST resolution block plus its six-line
// explanatory comment, and the comment in three of them even said "Mirrors
// test/forms-target/main.go". SEC-BE-007 then needed the same server-timeout fix
// applied to every copy, which is the point at which four copies stopped being
// cheaper than one function.
//
// Consolidating also makes the security-relevant part assertable in ONE place.
// The loopback default is a security control (SEC-BE-015): these targets are
// unauthenticated by design, so binding every interface exposes them to the local
// network for the lifetime of a test run. test/setup-live-targets_test.sh Test 18b
// pins the default here and separately pins that each target delegates to it —
// previously it had to pin the same structure four times, and a target that drifted
// to its own inline bind would have been caught only if someone remembered to add a
// fifth copy of the assertion.
package target
