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

import (
	"net"
	"net/http"
	"os"
	"time"
)

// ReadHeaderTimeout bounds how long a client may take to send request headers.
//
// SEC-BE-007: rest-api and soap-service previously called
// http.ListenAndServe with no server struct at all, and concat-spa set
// ReadHeaderTimeout: 0 explicitly, each carrying a "test server, timeouts not
// needed" rationale. That rationale held only while the targets were reachable
// solely over loopback. This PR adds and documents LIVE_TARGET_BIND_HOST=0.0.0.0
// for the devcontainer flow, so the same servers can now be asked to listen on
// every interface — at which point an unbounded header read is a trivial slow-loris
// against a developer's machine or a CI runner. forms-target already shipped this
// value; the other three now share it rather than each deciding again.
const ReadHeaderTimeout = 5 * time.Second

// Companion bounds to ReadHeaderTimeout, covering the whole-request and
// idle-connection cases it does not reach. See the note in Server().
const (
	ReadTimeout  = 30 * time.Second
	WriteTimeout = 30 * time.Second
	IdleTimeout  = 60 * time.Second
)

// Addr returns the address a live-test target should listen on.
//
// Binds loopback by DEFAULT. setup-live-targets.sh passes BIND_HOST explicitly and
// opts into a wider bind only when the devcontainer flow needs it (a crawler inside
// a container reaching the host via TEST_HOST). The unset path is the common one, so
// it is the one that must be safe.
func Addr(port string) string {
	host := os.Getenv("BIND_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// Server returns an http.Server bound to addr with the shared timeout applied.
//
// Deliberately a plain constructor rather than a configurable one: these are local
// test fixtures, and the only knob any of them ever needed is the address. A
// caller that eventually needs different timeouts should build its own
// http.Server rather than growing options here.
func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		// ReadHeaderTimeout alone bounds only the header read. With
		// LIVE_TARGET_BIND_HOST able to widen these unauthenticated fixtures off
		// loopback, a client that sends a complete header and then dribbles a body,
		// or that completes a request and holds the connection idle, was still
		// unbounded. Same threat, same fix, one line each. Generous relative to
		// what these fixtures serve (small local payloads), so they bound abuse
		// without capping any legitimate test.
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}
}
