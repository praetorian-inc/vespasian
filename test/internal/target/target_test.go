package target

import (
	"net/http"
	"testing"
	"time"
)

// TEST-009 / TEST-016. The loopback default and the header-read bound are
// security controls (SEC-BE-015, SEC-BE-007), and until now the only thing
// pinning them was a source-text grep in test/setup-live-targets_test.sh
// (Test 18b). That grep was defeated twice: its ReadHeaderTimeout pattern
// `[0-9]+ \* time\.Second` matches `0 * time.Second`, the exact value it
// claims to forbid, and its comment-stripper removes only `//` lines, so the
// matched structure can sit inside a `/* */` block while the real code differs.
//
// These are behavioural checks against the real functions. They cannot be
// satisfied by moving text into a comment, by re-implementing the logic
// inline, or by inverting a comparison, because they call the code and assert
// on what it returns. They need no build tag, no fixture and no network, so
// they run in the ordinary `make test` on every PR — unlike the shell guard,
// which lives in a CI job that installs no Go.

func TestAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv("BIND_HOST", "")

	got := Addr("8080")
	if want := "127.0.0.1:8080"; got != want {
		t.Fatalf("Addr with BIND_HOST unset = %q, want %q — the default bind is a security control: these targets are unauthenticated, so a wildcard default exposes them to the local network for the lifetime of a test run", got, want)
	}
}

func TestAddrHonoursBindHostOverride(t *testing.T) {
	t.Setenv("BIND_HOST", "0.0.0.0")

	got := Addr("8080")
	if want := "0.0.0.0:8080"; got != want {
		t.Fatalf("Addr with BIND_HOST=0.0.0.0 = %q, want %q — the documented LIVE_TARGET_BIND_HOST opt-in must still work", got, want)
	}
}

// The override must be honoured only when it is actually set. An implementation
// that reads the variable but ignores it, or one that inverts the emptiness
// test, passes TestAddrDefaultsToLoopback or the override test but not both.
func TestAddrEmptyAndSetAreDistinct(t *testing.T) {
	t.Setenv("BIND_HOST", "")
	unset := Addr("9999")

	t.Setenv("BIND_HOST", "192.0.2.1")
	set := Addr("9999")

	if unset == set {
		t.Fatalf("Addr returned %q both with BIND_HOST unset and with BIND_HOST=192.0.2.1 — the override is being ignored, or the emptiness test is inverted", unset)
	}
}

func TestAddrBracketsIPv6(t *testing.T) {
	t.Setenv("BIND_HOST", "::1")

	got := Addr("8080")
	if want := "[::1]:8080"; got != want {
		t.Fatalf("Addr with an IPv6 BIND_HOST = %q, want %q — net.JoinHostPort must be used rather than string concatenation", got, want)
	}
}

// The assertion the shell guard could not make. A literal `0 * time.Second`
// satisfies its regex; it does not satisfy this.
func TestServerAppliesNonZeroReadHeaderTimeout(t *testing.T) {
	srv := Server("127.0.0.1:8080", http.NewServeMux())

	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("Server().ReadHeaderTimeout = %v, want a positive duration — an unbounded header read is a slow-loris against a developer machine or CI runner once LIVE_TARGET_BIND_HOST widens the bind", srv.ReadHeaderTimeout)
	}
	if srv.ReadHeaderTimeout != ReadHeaderTimeout {
		t.Fatalf("Server().ReadHeaderTimeout = %v, want the shared constant %v — a target that hardcodes its own value has drifted from the one the other three share", srv.ReadHeaderTimeout, ReadHeaderTimeout)
	}
}

func TestReadHeaderTimeoutConstantIsSane(t *testing.T) {
	if ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want a positive duration", ReadHeaderTimeout)
	}
	// A bound so long it cannot fire is the same defect as no bound at all.
	if ReadHeaderTimeout > time.Minute {
		t.Fatalf("ReadHeaderTimeout = %v, want at most a minute — a bound this long does not meaningfully cap a slow header read", ReadHeaderTimeout)
	}
}

func TestServerCarriesAddrAndHandler(t *testing.T) {
	mux := http.NewServeMux()
	srv := Server("127.0.0.1:8081", mux)

	if srv.Addr != "127.0.0.1:8081" {
		t.Errorf("Server().Addr = %q, want %q", srv.Addr, "127.0.0.1:8081")
	}
	if srv.Handler != http.Handler(mux) {
		t.Errorf("Server().Handler is not the handler passed in")
	}
}
