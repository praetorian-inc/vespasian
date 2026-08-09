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

package httpx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyConfig carries a parsed, validated proxy target and its TLS posture. The
// zero value (URL == nil) means "no proxy", so structs and params that embed it
// default to today's unproxied behavior without any caller change.
type ProxyConfig struct {
	URL      *url.URL // scheme http|https|socks5, host required, no embedded creds
	Insecure bool     // --proxy-insecure; honored ONLY for http/https (MITM); ignored for socks5
}

// Enabled reports whether a proxy target is configured.
func (p ProxyConfig) Enabled() bool { return p.URL != nil }

// NoFollowRedirects is the shared http.Client.CheckRedirect policy for every
// proxy-aware stage (probe, WSDL discovery, JS-replay, jsstatic sourcemap): it
// returns http.ErrUseLastResponse so the client surfaces the 3xx response itself
// instead of following it. Following a redirect would let a same-host URL that
// 302s to another host slip past each stage's SSRF/same-origin checks, so every
// stage refuses redirects identically. Pass it to BuildHTTPClient's checkRedirect
// argument or assign it to http.Client.CheckRedirect.
func NoFollowRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// BuildHTTPClient returns an *http.Client whose transport routes through p.URL,
// mirroring pkg/crawl.newHTTPClient's proxy branch:
//
//   - clones http.DefaultTransport (keeps keep-alive / HTTP2 / idle tunings)
//   - sets Transport.Proxy = http.ProxyURL(p.URL) (stdlib tunnels http/https/socks5)
//   - clears Transport.DialContext: this drops the cloned DefaultTransport's plain
//     30s dial timeout (a net.Dialer bound, not an SSRF pin — there was never one on
//     the proxy connection since we dial the proxy, not the target); the connect
//     phase is instead bounded by the caller's Client.Timeout (≤15s everywhere).
//     URL-level scope stays the caller's job
//   - sets TLSClientConfig.InsecureSkipVerify only when p.Insecure && the proxy
//     scheme is http/https (an intercepting MITM proxy presenting its own CA).
//     socks5 is a transparent TCP tunnel, so verification always stays on for it.
//
// Precondition: p.Enabled(). Callers gate on p.Enabled() and keep their existing
// non-proxy builder for the unproxied path (zero regression to proven paths).
//
// Cross-reference: pkg/crawl.newHTTPClient's proxy branch encodes the SAME
// security-sensitive TLS-verify gate (InsecureSkipVerify only when
// Insecure && scheme ∈ {http,https}); keep the two in lockstep if that gate ever
// changes. They are intentionally NOT merged: this builder additionally pins
// MinVersion TLS 1.2 and clears DialContext, whereas crawl keeps DefaultTransport's
// dialer for the proxy connection (its tests assert a non-nil proxy-branch
// DialContext). That DialContext difference is a dial-timeout choice, not a security
// control — neither path pins the proxy dial — so delegating here would change
// crawl's proven dial-timeout behavior (its 30s dialer vs this builder's reliance on
// the caller's tighter Client.Timeout).
func BuildHTTPClient(p ProxyConfig, timeout time.Duration,
	checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Defensive: stdlib always sets *http.Transport, but fall back to a
		// fresh transport rather than panic if a future runtime changes that.
		base = &http.Transport{}
	}
	t := base.Clone()
	// Contract is p.Enabled(); every caller gates on it. Defensive fail-safe: if
	// ever called with a disabled proxy, return a non-proxied client that KEEPS the
	// cloned default dialer (its 30s bound) rather than one that neither proxies nor
	// dials. A cloned DefaultTransport carries Proxy=ProxyFromEnvironment, so clear it
	// too, since the disabled path must not silently route through an env proxy. [SEC-BE-002]
	if !p.Enabled() {
		t.Proxy = nil
		return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: checkRedirect}
	}
	t.Proxy = http.ProxyURL(p.URL)
	// Drop the cloned default dialer's DialContext: this removes DefaultTransport's
	// plain 30s dial timeout (a net.Dialer bound), NOT an SSRF pin — there was never
	// one on the proxy connection (we dial the proxy, not the target). The connect
	// phase is instead bounded by the caller's Client.Timeout, which is ≤15s
	// everywhere (tighter than the 30s we drop).
	t.DialContext = nil
	// TLS verification stays on by default. It is disabled only when the operator
	// explicitly opts in via --proxy-insecure AND the proxy is http/https: an
	// intercepting proxy (Burp, mitmproxy) terminates TLS and presents its own CA,
	// so verification must be off for that substitute certificate to be accepted.
	// socks5 tunnels TCP transparently — TLS runs directly against the real target
	// through the tunnel — so verification is always kept for socks5.
	if p.Insecure && (p.URL.Scheme == "http" || p.URL.Scheme == "https") {
		// #nosec G402 -- opt-in via --proxy-insecure for http/https proxy MITM; socks5 always verifies (see package doc)
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport:     t,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}
}

// ProxyDialer returns a dial function that establishes a raw TCP connection to
// the target THROUGH p.URL, for callers that cannot use http.Transport.Proxy
// (the gRPC reflection probe). http/https proxies use an HTTP CONNECT tunnel;
// socks5 uses golang.org/x/net/proxy. The proxy itself is dialed with a plain
// dialer (we contact the proxy, not the target), so it is not SSRF-pinned —
// consistent with the http.Transport proxy path. The returned conn is plaintext
// TCP; the caller layers TLS (e.g. gRPC transport credentials) on top. Returns
// an error for an unsupported scheme (unreachable after crawl.ValidateProxyAddr).
func ProxyDialer(p ProxyConfig) (func(ctx context.Context, addr string) (net.Conn, error), error) {
	if p.URL == nil {
		return nil, fmt.Errorf("httpx: proxy dialer requires a non-nil proxy URL")
	}
	switch p.URL.Scheme {
	case "http", "https":
		return connectDialer(p), nil
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", p.URL.Host, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("httpx: building socks5 dialer: %w", err)
		}
		ctxDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("httpx: socks5 dialer does not support context dialing")
		}
		return func(ctx context.Context, addr string) (net.Conn, error) {
			return ctxDialer.DialContext(ctx, "tcp", addr)
		}, nil
	default:
		return nil, fmt.Errorf("httpx: unsupported proxy scheme %q", p.URL.Scheme)
	}
}

// =============================================================================
// Helpers
// =============================================================================

// connectDialer returns a dial function that tunnels to addr through an
// http/https CONNECT proxy. For an https-scheme proxy the connection to the
// proxy is itself TLS (verified unless p.Insecure); the CONNECT payload and
// tunneled bytes are plaintext to the caller.
func connectDialer(p ProxyConfig) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		// Reject CR/LF in the target before it reaches the CONNECT request line:
		// otherwise an attacker-influenced addr could smuggle extra header lines
		// or a second request into the bytes written to the proxy. net.SplitHostPort
		// does NOT catch this (the payload splits cleanly), so check explicitly.
		if strings.ContainsAny(addr, "\r\n") {
			return nil, fmt.Errorf("httpx: invalid proxy target address %q: contains CR or LF", addr)
		}
		// net.SplitHostPort requires a single top-level host:port split: it
		// validates bracket syntax and colon count, so it rejects an absolute-form
		// URI or a multi-colon payload (e.g. "http://x" or "a:b:c"). It does NOT
		// validate host cleanliness or that the port is numeric — it accepts
		// "foo bar:80" and "example.com:80/path" — so this is a shape check that
		// addr is a lone host:port pair, NOT a "clean target" check. The CR/LF
		// denylist immediately above is the injection guard that keeps extra header
		// lines / request smuggling out of the CONNECT request line and Host header.
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("httpx: invalid proxy target address %q: %w", addr, err)
		}

		conn, err := dialProxy(ctx, p)
		if err != nil {
			return nil, err
		}

		// Interruptible handshake: a cancel-only context (context.WithCancel, no
		// deadline) has no Deadline() for SetDeadline to bound, so without this a
		// stalled Write/ReadResponse against a silent proxy would hang past
		// cancellation. A watcher goroutine closes the conn on ctx.Done() to unblock
		// an IN-FLIGHT handshake. It is made mutually exclusive with the success
		// handoff by mu+handshakeDone: the mainline marks the handshake complete
		// (under mu) BEFORE close(watcherStopped), so once that flag is set the
		// watcher can no longer close the conn. The guarantee is therefore precise —
		// the watcher interrupts only a still-running handshake, never the conn
		// returned to the caller. A cancel that races a just-completed handshake is
		// handled explicitly below: we return ctx.Err() rather than a live-but-closed
		// conn (never success + a closed conn). SetDeadline (inside connectHandshake)
		// still gives clean deadline errors when the caller's context has a deadline.
		var mu sync.Mutex
		handshakeDone := false
		watcherStopped := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				mu.Lock()
				if !handshakeDone {
					// #nosec G104 -- best-effort interrupt of the in-flight handshake; the dial fails below.
					conn.Close() //nolint:errcheck,gosec // unblock the in-flight handshake on cancellation
				}
				mu.Unlock()
			case <-watcherStopped:
			}
		}()

		br, handshakeErr := connectHandshake(ctx, conn, addr)

		mu.Lock()
		handshakeDone = true
		mu.Unlock()
		close(watcherStopped)

		return resolveConnectResult(ctx, conn, br, handshakeErr)
	}
}

// resolveConnectResult decides what connectDialer returns once the CONNECT
// handshake has finished and the watcher is stopped. It centralizes the
// cancel-vs-success contract: a canceled ctx yields ctx.Err() (closing conn),
// never a live-but-maybe-closed conn returned as success. On a clean success it
// returns the tunnel conn, wrapped in a *bufferedConn when the proxy pipelined
// bytes past the CONNECT reply (deliberately preserved, not drained — SEC-BE-003).
func resolveConnectResult(ctx context.Context, conn net.Conn, br *bufio.Reader, handshakeErr error) (net.Conn, error) {
	if handshakeErr != nil {
		// #nosec G104 -- best-effort cleanup; the conn is discarded on this error path (handshake failed or ctx canceled).
		conn.Close() //nolint:errcheck,gosec // discard the conn on handshake failure
		if ctx.Err() != nil {
			return nil, fmt.Errorf("httpx: proxy CONNECT canceled: %w", ctx.Err())
		}
		return nil, handshakeErr
	}

	// Handshake succeeded. If ctx was canceled (possibly after the watcher
	// already closed conn in the tiny success-vs-cancel window), return the
	// cancellation error rather than handing back a maybe-closed conn.
	if ctx.Err() != nil {
		// #nosec G104 -- best-effort cleanup; the conn is discarded on this cancel-after-success path.
		conn.Close() //nolint:errcheck,gosec // discard the conn: cancel raced a successful handshake
		return nil, fmt.Errorf("httpx: proxy CONNECT canceled after handshake: %w", ctx.Err())
	}

	// br chains any pipelined prefix (bytes the proxy sent immediately after the
	// CONNECT reply) ahead of the RAW, uncapped conn — connectHandshake captured
	// that prefix before discarding the header-capped reader (SEC-BE-003). Always
	// wrap so the prefix is served first: bufferedConn.Read draws from br while
	// writes go straight to conn. The reply body is never read or closed, so a
	// declared-body reply cannot drain the tunnel.
	return &bufferedConn{r: br, Conn: conn}, nil
}

// maxCONNECTHeaderBytes bounds the CONNECT reply's status line + headers so a
// hostile or misbehaving proxy cannot stream unbounded header bytes into memory.
// It does NOT bound the tunnel that follows (see connectHandshake).
const maxCONNECTHeaderBytes = 64 << 10

// connectHandshake performs the CONNECT request/response exchange on conn (an
// already-dialed proxy connection) and returns a reader positioned just past the
// "200 Connection established" reply. The reader serves any bytes the proxy
// pipelined immediately after the reply and then the RAW, uncapped conn. When the
// caller's context carries a deadline it bounds the exchange via conn.SetDeadline
// (clean deadline errors) and clears it on success so it does not leak into
// tunneled traffic; cancellation of a deadline-less context is handled by the
// ctx.Done() watcher in connectDialer. The reply header read is capped at
// maxCONNECTHeaderBytes (fails closed if exceeded); resp.Body is intentionally
// left unread/unclosed so a declared-body reply cannot drain the tunnel.
func connectHandshake(ctx context.Context, conn net.Conn, addr string) (*bufio.Reader, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("httpx: setting proxy CONNECT deadline: %w", err)
		}
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("httpx: writing CONNECT to proxy: %w", err)
	}

	// Bound the header read: a header block larger than the cap fails closed
	// because the limited reader returns EOF mid-headers and ReadResponse errors.
	limited := io.LimitReader(conn, maxCONNECTHeaderBytes)
	br := bufio.NewReader(limited)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("httpx: reading CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpx: proxy CONNECT to %s failed: %s", addr, resp.Status)
	}

	// Capture any bytes bufio read past the CONNECT header terminator (a proxy may
	// pipeline the first tunnel bytes right after the reply). They sit in br's
	// buffer, sourced from the capped reader; drain them here so nothing is
	// stranded when we discard that reader below.
	pipelined := make([]byte, br.Buffered())
	if _, err := io.ReadFull(br, pipelined); err != nil {
		return nil, fmt.Errorf("httpx: reading pipelined proxy bytes: %w", err)
	}

	// Clear the handshake deadline so it does not apply to tunneled traffic.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("httpx: clearing proxy CONNECT deadline: %w", err)
	}

	// Resume the tunnel over the RAW, uncapped conn, serving any pipelined prefix
	// first. The header-capped `limited` reader is intentionally discarded so the
	// cap never truncates real tunneled traffic (SEC-BE-003).
	return bufio.NewReader(io.MultiReader(bytes.NewReader(pipelined), conn)), nil
}

// dialProxy opens the transport connection to the proxy itself: TLS for an
// https-scheme proxy (cert verified unless p.Insecure), plain TCP otherwise.
func dialProxy(ctx context.Context, p ProxyConfig) (net.Conn, error) {
	if p.URL.Scheme == "https" {
		tlsCfg := &tls.Config{ServerName: p.URL.Hostname(), MinVersion: tls.VersionTLS12}
		if p.Insecure {
			// #nosec G402 -- opt-in via --proxy-insecure for https proxy MITM
			tlsCfg.InsecureSkipVerify = true
		}
		d := &tls.Dialer{Config: tlsCfg}
		conn, err := d.DialContext(ctx, "tcp", p.URL.Host)
		if err != nil {
			return nil, fmt.Errorf("httpx: dialing https proxy: %w", err)
		}
		return conn, nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", p.URL.Host)
	if err != nil {
		return nil, fmt.Errorf("httpx: dialing proxy: %w", err)
	}
	return conn, nil
}

// bufferedConn drains bytes already buffered by the CONNECT-response reader
// before falling through to the underlying connection. Writes go directly to
// the embedded net.Conn.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
