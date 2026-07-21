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

// Package httpx builds proxy-aware HTTP clients and dialers shared by the probe,
// WSDL-discovery, JS-replay, and sourcemap stages. It is a stdlib-only leaf
// (plus golang.org/x/net/proxy for SOCKS5) and imports nothing from crawl,
// probe, pipeline, or ssrf, so every consumer can depend on it without a cycle.
//
// The proxy-aware transport mirrors pkg/crawl/http_crawler.go's proxy branch:
// with a proxy configured the client dials the proxy (commonly loopback), not
// the target, so the dial-time SSRF guard is deliberately NOT installed. Target
// scope stays enforced at the URL level by each consumer's own validators.
package httpx

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

// BuildHTTPClient returns an *http.Client whose transport routes through p.URL,
// mirroring pkg/crawl.newHTTPClient's proxy branch:
//
//   - clones http.DefaultTransport (keeps keep-alive / HTTP2 / idle tunings)
//   - sets Transport.Proxy = http.ProxyURL(p.URL) (stdlib tunnels http/https/socks5)
//   - clears Transport.DialContext: no dial-time SSRF pin is installed because we
//     dial the proxy, not the target; URL-level scope stays the caller's job
//   - sets TLSClientConfig.InsecureSkipVerify only when p.Insecure && the proxy
//     scheme is http/https (an intercepting MITM proxy presenting its own CA).
//     socks5 is a transparent TCP tunnel, so verification always stays on for it.
//
// Precondition: p.Enabled(). Callers gate on p.Enabled() and keep their existing
// non-proxy builder for the unproxied path (zero regression to proven paths).
func BuildHTTPClient(p ProxyConfig, timeout time.Duration,
	checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Defensive: stdlib always sets *http.Transport, but fall back to a
		// fresh transport rather than panic if a future runtime changes that.
		base = &http.Transport{}
	}
	t := base.Clone()
	t.Proxy = http.ProxyURL(p.URL)
	// Drop the cloned default dialer: with a proxy we dial the proxy, not the
	// target, so the SSRF dial pin is neither installed nor needed here.
	t.DialContext = nil
	// TLS verification stays on by default. It is disabled only when the operator
	// explicitly opts in via --proxy-insecure AND the proxy is http/https: an
	// intercepting proxy (Burp, mitmproxy) terminates TLS and presents its own CA,
	// so verification must be off for that substitute certificate to be accepted.
	// socks5 tunnels TCP transparently — TLS runs directly against the real target
	// through the tunnel — so verification is always kept for socks5.
	if p.Insecure && p.URL != nil && (p.URL.Scheme == "http" || p.URL.Scheme == "https") {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: opt-in via --proxy-insecure for http/https proxy MITM (see doc comment)
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
		conn, err := dialProxy(ctx, p)
		if err != nil {
			return nil, err
		}

		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close() //nolint:errcheck,gosec // best-effort cleanup on write failure
			return nil, fmt.Errorf("httpx: writing CONNECT to proxy: %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close() //nolint:errcheck,gosec // best-effort cleanup on read failure
			return nil, fmt.Errorf("httpx: reading CONNECT response: %w", err)
		}
		resp.Body.Close() //nolint:errcheck,gosec // CONNECT response has no body
		if resp.StatusCode != http.StatusOK {
			conn.Close() //nolint:errcheck,gosec // best-effort cleanup on non-200
			return nil, fmt.Errorf("httpx: proxy CONNECT to %s failed: %s", addr, resp.Status)
		}

		// Preserve any bytes the proxy pipelined past the CONNECT reply so the
		// caller's TLS handshake does not lose them.
		if br.Buffered() > 0 {
			return &bufferedConn{r: br, Conn: conn}, nil
		}
		return conn, nil
	}
}

// dialProxy opens the transport connection to the proxy itself: TLS for an
// https-scheme proxy (cert verified unless p.Insecure), plain TCP otherwise.
func dialProxy(ctx context.Context, p ProxyConfig) (net.Conn, error) {
	if p.URL.Scheme == "https" {
		tlsCfg := &tls.Config{ServerName: p.URL.Hostname()}
		if p.Insecure {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // G402: opt-in via --proxy-insecure for https proxy MITM
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
