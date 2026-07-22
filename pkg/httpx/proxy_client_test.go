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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Task 1: ProxyConfig + BuildHTTPClient
// ---------------------------------------------------------------------------

func TestProxyConfig_Enabled(t *testing.T) {
	assert.False(t, ProxyConfig{}.Enabled(), "zero value ProxyConfig must report Enabled()==false")

	u, err := url.Parse("http://127.0.0.1:8080")
	require.NoError(t, err)
	assert.True(t, ProxyConfig{URL: u}.Enabled(), "ProxyConfig with a non-nil URL must report Enabled()==true")
}

func TestBuildHTTPClient_SetsProxyAndVerifiesByDefault(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	require.NoError(t, err)

	client := BuildHTTPClient(ProxyConfig{URL: proxyURL, Insecure: false}, 10*time.Second, nil)
	require.NotNil(t, client)

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "Transport must be *http.Transport, got %T", client.Transport)
	require.NotNil(t, tr.Proxy, "Transport.Proxy must be configured")
	if tr.TLSClientConfig != nil {
		assert.False(t, tr.TLSClientConfig.InsecureSkipVerify,
			"TLS verification must stay on by default (Insecure=false)")
	}
}

func TestBuildHTTPClient_InsecureOnlyForHTTPScheme(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			proxyURL, err := url.Parse(scheme + "://127.0.0.1:8080")
			require.NoError(t, err)

			client := BuildHTTPClient(ProxyConfig{URL: proxyURL, Insecure: true}, 10*time.Second, nil)
			tr, ok := client.Transport.(*http.Transport)
			require.True(t, ok)
			require.NotNil(t, tr.TLSClientConfig,
				"TLSClientConfig must be installed when Insecure=true for a %s proxy", scheme)
			assert.True(t, tr.TLSClientConfig.InsecureSkipVerify,
				"InsecureSkipVerify must be true for a %s proxy with Insecure=true", scheme)
		})
	}
}

func TestBuildHTTPClient_SOCKS5AlwaysVerifies(t *testing.T) {
	proxyURL, err := url.Parse("socks5://127.0.0.1:1080")
	require.NoError(t, err)

	client := BuildHTTPClient(ProxyConfig{URL: proxyURL, Insecure: true}, 10*time.Second, nil)
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	if tr.TLSClientConfig != nil {
		assert.False(t, tr.TLSClientConfig.InsecureSkipVerify,
			"socks5 is a transparent TCP tunnel; verification must stay on even with Insecure=true")
	}
}

func TestBuildHTTPClient_NoSSRFDialInstalled(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	require.NoError(t, err)

	checkRedirect := func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	client := BuildHTTPClient(ProxyConfig{URL: proxyURL}, 7*time.Second, checkRedirect)

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.DialContext,
		"no SSRF dial pin must be installed when proxied: the client dials the proxy, not the target")

	assert.Equal(t, 7*time.Second, client.Timeout, "client.Timeout must be the value passed in")
	require.NotNil(t, client.CheckRedirect, "CheckRedirect must be the value passed in")
	gotErr := client.CheckRedirect(nil, nil)
	assert.True(t, errors.Is(gotErr, http.ErrUseLastResponse),
		"CheckRedirect must be the exact function passed in")
}

// TestBuildHTTPClient_RoutesThroughProxy is an end-to-end check modeled on
// pkg/crawl/http_crawler_test.go:195 (TestHTTPCrawler_RoutesThroughProxy):
// httptest origin + a forwarding httptest proxy with an atomic.Int64 counter.
// The proxy runs on loopback, which the SSRF dial guard would reject — a
// successful round-trip through it proves BuildHTTPClient does not install a
// dial-time SSRF pin (LAB-4993).
func TestBuildHTTPClient_RoutesThroughProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>ok</body></html>") //nolint:errcheck // test handler
	}))
	defer origin.Close()

	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.RequestURI, nil) //nolint:gosec // test proxy forwards the received request URI
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // test cleanup
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck,gosec // test best-effort
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	client := BuildHTTPClient(ProxyConfig{URL: proxyURL}, 10*time.Second, nil)
	resp, err := client.Get(origin.URL)
	require.NoError(t, err, "request through the proxied client must succeed")
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	assert.NotZero(t, proxied.Load(), "request did not route through the proxy")
}

// ---------------------------------------------------------------------------
// Task 2: ProxyDialer (CONNECT + SOCKS5) for gRPC
// ---------------------------------------------------------------------------

// startTCPEchoServer starts a loopback TCP server that echoes back whatever it
// reads once per connection. Used as the "target" behind a proxy tunnel.
func startTCPEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck // test cleanup
				buf := make([]byte, 5)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n]) //nolint:errcheck,gosec // test best-effort echo
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() } //nolint:errcheck,gosec // test cleanup
}

// startRecordingCONNECTProxy starts a minimal HTTP CONNECT proxy on loopback
// that records the requested target, replies "200 Connection established",
// and then pipes bytes bidirectionally between the client and targetAddr.
// Modeled per architecture.md §5 / plan.md Task 2.
func startRecordingCONNECTProxy(t *testing.T, targetAddr string) (addr string, recordedTarget func() string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var recorded atomic.Value // string

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup

		reader := bufio.NewReader(conn)
		reqLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(reqLine)
		if len(fields) >= 2 && fields[0] == "CONNECT" {
			recorded.Store(fields[1])
		}
		// Drain headers until the blank line terminating the CONNECT request.
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}

		targetConn, err := net.Dial("tcp", targetAddr)
		if err != nil {
			return
		}
		defer targetConn.Close() //nolint:errcheck // test cleanup

		done := make(chan struct{})
		go func() {
			io.Copy(targetConn, reader) //nolint:errcheck,gosec // test tunnel copy
			close(done)
		}()
		io.Copy(conn, targetConn) //nolint:errcheck,gosec // test tunnel copy
		<-done
	}()

	return ln.Addr().String(),
		func() string {
			v, _ := recorded.Load().(string)
			return v
		},
		func() { ln.Close() } //nolint:errcheck,gosec // test cleanup
}

func TestProxyDialer_HTTPConnectTunnel(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoServer(t)
	defer stopTarget()

	proxyAddr, recordedTarget, stopProxy := startRecordingCONNECTProxy(t, targetAddr)
	defer stopProxy()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, targetAddr)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck // test cleanup

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf), "expected the echo server's reply through the tunnel")

	assert.Equal(t, targetAddr, recordedTarget(), "proxy must have recorded a CONNECT to the target address")
}

// startSOCKS5TestServer is a minimal SOCKS5 server (CONNECT command, no
// authentication) used to exercise ProxyDialer's socks5 branch against a real
// protocol handshake. It accepts exactly one connection, performs the SOCKS5
// handshake, dials the requested target, and pipes bytes bidirectionally.
func startSOCKS5TestServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup

		// Greeting: VER NMETHODS METHODS...
		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		methods := make([]byte, head[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		// No-auth method selected.
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		// Request: VER CMD RSV ATYP ...
		reqHead := make([]byte, 4)
		if _, err := io.ReadFull(conn, reqHead); err != nil {
			return
		}
		var host string
		switch reqHead[3] {
		case 0x01: // IPv4
			ipBuf := make([]byte, net.IPv4len)
			if _, err := io.ReadFull(conn, ipBuf); err != nil {
				return
			}
			host = net.IP(ipBuf).String()
		case 0x03: // domain name
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			domainBuf := make([]byte, lenBuf[0])
			if _, err := io.ReadFull(conn, domainBuf); err != nil {
				return
			}
			host = string(domainBuf)
		case 0x04: // IPv6
			ipBuf := make([]byte, net.IPv6len)
			if _, err := io.ReadFull(conn, ipBuf); err != nil {
				return
			}
			host = net.IP(ipBuf).String()
		default:
			return
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			return
		}
		port := int(portBuf[0])<<8 | int(portBuf[1])

		targetConn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck,gosec // test best-effort failure reply
			return
		}
		defer targetConn.Close() //nolint:errcheck // test cleanup

		// Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (all-zero addr/port).
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}

		done := make(chan struct{})
		go func() {
			io.Copy(targetConn, conn) //nolint:errcheck,gosec // test tunnel copy
			close(done)
		}()
		io.Copy(conn, targetConn) //nolint:errcheck,gosec // test tunnel copy
		<-done
	}()

	return ln.Addr().String(), func() { ln.Close() } //nolint:errcheck,gosec // test cleanup
}

func TestProxyDialer_SOCKS5(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoServer(t)
	defer stopTarget()

	socksAddr, stopSocks := startSOCKS5TestServer(t)
	defer stopSocks()

	proxyURL, err := url.Parse("socks5://" + socksAddr)
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, targetAddr)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck // test cleanup

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf), "expected the echo server's reply through the socks5 tunnel")
}

func TestProxyDialer_UnsupportedScheme(t *testing.T) {
	proxyURL, err := url.Parse("ftp://127.0.0.1:21")
	require.NoError(t, err)

	_, err = ProxyDialer(ProxyConfig{URL: proxyURL})
	assert.Error(t, err, "an unsupported proxy scheme must be rejected")
}

// TestProxyDialer_RejectsCRLFInAddr is a regression test for a CRLF-injection
// gap (LAB-4993 review): connectDialer builds the CONNECT request via
// fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr) with no
// validation that addr is free of "\r\n". An addr containing CRLF lets an
// attacker inject extra header lines (or a second smuggled request) into the
// bytes written to the proxy connection.
//
// The stub "proxy" below is deliberately naive: it replies "200 Connection
// established" without inspecting the request at all. So a *successful*
// ProxyDialer round-trip against it can only mean the client happily wrote
// the CRLF-laden addr onto the wire — proving no client-side validation
// exists. Once addr validation is added, ProxyDialer must reject the target
// before ever dialing/writing, so the call fails locally instead.
func TestProxyDialer_RejectsCRLFInAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // test cleanup

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()                                                //nolint:errcheck,gosec // test cleanup
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")) //nolint:errcheck,gosec // test best-effort: naive proxy accepts anything
	}()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, dialErr := dial(ctx, "evil\r\nHost: injected:80")
	assert.Error(t, dialErr,
		"ProxyDialer must reject a target address containing CRLF before writing it into the CONNECT request line "+
			"(the naive stub proxy accepts anything, so a nil error here proves the CRLF payload went out unvalidated)")
}

// TestProxyDialer_ConnectResponseRespectsContextDeadline is a regression test
// for an unbounded-read gap (LAB-4993 review, LOW): connectDialer's read of
// the CONNECT response (http.ReadResponse(br, ...)) is never wired to ctx —
// no SetReadDeadline derived from ctx, no goroutine closing conn on
// ctx.Done(). A proxy that completes the TCP handshake but never sends a
// status line therefore hangs the dial indefinitely, ignoring the caller's
// context deadline entirely.
//
// The stub "proxy" here accepts the connection and then sits silent past the
// test's own bound, simulating exactly that. The dial call runs in a
// goroutine so this test itself cannot hang forever even while the
// production bug is present; the outer select's time.After is the test's own
// deterministic ceiling, independent of whether ctx is honored.
func TestProxyDialer_ConnectResponseRespectsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // test cleanup

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		// Deliberately never write a response; hold the connection open well
		// past this test's own bound to simulate a slow/malicious proxy.
		time.Sleep(5 * time.Second)
	}()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, dialErr := dial(ctx, "127.0.0.1:1")
		done <- dialErr
	}()

	select {
	case dialErr := <-done:
		assert.Error(t, dialErr, "dial must fail once the context deadline is exceeded, not hang past it")
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyDialer did not respect the context deadline while waiting for the CONNECT response; " +
			"it hung well past ctx cancellation (no SetReadDeadline / ctx.Done() wiring on the response read)")
	}
}

// ---------------------------------------------------------------------------
// https-scheme proxy (dialProxy's TLS-to-the-proxy branch) — LAB-4993 coverage
// ---------------------------------------------------------------------------

// selfSignedProxyCert generates a fresh, in-memory self-signed certificate
// valid for 127.0.0.1, mirroring pkg/probe/grpc_test.go's selfSignedTLSConfig.
func selfSignedProxyCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

// startTLSRecordingCONNECTProxy starts a TLS-listening (self-signed cert) HTTP
// CONNECT proxy that records the requested target, replies "200 Connection
// established", then relays bytes to targetAddr. Mirrors
// startRecordingCONNECTProxy but over a TLS listener, exercising dialProxy's
// https branch (proxy_client.go:193-210: tls.Dialer to the proxy itself) —
// every other CONNECT-proxy test in this file uses a plain-TCP http:// proxy,
// leaving that branch uncovered.
func startTLSRecordingCONNECTProxy(t *testing.T, targetAddr string) (addr string, recordedTarget func() string, stop func()) {
	t.Helper()
	cert := selfSignedProxyCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}}) //nolint:gosec // test cert
	require.NoError(t, err)

	var recorded atomic.Value // string

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup

		reader := bufio.NewReader(conn)
		reqLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(reqLine)
		if len(fields) >= 2 && fields[0] == "CONNECT" {
			recorded.Store(fields[1])
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}

		targetConn, err := net.Dial("tcp", targetAddr)
		if err != nil {
			return
		}
		defer targetConn.Close() //nolint:errcheck // test cleanup

		done := make(chan struct{})
		go func() {
			io.Copy(targetConn, reader) //nolint:errcheck,gosec // test tunnel copy
			close(done)
		}()
		io.Copy(conn, targetConn) //nolint:errcheck,gosec // test tunnel copy
		<-done
	}()

	return ln.Addr().String(),
		func() string {
			v, _ := recorded.Load().(string)
			return v
		},
		func() { ln.Close() } //nolint:errcheck,gosec // test cleanup
}

// TestProxyDialer_HTTPSProxy_ConnectTunnel proves the https-scheme proxy path
// works end-to-end: dialProxy TLS-dials the proxy itself (Insecure=true opts
// into accepting the proxy's self-signed cert, mirroring an intercepting MITM
// proxy), the CONNECT tunnel establishes, and bytes round-trip to the real
// target through it.
func TestProxyDialer_HTTPSProxy_ConnectTunnel(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoServer(t)
	defer stopTarget()

	proxyAddr, recordedTarget, stopProxy := startTLSRecordingCONNECTProxy(t, targetAddr)
	defer stopProxy()

	proxyURL, err := url.Parse("https://" + proxyAddr)
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL, Insecure: true})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, targetAddr)
	require.NoError(t, err, "dialing an https-scheme CONNECT proxy with Insecure=true (self-signed cert) must succeed")
	defer conn.Close() //nolint:errcheck // test cleanup

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf), "expected the echo server's reply through the https-proxy tunnel")

	assert.Equal(t, targetAddr, recordedTarget(), "https-scheme proxy must have recorded a CONNECT to the target address")
}

// TestProxyDialer_HTTPSProxy_VerifiesCertByDefault covers the verify-on branch
// of dialProxy: without the Insecure opt-in, dialing an https-scheme proxy
// presenting a self-signed certificate must fail with a certificate-
// verification error rather than silently succeeding.
func TestProxyDialer_HTTPSProxy_VerifiesCertByDefault(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoServer(t)
	defer stopTarget()

	proxyAddr, _, stopProxy := startTLSRecordingCONNECTProxy(t, targetAddr)
	defer stopProxy()

	proxyURL, err := url.Parse("https://" + proxyAddr)
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL, Insecure: false})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, dialErr := dial(ctx, targetAddr)
	require.Error(t, dialErr, "dialing an https-scheme proxy with a self-signed cert must fail when Insecure=false (verify by default)")
	lower := strings.ToLower(dialErr.Error())
	assert.True(t, strings.Contains(lower, "certificate") || strings.Contains(lower, "x509"),
		"expected a certificate-verification error, got: %v", dialErr)
}

// ---------------------------------------------------------------------------
// PR #186 review findings (LAB-4993)
// ---------------------------------------------------------------------------

// TestProxyDialer_ConnectHandshakeRespectsContextCancel is a regression test
// for TEST-001/SEC-BE-002: connectDialer only calls
// conn.SetDeadline(ctx.Deadline()) — a deadline-based bound. A cancel-only
// context (context.WithCancel, no deadline) has no Deadline() at all, so
// nothing unblocks a stalled handshake when the caller cancels; the dial
// hangs until the underlying TCP connection itself times out or the process
// exits. The stub proxy below accepts the TCP connection and then goes
// silent forever (never writes a status line), so only ctx.Done()-driven
// cancellation (not a deadline) can end the dial.
func TestProxyDialer_ConnectHandshakeRespectsContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // test cleanup

	// accepted is closed once the stub proxy has Accept()-ed the dial's
	// connection, so the test can cancel() deterministically right after the
	// handshake is in flight instead of guessing a wall-clock sleep duration.
	accepted := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		defer conn.Close() //nolint:errcheck // test cleanup
		// Stay silent forever; never write a CONNECT response status line.
		<-make(chan struct{})
	}()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background()) // NO deadline

	done := make(chan error, 1)
	go func() {
		_, dialErr := dial(ctx, "127.0.0.1:1")
		done <- dialErr
	}()

	// Cancel once the proxy has accepted the connection (deterministic; no
	// wall-clock guess about when the handshake is in flight).
	go func() {
		<-accepted
		cancel()
	}()

	select {
	case dialErr := <-done:
		assert.Error(t, dialErr, "dial must fail promptly once ctx is canceled, even with no deadline set")
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyDialer did not respect ctx cancellation (no deadline) while waiting for the CONNECT response; " +
			"it hung well past cancel() — connectDialer only wires ctx.Deadline(), not ctx.Done()")
	}
}

// TestProxyDialer_ConnectPreservesPipelinedBytes is a regression test for
// TEST-002/SEC-BE-003/QUAL-004: the stub CONNECT proxy below writes the "200
// Connection established" status line AND target payload bytes in the SAME
// write, so http.ReadResponse's bufio.Reader buffers bytes past the response
// (br.Buffered() > 0). The tunnel's first bytes must not be silently dropped
// (e.g. by a regression that drains/discards the buffered reader instead of
// wrapping it): the returned conn must be a *bufferedConn, and reading from it
// must yield the pipelined payload intact.
func TestProxyDialer_ConnectPreservesPipelinedBytes(t *testing.T) {
	const pipelinedPayload = "PIPELINED-PAYLOAD"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // test cleanup

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup

		reader := bufio.NewReader(conn)
		if _, err := reader.ReadString('\n'); err != nil { // CONNECT request line
			return
		}
		for { // drain headers until the blank line
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}

		// Status line + pipelined target bytes in ONE write, so the client's
		// bufio.Reader ends up with buffered bytes past the response.
		reply := "HTTP/1.1 200 Connection established\r\n\r\n" + pipelinedPayload
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
		// Keep the connection open briefly so the client can read before we exit.
		time.Sleep(200 * time.Millisecond)
	}()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, "127.0.0.1:1")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck // test cleanup

	_, ok := conn.(*bufferedConn)
	require.True(t, ok, "expected the returned conn to be a *bufferedConn when the proxy pipelines bytes past the CONNECT response, got %T", conn)

	buf := make([]byte, len(pipelinedPayload))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, pipelinedPayload, string(buf), "the tunnel's first bytes must be the pipelined payload, not dropped/drained")
}

// TestProxyDialer_ConnectCancelAfterSuccessKeepsConnUsable is a regression
// test for PR #186 round-2 finding G: connectDialer starts a goroutine that
// watches ctx.Done() and calls conn.Close() to unblock a stalled handshake
// (see connectDialer's ctx.Done() watcher). That watcher's select races
// against close(done): even though close(done) happens before dial() returns
// a successful conn, the watcher goroutine may not be scheduled until AFTER
// the caller has already gotten the conn back and canceled ctx (e.g. via a
// deferred cancel() or a cancel unrelated to this dial's own lifetime). If
// ctx.Done() and done are both ready when the watcher's select finally runs,
// Go picks between them pseudo-randomly — so a cancel that arrives strictly
// AFTER a successful handshake can still race-close the tunnel conn that was
// already handed to the caller. This is a regression GUARD: it may already
// pass (that's fine), but it must stay green after any mutex-based fix that
// makes the watcher a no-op once the handshake has completed.
func TestProxyDialer_ConnectCancelAfterSuccessKeepsConnUsable(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoServer(t)
	defer stopTarget()

	proxyAddr, _, stopProxy := startRecordingCONNECTProxy(t, targetAddr)
	defer stopProxy()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	dial, err := ProxyDialer(ProxyConfig{URL: proxyURL})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	conn, err := dial(ctx, targetAddr)
	require.NoError(t, err, "dial must succeed before we test post-success cancellation")

	// Cancel AFTER a successful handshake: this must never be able to close
	// the tunnel conn already returned to the caller.
	cancel()

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err, "conn must remain usable for writes after a post-success ctx cancel")
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err, "conn must remain usable for reads after a post-success ctx cancel")
	assert.Equal(t, "hello", string(buf), "expected the echo server's reply through the tunnel after cancel")

	require.NoError(t, conn.Close())
}
