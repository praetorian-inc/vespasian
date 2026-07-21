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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
				c.Write(buf[:n]) //nolint:errcheck // test best-effort echo
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() } //nolint:errcheck // test cleanup
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
			io.Copy(targetConn, reader) //nolint:errcheck // test tunnel copy
			close(done)
		}()
		io.Copy(conn, targetConn) //nolint:errcheck // test tunnel copy
		<-done
	}()

	return ln.Addr().String(),
		func() string {
			v, _ := recorded.Load().(string)
			return v
		},
		func() { ln.Close() } //nolint:errcheck // test cleanup
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

		targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck // test best-effort failure reply
			return
		}
		defer targetConn.Close() //nolint:errcheck // test cleanup

		// Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (all-zero addr/port).
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}

		done := make(chan struct{})
		go func() {
			io.Copy(targetConn, conn) //nolint:errcheck // test tunnel copy
			close(done)
		}()
		io.Copy(conn, targetConn) //nolint:errcheck // test tunnel copy
		<-done
	}()

	return ln.Addr().String(), func() { ln.Close() } //nolint:errcheck // test cleanup
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
