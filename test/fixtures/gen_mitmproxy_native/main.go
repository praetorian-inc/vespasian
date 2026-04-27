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

// gen_mitmproxy_native writes a mitmproxy native-format (.mitm) fixture used
// by the `import-mitmproxy-native` live test. Regenerate with:
//
//	go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm
//
// The output mimics what `mitmdump -w flows.mitm` produces for the three HTTP
// flows exercised by the live import test. The shared tnetstring encoder from
// internal/tnetenc is used so the generator and the test helper
// stay in lockstep.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/praetorian-inc/vespasian/internal/tnetenc"
)

type flow struct {
	method, scheme, host, path string
	port, statusCode           int
	reqHeaders, respHeaders    [][2]string
	reqBody, respBody          []byte
}

func main() {
	flows := []flow{
		{
			method: "GET", scheme: "http", host: "localhost", port: 8990, path: "/api/users",
			reqHeaders:  [][2]string{{"Host", "localhost:8990"}, {"Accept", "application/json"}},
			statusCode:  200,
			respHeaders: [][2]string{{"Content-Type", "application/json"}},
			respBody:    []byte(`[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]`),
		},
		{
			method: "POST", scheme: "http", host: "localhost", port: 8990, path: "/api/orders",
			reqHeaders:  [][2]string{{"Host", "localhost:8990"}, {"Content-Type", "application/json"}},
			reqBody:     []byte(`{"user_id":1,"product_id":2,"quantity":1}`),
			statusCode:  201,
			respHeaders: [][2]string{{"Content-Type", "application/json"}},
			respBody:    []byte(`{"id":3,"user_id":1,"product_id":2,"quantity":1}`),
		},
		{
			method: "GET", scheme: "http", host: "localhost", port: 8990, path: "/api/products/1",
			reqHeaders:  [][2]string{{"Host", "localhost:8990"}, {"Accept", "application/json"}},
			statusCode:  200,
			respHeaders: [][2]string{{"Content-Type", "application/json"}},
			respBody:    []byte(`{"id":1,"name":"Widget","price":9.99}`),
		},
	}

	var out bytes.Buffer
	for i, f := range flows {
		out.Write(tnetenc.Encode(flowState(f, i+1)))
	}
	if _, err := os.Stdout.Write(out.Bytes()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func flowState(f flow, id int) map[string]any {
	reqHdr := make([]any, 0, len(f.reqHeaders))
	for _, h := range f.reqHeaders {
		reqHdr = append(reqHdr, []any{[]byte(h[0]), []byte(h[1])})
	}
	respHdr := make([]any, 0, len(f.respHeaders))
	for _, h := range f.respHeaders {
		respHdr = append(respHdr, []any{[]byte(h[0]), []byte(h[1])})
	}
	return map[string]any{
		"type":   []byte("http"),
		"id":     []byte(fmt.Sprintf("00000000-0000-0000-0000-%012d", id)),
		"marked": []byte(""),
		"request": map[string]any{
			"http_version": []byte("HTTP/1.1"),
			"method":       []byte(f.method),
			"scheme":       []byte(f.scheme),
			"host":         []byte(f.host),
			"port":         int64(f.port),
			"path":         []byte(f.path),
			"authority":    []byte(""),
			"headers":      reqHdr,
			"content":      f.reqBody,
		},
		"response": map[string]any{
			"http_version": []byte("HTTP/1.1"),
			"status_code":  int64(f.statusCode),
			"reason":       []byte("OK"),
			"headers":      respHdr,
			"content":      f.respBody,
		},
	}
}
