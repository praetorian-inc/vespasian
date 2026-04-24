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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// MitmproxyImporter imports mitmproxy traffic captures. It accepts two input
// formats:
//
//  1. The JSON export produced by `mitmdump -w 'json:out.json'` style exporters.
//  2. The native binary flow file produced by the mitmproxy `w` command
//     (`.mitm` / `.flows`), which uses tnetstring-serialized flow dicts.
//
// Format detection peeks the first non-whitespace byte: `[` or `{` selects the
// JSON path; an ASCII digit selects the native tnetstring path.
type MitmproxyImporter struct{}

type mitmproxyFlow struct {
	Request  mitmproxyRequest  `json:"request"`
	Response mitmproxyResponse `json:"response"`
}

// Content fields are []byte rather than *string so Go's encoding/json handles
// the base64 round-trip natively, and the native path can assign raw bytes
// directly without re-encoding. A 64 MB body would otherwise peak at
// raw + base64 + decoded ~= 3.3x memory because the native path base64-encoded
// into a *string only so parseFlow could base64-decode it back.
type mitmproxyRequest struct {
	Method  string     `json:"method"`
	Scheme  string     `json:"scheme"`
	Host    string     `json:"host"`
	Port    int        `json:"port"`
	Path    string     `json:"path"`
	Headers [][]string `json:"headers"`
	Content []byte     `json:"content"`
}

type mitmproxyResponse struct {
	StatusCode int        `json:"status_code"`
	Headers    [][]string `json:"headers"`
	Content    []byte     `json:"content"`
}

// Name returns the importer name.
func (MitmproxyImporter) Name() string {
	return "mitmproxy"
}

// Import reads mitmproxy traffic and converts it to ObservedRequest format.
// It supports both mitmproxy's JSON export and the native tnetstring-based
// flow dump produced by `File > Save` (the `w` command in mitmproxy).
func (i *MitmproxyImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	limitedReader := newLimitedReader(r, maxImportSize)
	bufReader := bufio.NewReader(limitedReader)

	firstByte, err := peekFirstNonWhitespace(bufReader)
	if err != nil {
		if limitedReader.hitLimit {
			return nil, ErrFileTooLarge
		}
		return nil, fmt.Errorf("mitmproxy importer: failed to read input: %w", err)
	}

	// Format dispatch by first non-whitespace byte. mitmproxy's JSON export
	// always begins with '[' (array of flows) or '{' (single flow). Its native
	// flow dump always begins with an ASCII digit (the tnetstring length
	// prefix). These triggers are disjoint so there is no overlap to resolve.
	switch {
	case firstByte == '[' || firstByte == '{':
		return i.importJSON(bufReader, limitedReader, firstByte)
	case firstByte >= '0' && firstByte <= '9':
		return i.importNative(bufReader, limitedReader)
	default:
		return nil, fmt.Errorf(
			"mitmproxy importer: unrecognized format (first byte %q); "+
				"expected JSON export starting with '[' or '{', or a native "+
				"tnetstring flow dump starting with an ASCII digit - for "+
				"native .mitm files, convert with "+
				"`mitmdump -nr input.mitm -w 'hardump:output.har'` and import "+
				"using --format har",
			string(firstByte),
		)
	}
}

// importJSON parses the JSON export format. firstByte is passed from the
// caller (Import) so we do not peek the stream twice; the caller has already
// guaranteed it is '[' or '{'. A default case guards that invariant.
//
// Memory efficiency (S3 fix): Uses streaming json.NewDecoder instead of io.ReadAll
// to avoid allocating the entire input as a raw byte buffer (up to 500MB).
func (i *MitmproxyImporter) importJSON(bufReader *bufio.Reader, limitedReader *limitedReader, firstByte byte) ([]crawl.ObservedRequest, error) {
	decoder := json.NewDecoder(bufReader)
	switch firstByte {
	case '[':
		return i.parseJSONArray(decoder, limitedReader)
	case '{':
		return i.parseJSONObject(decoder, limitedReader)
	default:
		// Defensive: Import's dispatch guarantees firstByte is '[' or '{'.
		// Surfacing an explicit error here prevents a silent (nil, nil)
		// return if a future refactor accidentally routes other bytes here.
		return nil, fmt.Errorf("mitmproxy importer: importJSON called with unexpected first byte %q", firstByte)
	}
}

// parseJSONArray decodes an array of mitmproxy flows ("[{...},{...}]"). The
// decoder has not yet consumed the opening '[' — Token() reads and validates
// it, then the loop decodes each element until ']'.
func (i *MitmproxyImporter) parseJSONArray(decoder *json.Decoder, limitedReader *limitedReader) ([]crawl.ObservedRequest, error) {
	if _, err := decoder.Token(); err != nil {
		if limitedReader.hitLimit {
			return nil, ErrFileTooLarge
		}
		return nil, fmt.Errorf("mitmproxy importer: failed to read array start: %w", err)
	}
	var requests []crawl.ObservedRequest
	for decoder.More() {
		var flow mitmproxyFlow
		if err := decoder.Decode(&flow); err != nil {
			if limitedReader.hitLimit {
				return nil, ErrFileTooLarge
			}
			return nil, fmt.Errorf("mitmproxy importer: failed to decode flow: %w", err)
		}
		req, err := i.parseFlow(flow)
		if err != nil {
			return nil, fmt.Errorf("mitmproxy importer: %w", err)
		}
		requests = append(requests, req)
	}
	if _, err := decoder.Token(); err != nil {
		if limitedReader.hitLimit {
			return nil, ErrFileTooLarge
		}
		return nil, fmt.Errorf("mitmproxy importer: failed to read array end: %w", err)
	}
	return requests, nil
}

// parseJSONObject decodes a single-flow JSON document ("{...}"). Decode reads
// the whole object in one call, so no separate Token() bracketing is needed.
func (i *MitmproxyImporter) parseJSONObject(decoder *json.Decoder, limitedReader *limitedReader) ([]crawl.ObservedRequest, error) {
	var flow mitmproxyFlow
	if err := decoder.Decode(&flow); err != nil {
		if limitedReader.hitLimit {
			return nil, ErrFileTooLarge
		}
		return nil, fmt.Errorf("mitmproxy importer: failed to decode flow: %w", err)
	}
	req, err := i.parseFlow(flow)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy importer: %w", err)
	}
	return []crawl.ObservedRequest{req}, nil
}

// maxNativeFlows caps the total number of flow records (HTTP + skipped) that
// importNative will iterate over. The 500MB file-size cap already bounds the
// raw input, but an attacker could encode millions of small non-HTTP flows to
// burn CPU parsing records that produce no output. A hard cap here is cheap
// and bounds the loop regardless of skipped-flow ratio.
//
// Declared as a var (not a const) so tests can lower the cap and exercise
// the rejection path with a small crafted payload. Production callers MUST
// treat this as read-only. NOT PARALLEL-SAFE: mutation via withTempCap is
// not concurrency-safe, so no caller may use t.Parallel(); see
// testhelpers_test.go::withTempCap for the constraint.
var maxNativeFlows = 500_000

// importNative parses mitmproxy's native binary flow format. Each flow is a
// tnetstring-encoded dict; multiple flows are simply concatenated.
func (i *MitmproxyImporter) importNative(bufReader *bufio.Reader, limitedReader *limitedReader) ([]crawl.ObservedRequest, error) {
	var requests []crawl.ObservedRequest
	var seen int
	for {
		// Detect end-of-stream between flows without consuming bytes.
		if _, err := bufReader.Peek(1); err != nil {
			if err == io.EOF {
				return requests, nil
			}
			if limitedReader.hitLimit {
				return nil, ErrFileTooLarge
			}
			return nil, fmt.Errorf("mitmproxy importer: peek native stream: %w", err)
		}

		if seen >= maxNativeFlows {
			return nil, fmt.Errorf("%w: native flow count exceeded %d", ErrTooManyEntries, maxNativeFlows)
		}
		seen++

		raw, err := decodeTnetstringStream(bufReader, 0)
		if err != nil {
			if limitedReader.hitLimit {
				return nil, ErrFileTooLarge
			}
			return nil, fmt.Errorf("mitmproxy importer: decode native flow: %w", err)
		}

		state, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mitmproxy importer: expected flow dict, got %T", raw)
		}

		// Only HTTP flows produce ObservedRequest entries. mitmproxy mixed
		// captures can include "tcp", "udp", "dns" records; skip those. A
		// missing/unparseable `type` key is also treated as non-HTTP because
		// HTTPFlow.get_state() always populates it.
		if flowType := tnetBytesOrString(state["type"]); flowType != "http" {
			continue
		}

		flow, err := flowFromNativeState(state)
		if err != nil {
			return nil, fmt.Errorf("mitmproxy importer: %w", err)
		}
		req, err := i.parseFlow(flow)
		if err != nil {
			return nil, fmt.Errorf("mitmproxy importer: %w", err)
		}
		requests = append(requests, req)
	}
}

// flowFromNativeState translates a tnetstring-decoded HTTPFlow state dict into
// the shared mitmproxyFlow struct used by the JSON path. Fields are sourced
// from mitmproxy.http.HTTPFlow.get_state().
//
// Scope note: mitmproxy flow state also carries `websocket` (WebSocket frames
// after an HTTP Upgrade), `error` (transport-level errors), and `trailers`
// (HTTP trailers) sub-dicts. vespasian's ObservedRequest model does not
// represent these, so they are intentionally dropped. If future probes or
// classifiers need them, extend ObservedRequest first and thread fields
// through here.
func flowFromNativeState(state map[string]any) (mitmproxyFlow, error) {
	reqAny, ok := state["request"]
	if !ok {
		return mitmproxyFlow{}, fmt.Errorf("flow missing \"request\" field")
	}
	reqMap, ok := reqAny.(map[string]any)
	if !ok {
		return mitmproxyFlow{}, fmt.Errorf("flow \"request\" is %T, want dict", reqAny)
	}

	method := tnetBytesOrString(reqMap["method"])
	port, err := requirePort(reqMap["port"])
	if err != nil {
		return mitmproxyFlow{}, err
	}
	req := mitmproxyRequest{
		Method:  method,
		Scheme:  tnetBytesOrString(reqMap["scheme"]),
		Host:    tnetBytesOrString(reqMap["host"]),
		Port:    port,
		Path:    buildRequestPath(reqMap),
		Headers: nativeHeaders(reqMap["headers"]),
		Content: nativeContent(reqMap["content"]),
	}

	var resp mitmproxyResponse
	if respAny, ok := state["response"]; ok && respAny != nil {
		respMap, ok := respAny.(map[string]any)
		if !ok {
			return mitmproxyFlow{}, fmt.Errorf("flow \"response\" is %T, want dict", respAny)
		}
		resp = mitmproxyResponse{
			StatusCode: int(tnetInt64(respMap["status_code"])),
			Headers:    nativeHeaders(respMap["headers"]),
			Content:    nativeContent(respMap["content"]),
		}
	}

	return mitmproxyFlow{Request: req, Response: resp}, nil
}

// buildRequestPath returns the `path` field from reqMap, normalized to "/"
// when absent or empty. mitmproxy's HTTPFlow.get_state() stores the full
// request target verbatim from the wire in `path` (e.g. "/api?x=1"), except
// for CONNECT flows whose target lives in the `authority` field (not path).
// CONNECT flows therefore arrive here with an empty path and receive the
// "/" fallback — the authority is already reflected in host/port, and
// embedding it into the path would produce malformed URLs like
// "https://example.com/example.com:443".
func buildRequestPath(reqMap map[string]any) string {
	if path := tnetBytesOrString(reqMap["path"]); path != "" {
		return path
	}
	return "/"
}

// nativeHeaders converts mitmproxy's [][name, value] byte-pair list (as returned
// by Headers.get_state()) into the [][]string format expected by parseFlow.
func nativeHeaders(v any) [][]string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([][]string, 0, len(list))
	for _, entry := range list {
		pair, ok := entry.([]any)
		if !ok || len(pair) < 2 {
			continue
		}
		out = append(out, []string{
			tnetBytesOrString(pair[0]),
			tnetBytesOrString(pair[1]),
		})
	}
	return out
}

// nativeContent passes the raw request/response body through to parseFlow as
// []byte (the same wire type mitmproxy stored), avoiding the base64 round-trip
// the JSON path uses. A 64 MB body would otherwise peak at
// raw(64MB) + base64(~85MB) + decoded(64MB) = ~213MB per flow.
//
// Returns nil for both absent bodies (no `content` key) and explicitly empty
// bodies (zero-length content). ObservedRequest already uses a nil-byte-slice
// Body field and does not distinguish "no body" from "Content-Length: 0", so
// conflating them here matches existing behavior and keeps the JSON and
// native paths aligned.
func nativeContent(v any) []byte {
	if v == nil {
		return nil
	}
	var raw []byte
	switch b := v.(type) {
	case []byte:
		raw = b
	case string:
		raw = []byte(b)
	default:
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// tnetBytesOrString coerces a tnetstring-decoded value to a string, accepting
// either a []byte (the common case for mitmproxy state) or a string.
func tnetBytesOrString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return ""
	}
}

// tnetInt64 coerces a tnetstring int value to int64. Only int64 is accepted
// because the decoder always emits int64 for `#`-type elements; broader
// coercion would silently mask schema drift (e.g. a status_code field
// unexpectedly serialized as a float). Missing or wrong-typed values
// intentionally return 0 so status_code defaults cleanly.
func tnetInt64(v any) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}

// previewString renders up to maxPreviewLen (helpers.go) bytes of s using %q
// quoting; longer inputs are truncated and annotated with the original byte
// length so the operator still sees "this was enormous" without pasting
// megabytes into a log. %q-quoting escapes control bytes (ANSI escapes, NUL,
// etc.) so a crafted method or scheme cannot clear the operator's terminal,
// recolor output, or poison log parsers when the error string is rendered —
// aligning with payloadPreview's quoting discipline in tnetstring.go.
func previewString(s string) string {
	if len(s) <= maxPreviewLen {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%q... (%d bytes total)", s[:maxPreviewLen], len(s))
}

// requirePort extracts a mitmproxy `port` field that MUST be a tnetstring
// integer. Missing, wrong-typed, or out-of-range values are errors — silently
// defaulting to 0 would produce URLs like "https://example.com:0/" for
// malformed captures, which is worse than a clear import failure.
//
// Only int64 is accepted (matching tnetInt64's narrowed contract, round-7).
// The tnetstring decoder always emits int64 for `#`-type elements, so
// accepting plain int or float64 would only mask schema drift or a
// hand-crafted capture — silently rounding 443.5 → 443 would hide real
// data-integrity problems, and int vs int64 is a decoder-internal detail
// that production code should never see.
func requirePort(v any) (int, error) {
	if v == nil {
		return 0, fmt.Errorf("flow missing \"port\" field")
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("flow \"port\" is %T, want integer", v)
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("invalid port: %d (must be 0-65535)", n)
	}
	return int(n), nil
}

// peekFirstNonWhitespace reads and unreads bytes until finding a non-whitespace character.
func peekFirstNonWhitespace(r *bufio.Reader) (byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			if err := r.UnreadByte(); err != nil {
				return 0, err
			}
			return b, nil
		}
	}
}

// allowedSchemes enumerates URL schemes accepted from mitmproxy captures.
// The native path accepts untrusted `.mitm` files, so an attacker could
// forge `scheme=file|javascript|gopher|data|ldap|dict|...` which would then
// ride through to any downstream consumer that re-fetches, replays, or
// inspects the ObservedRequest.URL. mitmproxy itself only emits http/https,
// so constraining at the importer boundary costs nothing legitimate.
var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// maxHostLength is RFC 1035's 253-octet limit for a fully qualified domain
// name (excluding the trailing dot). mitmproxy `.mitm` files are attacker-
// controllable input; without a bound the `host` field can carry up to the
// 64 MB per-element tnetstring cap, which is nonsense as a hostname and a
// foot-gun for downstream consumers (rate limiters, scope filters, loggers)
// that trust the host-derived slice.
const maxHostLength = 253

// validateHost rejects empty hosts, overlong hosts, embedded userinfo, and
// whitespace or control bytes. The check is deliberately conservative — a
// legitimate mitmproxy capture never contains any of these — so a rejection
// reliably indicates a forged or malformed capture, not a real site.
//
// Applied at the importer boundary (both JSON and native paths) so downstream
// code that URL-parses `ObservedRequest.URL` receives a host that satisfies
// the invariants documented here, rather than having to re-validate.
func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if len(host) > maxHostLength {
		return fmt.Errorf("host length %d exceeds RFC 1035 limit of %d", len(host), maxHostLength)
	}
	if strings.ContainsRune(host, '@') {
		// Embedded userinfo ("user:pass@host") weaponizes the host field into
		// a credential smuggler if a downstream consumer splits on `@`.
		return fmt.Errorf("host contains embedded userinfo (\"@\")")
	}
	if strings.ContainsRune(host, ':') {
		// A ':' in host smuggles an attacker-chosen port past requirePort's
		// 0-65535 check: constructURL's isDefaultPort branch assigns
		// u.Host = host verbatim, so host="evil.com:1337" with port=443
		// (https default) yields URL "https://evil.com:1337/...". mitmproxy's
		// HTTPFlow.get_state() never populates host with a port suffix (port
		// lives in its own field), so this rejection has zero legitimate cost.
		return fmt.Errorf("host contains port separator (\":\"); port must be carried in the port field")
	}
	for _, r := range host {
		// Reject ASCII control bytes and whitespace. Non-ASCII (e.g. IDN) is
		// permitted because mitmproxy's host field may carry punycode or
		// UTF-8 forms; deeper validation is the URL-parser's job.
		if r < 0x21 || r == 0x7f {
			return fmt.Errorf("host contains control/whitespace byte %q", r)
		}
	}
	return nil
}

// parseFlow converts a mitmproxyFlow into an ObservedRequest.
// Constructs URL from request components and extracts headers. Bodies are
// already raw []byte (native path assigns directly; JSON path base64-decodes
// during json.Decode since Go maps JSON strings into []byte as base64).
func (i *MitmproxyImporter) parseFlow(flow mitmproxyFlow) (crawl.ObservedRequest, error) {
	if flow.Request.Port < 0 || flow.Request.Port > 65535 {
		return crawl.ObservedRequest{}, fmt.Errorf("invalid port: %d (must be 0-65535)", flow.Request.Port)
	}

	if !validHTTPMethods[flow.Request.Method] {
		return crawl.ObservedRequest{}, fmt.Errorf("invalid HTTP method: %s", previewString(flow.Request.Method))
	}

	if !allowedSchemes[flow.Request.Scheme] {
		return crawl.ObservedRequest{}, fmt.Errorf("unsupported scheme %s (only http/https allowed)", previewString(flow.Request.Scheme))
	}

	if err := validateHost(flow.Request.Host); err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("invalid host: %w", err)
	}

	url := constructURL(flow.Request.Scheme, flow.Request.Host, flow.Request.Port, flow.Request.Path)

	respHeaders := convertMitmproxyHeaders(flow.Response.Headers)
	return crawl.ObservedRequest{
		Method:      flow.Request.Method,
		URL:         url,
		Headers:     convertMitmproxyHeaders(flow.Request.Headers),
		QueryParams: extractQueryParams(url),
		Body:        nilIfEmpty(flow.Request.Content),
		Response: crawl.ObservedResponse{
			StatusCode:  flow.Response.StatusCode,
			Headers:     respHeaders,
			ContentType: respHeaders["Content-Type"],
			Body:        nilIfEmpty(flow.Response.Content),
		},
		Source: "import:mitmproxy",
	}, nil
}

// nilIfEmpty normalizes a zero-length body to nil so downstream consumers
// cannot tell "no body" apart from "Content-Length: 0". Matches pre-existing
// behavior where the JSON path's decodeContent returned (nil, nil) for both
// nil *string and empty string.
func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// constructURL builds URL from mitmproxy components using url.URL struct.
//
// mitmproxy stores the verbatim wire request target in `path` (per
// HTTPFlow.get_state()), so pathPart is expected to already be RFC 3986
// percent-encoded. Assigning it to u.Path alone would cause url.URL.String()
// to re-encode any `%` characters, double-encoding sequences like
// `/api/hello%20world` into `/api/hello%2520world`. Setting both u.Path
// (decoded) and u.RawPath (verbatim) makes EscapedPath() emit the wire form
// unchanged; if the path isn't well-formed percent-encoding, we fall back to
// Path-only and let url.URL handle it.
func constructURL(scheme, host string, port int, path string) string {
	pathPart, query, _ := strings.Cut(path, "?")

	u := &url.URL{
		Scheme:   scheme,
		Host:     host,
		RawQuery: query,
	}
	if decoded, err := url.PathUnescape(pathPart); err == nil {
		u.Path = decoded
		u.RawPath = pathPart
	} else {
		u.Path = pathPart
	}

	isDefaultPort := (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
	if !isDefaultPort {
		u.Host = fmt.Sprintf("%s:%d", host, port)
	}

	return u.String()
}

// convertMitmproxyHeaders converts mitmproxy header tuples to map.
// Skips headers with empty names or malformed tuples (per RFC 7230).
func convertMitmproxyHeaders(mitmHeaders [][]string) map[string]string {
	headers := make(map[string]string)
	for _, h := range mitmHeaders {
		if len(h) >= 2 && h[0] != "" {
			headers[h[0]] = h[1]
		}
	}
	return headers
}
