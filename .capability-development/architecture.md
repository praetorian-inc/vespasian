# Architecture Plan: PR #63 Review Fixes

## Scope

Address all 30 findings from Blayne's review of PR #63 (LAB-1505).

## Approach Summary

The bulk of the work happens in `pkg/crawl/jsreplay.go` and its test. Two
secondary changes touch `cmd/vespasian/main.go` (plumb `AllowPrivate` and
target URL), `pkg/crawl/doc.go`, `CLAUDE.md`, and `README.md`.

`pkg/crawl` will gain a new (test-only) dependency on `pkg/probe` for
SSRF helpers. There is no import cycle: `pkg/probe` imports `pkg/crawl`
only in test files.

## Phase A: Core security plumbing

1. **JSReplayConfig surface** (jsreplay.go:30-48):
   - Add `TargetURL string` (used to derive same-origin host).
   - Add `AllowPrivate bool` (skip SSRF validation when true).
   - Add `AllowCrossOrigin bool` (allow probes/JS fetches outside target origin; default false).
   - Add `MaxTotalTime time.Duration` (overall deadline for ReplayJSExtracted).

2. **withDefaults**:
   - Default `MaxTotalTime` to `MaxEndpoints * Timeout` capped to e.g. 10 min.
   - When `!AllowPrivate`, install `probe.SSRFSafeDialContext` on a copy of
     the default `http.Transport` for `cfg.Client`.

3. **Target origin**:
   - Capture `targetOrigin = scheme://host[:port]` once at start of
     `ReplayJSExtracted` from `cfg.TargetURL` (fall back to first request URL).

4. **Same-origin gate**:
   - Helper `isSameOrigin(rawURL, targetOrigin)` - parses URL and compares
     scheme+host+port.
   - **Probe loop**: skip full URLs whose origin != target origin unless
     `AllowCrossOrigin`. Log a warning when skipped.
   - **JS fetch**: skip cross-origin script srcs unless `AllowCrossOrigin`.
   - **Headers**: only attach `cfg.Headers` when target host matches.

5. **SSRF validation**:
   - Helper `safeURL(rawURL, allowPrivate)` calling `probe.ValidateProbeURL`.
   - Wire through `fetchJSBody` and the probe loop.

6. **URL hygiene** (SEC-BE-003):
   - In `addPath` for full URLs, parse and reject:
     - non-http/https schemes
     - URLs with `u.User` (credentials)
     - empty Host

## Phase B: Determinism & correctness

7. **Deterministic iteration** (QUAL-007): collect `allPaths` keys into a
   sorted slice before the probe loop.

8. **MaxEndpoints semantics** (QUAL-005, QUAL-006):
   - Increment a `probed` counter on every probe attempt (not just success).
   - Emit a warning to `cfg.Stderr` (unconditional) when the cap is reached
     with paths still pending.

9. **MaxTotalTime deadline** (SEC-BE-001):
   - Wrap loop ctx with `context.WithTimeout(ctx, cfg.MaxTotalTime)`.

10. **Defensive header copy** (SEC-BE-008): build a per-request copy of
    `cfg.Headers` when constructing each `ObservedRequest`.

## Phase C: Extraction improvements

11. **Template literal interpolation** (REQ-001):
    - New parser `extractTemplateLiteralPaths(jsBody []byte) []string` that
      walks each backtick-delimited literal, replacing `${...}` segments
      with `{param}` and concatenating the literal pieces. Stop at the
      closing backtick. Reject if the resulting string contains no API
      indicator.
    - Replace the existing single-shot `templateLiteralPattern` with this
      walker (the existing pattern stays as a fallback for partial matches
      to avoid regressions).

12. **`.concat()` notice** (REQ-002):
    - Add a comment near `servicePrefixPattern` documenting that
      `String.prototype.concat` is intentionally out of scope and pointing
      at LAB-1368.

13. **apiPathPattern false-positive note** (QUAL-003):
    - Add comment near pattern noting the regex strategy and the 404 filter
      as the primary defense.

14. **servicePrefixPattern note** (QUAL-004):
    - Add note that backtick template literal concatenations are not matched.

## Phase D: Refactors

15. **Content-type matcher** (QUAL-002):
    - Extract `matchesContentType(contentType string, types []string) bool`.
    - `isHTMLResponse` and `isJSResponse` become one-liners.

16. **doRequest helper** (QUAL-008):
    - Extract a helper that builds the request, applies headers (subject to
      same-origin gate), and runs `cfg.Client.Do` with body drain on close.
    - Both `fetchJSBody` and `probeURL` call into it.

17. **Log sanitization** (SEC-BE-005):
    - Add helper `sanitizeForLog(s string) string` using `strconv.Quote`-
      style escaping for non-printable bytes.
    - Apply to all `logf` calls that emit attacker-controlled strings.

## Phase E: Tests

Each TEST-* finding maps to a test case:

- TEST-001: `TestJSReplayConfig_WithDefaults` (defaults + non-zero preserved).
- TEST-002: invalid pageURL case in `TestExtractScriptURLs`.
- TEST-003: `TestReplayJSExtracted_EmptyInput` (nil/empty/no-URL slice).
- TEST-004: `TestReplayJSExtracted_Filters404` and
  `TestReplayJSExtracted_ProbeNetworkError`.
- TEST-005: `TestFetchJSBody_RejectsErrorStatus` (404 and 500 with non-HTML body).
- TEST-006: assert `result[0]` equality in `TestReplayJSExtracted_NoJSFiles`.
- TEST-007: change `LessOrEqual` to `Equal` in `TestReplayJSExtracted_MaxEndpoints`.
- TEST-008: hit-counter and request-equality in `TestReplayJSExtracted_ContextCancellation`.

New security tests:

- `TestReplayJSExtracted_SkipsCrossOriginByDefault` — full URL pointing to a
  different origin is dropped; headers not forwarded.
- `TestReplayJSExtracted_RejectsPrivateIPWhenSSRFEnforced` — extracted full
  URL pointing at `127.0.0.1` is dropped when AllowPrivate=false.
- `TestExtractAPIPaths_TemplateLiteralInterpolation` — verify
  `` `/api/users/${id}/profile` `` becomes `/api/users/{id}/profile`.
- `TestAddPath_RejectsURLCredentials` — full URL with `user:pass@host` is dropped.

## Phase F: Documentation

- `pkg/crawl/doc.go`: add bullet for `JSReplayConfig` / `ReplayJSExtracted`.
- `CLAUDE.md`: extend `pkg/crawl` description with JS-replay step.
- `README.md`: new "SPA support" subsection summarising the post-crawl JS
  extraction.
- `pkg/crawl/jsreplay.go`: top-of-file comment block summarising threat-model
  decisions (same-origin default, SSRF protection).

## Phase G: Wiring

`cmd/vespasian/main.go`:

- In `ScanCmd.Run()`, plumb `c.URL` and `c.DangerousAllowPrivate` into the
  `crawl.JSReplayConfig` literal.

## Test verification

`make check` (fmt + vet + lint + test) must pass before pushing.
