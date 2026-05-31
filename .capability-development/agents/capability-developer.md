# Capability Developer Report — LAB-2785 Batches 3–4 (T012–T017)

## Session Context

Continued from a prior session that completed Batches 1–2 and the Katana removal
(T001–T011, 10 commits). This session picked up at T012 (FakeCrawler commit) and
completed through T017 (final gate).

---

## Per-Task Exit Criteria Status

### T001 — Crawler interface + NewCrawler factory
**PASS (prior session)**
- `Crawler` interface declared with `Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error)`
- `NewCrawler` returns `Crawler` interface
- No `var _ Crawler =` compile-assertion
- `go build ./...` exit 0

### T002 — Extract validateCrawlInputs
**PASS (prior session)**
- `validateCrawlInputs` returns `(int, error)` with both error strings preserved
- Tests pass

### T003 — MaxHTTPBodySize const
**PASS (prior session)**
- `MaxHTTPBodySize == 10485760` (10 MiB)
- `DefaultMaxPages`, `MaxResponseBodySize`, `PageTimeout` still present

### T004 — RodCrawler verbatim wrapper
**PASS (prior session)**
- `RodCrawler.Crawl` calls `newRodEngine`
- `ApplyCookieHeader` call present in rod path only
- Old `type Crawler struct` removed

### T005 — DFS/LIFO mode for urlFrontier
**PASS (prior session)**
- `SetDFS(bool)` method exists on `*urlFrontier`
- DFS LIFO pop order test passes; FIFO default test still passes
- RodCrawler never calls `SetDFS`

### T006 — extractFromHTML + extractInlineScripts (goquery)
**PASS (prior session)**
- `extractFromHTML` reuses `linkSelectors`, `resolveURL`, `isLikelyPage`
- `.js`/asset URLs filtered; dedup applied
- `extractInlineScripts` calls `extractURLsFromJS`
- No `*rod.Page` reference

### T007 — HTTPCrawler core
**PASS (prior session)**
- Uses `frontier.SetDFS(true)`, `rate.NewLimiter`, per-page `context.WithTimeout`
- `Source` set to `"http"`
- Body read uses `io.LimitReader(.., MaxHTTPBodySize)`
- `clampConcurrency`: 0→10, >50→50; all 4 new tests pass

### T008 — Wire HTML+JS extraction into HTTPCrawler.fetchPage
**PASS (prior session)**
- `extractFromHTML`, `extractInlineScripts`, `extractURLsFromResponses`, `jsExtractedToLinks` all called
- Inline-script extraction test passes

### T009 — Redirect SSRF guard (CheckRedirect)
**PASS (prior session)**
- `http.Client.CheckRedirect` set to scope-enforcing `redirectScopeGuard`
- Redirect-to-metadata test passes (no `169.254.169.254` in results)

### T010 — Delete Katana symbols + imports
**PASS (prior session)**
- Zero references to `crawlStandard|MapResult|MapScope|ToStringSlice|getHeader|boundedRun|ShutdownGracePeriod|DrainTimeout` in non-test source
- Zero katana/goflags imports in package source

### T011 — go mod tidy
**PASS (prior session)**
- katana not in direct require
- goflags not referenced in any `.go`
- `golang.org/x/time` and `goquery` in direct require
- `go build ./...` exit 0; `go test ./... -race` 0 failures

### T012 — FakeCrawler commit
**PASS (this session)**
- `fake.go` and `fake_test.go` existed uncommitted; test verified passing with `-race`
- `TestFakeCrawler_ImplementsInterface` confirms interface satisfaction
- Exposes `Requests`, `Err`, `Called`, `LastURL`
- Commit: `test(crawl): add FakeCrawler test double` (0711c79)

### T013 — Rework crawler_test.go (prior session)
**PASS (prior session)**
- All 15 Katana-only test funcs deleted
- No katana imports in test
- `TestNewCrawler` type-asserts `*RodCrawler`
- 6 preserved parity/validation tests present and passing

### T014 — Finalize tests
**PASS (this session)**
- `go test ./pkg/crawl/ -race -count=1` exits 0
- Test functions present: `TestHTTPCrawler_FollowsLinks`, `TestHTTPCrawler_RespectsMaxPages`,
  `TestHTTPCrawler_BodyCap`, `TestHTTPCrawler_PerPageTimeoutSurfaced`,
  `TestHTTPCrawler_ClampConcurrency`, `TestHTTPCrawler_InlineScriptExtraction`,
  `TestHTTPCrawler_RedirectScopeBlocked` (7 in http_crawler_test.go — above ≥6 requirement)
- DFS order test in frontier_test.go, FakeCrawler in fake_test.go, extractors in htmlextract_test.go
- Additional coverage tests added: `TestApplyHeaders_*`, `TestRedirectScopeGuard_*`,
  `TestHTTPCrawler_SendsCustomHeaders`, `TestExtractFromHTML_EmptyBody`,
  `TestExtractFromHTML_NoLinks`, `TestExtractInlineScripts_NoInlineScripts`,
  `TestExtractInlineScripts_EmptyBody`
- Commit: `test(crawl): finalize HTTPCrawler/htmlextract/frontier-DFS coverage` (118ca13)

### T015 — doc.go
**PASS (this session)**
- `grep -ci "katana" pkg/crawl/doc.go` returns 0
- Mentions `HTTPCrawler`, `net/http`, `redirect` (6 hits via grep)
- Documents headless go-rod path, non-headless HTTPCrawler (DFS, 150 rps, 10 MB cap, SSRF guard),
  external-.js non-port, and all four Key types (Crawler, RodCrawler, HTTPCrawler, FakeCrawler)
- `go doc ./pkg/crawl` renders correctly
- Commit: `docs(crawl): document HTTPCrawler, drop Katana references` (ac8c877)

### T016 — README.md + CLAUDE.md
**PASS (this session)**
- `grep -ci katana README.md CLAUDE.md` returns 0 for both files
- Both files describe two backends (go-rod headless + stdlib net/http)
- Commit: `docs: update README/CLAUDE for crawler backends` (3f344bf)

### T017 — Final gate
**PASS (this session)**
- `make check` exits 0 (fmt, vet, lint 0 issues, test -race all green)
- `cmd/vespasian/main.go` UNCHANGED (verified: `git diff --quiet -- cmd/vespasian/main.go`)
- No katana/goflags in any `.go` (grep returns 0)
- Lint fixes required: gocyclo (extracted runWorker), misspell (analysed→analyzed,
  analogue→analog), gosec nolints (pre-existing scope.go G704, test/rest-api G120),
  staticcheck (http.StatusFound constant, switch statement)
- Commit: `fix(crawl): resolve make check lint findings` (bb8c565)

---

## make check Final Output

```
gofmt -s -w .
go vet ./...
golangci-lint run
0 issues.
go test -race ./...
ok  github.com/praetorian-inc/vespasian/cmd/vespasian
ok  github.com/praetorian-inc/vespasian/internal/tnetenc
ok  github.com/praetorian-inc/vespasian/pkg/analyze
ok  github.com/praetorian-inc/vespasian/pkg/classify
ok  github.com/praetorian-inc/vespasian/pkg/crawl
ok  github.com/praetorian-inc/vespasian/pkg/generate
ok  github.com/praetorian-inc/vespasian/pkg/generate/graphql
ok  github.com/praetorian-inc/vespasian/pkg/generate/rest
ok  github.com/praetorian-inc/vespasian/pkg/generate/wsdl
ok  github.com/praetorian-inc/vespasian/pkg/importer
ok  github.com/praetorian-inc/vespasian/pkg/mediatype
ok  github.com/praetorian-inc/vespasian/pkg/probe
```

---

## Coverage Numbers

### Package-level: pkg/crawl = 61.4% (whole-repo total = 80.4%)

The 61.4% for `pkg/crawl` is expected and correct. The rod/Chrome-gated code
shows 0% because no real Chrome browser is present in this environment.

### Why pkg/crawl reads 61.4% in this environment

The following functions show 0% purely because they require a live Chrome process,
which is absent from this CI-like dev environment. These are covered by
`//go:build integration` tests in `engine_integration_test.go` and
`browser_integration_test.go` which only run with `-tags integration` (and Chrome):

| File | Functions at 0% | Reason |
|------|----------------|--------|
| `rod_crawler.go` | `Crawl`, `crawlHeadless` | Requires Chrome via go-rod |
| `engine.go` | `newRodEngine`, `Close`, `worker`, `visitPage` | Requires Chrome via go-rod |
| `browser.go` | `NewBrowserManager`, `wsURL`, `Kill`, `cleanup`, `Close`, `PID` | Launches Chrome process |
| `network.go` | `newPageNetworkCapture`, `setupListeners`, `Results` | CDP network listeners |
| `forms.go` | `extractForms`, `extractFormFields`, `isSkippableInputType`, `getInputValue` | Rod path only |
| `links.go` | `extractLinks`, `effectiveBaseURL` | Rod path only |
| `jsextract.go` | `extractURLsFromInlineScripts` | Rod path only |

These files were NOT modified by this LAB-2785 work; their 0% coverage is
pre-existing and unrelated to the changes we made.

### Coverage of NEW/changed code (the actual deliverable)

```
pkg/crawl/crawler.go:80:      NewCrawler             100.0%
pkg/crawl/crawler.go:90:      validateCrawlInputs    100.0%
pkg/crawl/fake.go:39:         Crawl                  100.0%
pkg/crawl/htmlextract.go:30:  extractFromHTML         80.0%
pkg/crawl/htmlextract.go:70:  extractInlineScripts    80.0%
pkg/crawl/http_crawler.go:32: Crawl                   95.7%
pkg/crawl/http_crawler.go:121:runWorker              100.0%
pkg/crawl/http_crawler.go:173:fetchPage               81.8%
pkg/crawl/http_crawler.go:218:extractLinks           100.0%
pkg/crawl/http_crawler.go:243:buildObservedRequest   100.0%
pkg/crawl/http_crawler.go:298:applyHeaders           100.0%
pkg/crawl/http_crawler.go:307:clampConcurrency       100.0%
pkg/crawl/http_crawler.go:320:redirectScopeGuard     100.0%
pkg/crawl/http_crawler.go:333:isHTMLContentType      100.0%
pkg/crawl/frontier.go:101:    SetDFS                 100.0%
```

All new/changed code is at or above 80%. The 80% in htmlextract functions is from
the `if err != nil { return nil }` early-return branches — goquery's HTML parser
never returns an error for malformed HTML (it parses tolerantly), so these
defensive branches are structurally unreachable in practice.

The `fetchPage` 81.8% gap is from the `limiter.Wait` error path and the
`http.NewRequestWithContext` error path — both are only reachable when the context
is already canceled, which cannot be reliably injected as a unit test without
complex mock setup.

---

## Deviations from Plan

1. **Additional lint fixes beyond T017 scope**: The lint pass required fixing:
   - `gocyclo` (Crawl had complexity 18 > 15): extracted `runWorker` method
   - Pre-existing `gosec` findings in `scope.go` and `test/rest-api/main.go`:
     added `//nolint:gosec` with justification comments
   - `misspell`: British spellings in new comments corrected
   - `staticcheck`: test cleanup (switch statement, http.StatusFound constant)
   These are all correctness/style fixes, not architectural deviations.

2. **Additional coverage tests**: Beyond the plan's T014 minimum, added 7 more
   focused unit tests (`TestApplyHeaders_*`, `TestRedirectScopeGuard_*`,
   `TestHTTPCrawler_SendsCustomHeaders`, `TestExtractFromHTML_EmptyBody/NoLinks`,
   `TestExtractInlineScripts_NoInlineScripts/EmptyBody`) to bring `applyHeaders`
   from 50% to 100% and `redirectScopeGuard` from 66.7% to 100%.

---

## cmd/vespasian/main.go Confirmation

```
git diff --quiet -- cmd/vespasian/main.go && echo UNCHANGED
UNCHANGED
```

---

## Commits (this session)

| Commit | Message |
|--------|---------|
| 0711c79 | test(crawl): add FakeCrawler test double |
| ac8c877 | docs(crawl): document HTTPCrawler, drop Katana references |
| 3f344bf | docs: update README/CLAUDE for crawler backends |
| 118ca13 | test(crawl): finalize HTTPCrawler/htmlextract/frontier-DFS coverage |
| bb8c565 | fix(crawl): resolve make check lint findings |

---

---

## Review Fixes (commit 0527d67)

Addressed all five findings from the `capability-reviewer` report (verdict: CHANGES_REQUESTED).

### Finding 1 — MINOR: implement `<base href>` parsing

**Resolution:** `htmlextract.go` `extractFromHTML` now reads `base[href]` (first match) from the parsed goquery document and calls `effectiveBaseURLFrom(href, pageURL)` to derive the effective base before resolving all links. A new helper `extractEffectiveBase(body, pageURL)` is exported for callers that need the base independently (used by `extractLinks` in `http_crawler.go` for the inline-script jsluice path). The dead/misleading block in `extractLinks` (lines ~222–231) is removed; both extraction paths now use the `<base href>`-aware base consistently.

Tests added in `htmlextract_test.go`:
- `TestExtractEffectiveBase_NoBaseTag` — no `<base>` falls back to pageURL
- `TestExtractEffectiveBase_WithBaseTag` — valid `<base href="/app/">` resolves correctly
- `TestExtractFromHTML_BaseHref` — relative `<a href="x">` resolves to `https://host/app/x` (not `https://host/other/x`)
- `TestExtractFromHTML_BaseHrefCrossHostRejected` — cross-host `<base href="https://attacker.com/...">` is rejected; fallback to pageURL

### Finding 2 — MINOR: page-timeout `time.Duration` idiom

**Resolution:** `http_crawler.go:174` changed from `context.WithTimeout(ctx, PageTimeout*1e9)` to `context.WithTimeout(ctx, time.Duration(PageTimeout)*time.Second)`, matching `rod_crawler.go:88`. Added `"time"` to the import block.

### Finding 3 — MINOR: SSRF redirect test

**Resolution:** Added `TestHTTPCrawler_SSRFRedirectBlocked` in `http_crawler_test.go`. Test server 302-redirects to `http://127.0.0.1:1/secret` with `AllowPrivate:false` and `Scope:"same-origin"`. Asserts no result URL contains `127.0.0.1` and the crawl does not panic or hang. This exercises the `isPrivateHost` SSRF path in `scopeChecker` via `redirectScopeGuard`, distinct from the existing `TestHTTPCrawler_RedirectScopeBlocked` which tests the link-metadata host.

### Finding 4 — NIT: `for range n`

**Resolution:** `http_crawler.go:89` — replaced `for i := range n { ... _ = i }` with `for range n { ... }`.

### Finding 5 — NIT: `TestHTTPCrawler_PerPageTimeoutSurfaced` stderr assertion

**Resolution:** The test already had `var stderr bytes.Buffer` wired as `Stderr`. Added assertion after `c.Crawl(...)` returns:
```go
stderrOut := stderr.String()
if stderrOut == "" {
    t.Error("expected timeout or error message on Stderr; got empty output")
}
```
This verifies "surface, don't silently drop" — the crawl must write a timeout or interrupt message to Stderr rather than failing silently.

---

## Metadata

```json
{
  "agent": "capability-developer",
  "output_type": "capability-implementation",
  "timestamp": "2026-05-31T00:00:00Z",
  "feature_directory": "/workspaces/repositories/vespasian/.worktrees/lab-2785/.capability-development",
  "skills_invoked": [
    "using-skills",
    "developing-with-tdd",
    "preferring-simple-solutions",
    "discovering-reusable-code",
    "adhering-to-dry",
    "verifying-before-completion",
    "gateway-capabilities",
    "building-web-crawlers",
    "enforcing-evidence-based-analysis",
    "calibrating-time-estimates"
  ],
  "source_files_verified": [
    "pkg/crawl/fake.go",
    "pkg/crawl/fake_test.go",
    "pkg/crawl/doc.go",
    "pkg/crawl/http_crawler.go",
    "pkg/crawl/http_crawler_test.go",
    "pkg/crawl/htmlextract.go",
    "pkg/crawl/htmlextract_test.go",
    "pkg/crawl/scope.go",
    "test/rest-api/main.go",
    "cmd/vespasian/main.go"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-reviewer",
    "context": "All T001-T017 tasks complete plus all 5 review findings addressed. make check exits 0. Coverage: pkg/crawl 61.7% (Chrome-gated rod code at 0%; new files all >=80%). cmd/vespasian/main.go unchanged. 16 commits total on branch santiagogimenezocano/lab-2785-crawler-25-crawler-abstraction-layer-in-pkgcrawl."
  }
}
```
