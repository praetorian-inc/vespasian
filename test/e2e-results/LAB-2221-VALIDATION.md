# LAB-2221 Validation: SPA Crawl Fixes

**Date:** 2026-04-20
**Branch:** `eliwald/lab-2221-spa-crawl-url-resolution-bug-and-no-xhrfetch-interception`
**Target:** OWASP Juice Shop (`http://localhost:3000`)

## Summary

Both issues from LAB-2221 are resolved. A 17KB OpenAPI spec is now generated
from Juice Shop (previously 0 bytes) with 8 concrete API endpoints.

## Fixes

### Issue A — URL resolution does not respect `<base href>`

`pkg/crawl/links.go` now calls `effectiveBaseURL(page, pageURL)` before
resolving relative refs. `effectiveBaseURL` reads `<base href>` from the DOM,
resolves it against the page URL (the base tag itself may be relative), and
returns the result. `pkg/crawl/engine.go` (`enrichFromPage`) and
`pkg/crawl/forms.go` now use the same helper, so DOM links, form actions, and
jsluice-discovered URLs all honor the base tag consistently.

### Issue B — No XHR/fetch interception

Already landed on `main` via PR #66 (`feat: replace Katana headless crawl with
concurrent go-rod engine`). The go-rod engine enables the CDP Network domain
and captures every `NetworkRequestWillBeSent` / `NetworkResponseReceived` /
`NetworkLoadingFinished` event on each tab. Confirmed in the E2E run below.

### Asset-filter (defensive fix for the same symptom)

`isLikelyPage` filters obvious non-page resources (JS bundles, stylesheets,
images, fonts, socket.io/engine.io) before they enter the frontier. Navigating
to those paths on an SPA catch-all server produces recursive mangled paths
(`/socket.io/socket.io/...`) that waste the page budget without surfacing any
new endpoints. Their content is still captured when the parent page loads
them, so we lose no coverage.

## E2E evidence

| Metric                              | Before (ticket)         | After (this branch)             |
| ----------------------------------- | ----------------------- | ------------------------------- |
| Requests captured                   | 22                      | 200                             |
| Unique URLs                         | ~7                      | 56                              |
| API requests in spec                | 0                       | 8                               |
| Spec size                           | 0 bytes                 | 17428 bytes                     |
| Mangled `/walletExploitAddress/...` | present                 | absent                          |
| Nested `/socket.io/socket.io/...`   | observed pre-fix        | absent                          |

### API endpoints surfaced in the generated spec

```
/api/Challenges
/api/Challenges/
/api/Quantitys/
/rest/admin/application-configuration
/rest/admin/application-version
/rest/languages
/rest/products/search
/socket.io/
```

### Reproduction

```bash
cd ~/tools/caesars/vespasian
make build
./bin/vespasian scan \
  --dangerous-allow-private --headless \
  --max-pages=200 --depth=5 --timeout=180s \
  -o juiceshop-spec.yaml \
  http://localhost:3000
```

Artifacts:
- `lab2221-fix-crawl.json` — raw capture with all 200 requests
- `lab2221-fix-spec.yaml` — generated OpenAPI 3 spec

## Tests

- Unit: `TestResolveURL_BaseHrefRoot`, `TestIsLikelyPage_*` in
  `pkg/crawl/links_test.go`
- Integration (`-tags=integration`): `TestRodEngine_BaseHrefResolution` in
  `pkg/crawl/engine_integration_test.go` — crawls a test server that mimics
  Juice Shop's `<base href="/">` + deep-path catch-all, asserts that
  `/login` (base-resolved) is crawled and `/deep/page/login` (page-URL-
  resolved) is not.
