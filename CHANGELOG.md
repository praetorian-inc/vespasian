# Changelog

All notable changes to Vespasian are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is maintained by hand and is the curated, human-readable history: each
pull request that changes user-facing behavior adds an entry under
[Unreleased](#unreleased), and at release time a maintainer renames that section
to the new version. It complements — rather than replaces — the per-release
GitHub Release notes that goreleaser generates from conventional commits (see
[`.goreleaser.yml`](.goreleaser.yml)). Those notes list the commit log for the
release, minus `docs:`/`ci:`/`deps:` commits (per that file's
`changelog.filters.exclude`); this file summarizes what matters to users and is
the canonical record of breaking changes. See
[CONTRIBUTING.md](CONTRIBUTING.md#changelog) for the per-PR update workflow.

## [Unreleased]

Work landed on `main` since `v1.0.0` but not yet tagged. Because this includes a
change to a persisted on-disk format (see Breaking changes), the next tagged
release is a new major version under SemVer.

### Breaking changes

- **`capture.json` `query_params` changed shape.** To support repeated query
  parameters (e.g. `?tag=a&tag=b`), the `query_params` field of each captured
  request changed from `map[string]string` to `map[string][]string`. Capture
  files produced by `v1.0.0` use the old single-value shape and are **not
  compatible** — they will not round-trip through `generate`. Regenerate the
  capture against the target with `crawl` or `import` (`scan` writes a
  generated spec, not a `capture.json`).
  ([LAB-2110](https://linear.app/praetorianlabs/issue/LAB-2110))
- **`crawl` now rejects private seed URLs by default.** At `v1.0.0` a `crawl`
  against a private host (`localhost`, `127.0.0.1`, RFC1918, link-local)
  succeeded; the crawl frontier's SSRF scope check now rejects such a seed and
  the crawl exits non-zero with no captures. Interactive users see an error
  naming the remedy, but scripted/CI callers crawling internal targets must be
  updated. Migration: pass `--dangerous-allow-private` to crawl a private host.
  ([LAB-2438](https://linear.app/praetorianlabs/issue/LAB-2438))

### Added

- **gRPC support.** Classifier, HTTP/2 length-prefixed wire-format parser,
  server-reflection probe, and `.proto` (proto3) generation, plus gRPC-Web
  bindings and grpc-gateway enumeration. gRPC is not auto-detected — pass
  `--api-type grpc` explicitly. `generate grpc` is not fully offline: descriptors
  are not stored in the capture, so it re-runs the reflection probe live.
  `--grpc-insecure-skip-verify` opts into skipping the TLS trust chain for
  self-signed reflection targets.
  ([LAB-2783](https://linear.app/praetorianlabs/issue/LAB-2783),
  [LAB-3864](https://linear.app/praetorianlabs/issue/LAB-3864))
- **JavaScript analysis for SPA endpoint discovery.** Static analysis of captured
  JS bundles (via jsluice) for API endpoints, source-map fetching, and
  fully-offline reconstruction of concat/service-prefix endpoints. JS-replay now
  also runs during `generate`, so a two-stage `crawl` → `generate` recovers the
  same SPA endpoints as a single `scan`.
  ([LAB-2108](https://linear.app/praetorianlabs/issue/LAB-2108),
  [LAB-3892](https://linear.app/praetorianlabs/issue/LAB-3892),
  [LAB-4992](https://linear.app/praetorianlabs/issue/LAB-4992))
- **HTML form extraction** from captured pages, for API parameter discovery.
- **Request-body parsing.** Form-encoded and multipart request bodies
  ([LAB-2106](https://linear.app/praetorianlabs/issue/LAB-2106)) and typed
  parameter extraction from SOAP request bodies
  ([LAB-2111](https://linear.app/praetorianlabs/issue/LAB-2111)).
- **Multi-value query parameters** preserved end-to-end from capture through spec
  generation (the change behind the breaking `query_params` shape above).
  ([LAB-2110](https://linear.app/praetorianlabs/issue/LAB-2110))
- **Richer REST path handling.** Path-parameter detection beyond UUIDs and numeric
  IDs, and opt-in slug path-merging via `--merge-slugs` / `--slug-threshold`.
  ([LAB-2107](https://linear.app/praetorianlabs/issue/LAB-2107),
  [LAB-4107](https://linear.app/praetorianlabs/issue/LAB-4107))
- **Proxy support.** `--proxy` on the HTTP crawl backend, threaded through the
  probe, JS-replay, WSDL-discovery, gRPC-reflection, and source-map fetch paths,
  with a CONNECT/SOCKS5 dialer. `--proxy-insecure` opts into bypassing proxy TLS
  verification.
  ([LAB-4011](https://linear.app/praetorianlabs/issue/LAB-4011),
  [LAB-4993](https://linear.app/praetorianlabs/issue/LAB-4993))
- **Session cookie propagation** across headless crawl requests.
  ([LAB-2222](https://linear.app/praetorianlabs/issue/LAB-2222))
- **mitmproxy native tnetstring flow format** support in the importer, alongside
  the existing Burp XML and HAR importers.
  ([LAB-2309](https://linear.app/praetorianlabs/issue/LAB-2309))
- **`pkg/sdk`** — capability-SDK integration for embedding Vespasian in
  Chariot/Guard hosts.

### Changed

- **Headless crawler replaced.** The Katana-based crawler was replaced by a
  concurrent go-rod engine, then generalized behind a `Crawler` interface with
  go-rod (headless) and `net/http` backends; Katana was removed entirely.
  ([LAB-2785](https://linear.app/praetorianlabs/issue/LAB-2785),
  [LAB-2786](https://linear.app/praetorianlabs/issue/LAB-2786))
- **Crawler egress hardened.** The crawler now pins the system Chrome (no
  auto-download) and disables browser telemetry; set `VESPASIAN_NO_SANDBOX=true`
  for containerized runs.
  ([LAB-4999](https://linear.app/praetorianlabs/issue/LAB-4999))
- **Deterministic output.** Request-to-endpoint mapping and classification
  ordering are now stable, so repeated runs and `scan` vs. two-stage
  `crawl`/`generate` produce byte-identical specs.
  ([LAB-4678](https://linear.app/praetorianlabs/issue/LAB-4678))
- Seed URLs rejected by the crawl frontier now fail loudly instead of silently,
  with user credentials redacted from the error.
  ([LAB-2438](https://linear.app/praetorianlabs/issue/LAB-2438))

### Fixed

- Honor `<base href>` and skip static asset URLs during SPA crawling.
  ([LAB-2221](https://linear.app/praetorianlabs/issue/LAB-2221))

### Security

- SSRF validation applied to proxied source-map fetches, so reaching private
  targets still requires `--dangerous-allow-private`.
  ([LAB-4993](https://linear.app/praetorianlabs/issue/LAB-4993))
- Importer input hardened against untrusted traffic. A shared 500 MB file-size
  cap bounds every format (Burp XML, HAR, and both mitmproxy paths). The native
  mitmproxy tnetstring path adds finer-grained limits — a 64 MB per-element cap
  and a 500k flow-count cap — and rejects host/port smuggling.

### Compatibility notes

- Capture files produced before the offline concat/service-prefix recovery
  ([LAB-4992](https://linear.app/praetorianlabs/issue/LAB-4992)) remain readable,
  but a later `generate` will not reconstruct concat/service-prefix SPA endpoints
  from them — they carry `static:js` entries but no `static:js-concat`, so the
  offline JS pass short-circuits. Regenerate the capture to pick these endpoints
  up. `import`-produced captures are unaffected.

## [1.0.0] - 2026-04-03

Initial public release of Vespasian — a black-box API specification generator
that discovers endpoints from observed HTTP traffic.

### Added

- **Two-stage pipeline.** Capture traffic (headless-browser crawl or import) into
  an intermediate `capture.json`, then classify, probe, and generate a
  specification from it. The `scan` command runs both stages; `crawl`/`import`
  and `generate` run them independently.
- **Specification generators:** OpenAPI 3.0 (REST), GraphQL SDL, and WSDL.
- **Traffic importers:** Burp XML, HAR, and mitmproxy.
- **SSRF protection** with connect-time re-resolution to defeat DNS rebinding;
  private targets require an explicit `--dangerous-allow-private`.

[Unreleased]: https://github.com/praetorian-inc/vespasian/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/praetorian-inc/vespasian/releases/tag/v1.0.0
