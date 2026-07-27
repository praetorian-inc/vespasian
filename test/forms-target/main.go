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

// Command forms-target is a live test target for LAB-3269: end-to-end coverage
// of the static HTML <form> extraction analyzer (analyze.ExtractForms, added in
// LAB-2109 / PR #87). It serves a single HTML page containing several <form>
// elements whose submission endpoints exist ONLY as <form action=...> markup —
// never as an <a href> link or a fetch() call — so the headless/HTTP crawl can
// never reach them directly (Katana does not fill and submit forms). They enter
// the generated spec solely because `vespasian generate` runs ExtractForms over
// the captured HTML body (Source="static:html").
//
//	POST /api/login    urlencoded form  (text, password, hidden CSRF)
//	POST /api/register urlencoded form  (text, email, password, checkbox,
//	                                     radio, <select>, <textarea>, hidden)
//	POST /api/feedback multipart form   (text, <textarea>, file)
//	GET  /api/search   query form       (text "q", <select> "category")
//
// /api/search is ALSO reachable via an <a href> link so the crawler captures it
// as a real request; the co-located GET search form then contributes its query
// parameters (q, category) to that endpoint. Because a GET form scores 0
// confidence (no body, no API content-type) it is filtered out at the default
// 0.5 threshold — the runner re-generates at --confidence 0 to assert those
// merged parameters (see test_forms_target in run-live-tests.sh).
//
// The three POST endpoints are NOT backed by real handlers: the crawler only
// issues GET navigations, so a GET to a POST-form action falls through to the
// catch-all "/" handler and returns 404 (never classified). Their presence in
// the generated spec therefore proves ExtractForms parsed the forms.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8994"
	}

	mux := http.NewServeMux()

	// Readiness probe used by setup-live-targets.sh wait_for_http. It is NOT
	// linked from the page, so the crawl never visits it and it stays out of
	// the capture/spec.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok") //nolint:errcheck // test target best-effort
	})

	// Index page: the ONLY HTML the crawl captures. It carries every <form>
	// (login/register/feedback/search) plus a single <a href> link to
	// /api/search. The catch-all guard returns 404 for anything else — notably
	// a stray GET to a POST-form action — so those endpoints can only ever come
	// from static-HTML form extraction, not from a captured GET response.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, indexHTML) //nolint:errcheck // test target best-effort
	})

	// Real GET endpoint, linked from the index so the crawl captures it as an
	// observed request (application/json → classified as REST). The GET search
	// form's query parameters merge onto this endpoint during generation.
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"results":[],"query":""}`) //nolint:errcheck // test target best-effort
	})

	// Bind loopback by default. The devcontainer flow (a crawler inside a
	// container reaching this host via TEST_HOST=host.docker.internal) needs a
	// wider bind; setup-live-targets.sh opts into that explicitly via BIND_HOST.
	host := os.Getenv("BIND_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	log.Printf("forms-target listening on http://%s/", addr) //nolint:gosec // G706: host/port come from controlled BIND_HOST/PORT env vars for a local test target, not attacker input
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// indexHTML is the sole captured page. Every form uses a same-origin relative
// action (resolved against the page URL by analyze.resolveAction) and exercises
// a distinct input mix. The login/register/feedback actions are POST and appear
// standalone at the default 0.5 confidence; the search form is GET and is
// validated at --confidence 0. Hidden/CSRF field VALUES are blanked by the
// analyzer but their NAMES are still emitted.
const indexHTML = `<!doctype html>
<html>
<head><title>Forms Target</title></head>
<body>
<h1>Forms Target</h1>

<!-- POST, application/x-www-form-urlencoded: text, password, hidden CSRF -->
<form action="/api/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="csrf_token" value="live-test-csrf">
  <button type="submit">Log in</button>
</form>

<!-- POST, urlencoded: various input types (text/email/password/checkbox/radio/select/textarea/hidden) -->
<form action="/api/register" method="post">
  <input type="text" name="username">
  <input type="email" name="email">
  <input type="password" name="password">
  <input type="checkbox" name="subscribe" value="yes">
  <input type="radio" name="plan" value="free">
  <input type="radio" name="plan" value="pro">
  <select name="role">
    <option value="user">User</option>
    <option value="admin">Admin</option>
  </select>
  <textarea name="bio"></textarea>
  <input type="hidden" name="_token" value="live-test-token">
  <button type="submit">Register</button>
</form>

<!-- POST, multipart/form-data: exercises enctype handling (file field is skipped by the analyzer) -->
<form action="/api/feedback" method="post" enctype="multipart/form-data">
  <input type="text" name="subject">
  <textarea name="message"></textarea>
  <input type="file" name="attachment">
  <button type="submit">Send feedback</button>
</form>

<!-- GET: query-parameter form; its q/category params merge onto the crawled /api/search endpoint -->
<form action="/api/search" method="get">
  <input type="text" name="q">
  <select name="category">
    <option value="all">All</option>
    <option value="docs">Docs</option>
  </select>
  <button type="submit">Search</button>
</form>

<p><a href="/api/search">Browse all results</a></p>
</body>
</html>`
