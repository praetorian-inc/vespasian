// Command concat-spa is a live test target for LAB-1368 concatenated URL
// extraction. It serves a single-page app whose API endpoints exist ONLY as
// runtime string concatenations inside an external JavaScript bundle:
//
//	"/api/users/".concat(uid, "/orders")   -> /api/users/0/orders
//	"/api/products/" + pid + "/reviews"    -> /api/products/0/reviews
//
// Neither full path appears as an href link or a plain string literal, so the
// headless crawl alone cannot reach them — only the post-crawl JS-replay
// concat extractor (Strategy 5) can reconstruct and probe them. The server
// answers the reconstructed paths (sentinel id = 0) with 200 JSON so they
// survive the 404 filter and land in the capture; a never-referenced control
// path (/api/missing/0/gone) returns 404 to confirm the crawler is not
// guessing.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8993"
	}

	mux := http.NewServeMux()

	// Readiness probe used by setup-live-targets.sh wait_for_http. It is NOT
	// linked from the SPA, so the crawl never visits it and it stays out of
	// the capture/spec.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok") //nolint:errcheck // test target best-effort
	})

	// Index page: only a <script src> tag, NO API paths. The crawl must
	// fetch app.js and run the concat extractor to discover any endpoint.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, indexHTML) //nolint:errcheck // test target best-effort
	})

	// External JS bundle: API paths exist only as concat / +-string
	// expressions with non-literal (identifier) operands.
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, appJS) //nolint:errcheck // test target best-effort
	})

	// Reconstructed concat endpoints (sentinel id = 0); match any id.
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/orders") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"orders":[{"id":1,"total":42}]}`) //nolint:errcheck // test target best-effort
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/products/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/reviews") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"reviews":[{"id":1,"stars":5}]}`) //nolint:errcheck // test target best-effort
			return
		}
		http.NotFound(w, r)
	})

	addr := ":" + port
	log.Printf("concat-spa listening on http://localhost%s/", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 0} //nolint:gosec // local test target, no timeout needed
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

const indexHTML = `<!doctype html><html><head>
<script src="/app.js"></script>
</head><body><h1>Concat SPA</h1></body></html>`

const appJS = `
function loadOrders(uid)  { return fetch("/api/users/".concat(uid, "/orders")).then(function (r) { return r.json(); }); }
function loadReviews(pid) { var u = "/api/products/" + pid + "/reviews"; return fetch(u).then(function (r) { return r.json(); }); }
function loadGone(x)      { return fetch("/api/missing/".concat(x, "/gone")); }
window.loadOrders = loadOrders;
window.loadReviews = loadReviews;
`
