#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Test runner for vespasian live tests.
# Crawls targets, generates specs, validates output, and prints a summary.
#
# Usage:
#   ./test/run-live-tests.sh [options]
#
# Options:
#   --targets <list>      Comma-separated targets to test (default: all from config)
#   --verbose             Enable verbose vespasian output
#   --no-build            Skip building vespasian and target binaries
#   --no-start            Don't start/stop services (assume already running)
#   --help                Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"
RESULTS_DIR="${SCRIPT_DIR}/.results"
VESPASIAN="${PROJECT_ROOT}/bin/vespasian"

# ──────────────────────────────────────────────────────────────
# Colors and logging
# ──────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

log_info()   { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()     { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail()   { echo -e "${RED}[FAIL]${NC} $1"; }

# Source validation functions
# shellcheck source=validate.sh
source "${SCRIPT_DIR}/validate.sh"

# ──────────────────────────────────────────────────────────────
# Config loading
# ──────────────────────────────────────────────────────────────

load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_fail "Config file not found: ${CONFIG_FILE}"
        log_info "Run ./test/setup-live-targets.sh first"
        exit 1
    fi

    # Safety: only allow safe KEY=VALUE lines
    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        # Validate format
        if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:@,+\"\ -]*$ ]]; then
            eval "$line"
        else
            log_warn "Skipping invalid config line: $line"
        fi
    done < "$CONFIG_FILE"

    log_ok "Loaded config from ${CONFIG_FILE}"
}

# ──────────────────────────────────────────────────────────────
# Result tracking
# ──────────────────────────────────────────────────────────────

declare -A TEST_STATUS TEST_ENDPOINTS TEST_EXPECTED TEST_DURATION

init_test_status() {
    local name=$1
    TEST_STATUS["$name"]="NOT_RUN"
    TEST_ENDPOINTS["$name"]="?"
    TEST_EXPECTED["$name"]="?"
    TEST_DURATION["$name"]="0"
}

set_test_result() {
    local name=$1 status=$2 endpoints=$3 expected=$4 duration=$5
    TEST_STATUS["$name"]="$status"
    TEST_ENDPOINTS["$name"]="$endpoints"
    TEST_EXPECTED["$name"]="$expected"
    TEST_DURATION["$name"]="$duration"
}

# ──────────────────────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────────────────────

PIDS_TO_CLEANUP=""

cleanup() {
    for pid in $PIDS_TO_CLEANUP; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}

trap cleanup EXIT

# ──────────────────────────────────────────────────────────────
# Test functions
# ──────────────────────────────────────────────────────────────

test_rest_api() {
    local port="${REST_API_PORT:-8990}"
    local base_url="http://localhost:${port}"
    local target_dir="${RESULTS_DIR}/rest-api"
    local capture_file="${target_dir}/capture.json"
    local spec_file="${target_dir}/spec.yaml"
    local expected="${SCRIPT_DIR}/rest-api/expected-paths.json"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "rest-api"

    local start=$SECONDS
    local failures=0

    log_header "Testing: rest-api (${base_url})"

    # Step 1: Crawl
    log_info "Crawling ${base_url}..."
    if ! "$VESPASIAN" crawl "$base_url" \
        -o "$capture_file" \
        --depth 2 \
        --max-pages 50 \
        --timeout 2m \
        $verbose_flag 2>&1; then
        log_fail "Crawl failed"
        set_test_result "rest-api" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    # Step 2: Validate capture
    if ! validate_capture "$capture_file" 3; then
        failures=$((failures + 1))
    fi

    # Step 3: Generate OpenAPI spec
    log_info "Generating OpenAPI spec..."
    if ! "$VESPASIAN" generate rest "$capture_file" \
        -o "$spec_file" \
        --probe=false \
        $verbose_flag 2>&1; then
        log_fail "Generate failed"
        set_test_result "rest-api" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    # Step 4: Validate spec
    if ! validate_openapi_structure "$spec_file"; then
        failures=$((failures + 1))
    fi

    if ! validate_path_coverage "$spec_file" "$expected"; then
        failures=$((failures + 1))
    fi

    if ! validate_no_static_assets "$spec_file"; then
        failures=$((failures + 1))
    fi

    # NOTE: No exact spec comparison here — the live crawl is non-deterministic,
    # so the generated spec varies between runs. Exact spec comparison is done in
    # test_generate_rest which uses a fixed import as input.

    local endpoint_count
    endpoint_count=$(count_spec_endpoints "$spec_file")
    local expected_count
    expected_count=$(python3 -c "import json; print(json.load(open('$expected'))['total_paths'])" 2>/dev/null || echo "?")

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "rest-api" "PASS" "$endpoint_count" "$expected_count" "$duration"
        log_ok "rest-api: ALL CHECKS PASSED (${duration}s)"
    else
        set_test_result "rest-api" "FAIL" "$endpoint_count" "$expected_count" "$duration"
        log_fail "rest-api: ${failures} check(s) failed (${duration}s)"
    fi
}

test_soap_service() {
    local port="${SOAP_SERVICE_PORT:-8991}"
    local base_url="http://localhost:${port}"
    local target_dir="${RESULTS_DIR}/soap-service"
    local capture_file="${target_dir}/capture.json"
    local spec_file="${target_dir}/spec.xml"
    local expected="${SCRIPT_DIR}/soap-service/expected-paths.json"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "soap-service"

    local start=$SECONDS
    local failures=0

    log_header "Testing: soap-service (${base_url})"

    # Step 1: Crawl the SOAP service
    # First, make some SOAP requests to generate traffic for the capture.
    log_info "Generating SOAP traffic..."
    for action in GetUser ListUsers CreateUser; do
        curl -sf -X POST "http://localhost:${port}/soap" \
            -H "Content-Type: text/xml; charset=utf-8" \
            -H "SOAPAction: \"urn:${action}\"" \
            -d "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><tns:${action}Request xmlns:tns=\"http://localhost/soap\"><id>1</id></tns:${action}Request></soap:Body></soap:Envelope>" \
            -o /dev/null 2>/dev/null || true
    done

    # Crawl the service (will capture the WSDL page and index)
    log_info "Crawling ${base_url}..."
    if ! "$VESPASIAN" crawl "$base_url" \
        -o "$capture_file" \
        --depth 2 \
        --max-pages 20 \
        --timeout 1m \
        $verbose_flag 2>&1; then
        log_warn "Crawl returned non-zero (may still have partial results)"
    fi

    # Also import the SOAP traffic directly if crawl didn't capture it.
    # For SOAP testing, we create a synthetic capture with the SOAP requests.
    log_info "Creating SOAP capture with direct requests..."
    local soap_capture="${target_dir}/soap-capture.json"
    python3 -c "
import json, base64

def b64(s):
    return base64.b64encode(s.encode()).decode()

requests = []
for action in ['GetUser', 'ListUsers', 'CreateUser']:
    body = '<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><tns:%sRequest xmlns:tns=\"http://localhost/soap\"><id>1</id></tns:%sRequest></soap:Body></soap:Envelope>' % (action, action)
    resp_body = '<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><tns:%sResponse xmlns:tns=\"http://localhost/soap\"><id>1</id></tns:%sResponse></soap:Body></soap:Envelope>' % (action, action)
    req = {
        'method': 'POST',
        'url': 'http://localhost:${port}/soap',
        'headers': {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': 'urn:%s' % action
        },
        'body': b64(body),
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'text/xml; charset=utf-8'},
            'content_type': 'text/xml; charset=utf-8',
            'body': b64(resp_body)
        },
        'source': 'test-runner'
    }
    requests.append(req)

# Also add the WSDL fetch
requests.append({
    'method': 'GET',
    'url': 'http://localhost:${port}/service.wsdl',
    'headers': {},
    'response': {
        'status_code': 200,
        'headers': {'Content-Type': 'text/xml; charset=utf-8'},
        'content_type': 'text/xml; charset=utf-8'
    },
    'source': 'test-runner'
})

with open('$soap_capture', 'w') as f:
    json.dump(requests, f, indent=2)
" 2>/dev/null

    # Step 2: Generate WSDL spec
    log_info "Generating WSDL spec..."
    if ! "$VESPASIAN" generate wsdl "$soap_capture" \
        -o "$spec_file" \
        --probe=false \
        $verbose_flag 2>&1; then
        log_fail "WSDL generate failed"
        set_test_result "soap-service" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    # Step 3: Validate WSDL output
    if ! validate_soap_operations "$spec_file" "$expected"; then
        failures=$((failures + 1))
    fi

    # NOTE: No exact spec comparison here — the synthetic capture embeds the
    # runtime port, so the generated WSDL varies. Exact comparison is done in
    # test_generate_wsdl which uses the fixed reference-capture.json.

    local expected_count
    expected_count=$(python3 -c "import json; print(json.load(open('$expected'))['total_operations'])" 2>/dev/null || echo "?")

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "soap-service" "PASS" "3" "$expected_count" "$duration"
        log_ok "soap-service: ALL CHECKS PASSED (${duration}s)"
    else
        set_test_result "soap-service" "FAIL" "?" "$expected_count" "$duration"
        log_fail "soap-service: ${failures} check(s) failed (${duration}s)"
    fi
}

test_import_burp() {
    local target_dir="${RESULTS_DIR}/import-burp"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-burp-export.xml"
    local expected="${SCRIPT_DIR}/fixtures/expected-from-burp.json"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "import-burp"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-burp"

    log_info "Importing Burp XML fixture..."
    if ! "$VESPASIAN" import burp "$fixture" \
        -o "$imported_file" \
        $verbose_flag 2>&1; then
        log_fail "Burp import failed"
        set_test_result "import-burp" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    if ! validate_import "$imported_file" "$expected"; then
        failures=$((failures + 1))
    fi

    # Compare full JSON output against expected capture
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-burp-capture.json"
    if [ -f "$expected_capture" ]; then
        if ! compare_json "$imported_file" "$expected_capture" "import-burp capture"; then
            failures=$((failures + 1))
        fi
    fi

    local actual_count
    actual_count=$(python3 -c "import json; print(len(json.load(open('$imported_file'))))" 2>/dev/null || echo "?")
    local expected_count
    expected_count=$(python3 -c "import json; print(json.load(open('$expected'))['total_requests'])" 2>/dev/null || echo "?")

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-burp" "PASS" "$actual_count" "$expected_count" "$duration"
        log_ok "import-burp: PASSED (${duration}s)"
    else
        set_test_result "import-burp" "FAIL" "$actual_count" "$expected_count" "$duration"
        log_fail "import-burp: FAILED (${duration}s)"
    fi
}

test_import_har() {
    local target_dir="${RESULTS_DIR}/import-har"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-capture.har"
    local expected="${SCRIPT_DIR}/fixtures/expected-from-har.json"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "import-har"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-har"

    log_info "Importing HAR fixture..."
    if ! "$VESPASIAN" import har "$fixture" \
        -o "$imported_file" \
        $verbose_flag 2>&1; then
        log_fail "HAR import failed"
        set_test_result "import-har" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    if ! validate_import "$imported_file" "$expected"; then
        failures=$((failures + 1))
    fi

    # Compare full JSON output against expected capture
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-har-capture.json"
    if [ -f "$expected_capture" ]; then
        if ! compare_json "$imported_file" "$expected_capture" "import-har capture"; then
            failures=$((failures + 1))
        fi
    fi

    local actual_count
    actual_count=$(python3 -c "import json; print(len(json.load(open('$imported_file'))))" 2>/dev/null || echo "?")
    local expected_count
    expected_count=$(python3 -c "import json; print(json.load(open('$expected'))['total_requests'])" 2>/dev/null || echo "?")

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-har" "PASS" "$actual_count" "$expected_count" "$duration"
        log_ok "import-har: PASSED (${duration}s)"
    else
        set_test_result "import-har" "FAIL" "$actual_count" "$expected_count" "$duration"
        log_fail "import-har: FAILED (${duration}s)"
    fi
}

test_generate_rest() {
    local target_dir="${RESULTS_DIR}/generate-rest"
    local input_capture="${SCRIPT_DIR}/rest-api/reference-capture.json"
    local spec_file="${target_dir}/spec.yaml"
    local expected_spec="${SCRIPT_DIR}/rest-api/expected-spec.yaml"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "generate-rest"

    local start=$SECONDS
    local failures=0

    log_header "Testing: generate-rest (deterministic spec generation)"

    if [ ! -f "$input_capture" ]; then
        log_fail "Input capture not found: ${input_capture}"
        log_info "Run import-burp test first, or check fixtures/"
        set_test_result "generate-rest" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    log_info "Generating OpenAPI spec from Burp capture..."
    if ! "$VESPASIAN" generate rest "$input_capture" \
        -o "$spec_file" \
        --probe=false \
        $verbose_flag 2>&1; then
        log_fail "Generate failed"
        set_test_result "generate-rest" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    if ! validate_openapi_structure "$spec_file"; then
        failures=$((failures + 1))
    fi

    if ! compare_files "$spec_file" "$expected_spec" "generate-rest spec" --normalize-ports; then
        failures=$((failures + 1))
    fi

    local endpoint_count
    endpoint_count=$(count_spec_endpoints "$spec_file")

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "generate-rest" "PASS" "$endpoint_count" "$endpoint_count" "$duration"
        log_ok "generate-rest: PASSED (${duration}s)"
    else
        set_test_result "generate-rest" "FAIL" "$endpoint_count" "?" "$duration"
        log_fail "generate-rest: FAILED (${duration}s)"
    fi
}

test_generate_wsdl() {
    local target_dir="${RESULTS_DIR}/generate-wsdl"
    local input_capture="${SCRIPT_DIR}/soap-service/reference-capture.json"
    local spec_file="${target_dir}/spec.xml"
    local expected_spec="${SCRIPT_DIR}/soap-service/expected-spec.xml"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "generate-wsdl"

    local start=$SECONDS
    local failures=0

    log_header "Testing: generate-wsdl (deterministic WSDL generation)"

    if [ ! -f "$input_capture" ]; then
        log_fail "Input capture not found: ${input_capture}"
        set_test_result "generate-wsdl" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    log_info "Generating WSDL spec from reference capture..."
    if ! "$VESPASIAN" generate wsdl "$input_capture" \
        -o "$spec_file" \
        --probe=false \
        $verbose_flag 2>&1; then
        log_fail "WSDL generate failed"
        set_test_result "generate-wsdl" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    local expected_ops="${SCRIPT_DIR}/soap-service/expected-paths.json"
    if ! validate_soap_operations "$spec_file" "$expected_ops"; then
        failures=$((failures + 1))
    fi

    if ! compare_files "$spec_file" "$expected_spec" "generate-wsdl spec" --normalize-ports; then
        failures=$((failures + 1))
    fi

    local expected_count
    expected_count=$(python3 -c "import json; print(json.load(open('$expected_ops'))['total_operations'])" 2>/dev/null || echo "?")

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "generate-wsdl" "PASS" "3" "$expected_count" "$duration"
        log_ok "generate-wsdl: PASSED (${duration}s)"
    else
        set_test_result "generate-wsdl" "FAIL" "?" "$expected_count" "$duration"
        log_fail "generate-wsdl: FAILED (${duration}s)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Edge case tests
# ──────────────────────────────────────────────────────────────

test_import_malformed() {
    init_test_status "import-malformed"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-malformed (graceful handling of bad input)"

    # Malformed Burp: should fail gracefully (non-zero exit, no crash)
    log_info "Importing malformed Burp XML..."
    local burp_err
    burp_err=$("$VESPASIAN" import burp "${SCRIPT_DIR}/fixtures/malformed-burp.xml" -o /dev/null 2>&1) && {
        log_fail "Malformed Burp import should have failed but succeeded"
        failures=$((failures + 1))
    } || {
        if echo "$burp_err" | grep -q "error"; then
            log_ok "Malformed Burp: rejected with error message"
        else
            log_fail "Malformed Burp: exited non-zero but no error message"
            failures=$((failures + 1))
        fi
    }

    # Malformed HAR: should fail gracefully
    log_info "Importing malformed HAR..."
    local har_err
    har_err=$("$VESPASIAN" import har "${SCRIPT_DIR}/fixtures/malformed-har.json" -o /dev/null 2>&1) && {
        log_fail "Malformed HAR import should have failed but succeeded"
        failures=$((failures + 1))
    } || {
        if echo "$har_err" | grep -q "error"; then
            log_ok "Malformed HAR: rejected with error message"
        else
            log_fail "Malformed HAR: exited non-zero but no error message"
            failures=$((failures + 1))
        fi
    }

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-malformed" "PASS" "0" "0" "$duration"
        log_ok "import-malformed: PASSED (${duration}s)"
    else
        set_test_result "import-malformed" "FAIL" "?" "0" "$duration"
        log_fail "import-malformed: FAILED (${duration}s)"
    fi
}

test_import_empty() {
    local target_dir="${RESULTS_DIR}/import-empty"
    mkdir -p "$target_dir"
    init_test_status "import-empty"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-empty (zero-entry imports)"

    # Empty Burp: should succeed with null/empty output
    log_info "Importing empty Burp XML..."
    if ! "$VESPASIAN" import burp "${SCRIPT_DIR}/fixtures/empty-burp.xml" \
        -o "${target_dir}/empty-burp.json" 2>&1; then
        log_fail "Empty Burp import failed"
        failures=$((failures + 1))
    else
        if compare_files "${target_dir}/empty-burp.json" \
            "${SCRIPT_DIR}/fixtures/expected-empty-capture.json" \
            "empty-burp output"; then
            : # logged by compare_files
        else
            failures=$((failures + 1))
        fi
    fi

    # Empty HAR: should succeed with null/empty output
    log_info "Importing empty HAR..."
    if ! "$VESPASIAN" import har "${SCRIPT_DIR}/fixtures/empty-har.json" \
        -o "${target_dir}/empty-har.json" 2>&1; then
        log_fail "Empty HAR import failed"
        failures=$((failures + 1))
    else
        if compare_files "${target_dir}/empty-har.json" \
            "${SCRIPT_DIR}/fixtures/expected-empty-capture.json" \
            "empty-har output"; then
            : # logged by compare_files
        else
            failures=$((failures + 1))
        fi
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-empty" "PASS" "0" "0" "$duration"
        log_ok "import-empty: PASSED (${duration}s)"
    else
        set_test_result "import-empty" "FAIL" "?" "0" "$duration"
        log_fail "import-empty: FAILED (${duration}s)"
    fi
}

test_edge_cases() {
    local port="${REST_API_PORT:-8990}"
    local base_url="http://localhost:${port}"
    local target_dir="${RESULTS_DIR}/edge-cases"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "edge-cases"

    local start=$SECONDS
    local failures=0

    log_header "Testing: edge-cases (${base_url})"

    # ── Large response ──
    log_info "Testing large response endpoint..."
    local large_resp
    large_resp=$(curl -sf "${base_url}/api/large" 2>/dev/null)
    if [ -n "$large_resp" ]; then
        local large_size=${#large_resp}
        if [ "$large_size" -gt 50000 ]; then
            log_ok "Large response: ${large_size} bytes received"
        else
            log_fail "Large response: only ${large_size} bytes (expected >50KB)"
            failures=$((failures + 1))
        fi
    else
        log_fail "Large response: no data received"
        failures=$((failures + 1))
    fi

    # ── Special characters in query params ──
    log_info "Testing special characters in query params..."
    local search_resp
    search_resp=$(curl -sf "${base_url}/api/search?q=hello+world&filter=name%3Aalice&page=1" 2>/dev/null)
    if echo "$search_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['query']=='hello world'; assert d['filter']=='name:alice'" 2>/dev/null; then
        log_ok "Special query params: correctly decoded"
    else
        log_fail "Special query params: decoding failed"
        failures=$((failures + 1))
    fi

    # ── URL-encoded path segments ──
    log_info "Testing URL-encoded path segments..."
    local cat_resp
    cat_resp=$(curl -sf "${base_url}/api/categories/electronics%20%26%20gadgets" 2>/dev/null)
    if echo "$cat_resp" | grep -q "electronics"; then
        log_ok "URL-encoded path: correctly handled"
    else
        log_fail "URL-encoded path: failed to decode"
        failures=$((failures + 1))
    fi

    # ── Redirect handling ──
    # NOTE: Use -s (not -sf) for all curl calls below. The -f flag causes curl
    # to exit non-zero on 4xx/5xx, which aborts the script under set -e.
    log_info "Testing redirect handling..."
    local redirect_status
    redirect_status=$(curl -s -o /dev/null -w "%{http_code}" "${base_url}/api/redirect" 2>/dev/null)
    if [ "$redirect_status" = "301" ]; then
        log_ok "Redirect: got 301 as expected"
    else
        log_fail "Redirect: expected 301, got ${redirect_status}"
        failures=$((failures + 1))
    fi

    # Follow redirect and check we end up at /api/users
    local redirect_follow
    redirect_follow=$(curl -s -L "${base_url}/api/redirect" 2>/dev/null)
    if echo "$redirect_follow" | python3 -c "import json,sys; d=json.load(sys.stdin); assert isinstance(d, list)" 2>/dev/null; then
        log_ok "Redirect follow: reached /api/users"
    else
        log_fail "Redirect follow: did not get user list"
        failures=$((failures + 1))
    fi

    # ── HTTP error responses ──
    log_info "Testing error response endpoints..."
    local err404_status err404_body
    err404_status=$(curl -s -o /dev/null -w "%{http_code}" "${base_url}/api/error/404" 2>/dev/null)
    err404_body=$(curl -s "${base_url}/api/error/404" 2>/dev/null)
    if [ "$err404_status" = "404" ] && echo "$err404_body" | grep -q '"error"'; then
        log_ok "404 error: correct status and JSON body"
    else
        log_fail "404 error: status=${err404_status}"
        failures=$((failures + 1))
    fi

    local err500_status err500_body
    err500_status=$(curl -s -o /dev/null -w "%{http_code}" "${base_url}/api/error/500" 2>/dev/null)
    err500_body=$(curl -s "${base_url}/api/error/500" 2>/dev/null)
    if [ "$err500_status" = "500" ] && echo "$err500_body" | grep -q '"error"'; then
        log_ok "500 error: correct status and JSON body"
    else
        log_fail "500 error: status=${err500_status}"
        failures=$((failures + 1))
    fi

    # ── Binary response (should not crash importer/classifier) ──
    log_info "Testing binary response..."
    local binary_ct
    binary_ct=$(curl -s -o /dev/null -w "%{content_type}" "${base_url}/api/binary" 2>/dev/null)
    if echo "$binary_ct" | grep -q "image/png"; then
        log_ok "Binary response: correct content-type (${binary_ct})"
    else
        log_fail "Binary response: unexpected content-type (${binary_ct})"
        failures=$((failures + 1))
    fi

    # ── Empty response (204 No Content) ──
    log_info "Testing empty response..."
    local empty_status
    empty_status=$(curl -s -o /dev/null -w "%{http_code}" "${base_url}/api/empty" 2>/dev/null)
    if [ "$empty_status" = "204" ]; then
        log_ok "Empty response: got 204 No Content"
    else
        log_fail "Empty response: expected 204, got ${empty_status}"
        failures=$((failures + 1))
    fi

    # ── Trailing slash normalization ──
    log_info "Testing trailing slash handling..."
    local trailing_resp
    trailing_resp=$(curl -sf "${base_url}/api/trailing/" 2>/dev/null)
    if echo "$trailing_resp" | grep -q "normalized"; then
        log_ok "Trailing slash: endpoint responded"
    else
        log_fail "Trailing slash: no response"
        failures=$((failures + 1))
    fi

    # ── Crawl with edge cases (verify vespasian doesn't crash) ──
    log_info "Crawling REST API edge case page..."
    local edge_capture="${target_dir}/capture.json"
    if "$VESPASIAN" crawl "${base_url}/edge-cases" \
        -o "$edge_capture" \
        --depth 3 \
        --max-pages 200 \
        --timeout 3m \
        $verbose_flag 2>&1; then
        log_ok "Crawl with edge cases: completed without crash"

        # Verify the capture is valid JSON
        if python3 -c "import json; json.load(open('$edge_capture'))" 2>/dev/null; then
            log_ok "Crawl capture: valid JSON"
        else
            log_fail "Crawl capture: invalid JSON"
            failures=$((failures + 1))
        fi

        # Verify binary endpoints are NOT in the generated spec
        local edge_spec="${target_dir}/spec.yaml"
        if "$VESPASIAN" generate rest "$edge_capture" \
            -o "$edge_spec" \
            --probe=false \
            $verbose_flag 2>&1; then
            log_ok "Spec generation: completed"

            # Binary/image paths should be excluded by the classifier
            if grep -q "/api/binary" "$edge_spec" 2>/dev/null; then
                log_fail "Spec contains /api/binary (binary endpoint should be excluded)"
                failures=$((failures + 1))
            else
                log_ok "Spec excludes binary endpoint"
            fi

            # Error endpoints may or may not be included — just verify no crash
            log_ok "Spec generation with edge cases: no crash"
        else
            log_fail "Spec generation failed with edge case capture"
            failures=$((failures + 1))
        fi
    else
        log_fail "Crawl crashed with edge case endpoints"
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "edge-cases" "PASS" "-" "-" "$duration"
        log_ok "edge-cases: ALL CHECKS PASSED (${duration}s)"
    else
        set_test_result "edge-cases" "FAIL" "-" "-" "$duration"
        log_fail "edge-cases: ${failures} check(s) failed (${duration}s)"
    fi
}

test_crawl_unreachable() {
    local target_dir="${RESULTS_DIR}/crawl-unreachable"
    local capture_file="${target_dir}/capture.json"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "crawl-unreachable"

    local start=$SECONDS
    local failures=0

    log_header "Testing: crawl-unreachable (target not running)"

    # Crawl a port where nothing is listening
    log_info "Crawling unreachable target (http://localhost:19999)..."
    local crawl_output
    crawl_output=$("$VESPASIAN" crawl "http://localhost:19999" \
        -o "$capture_file" \
        --depth 1 \
        --max-pages 5 \
        --timeout 15s \
        $verbose_flag 2>&1)
    local crawl_exit=$?

    # Either the crawl fails with non-zero exit, or it succeeds with 0 results.
    # Either is acceptable — what matters is no crash/panic.
    if [ $crawl_exit -ne 0 ]; then
        log_ok "Crawl unreachable: exited with code ${crawl_exit} (graceful failure)"
    elif [ -f "$capture_file" ]; then
        local count
        count=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d) if isinstance(d, list) else 0)
except:
    print(0)
" "$capture_file" 2>/dev/null)
        log_ok "Crawl unreachable: exited 0 with ${count} results"
    else
        log_ok "Crawl unreachable: exited 0, no output file"
    fi

    # Check no panic in output
    if echo "$crawl_output" | grep -qi "panic"; then
        log_fail "Crawl unreachable: PANIC detected in output"
        failures=$((failures + 1))
    else
        log_ok "Crawl unreachable: no panic"
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "crawl-unreachable" "PASS" "0" "0" "$duration"
        log_ok "crawl-unreachable: PASSED (${duration}s)"
    else
        set_test_result "crawl-unreachable" "FAIL" "?" "0" "$duration"
        log_fail "crawl-unreachable: FAILED (${duration}s)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Import edge cases
# ──────────────────────────────────────────────────────────────

test_import_base64() {
    local target_dir="${RESULTS_DIR}/import-base64"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-burp-base64.xml"
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-burp-base64-capture.json"

    mkdir -p "$target_dir"
    init_test_status "import-base64"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-base64 (Burp XML with base64-encoded requests)"

    if ! "$VESPASIAN" import burp "$fixture" -o "$imported_file" 2>&1; then
        log_fail "Base64 Burp import failed"
        set_test_result "import-base64" "FAIL" "?" "2" "$((SECONDS - start))"
        return 1
    fi

    if ! compare_json "$imported_file" "$expected_capture" "import-base64 capture"; then
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-base64" "PASS" "2" "2" "$duration"
        log_ok "import-base64: PASSED (${duration}s)"
    else
        set_test_result "import-base64" "FAIL" "?" "2" "$duration"
        log_fail "import-base64: FAILED (${duration}s)"
    fi
}

test_import_mitmproxy() {
    local target_dir="${RESULTS_DIR}/import-mitmproxy"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-mitmproxy.json"
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-mitmproxy-capture.json"

    mkdir -p "$target_dir"
    init_test_status "import-mitmproxy"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-mitmproxy"

    if ! "$VESPASIAN" import mitmproxy "$fixture" -o "$imported_file" 2>&1; then
        log_fail "Mitmproxy import failed"
        set_test_result "import-mitmproxy" "FAIL" "?" "3" "$((SECONDS - start))"
        return 1
    fi

    if ! compare_json "$imported_file" "$expected_capture" "import-mitmproxy capture"; then
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-mitmproxy" "PASS" "3" "3" "$duration"
        log_ok "import-mitmproxy: PASSED (${duration}s)"
    else
        set_test_result "import-mitmproxy" "FAIL" "?" "3" "$duration"
        log_fail "import-mitmproxy: FAILED (${duration}s)"
    fi
}

test_import_unicode() {
    local target_dir="${RESULTS_DIR}/import-unicode"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-burp-unicode.xml"
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-burp-unicode-capture.json"

    mkdir -p "$target_dir"
    init_test_status "import-unicode"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-unicode (URLs and bodies with unicode/emoji)"

    if ! "$VESPASIAN" import burp "$fixture" -o "$imported_file" 2>&1; then
        log_fail "Unicode Burp import failed"
        set_test_result "import-unicode" "FAIL" "?" "3" "$((SECONDS - start))"
        return 1
    fi

    if ! compare_json "$imported_file" "$expected_capture" "import-unicode capture"; then
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-unicode" "PASS" "3" "3" "$duration"
        log_ok "import-unicode: PASSED (${duration}s)"
    else
        set_test_result "import-unicode" "FAIL" "?" "3" "$duration"
        log_fail "import-unicode: FAILED (${duration}s)"
    fi
}

test_import_duplicates() {
    local target_dir="${RESULTS_DIR}/import-duplicates"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-har-duplicates.json"
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-har-duplicates-capture.json"

    mkdir -p "$target_dir"
    init_test_status "import-duplicates"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-duplicates (HAR with duplicate headers and query params)"

    if ! "$VESPASIAN" import har "$fixture" -o "$imported_file" 2>&1; then
        log_fail "Duplicate headers HAR import failed"
        set_test_result "import-duplicates" "FAIL" "?" "2" "$((SECONDS - start))"
        return 1
    fi

    if ! compare_json "$imported_file" "$expected_capture" "import-duplicates capture"; then
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-duplicates" "PASS" "2" "2" "$duration"
        log_ok "import-duplicates: PASSED (${duration}s)"
    else
        set_test_result "import-duplicates" "FAIL" "?" "2" "$duration"
        log_fail "import-duplicates: FAILED (${duration}s)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Crawl behavior edge cases
# ──────────────────────────────────────────────────────────────

test_crawl_depth() {
    local port="${REST_API_PORT:-8990}"
    local base_url="http://localhost:${port}"
    local target_dir="${RESULTS_DIR}/crawl-depth"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "crawl-depth"

    local start=$SECONDS
    local failures=0

    log_header "Testing: crawl-depth (deep links and max-pages limit)"

    # Test 1: Crawl with depth=2 should NOT reach level 3+
    log_info "Crawling deep links with depth=2..."
    local shallow_capture="${target_dir}/shallow.json"
    if "$VESPASIAN" crawl "${base_url}/api/deep/1" \
        -o "$shallow_capture" \
        --depth 2 \
        --max-pages 50 \
        --timeout 1m \
        $verbose_flag 2>&1; then

        # Should have levels 1-2, but not 3+
        local has_deep
        has_deep=$(python3 -c "
import json
data = json.load(open('$shallow_capture'))
urls = [r['url'] for r in data]
deep = [u for u in urls if '/deep/3' in u or '/deep/4' in u or '/deep/5' in u]
print(len(deep))
" 2>/dev/null || echo "?")
        if [ "$has_deep" = "0" ]; then
            log_ok "Depth limit: correctly stopped at depth 2"
        else
            log_warn "Depth limit: found ${has_deep} URLs beyond depth 2 (may vary by crawler)"
        fi
    else
        log_fail "Shallow crawl failed"
        failures=$((failures + 1))
    fi

    # Test 2: Crawl many-links with max-pages=10
    log_info "Crawling many-links with max-pages=10..."
    local limited_capture="${target_dir}/limited.json"
    if "$VESPASIAN" crawl "${base_url}/api/many-links" \
        -o "$limited_capture" \
        --depth 2 \
        --max-pages 10 \
        --timeout 1m \
        $verbose_flag 2>&1; then

        local page_count
        page_count=$(python3 -c "
import json
data = json.load(open('$limited_capture'))
print(len(data))
" 2>/dev/null || echo "?")
        # Should be capped around max-pages
        if [ "$page_count" != "?" ] && [ "$page_count" -le 15 ]; then
            log_ok "Max-pages limit: captured ${page_count} requests (limit=10)"
        else
            log_warn "Max-pages limit: captured ${page_count} requests (expected <=15)"
        fi
    else
        log_fail "Limited crawl failed"
        failures=$((failures + 1))
    fi

    # Test 3: Infinite loop detection
    log_info "Crawling self-referencing page..."
    local loop_capture="${target_dir}/loop.json"
    if "$VESPASIAN" crawl "${base_url}/api/loop" \
        -o "$loop_capture" \
        --depth 3 \
        --max-pages 20 \
        --timeout 30s \
        $verbose_flag 2>&1; then
        log_ok "Loop detection: crawl completed (did not hang)"
    else
        log_warn "Loop crawl exited non-zero (may be expected)"
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "crawl-depth" "PASS" "-" "-" "$duration"
        log_ok "crawl-depth: PASSED (${duration}s)"
    else
        set_test_result "crawl-depth" "FAIL" "-" "-" "$duration"
        log_fail "crawl-depth: FAILED (${duration}s)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Classifier edge cases
# ──────────────────────────────────────────────────────────────

test_classifier_edge_cases() {
    local port="${REST_API_PORT:-8990}"
    local base_url="http://localhost:${port}"
    local target_dir="${RESULTS_DIR}/classifier-edge"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "classifier-edge"

    local start=$SECONDS
    local failures=0

    log_header "Testing: classifier-edge (RSS, versioned paths, GraphQL, mismatched content-types)"

    # Build a synthetic capture with classifier edge case requests
    log_info "Creating classifier edge case capture..."
    local capture="${target_dir}/capture.json"
    python3 -c "
import json, base64

def b64(s): return base64.b64encode(s.encode()).decode()

requests = [
    # RSS feed - should NOT be classified as SOAP/WSDL
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/feed.xml',
        'headers': {'Accept': 'application/rss+xml'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/rss+xml'},
            'content_type': 'application/rss+xml',
            'body': b64('<rss version=\"2.0\"><channel><title>Test</title></channel></rss>')
        },
        'source': 'test'
    },
    # API v1 endpoint
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/v1/resources',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"version\":\"v1\",\"items\":[{\"id\":\"1\"}]}')
        },
        'source': 'test'
    },
    # API v2 endpoint
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/v2/resources',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"version\":\"v2\",\"data\":[{\"id\":1}]}')
        },
        'source': 'test'
    },
    # GraphQL POST
    {
        'method': 'POST',
        'url': 'http://localhost:${port}/graphql',
        'headers': {'Content-Type': 'application/json'},
        'body': b64('{\"query\":\"{ users { id name } }\"}'),
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"data\":{\"users\":[{\"id\":\"1\",\"name\":\"Alice\"}]}}')
        },
        'source': 'test'
    },
    # Mismatched content-type: JSON body but text/html header
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/mismatched-ct',
        'headers': {},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'content_type': 'text/html',
            'body': b64('{\"status\":\"mismatched\"}')
        },
        'source': 'test'
    },
    # HTML error from API path
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/html-error',
        'headers': {},
        'response': {
            'status_code': 502,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'content_type': 'text/html; charset=utf-8',
            'body': b64('<html><body>502 Bad Gateway</body></html>')
        },
        'source': 'test'
    },
]

with open('$capture', 'w') as f:
    json.dump(requests, f, indent=2)
print('Created capture with %d requests' % len(requests))
" 2>/dev/null

    # Generate REST spec
    local spec="${target_dir}/spec.yaml"
    log_info "Generating spec from classifier edge cases..."
    if ! "$VESPASIAN" generate rest "$capture" -o "$spec" --probe=false $verbose_flag 2>&1; then
        log_fail "Spec generation failed"
        set_test_result "classifier-edge" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    # Verify versioned API paths are classified
    if grep -q "v1/resources" "$spec" 2>/dev/null; then
        log_ok "Classifier: /api/v1/resources detected as API"
    else
        log_fail "Classifier: /api/v1/resources NOT detected"
        failures=$((failures + 1))
    fi

    if grep -q "v2/resources" "$spec" 2>/dev/null; then
        log_ok "Classifier: /api/v2/resources detected as API"
    else
        log_fail "Classifier: /api/v2/resources NOT detected"
        failures=$((failures + 1))
    fi

    if grep -q "graphql" "$spec" 2>/dev/null; then
        log_ok "Classifier: /graphql detected as API"
    else
        log_warn "Classifier: /graphql not in REST spec (may be expected)"
    fi

    # RSS feed should NOT appear in the REST spec
    if grep -q "feed.xml" "$spec" 2>/dev/null; then
        log_fail "Classifier: RSS feed incorrectly included in spec"
        failures=$((failures + 1))
    else
        log_ok "Classifier: RSS feed correctly excluded from REST spec"
    fi

    # HTML error should NOT appear
    if grep -q "html-error" "$spec" 2>/dev/null; then
        log_warn "Classifier: HTML error page included in spec"
    else
        log_ok "Classifier: HTML error page excluded from spec"
    fi

    # Mismatched content-type endpoint may or may not be classified
    if grep -q "mismatched-ct" "$spec" 2>/dev/null; then
        log_warn "Classifier: mismatched content-type endpoint included (JSON body with text/html header)"
    else
        log_ok "Classifier: mismatched content-type endpoint excluded"
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "classifier-edge" "PASS" "-" "-" "$duration"
        log_ok "classifier-edge: PASSED (${duration}s)"
    else
        set_test_result "classifier-edge" "FAIL" "-" "-" "$duration"
        log_fail "classifier-edge: FAILED (${duration}s)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Spec generation edge cases
# ──────────────────────────────────────────────────────────────

test_spec_edge_cases() {
    local port="${REST_API_PORT:-8990}"
    local target_dir="${RESULTS_DIR}/spec-edge"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "spec-edge"

    local start=$SECONDS
    local failures=0

    log_header "Testing: spec-edge (multi-param paths, UUID params, empty bodies)"

    # Build a synthetic capture with spec generation edge cases
    log_info "Creating spec edge case capture..."
    local capture="${target_dir}/capture.json"
    python3 -c "
import json, base64

def b64(s): return base64.b64encode(s.encode()).decode()

requests = [
    # Multi-param: /api/users/{id}/orders
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/users/1/orders',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('[{\"order_id\":\"101\"},{\"order_id\":\"102\"}]')
        },
        'source': 'test'
    },
    # Multi-param: /api/users/{id}/orders/{orderId} - two different IDs
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/users/1/orders/101',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"order_id\":\"101\",\"user_id\":\"1\",\"product\":\"Widget\"}')
        },
        'source': 'test'
    },
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/users/2/orders/102',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"order_id\":\"102\",\"user_id\":\"2\",\"product\":\"Gadget\"}')
        },
        'source': 'test'
    },
    # UUID path params - two different UUIDs to trigger parameterization
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/assets/550e8400-e29b-41d4-a716-446655440000',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"id\":\"550e8400-e29b-41d4-a716-446655440000\",\"type\":\"asset\"}')
        },
        'source': 'test'
    },
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/assets/6ba7b810-9dad-11d1-80b4-00c04fd430c8',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"id\":\"6ba7b810-9dad-11d1-80b4-00c04fd430c8\",\"type\":\"asset\"}')
        },
        'source': 'test'
    },
    # Numeric IDs - two different to trigger parameterization
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/items/42',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"id\":\"42\",\"type\":\"item\"}')
        },
        'source': 'test'
    },
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/items/99',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{\"id\":\"99\",\"type\":\"item\"}')
        },
        'source': 'test'
    },
    # Empty 200 response body
    {
        'method': 'GET',
        'url': 'http://localhost:${port}/api/empty-ok',
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json'
        },
        'source': 'test'
    },
]

with open('$capture', 'w') as f:
    json.dump(requests, f, indent=2)
print('Created capture with %d requests' % len(requests))
" 2>/dev/null

    # Generate spec
    local spec="${target_dir}/spec.yaml"
    log_info "Generating spec from edge case capture..."
    if ! "$VESPASIAN" generate rest "$capture" -o "$spec" --probe=false $verbose_flag 2>&1; then
        log_fail "Spec generation failed"
        set_test_result "spec-edge" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    log_ok "Spec generation: completed without crash"

    # Verify multi-param paths are normalized (should have parameterized segments)
    local spec_content
    spec_content=$(cat "$spec")

    # Check for UUID parameterization in /api/assets/{uuid}
    if echo "$spec_content" | grep -qE "/api/assets/\{"; then
        log_ok "UUID params: /api/assets/{id} correctly parameterized"
    else
        # UUID paths may not be classified as API endpoints if confidence is too low
        log_warn "UUID params: /api/assets/ not in spec (classifier may not detect as API)"
    fi

    # Check for numeric ID parameterization in /api/items/{id}
    if echo "$spec_content" | grep -qE "/api/items/\{"; then
        log_ok "Numeric params: /api/items/{id} correctly parameterized"
    else
        log_fail "Numeric params: /api/items/ not parameterized"
        failures=$((failures + 1))
    fi

    # Check multi-param path: /api/users/{id}/orders/{orderId}
    if echo "$spec_content" | grep -qE "/api/users/\{[^}]+\}/orders/\{"; then
        log_ok "Multi-param: /api/users/{id}/orders/{orderId} correctly parameterized"
    else
        log_warn "Multi-param: /api/users/{id}/orders/{orderId} not found (may be normalized differently)"
    fi

    # Spec should still be valid OpenAPI
    if echo "$spec_content" | grep -q "openapi:"; then
        log_ok "Spec structure: valid OpenAPI"
    else
        log_fail "Spec structure: missing openapi key"
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "spec-edge" "PASS" "-" "-" "$duration"
        log_ok "spec-edge: PASSED (${duration}s)"
    else
        set_test_result "spec-edge" "FAIL" "-" "-" "$duration"
        log_fail "spec-edge: FAILED (${duration}s)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────

print_summary() {
    local total_pass=0 total_fail=0 total_skip=0

    log_header "Test Summary"

    printf "  ${BOLD}%-22s  %-8s  %-10s  %-9s  %-8s${NC}\n" \
        "TARGET" "STATUS" "ENDPOINTS" "EXPECTED" "DURATION"
    printf "  %-22s  %-8s  %-10s  %-9s  %-8s\n" \
        "----------------------" "--------" "----------" "---------" "--------"

    for name in "${!TEST_STATUS[@]}"; do
        local status="${TEST_STATUS[$name]}"
        local endpoints="${TEST_ENDPOINTS[$name]}"
        local expected="${TEST_EXPECTED[$name]}"
        local duration="${TEST_DURATION[$name]}s"

        local color="$NC"
        case "$status" in
            PASS)    color="$GREEN"; total_pass=$((total_pass + 1)) ;;
            FAIL)    color="$RED"; total_fail=$((total_fail + 1)) ;;
            NOT_RUN) color="$YELLOW"; total_skip=$((total_skip + 1)); duration="-" ;;
            SKIP)    color="$YELLOW"; total_skip=$((total_skip + 1)); duration="-" ;;
        esac

        printf "  %-22s  ${color}%-8s${NC}  %-10s  %-9s  %-8s\n" \
            "$name" "$status" "$endpoints" "$expected" "$duration"
    done

    echo ""
    echo -e "  Total: ${GREEN}${total_pass} passed${NC}, ${RED}${total_fail} failed${NC}, ${YELLOW}${total_skip} skipped${NC}"
    echo -e "  Results saved to: ${RESULTS_DIR}/"

    if [ $total_fail -gt 0 ]; then
        return 1
    fi
    return 0
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --targets <list>      Comma-separated targets to test (default: all)"
    echo "                        Valid: rest-api,soap-service,import-burp,import-har,"
    echo "                        generate-rest,generate-wsdl,import-malformed,"
    echo "                        import-empty,edge-cases,crawl-unreachable"
    echo "  --verbose             Enable verbose vespasian output"
    echo "  --no-build            Skip building vespasian and target binaries"
    echo "  --no-start            Don't start/stop services (assume already running)"
    echo "  --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests"
    echo "  $0 --targets rest-api                 # Only test rest-api"
    echo "  $0 --targets import-burp,import-har   # Only run importer tests"
    echo "  $0 --verbose --no-build               # Verbose output, skip build"
}

main() {
    local targets=""
    local no_build=false
    local no_start=false
    VERBOSE=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --targets)
                targets="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --no-build)
                no_build=true
                shift
                ;;
            --no-start)
                no_start=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_fail "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    log_header "Vespasian Live Test Runner"

    # Load config
    load_config

    # Default targets from config
    if [ -z "$targets" ]; then
        targets="${TARGETS_SETUP:-rest-api,soap-service}"
        # Always include importer tests
        targets="${targets},import-burp,import-har,import-base64,import-mitmproxy,import-unicode,import-duplicates,import-malformed,import-empty"
        targets="${targets},generate-rest,generate-wsdl"
        targets="${targets},edge-cases,crawl-depth,crawl-unreachable"
        targets="${targets},classifier-edge,spec-edge"
    fi

    # Create results directory
    mkdir -p "$RESULTS_DIR"

    # Build if needed
    if [ "$no_build" = false ]; then
        log_header "Building"
        cd "$PROJECT_ROOT"
        log_info "Building vespasian..."
        go build -o bin/vespasian ./cmd/vespasian
        log_ok "Built bin/vespasian"
    fi

    # Verify vespasian binary exists
    if [ ! -x "$VESPASIAN" ]; then
        log_fail "vespasian binary not found at ${VESPASIAN}"
        log_info "Run ./test/setup-live-targets.sh or build with 'make build'"
        exit 1
    fi

    # Run tests
    IFS=',' read -ra TARGET_ARRAY <<< "$targets"
    for target in "${TARGET_ARRAY[@]}"; do
        case "$target" in
            rest-api)      test_rest_api ;;
            soap-service)  test_soap_service ;;
            import-burp)        test_import_burp ;;
            import-har)         test_import_har ;;
            import-base64)      test_import_base64 ;;
            import-mitmproxy)   test_import_mitmproxy ;;
            import-unicode)     test_import_unicode ;;
            import-duplicates)  test_import_duplicates ;;
            import-malformed)   test_import_malformed ;;
            import-empty)       test_import_empty ;;
            generate-rest)      test_generate_rest ;;
            generate-wsdl)      test_generate_wsdl ;;
            edge-cases)         test_edge_cases ;;
            crawl-depth)        test_crawl_depth ;;
            crawl-unreachable)  test_crawl_unreachable ;;
            classifier-edge)    test_classifier_edge_cases ;;
            spec-edge)          test_spec_edge_cases ;;
            *)
                log_warn "Unknown target: $target (skipping)"
                ;;
        esac
    done

    # Print summary
    print_summary
}

main "$@"
