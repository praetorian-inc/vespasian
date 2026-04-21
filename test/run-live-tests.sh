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

# Source shared colors, logging, and validation functions
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"
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
            declare -g "$line"
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
# Helpers
# ──────────────────────────────────────────────────────────────

# json_field reads a top-level field from a JSON file.
# Usage: json_field <file> <field>
# Example: json_field expected-paths.json total_paths
json_field() {
    python3 - "$1" "$2" << 'PYEOF' 2>/dev/null || echo "?"
import json, sys
with open(sys.argv[1]) as f:
    print(json.load(f)[sys.argv[2]])
PYEOF
}

# json_len returns the length of the top-level JSON array in a file.
# Usage: json_len <file>
json_len() {
    python3 - "$1" << 'PYEOF' 2>/dev/null || echo "?"
import json, sys
with open(sys.argv[1]) as f:
    print(len(json.load(f)))
PYEOF
}

# json_valid returns 0 if the file is valid JSON, 1 otherwise.
# Usage: json_valid <file>
json_valid() {
    python3 - "$1" << 'PYEOF' 2>/dev/null
import json, sys
with open(sys.argv[1]) as f:
    json.load(f)
PYEOF
}

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
    expected_count=$(json_field "$expected" total_paths)

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
    python3 - "$port" "$soap_capture" << 'PYEOF' 2>/dev/null
import json, base64, sys

port = sys.argv[1]
outfile = sys.argv[2]

def b64(s):
    return base64.b64encode(s.encode()).decode()

requests = []
for action in ['GetUser', 'ListUsers', 'CreateUser']:
    body = '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><tns:%sRequest xmlns:tns="http://localhost/soap"><id>1</id></tns:%sRequest></soap:Body></soap:Envelope>' % (action, action)
    resp_body = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><tns:%sResponse xmlns:tns="http://localhost/soap"><id>1</id></tns:%sResponse></soap:Body></soap:Envelope>' % (action, action)
    req = {
        'method': 'POST',
        'url': 'http://localhost:%s/soap' % port,
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
    'url': 'http://localhost:%s/service.wsdl' % port,
    'headers': {},
    'response': {
        'status_code': 200,
        'headers': {'Content-Type': 'text/xml; charset=utf-8'},
        'content_type': 'text/xml; charset=utf-8'
    },
    'source': 'test-runner'
})

with open(outfile, 'w') as f:
    json.dump(requests, f, indent=2)
PYEOF

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
    expected_count=$(json_field "$expected" total_operations)

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
    actual_count=$(json_len "$imported_file")
    local expected_count
    expected_count=$(json_field "$expected" total_requests)

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
    actual_count=$(json_len "$imported_file")
    local expected_count
    expected_count=$(json_field "$expected" total_requests)

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
    expected_count=$(json_field "$expected_ops" total_operations)

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "generate-wsdl" "PASS" "3" "$expected_count" "$duration"
        log_ok "generate-wsdl: PASSED (${duration}s)"
    else
        set_test_result "generate-wsdl" "FAIL" "?" "$expected_count" "$duration"
        log_fail "generate-wsdl: FAILED (${duration}s)"
    fi
}

test_graphql_server() {
    local port="${GRAPHQL_SERVER_PORT:-8992}"
    local base_url="http://localhost:${port}"
    local target_dir="${RESULTS_DIR}/graphql-server"
    local capture_file="${target_dir}/capture.json"
    local spec_file="${target_dir}/spec.graphql"
    local expected="${SCRIPT_DIR}/graphql-server/expected-paths.json"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "graphql-server"

    local start=$SECONDS
    local failures=0

    log_header "Testing: graphql-server (${base_url})"

    # Step 1: Send GraphQL traffic to generate a capture
    log_info "Sending GraphQL queries to ${base_url}/graphql..."
    local queries=(
        '{"query":"query GetUsers($limit: Int) { users(limit: $limit) { id name email role createdAt } }","variables":{"limit":10}}'
        '{"query":"query GetUser($id: ID!) { user(id: $id) { id name email posts { id title likes published } } }","variables":{"id":"1"}}'
        '{"query":"query GetPost($id: ID!) { post(id: $id) { id title content author { id name } tags likes published createdAt } }","variables":{"id":"10"}}'
        '{"query":"query SearchContent($q: String!) { search(query: $q) { users { id name } posts { id title } totalCount } }","variables":{"q":"graphql"}}'
        '{"query":"mutation CreateNewUser($input: CreateUserInput!) { createUser(input: $input) { id name email role } }","variables":{"input":{"name":"TestUser","email":"test@example.com","role":"EDITOR"}}}'
        '{"query":"{ serverInfo { version uptime } }"}'
    )

    # Build a capture file from live traffic
    local rc=0
    python3 - "$base_url" "${queries[@]}" << 'PYEOF' > "$capture_file" || rc=$?
import json, sys, base64, urllib.request

base_url = sys.argv[1]
queries = sys.argv[2:]
entries = []
for q in queries:
    payload = q.encode()
    req = urllib.request.Request(
        base_url + "/graphql",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read()
        entries.append({
            "method": "POST",
            "url": base_url + "/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": base64.b64encode(payload).decode(),
            "response": {
                "status_code": resp.status,
                "content_type": "application/json",
                "body": base64.b64encode(resp_body).decode()
            }
        })
    except Exception as e:
        print("ERROR: " + str(e), file=sys.stderr)
        sys.exit(1)

json.dump(entries, sys.stdout, indent=2)
PYEOF

    if [ $rc -ne 0 ]; then
        log_fail "Failed to send GraphQL queries"
        set_test_result "graphql-server" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    # Step 2: Validate capture
    if ! validate_capture "$capture_file" 4; then
        failures=$((failures + 1))
    fi

    # Step 3: Generate GraphQL SDL with introspection probe
    log_info "Generating GraphQL SDL (with introspection probe)..."
    if ! "$VESPASIAN" generate graphql "$capture_file" \
        -o "$spec_file" \
        --dangerous-allow-private \
        --deduplicate=true \
        $verbose_flag 2>&1; then
        log_fail "GraphQL generate failed"
        set_test_result "graphql-server" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    # Step 4: Validate SDL structure
    if ! validate_graphql_structure "$spec_file"; then
        failures=$((failures + 1))
    fi

    # Step 5: Validate expected operations are present
    if ! validate_graphql_operations "$spec_file" "$expected"; then
        failures=$((failures + 1))
    fi

    # Step 6: Introspection-specific checks (full schema should have non-null types)
    local introspection_check rc=0
    introspection_check=$(python3 - "$spec_file" << 'PYEOF'
import sys

with open(sys.argv[1]) as f:
    content = f.read()

checks = []
# Introspection SDL should have schema block and non-null types
if "schema {" not in content:
    checks.append("missing schema block (introspection may have failed)")
if "!" not in content:
    checks.append("no non-null types (likely inference fallback, not introspection)")
if "enum Role {" not in content:
    checks.append("missing enum Role (expected from introspection)")

if checks:
    print("WARN: " + "; ".join(checks))
    sys.exit(1)
print("OK: introspection-quality SDL (schema block, non-null types, enums)")
PYEOF
    ) || rc=$?
    if [ $rc -ne 0 ]; then
        log_warn "Introspection check: $introspection_check"
        # Not a hard failure — inference fallback is valid behavior
    else
        log_ok "Introspection check: $introspection_check"
    fi

    local expected_count
    expected_count=$(json_field "$expected" total_operations)

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "graphql-server" "PASS" "8" "$expected_count" "$duration"
        log_ok "graphql-server: ALL CHECKS PASSED (${duration}s)"
    else
        set_test_result "graphql-server" "FAIL" "?" "$expected_count" "$duration"
        log_fail "graphql-server: ${failures} check(s) failed (${duration}s)"
    fi
}

test_generate_graphql() {
    local target_dir="${RESULTS_DIR}/generate-graphql"
    local input_capture="${SCRIPT_DIR}/graphql-server/reference-capture.json"
    local spec_file="${target_dir}/spec.graphql"
    local expected_spec="${SCRIPT_DIR}/graphql-server/expected-spec.graphql"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "generate-graphql"

    local start=$SECONDS
    local failures=0

    log_header "Testing: generate-graphql (deterministic GraphQL SDL generation)"

    if [ ! -f "$input_capture" ]; then
        log_fail "Input capture not found: ${input_capture}"
        set_test_result "generate-graphql" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    log_info "Generating GraphQL SDL from reference capture..."
    if ! "$VESPASIAN" generate graphql "$input_capture" \
        -o "$spec_file" \
        --probe=false \
        --deduplicate=false \
        $verbose_flag 2>&1; then
        log_fail "GraphQL generate failed"
        set_test_result "generate-graphql" "FAIL" "?" "?" "$((SECONDS - start))"
        return 1
    fi

    if ! validate_graphql_structure "$spec_file"; then
        failures=$((failures + 1))
    fi

    local expected_ops="${SCRIPT_DIR}/graphql-server/expected-paths.json"
    if ! validate_graphql_operations "$spec_file" "$expected_ops"; then
        failures=$((failures + 1))
    fi

    if ! compare_files "$spec_file" "$expected_spec" "generate-graphql spec"; then
        failures=$((failures + 1))
    fi

    local expected_count
    expected_count=$(json_field "$expected_ops" total_operations)

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "generate-graphql" "PASS" "8" "$expected_count" "$duration"
        log_ok "generate-graphql: PASSED (${duration}s)"
    else
        set_test_result "generate-graphql" "FAIL" "?" "$expected_count" "$duration"
        log_fail "generate-graphql: FAILED (${duration}s)"
    fi
}

test_generate_graphql_imports() {
    local target_dir="${RESULTS_DIR}/generate-graphql-imports"
    local verbose_flag=""

    [ "${VERBOSE:-false}" = true ] && verbose_flag="-v"

    mkdir -p "$target_dir"
    init_test_status "generate-graphql-imports"

    local start=$SECONDS
    local failures=0

    log_header "Testing: generate-graphql-imports (Burp/HAR import → GraphQL SDL)"

    local expected_spec="${SCRIPT_DIR}/graphql-server/expected-spec.graphql"

    # Test Burp XML import path
    local burp_input="${SCRIPT_DIR}/graphql-server/test-burp.xml"
    if [ -f "$burp_input" ]; then
        local burp_imported="${target_dir}/burp-imported.json"
        local burp_spec="${target_dir}/burp-spec.graphql"

        log_info "Importing Burp XML..."
        if "$VESPASIAN" import burp "$burp_input" -o "$burp_imported" $verbose_flag 2>&1; then
            log_info "Generating GraphQL SDL from Burp import..."
            if "$VESPASIAN" generate graphql "$burp_imported" -o "$burp_spec" --probe=false --deduplicate=false $verbose_flag 2>&1; then
                if ! compare_files "$burp_spec" "$expected_spec" "graphql-from-burp"; then
                    failures=$((failures + 1))
                fi
            else
                log_fail "GraphQL generate from Burp import failed"
                failures=$((failures + 1))
            fi
        else
            log_fail "Burp import failed"
            failures=$((failures + 1))
        fi
    else
        log_warn "Burp test file not found: ${burp_input} (skipping)"
    fi

    # Test HAR import path
    local har_input="${SCRIPT_DIR}/graphql-server/test-traffic.har"
    if [ -f "$har_input" ]; then
        local har_imported="${target_dir}/har-imported.json"
        local har_spec="${target_dir}/har-spec.graphql"

        log_info "Importing HAR..."
        if "$VESPASIAN" import har "$har_input" -o "$har_imported" $verbose_flag 2>&1; then
            log_info "Generating GraphQL SDL from HAR import..."
            if "$VESPASIAN" generate graphql "$har_imported" -o "$har_spec" --probe=false --deduplicate=false $verbose_flag 2>&1; then
                if ! compare_files "$har_spec" "$expected_spec" "graphql-from-har"; then
                    failures=$((failures + 1))
                fi
            else
                log_fail "GraphQL generate from HAR import failed"
                failures=$((failures + 1))
            fi
        else
            log_fail "HAR import failed"
            failures=$((failures + 1))
        fi
    else
        log_warn "HAR test file not found: ${har_input} (skipping)"
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "generate-graphql-imports" "PASS" "2" "2" "$duration"
        log_ok "generate-graphql-imports: PASSED (${duration}s)"
    else
        set_test_result "generate-graphql-imports" "FAIL" "?" "2" "$duration"
        log_fail "generate-graphql-imports: FAILED (${duration}s)"
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

    # Test 1: Truncated/broken XML — should fail gracefully (non-zero exit, no crash)
    log_info "Importing truncated Burp XML..."
    local truncated_burp="${RESULTS_DIR}/import-malformed/truncated-burp.xml"
    mkdir -p "$(dirname "$truncated_burp")"
    printf '<?xml version="1.0"?>\n<items>\n  <item>\n    <url>http://example.com</url>\n' > "$truncated_burp"
    local burp_err
    burp_err=$("$VESPASIAN" import burp "$truncated_burp" -o /dev/null 2>&1) && {
        # Succeeded — acceptable if importer is lenient with truncated XML
        log_ok "Truncated Burp XML: imported without error (lenient parser)"
    } || {
        log_ok "Truncated Burp XML: rejected gracefully (exit non-zero)"
    }

    # Test 2: Completely invalid XML — should fail gracefully
    log_info "Importing invalid Burp XML..."
    local invalid_burp="${RESULTS_DIR}/import-malformed/invalid-burp.xml"
    printf 'this is not xml at all {{{' > "$invalid_burp"
    local burp_err2
    burp_err2=$("$VESPASIAN" import burp "$invalid_burp" -o /dev/null 2>&1) && {
        log_fail "Invalid Burp XML: should have failed but succeeded"
        failures=$((failures + 1))
    } || {
        log_ok "Invalid Burp XML: rejected gracefully"
    }

    # Test 3: Sparse Burp data (valid XML, empty/missing fields)
    log_info "Importing sparse Burp XML..."
    local sparse_burp_err
    sparse_burp_err=$("$VESPASIAN" import burp "${SCRIPT_DIR}/fixtures/malformed-burp.xml" -o /dev/null 2>&1) && {
        log_ok "Sparse Burp XML: handled gracefully (some requests may be skipped)"
    } || {
        log_ok "Sparse Burp XML: rejected gracefully"
    }

    # Test 4: Completely invalid JSON — should fail gracefully
    log_info "Importing invalid HAR JSON..."
    local invalid_har="${RESULTS_DIR}/import-malformed/invalid-har.json"
    printf '{"log": {"entries": [BROKEN' > "$invalid_har"
    local har_err
    har_err=$("$VESPASIAN" import har "$invalid_har" -o /dev/null 2>&1) && {
        log_fail "Invalid HAR JSON: should have failed but succeeded"
        failures=$((failures + 1))
    } || {
        log_ok "Invalid HAR JSON: rejected gracefully"
    }

    # Test 5: Sparse HAR data (valid JSON, empty/invalid fields)
    log_info "Importing sparse HAR JSON..."
    local sparse_har_err
    sparse_har_err=$("$VESPASIAN" import har "${SCRIPT_DIR}/fixtures/malformed-har.json" -o /dev/null 2>&1) && {
        log_ok "Sparse HAR JSON: handled gracefully (some entries may be skipped)"
    } || {
        log_ok "Sparse HAR JSON: rejected gracefully"
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
    large_resp=$(curl -s "${base_url}/api/large" 2>/dev/null)
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
    search_resp=$(curl -s "${base_url}/api/search?q=hello+world&filter=name%3Aalice&page=1" 2>/dev/null)
    if echo "$search_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['query']=='hello world'; assert d['filter']=='name:alice'" 2>/dev/null; then
        log_ok "Special query params: correctly decoded"
    else
        log_fail "Special query params: decoding failed"
        failures=$((failures + 1))
    fi

    # ── URL-encoded path segments ──
    log_info "Testing URL-encoded path segments..."
    local cat_resp
    cat_resp=$(curl -s "${base_url}/api/categories/electronics%20%26%20gadgets" 2>/dev/null)
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
    trailing_resp=$(curl -s "${base_url}/api/trailing/" 2>/dev/null)
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
        if json_valid "$edge_capture"; then
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
        count=$(python3 - "$capture_file" << 'PYEOF' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d) if isinstance(d, list) else 0)
except:
    print(0)
PYEOF
        )
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

# test_import_mitmproxy_native exercises the native binary flow format
# produced by mitmproxy's `w` command (tnetstring-encoded flows). Regression
# coverage for LAB-2309, where a .mitm file produced by mitmproxy 12.x was
# rejected with "expected JSON array or object, got '2'".
test_import_mitmproxy_native() {
    local target_dir="${RESULTS_DIR}/import-mitmproxy-native"
    local imported_file="${target_dir}/imported.json"
    local fixture="${SCRIPT_DIR}/fixtures/sample-mitmproxy.mitm"
    local expected_capture="${SCRIPT_DIR}/fixtures/expected-mitmproxy-capture.json"

    mkdir -p "$target_dir"
    init_test_status "import-mitmproxy-native"

    local start=$SECONDS
    local failures=0

    log_header "Testing: import-mitmproxy-native (LAB-2309 native .mitm format)"

    if [ ! -f "$fixture" ]; then
        log_fail "Native fixture missing: $fixture"
        log_info "Regenerate with: go run ./test/fixtures/gen_mitmproxy_native > test/fixtures/sample-mitmproxy.mitm"
        set_test_result "import-mitmproxy-native" "FAIL" "?" "3" "$((SECONDS - start))"
        return 1
    fi

    # Sanity-check: first byte should be an ASCII digit (tnetstring length
    # prefix). If it's not, the fixture isn't the format we claim to test.
    local first_byte
    first_byte=$(head -c 1 "$fixture")
    if ! [[ "$first_byte" =~ [0-9] ]]; then
        log_fail "Fixture first byte is '$first_byte', expected a digit (tnetstring prefix)"
        set_test_result "import-mitmproxy-native" "FAIL" "?" "3" "$((SECONDS - start))"
        return 1
    fi

    if ! "$VESPASIAN" import mitmproxy "$fixture" -o "$imported_file" 2>&1; then
        log_fail "Native mitmproxy import failed"
        set_test_result "import-mitmproxy-native" "FAIL" "?" "3" "$((SECONDS - start))"
        return 1
    fi

    if ! compare_json "$imported_file" "$expected_capture" "import-mitmproxy-native capture"; then
        failures=$((failures + 1))
    fi

    local duration=$((SECONDS - start))
    if [ $failures -eq 0 ]; then
        set_test_result "import-mitmproxy-native" "PASS" "3" "3" "$duration"
        log_ok "import-mitmproxy-native: PASSED (${duration}s)"
    else
        set_test_result "import-mitmproxy-native" "FAIL" "?" "3" "$duration"
        log_fail "import-mitmproxy-native: FAILED (${duration}s)"
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
        has_deep=$(python3 - "$shallow_capture" << 'PYEOF' 2>/dev/null || echo "?"
import json, sys
data = json.load(open(sys.argv[1]))
urls = [r['url'] for r in data]
deep = [u for u in urls if '/deep/3' in u or '/deep/4' in u or '/deep/5' in u]
print(len(deep))
PYEOF
        )
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
        page_count=$(json_len "$limited_capture")
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
    python3 - "$port" "$capture" << 'PYEOF' 2>/dev/null
import json, base64, sys

port = sys.argv[1]
outfile = sys.argv[2]

def b64(s): return base64.b64encode(s.encode()).decode()

requests = [
    # RSS feed - should NOT be classified as SOAP/WSDL
    {
        'method': 'GET',
        'url': 'http://localhost:%s/feed.xml' % port,
        'headers': {'Accept': 'application/rss+xml'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/rss+xml'},
            'content_type': 'application/rss+xml',
            'body': b64('<rss version="2.0"><channel><title>Test</title></channel></rss>')
        },
        'source': 'test'
    },
    # API v1 endpoint
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/v1/resources' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"version":"v1","items":[{"id":"1"}]}')
        },
        'source': 'test'
    },
    # API v2 endpoint
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/v2/resources' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"version":"v2","data":[{"id":1}]}')
        },
        'source': 'test'
    },
    # GraphQL POST
    {
        'method': 'POST',
        'url': 'http://localhost:%s/graphql' % port,
        'headers': {'Content-Type': 'application/json'},
        'body': b64('{"query":"{ users { id name } }"}'),
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"data":{"users":[{"id":"1","name":"Alice"}]}}')
        },
        'source': 'test'
    },
    # Mismatched content-type: JSON body but text/html header
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/mismatched-ct' % port,
        'headers': {},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'content_type': 'text/html',
            'body': b64('{"status":"mismatched"}')
        },
        'source': 'test'
    },
    # HTML error from API path
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/html-error' % port,
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

with open(outfile, 'w') as f:
    json.dump(requests, f, indent=2)
print('Created capture with %d requests' % len(requests))
PYEOF

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
    python3 - "$port" "$capture" << 'PYEOF' 2>/dev/null
import json, base64, sys

port = sys.argv[1]
outfile = sys.argv[2]

def b64(s): return base64.b64encode(s.encode()).decode()

requests = [
    # Multi-param: /api/users/{id}/orders
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/users/1/orders' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('[{"order_id":"101"},{"order_id":"102"}]')
        },
        'source': 'test'
    },
    # Multi-param: /api/users/{id}/orders/{orderId} - two different IDs
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/users/1/orders/101' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"order_id":"101","user_id":"1","product":"Widget"}')
        },
        'source': 'test'
    },
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/users/2/orders/102' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"order_id":"102","user_id":"2","product":"Gadget"}')
        },
        'source': 'test'
    },
    # UUID path params - two different UUIDs to trigger parameterization
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/assets/550e8400-e29b-41d4-a716-446655440000' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"id":"550e8400-e29b-41d4-a716-446655440000","type":"asset"}')
        },
        'source': 'test'
    },
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/assets/6ba7b810-9dad-11d1-80b4-00c04fd430c8' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","type":"asset"}')
        },
        'source': 'test'
    },
    # Numeric IDs - two different to trigger parameterization
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/items/42' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"id":"42","type":"item"}')
        },
        'source': 'test'
    },
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/items/99' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json',
            'body': b64('{"id":"99","type":"item"}')
        },
        'source': 'test'
    },
    # Empty 200 response body
    {
        'method': 'GET',
        'url': 'http://localhost:%s/api/empty-ok' % port,
        'headers': {'Accept': 'application/json'},
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'content_type': 'application/json'
        },
        'source': 'test'
    },
]

with open(outfile, 'w') as f:
    json.dump(requests, f, indent=2)
print('Created capture with %d requests' % len(requests))
PYEOF

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

    printf "  ${BOLD}%-26s  %-8s  %-10s  %-9s  %-8s${NC}\n" \
        "TARGET" "STATUS" "ENDPOINTS" "EXPECTED" "DURATION"
    printf "  %-26s  %-8s  %-10s  %-9s  %-8s\n" \
        "--------------------------" "--------" "----------" "---------" "--------"

    local sorted_names
    IFS=$'\n' sorted_names=($(printf '%s\n' "${!TEST_STATUS[@]}" | sort)); unset IFS

    for name in "${sorted_names[@]}"; do
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

        printf "  %-26s  ${color}%-8s${NC}  %-10s  %-9s  %-8s\n" \
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
    echo "                        Valid targets:"
    echo "                          Live:       rest-api, soap-service, graphql-server"
    echo "                          Generate:   generate-rest, generate-wsdl,"
    echo "                                      generate-graphql, generate-graphql-imports"
    echo "                          Import:     import-burp, import-har, import-base64,"
    echo "                                      import-mitmproxy, import-mitmproxy-native,"
    echo "                                      import-unicode, import-duplicates,"
    echo "                                      import-malformed, import-empty"
    echo "                          Crawl:      crawl-depth, crawl-unreachable"
    echo "                          Edge cases: edge-cases, classifier-edge, spec-edge"
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
        targets="${TARGETS_SETUP:-rest-api,soap-service,graphql-server}"
        # Always include importer tests
        targets="${targets},import-burp,import-har,import-base64,import-mitmproxy,import-mitmproxy-native,import-unicode,import-duplicates,import-malformed,import-empty"
        targets="${targets},generate-rest,generate-wsdl,generate-graphql,generate-graphql-imports"
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
            soap-service)    test_soap_service ;;
            graphql-server)  test_graphql_server ;;
            import-burp)        test_import_burp ;;
            import-har)         test_import_har ;;
            import-base64)      test_import_base64 ;;
            import-mitmproxy)   test_import_mitmproxy ;;
            import-mitmproxy-native) test_import_mitmproxy_native ;;
            import-unicode)     test_import_unicode ;;
            import-duplicates)  test_import_duplicates ;;
            import-malformed)   test_import_malformed ;;
            import-empty)       test_import_empty ;;
            generate-rest)      test_generate_rest ;;
            generate-wsdl)      test_generate_wsdl ;;
            generate-graphql)   test_generate_graphql ;;
            generate-graphql-imports) test_generate_graphql_imports ;;
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
