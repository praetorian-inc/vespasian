#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Shared validation functions for vespasian live tests.
# Source this file from run-live-tests.sh.

# Directory containing this script, used to locate the Node spec-validators
# package (LAB-3890 T1). validate.sh is sourced, so resolve from BASH_SOURCE.
VALIDATE_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEC_VALIDATORS_DIR="${VALIDATE_SH_DIR}/spec-validators"

# SPEC_VALIDATOR_TIMEOUT bounds each node validator run. js-yaml enforces no
# alias-expansion cap, so a YAML anchor bomb parses unbounded AND exits 0
# reporting a valid spec; without this the only backstop is the CI job's
# timeout-minutes, which surfaces as an opaque job kill rather than a validator
# failure (PR #187 review finding SEC-FE-003).
SPEC_VALIDATOR_TIMEOUT="${SPEC_VALIDATOR_TIMEOUT:-30}"

# _run_spec_validator runs a node validator under a wall-clock bound, echoing
# its combined output and returning its exit status. Exit 124 (timeout) is
# rewritten into an explicit message so a hang is diagnosable.
# GNU `timeout` is absent on macOS by default, so fall back to `gtimeout` and
# then to running unwrapped rather than failing the whole suite.
# Usage: _run_spec_validator <script> <file>
_run_spec_validator() {
    local script=$1 file=$2
    local runner=""
    if command -v timeout >/dev/null 2>&1; then
        runner="timeout"
    elif command -v gtimeout >/dev/null 2>&1; then
        runner="gtimeout"
    fi

    local out rc=0
    if [ -n "$runner" ]; then
        out=$("$runner" "$SPEC_VALIDATOR_TIMEOUT" node "$script" "$file" 2>&1) || rc=$?
        if [ $rc -eq 124 ]; then
            printf '%s\n' "validator timed out after ${SPEC_VALIDATOR_TIMEOUT}s: $(basename "$script")"
            return 1
        fi
    else
        out=$(node "$script" "$file" 2>&1) || rc=$?
    fi
    printf '%s\n' "$out"
    return $rc
}

# _ensure_spec_validators fails with an actionable message if the Node
# validator dependencies have not been installed.
_ensure_spec_validators() {
    # Check the actual entry points, not just the directory: an interrupted
    # npm ci or a pruned cache leaves node_modules present but unusable, which
    # would skip this actionable message and surface as a raw
    # ERR_MODULE_NOT_FOUND stack trace instead (PR #187 review finding
    # SEC-FE-004).
    local pkg
    for pkg in "@apidevtools/swagger-parser" "graphql"; do
        if [ ! -f "${SPEC_VALIDATORS_DIR}/node_modules/${pkg}/package.json" ]; then
            log_fail "spec-validators deps missing or incomplete (${pkg}) — run: (cd ${SPEC_VALIDATORS_DIR} && npm ci)"
            return 1
        fi
    done
    return 0
}

# validate_path_coverage checks that all expected paths exist in a generated OpenAPI spec.
# Usage: validate_path_coverage <spec_file> <expected_paths_json>
# Returns 0 if all paths found, 1 otherwise.
validate_path_coverage() {
    local spec_file=$1
    local expected_json=$2
    local missing=0

    if [ ! -f "$spec_file" ]; then
        log_fail "Spec file not found: $spec_file"
        return 1
    fi

    local paths
    paths=$(python3 - "$expected_json" "$spec_file" << 'PYEOF'
import json, sys, re

def paths_match(expected_path, found_path):
    e_parts = expected_path.strip("/").split("/")
    f_parts = found_path.strip("/").split("/")
    if len(e_parts) != len(f_parts):
        return False
    for e, f in zip(e_parts, f_parts):
        e_is_param = e.startswith("{") and e.endswith("}")
        f_is_param = f.startswith("{") and f.endswith("}")
        if e_is_param or f_is_param:
            continue
        if e != f:
            return False
    return True

with open(sys.argv[1]) as f:
    expected = json.load(f)

with open(sys.argv[2]) as f:
    content = f.read()

# Parse YAML: find path entries under the top-level 'paths:' key.
# Paths are the first level of children under 'paths:', indented by
# exactly one level (could be 2 or 4 spaces depending on the serializer).
in_paths = False
paths_indent = None
found_paths = []
for line in content.split("\n"):
    stripped = line.rstrip()
    if re.match(r"^paths:\s*(|\{\})\s*$", stripped):
        in_paths = True
        if "{}" in stripped:
            break  # inline empty mapping, no children
        continue
    if in_paths:
        # Another top-level key ends paths section
        if stripped and not stripped[0].isspace():
            break
        # Detect the indent of the first child to know the path indent level
        m = re.match(r'^(\s+)(?:"(/[^"]*)"|\'(/[^\']*)\'|(/[^:"\']*)):', stripped)
        if m:
            indent = m.group(1)
            path = m.group(2) or m.group(3) or m.group(4)
            if paths_indent is None:
                paths_indent = indent
            # Only match paths at the same indent level (not nested keys)
            if indent == paths_indent:
                found_paths.append(path)

missing = []
for path in expected["paths"]:
    matched = any(paths_match(path, fp) for fp in found_paths)
    if not matched:
        missing.append(path)

if missing:
    print("MISSING:" + ",".join(missing))
    sys.exit(1)
else:
    print("OK:" + str(len(expected["paths"])) + " paths found")
    sys.exit(0)
PYEOF
    ) || missing=1

    if [ $missing -ne 0 ]; then
        log_fail "Path coverage: $paths"
        return 1
    fi
    log_ok "Path coverage: $paths"
    return 0
}

# validate_openapi_structure validates an OpenAPI document with a real parser.
# LAB-3890 T1: replaces the old grep-for-top-level-keys check (which passed any
# file merely containing "openapi:"/"info:"/"paths:"). Uses swagger-parser,
# which validates against the OpenAPI 3.0 schema and resolves $refs.
# Usage: validate_openapi_structure <spec_file>
validate_openapi_structure() {
    local spec_file=$1

    if [ ! -f "$spec_file" ]; then
        log_fail "Spec file not found: $spec_file"
        return 1
    fi
    _ensure_spec_validators || return 1

    local result rc=0
    result=$(_run_spec_validator "${SPEC_VALIDATORS_DIR}/validate-openapi.mjs" "$spec_file") || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "OpenAPI structure: $result"
        return 1
    fi
    log_ok "OpenAPI structure: $result"
    return 0
}

# validate_no_static_assets checks that static asset paths are excluded from the spec.
# Usage: validate_no_static_assets <spec_file>
validate_no_static_assets() {
    local spec_file=$1

    if [ ! -f "$spec_file" ]; then
        log_fail "Spec file not found: $spec_file"
        return 1
    fi

    local result rc=0
    result=$(python3 - "$spec_file" << 'PYEOF'
import sys, re

with open(sys.argv[1]) as f:
    content = f.read()

static_patterns = [
    r'\.js["\']', r'\.css["\']', r'\.png["\']',
    r'\.ico["\']', r'\.svg["\']', r'\.woff["\']',
    r"/static/", r"/assets/"
]
found = []
for p in static_patterns:
    if re.search(p, content):
        found.append(p)

if found:
    print("FOUND static assets: " + ", ".join(found))
    sys.exit(1)
print("OK: no static assets in spec")
PYEOF
    ) || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "Static asset check: $result"
        return 1
    fi
    log_ok "Static asset check: $result"
    return 0
}

# validate_capture checks that a capture file has the minimum expected request count.
# Usage: validate_capture <capture_file> <min_requests>
validate_capture() {
    local capture_file=$1
    local min_requests=$2

    if [ ! -f "$capture_file" ]; then
        log_fail "Capture file not found: $capture_file"
        return 1
    fi

    local result rc=0
    result=$(python3 - "$capture_file" "$min_requests" << 'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

count = len(data) if isinstance(data, list) else 0
min_req = int(sys.argv[2])
if count < min_req:
    print("INSUFFICIENT: got %d requests, expected at least %d" % (count, min_req))
    sys.exit(1)
print("OK: %d requests captured (minimum: %d)" % (count, min_req))
PYEOF
    ) || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "Capture validation: $result"
        return 1
    fi
    log_ok "Capture validation: $result"
    return 0
}

# validate_import checks imported capture against expected output.
# Usage: validate_import <imported_file> <expected_json>
validate_import() {
    local imported_file=$1
    local expected_json=$2

    if [ ! -f "$imported_file" ]; then
        log_fail "Imported file not found: $imported_file"
        return 1
    fi

    local result rc=0
    result=$(python3 - "$imported_file" "$expected_json" << 'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    imported = json.load(f)

with open(sys.argv[2]) as f:
    expected = json.load(f)

actual_count = len(imported) if isinstance(imported, list) else 0
expected_count = expected["total_requests"]

if actual_count != expected_count:
    print("COUNT MISMATCH: got %d, expected %d" % (actual_count, expected_count))
    sys.exit(1)

# Verify expected URLs are present
actual_urls = set()
for req in imported:
    url = req.get("url", "")
    url = url.split("?")[0]
    actual_urls.add(url)

missing = []
for url in expected["expected_urls"]:
    if url not in actual_urls:
        missing.append(url)

if missing:
    print("MISSING URLs: " + ", ".join(missing))
    sys.exit(1)

print("OK: %d requests with all expected URLs" % actual_count)
PYEOF
    ) || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "Import validation: $result"
        return 1
    fi
    log_ok "Import validation: $result"
    return 0
}

# validate_soap_operations validates a WSDL with a real XML parser and checks
# that every expected operation is present, using exact per-name matching
# against portType operation names. This is an expected-subset check: extra
# or unexpected operations in the WSDL are NOT flagged (PR #187 review finding
# TEST-004).
# LAB-3890 T1: replaces the old substring check (`GetUser` false-passed on
# `GetUserList`, and names in comments false-passed).
#
# Parses with python3 xml.etree rather than xmllint (PR #187 review finding
# QUAL-002): xmllint ships in libxml2-utils, which is NOT installed on the
# ubuntu-24.04 runner image and cannot be added from a later step because
# harden-runner sets disable-sudo. python3 is already a hard dependency of every
# other validator in this file, so the XML path is now provisioned identically
# to the rest of the suite and the whole function is hermetic.
#
# ElementTree drops comments during parse, so an operation name that appears
# only inside an XML comment is not in the extracted set.
# Usage: validate_soap_operations <wsdl_file> <expected_json>
validate_soap_operations() {
    local wsdl_file=$1
    local expected_json=$2

    if [ ! -f "$wsdl_file" ]; then
        log_fail "SOAP operations: WSDL file not found: $wsdl_file"
        return 1
    fi
    if [ ! -f "$expected_json" ]; then
        log_fail "SOAP operations: expected-operations file not found: $expected_json"
        return 1
    fi

    local result rc=0
    result=$(python3 - "$wsdl_file" "$expected_json" << 'PYEOF'
import json, sys
import xml.etree.ElementTree as ET

wsdl_file, expected_file = sys.argv[1], sys.argv[2]

try:
    root = ET.parse(wsdl_file).getroot()
except ET.ParseError as e:
    print("not well-formed XML: %s" % e)
    sys.exit(1)

try:
    with open(expected_file) as f:
        expected = json.load(f)
except (OSError, ValueError) as e:
    print("could not read expected operations from %s: %s" % (expected_file, e))
    sys.exit(1)

expected_ops = expected.get("operations") or []
if not expected_ops:
    print("no expected operations listed in %s" % expected_file)
    sys.exit(1)


def local_name(tag):
    """Strip any {namespace} prefix — WSDLs vary in how they bind the wsdl ns."""
    return tag.rsplit("}", 1)[-1]


# Only direct operation children of a portType count, so an <operation> under
# <binding> does not satisfy the check.
actual_ops = set()
for elem in root.iter():
    if local_name(elem.tag) != "portType":
        continue
    for child in elem:
        if local_name(child.tag) == "operation":
            name = child.get("name")
            if name:
                actual_ops.add(name)

missing = [op for op in expected_ops if op not in actual_ops]
if missing:
    print("MISSING operations: " + ", ".join(missing))
    sys.exit(1)

print("all %d expected operations present (exact name match)" % len(expected_ops))
PYEOF
    ) || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "SOAP operations: $result"
        return 1
    fi
    log_ok "SOAP operations: $result"
    return 0
}

# assert_no_panic checks that captured tool output contains no Go panic or
# goroutine stack trace. A panic is a crash, NOT graceful handling, so it must
# never be accepted as a "graceful" non-zero exit (LAB-3890 T3, gap B3).
# Extracted from test_import_malformed's nested check_panic so the regex itself
# is regression-tested by validate_test.sh (PR #187 review finding TEST-002).
# Returns 0 when the output is panic-free, 1 when a panic/stack trace is found.
# Usage: assert_no_panic <label> <output>
assert_no_panic() {
    local label=$1 output=$2
    if printf '%s' "$output" | grep -qiE 'panic:|goroutine [0-9]+ \[running\]'; then
        log_fail "${label}: PANICKED (not graceful): $(printf '%s' "$output" | grep -iE 'panic:' | head -1)"
        return 1
    fi
    return 0
}

# assert_ssrf_rejected checks that captured crawl output proves the crawl
# frontier's SSRF gate rejected a seed, rather than the command merely having
# failed for some other reason (PR #187 review finding SEC-BE-003).
#
# The predicate lives here, not inline in run-live-tests.sh, so validate_test.sh
# can regression-lock it the same way assert_no_panic is locked.
#
# The old inline check grepped case-insensitively for
# 'ssrf|private|rejected by frontier|dangerous-allow-private'. kong is built
# with kong.UsageOnError() (cmd/vespasian/main.go:771), so any parse error
# prints the usage block — which lists --dangerous-allow-private and its
# "Disable SSRF protection ... private/localhost targets" help text. Renaming
# the crawl subcommand or the -o short flag would therefore have satisfied that
# grep with the gate never having run.
#
# Note the underlying error is deliberately multi-cause ("scope, SSRF, or
# parse", pkg/crawl/engine.go:162 and pkg/crawl/http_crawler.go:164), so this
# asserts the FRONTIER rejected the seed, which is the strongest signal the
# binary currently emits. Narrowing further needs a distinct SSRF-specific
# message from pkg/crawl.
# Returns 0 when the output proves a frontier rejection of <seed_url>.
# Usage: assert_ssrf_rejected <label> <seed_url> <output>
assert_ssrf_rejected() {
    local label=$1 seed_url=$2 output=$3

    if printf '%s' "$output" | grep -qF 'Usage: vespasian'; then
        log_fail "${label}: kong printed its usage banner — the command failed to PARSE, so the SSRF gate never ran"
        return 1
    fi
    if ! printf '%s' "$output" | grep -qF 'seed URL rejected by frontier'; then
        log_fail "${label}: output has no frontier rejection: $(printf '%s' "$output" | tail -1)"
        return 1
    fi
    if ! printf '%s' "$output" | grep -qF -- "$seed_url"; then
        log_fail "${label}: frontier rejection did not name the seed ${seed_url}"
        return 1
    fi
    return 0
}

# validate_graphql_operations checks that a GraphQL SDL file contains expected operations.
# Usage: validate_graphql_operations <sdl_file> <expected_json>
validate_graphql_operations() {
    local sdl_file=$1
    local expected_json=$2

    if [ ! -f "$sdl_file" ]; then
        log_fail "SDL file not found: $sdl_file"
        return 1
    fi

    local result rc=0
    result=$(python3 - "$sdl_file" "$expected_json" << 'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    content = f.read()

with open(sys.argv[2]) as f:
    expected = json.load(f)

missing = []
for op in expected.get("queries", []):
    # Check for field name in Query type (e.g., "  users(" or "  users:")
    if op + "(" not in content and op + ":" not in content:
        missing.append("query:" + op)

for op in expected.get("mutations", []):
    if op + "(" not in content and op + ":" not in content:
        missing.append("mutation:" + op)

if missing:
    print("MISSING operations: " + ", ".join(missing))
    sys.exit(1)

total = len(expected.get("queries", [])) + len(expected.get("mutations", []))
print("OK: all %d operations found" % total)
PYEOF
    ) || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "GraphQL operations: $result"
        return 1
    fi
    log_ok "GraphQL operations: $result"
    return 0
}

# validate_graphql_structure validates a GraphQL SDL file with a real parser.
# LAB-3890 T1: replaces the old check for the literals "type Query {" + "}".
# Uses graphql-js buildSchema + validateSchema.
# Usage: validate_graphql_structure <sdl_file>
validate_graphql_structure() {
    local sdl_file=$1

    if [ ! -f "$sdl_file" ]; then
        log_fail "SDL file not found: $sdl_file"
        return 1
    fi
    _ensure_spec_validators || return 1

    local result rc=0
    result=$(_run_spec_validator "${SPEC_VALIDATORS_DIR}/validate-graphql.mjs" "$sdl_file") || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "GraphQL structure: $result"
        return 1
    fi
    log_ok "GraphQL structure: $result"
    return 0
}

# compare_files diffs an actual file against an expected file.
# For specs/WSDL, port numbers are normalized before comparison since they may vary.
# Usage: compare_files <actual_file> <expected_file> <label> [--normalize-ports]
# Returns 0 if identical (after normalization), 1 if different.
compare_files() {
    local actual=$1
    local expected=$2
    local label=$3
    local normalize=${4:-}

    if [ ! -f "$actual" ]; then
        log_fail "${label}: actual file not found: $actual"
        return 1
    fi
    if [ ! -f "$expected" ]; then
        log_fail "${label}: expected file not found: $expected"
        return 1
    fi

    local actual_normalized expected_normalized
    if [ "$normalize" = "--normalize-ports" ]; then
        # Replace localhost:<port> with localhost:PORT for comparison
        actual_normalized=$(sed -E 's/localhost:[0-9]+/localhost:PORT/g' "$actual")
        expected_normalized=$(sed -E 's/localhost:[0-9]+/localhost:PORT/g' "$expected")
    else
        actual_normalized=$(cat "$actual")
        expected_normalized=$(cat "$expected")
    fi

    local diff_output
    diff_output=$(diff <(echo "$expected_normalized") <(echo "$actual_normalized") 2>&1) || true

    if [ -z "$diff_output" ]; then
        log_ok "${label}: matches expected output"
        return 0
    else
        log_fail "${label}: differs from expected output"
        # Show first 20 lines of diff
        echo "$diff_output" | head -20
        # Save full diff to results dir for later review
        local diff_file
        diff_file="${RESULTS_DIR:-/tmp}/${label//[ \/]/_}.diff"
        echo "$diff_output" > "$diff_file" 2>/dev/null || true
        log_info "Full diff saved to: $diff_file"
        return 1
    fi
}

# compare_json diffs two JSON files after pretty-printing and optional port normalization.
# Usage: compare_json <actual_file> <expected_file> <label> [--normalize-ports]
# Returns 0 if semantically identical, 1 if different.
compare_json() {
    local actual=$1
    local expected=$2
    local label=$3
    local normalize=${4:-}

    if [ ! -f "$actual" ]; then
        log_fail "${label}: actual file not found: $actual"
        return 1
    fi
    if [ ! -f "$expected" ]; then
        log_fail "${label}: expected file not found: $expected"
        return 1
    fi

    local result rc=0
    result=$(python3 - "$actual" "$expected" "$normalize" << 'PYEOF'
import json, sys, re

with open(sys.argv[1]) as f:
    actual = json.load(f)
with open(sys.argv[2]) as f:
    expected = json.load(f)

normalize = sys.argv[3] == "--normalize-ports"

def normalize_ports(obj):
    """Replace localhost:<port> with localhost:PORT in all string values."""
    if isinstance(obj, str):
        return re.sub(r"localhost:\d+", "localhost:PORT", obj)
    if isinstance(obj, list):
        return [normalize_ports(x) for x in obj]
    if isinstance(obj, dict):
        return {k: normalize_ports(v) for k, v in obj.items()}
    return obj

if normalize:
    actual = normalize_ports(actual)
    expected = normalize_ports(expected)

actual_str = json.dumps(actual, indent=2, sort_keys=True)
expected_str = json.dumps(expected, indent=2, sort_keys=True)

if actual_str == expected_str:
    print("OK")
    sys.exit(0)

# Find first differing line
a_lines = actual_str.split("\n")
e_lines = expected_str.split("\n")
for i, (a, e) in enumerate(zip(a_lines, e_lines)):
    if a != e:
        print("DIFF at line %d:" % (i + 1))
        print("  expected: %s" % e)
        print("  actual:   %s" % a)
        sys.exit(1)
if len(a_lines) != len(e_lines):
    print("DIFF: expected %d lines, got %d" % (len(e_lines), len(a_lines)))
    sys.exit(1)
PYEOF
    ) || rc=$?

    if [ $rc -ne 0 ]; then
        log_fail "${label}: ${result}"
        return 1
    fi
    log_ok "${label}: matches expected output"
    return 0
}

# count_spec_endpoints counts the number of path entries in an OpenAPI spec.
# Usage: count_spec_endpoints <spec_file>
count_spec_endpoints() {
    local spec_file=$1
    python3 - "$spec_file" << 'PYEOF'
import sys, re

with open(sys.argv[1]) as f:
    content = f.read()

in_paths = False
paths_indent = None
count = 0
for line in content.split("\n"):
    stripped = line.rstrip()
    if re.match(r"^paths:\s*(|\{\})\s*$", stripped):
        in_paths = True
        if "{}" in stripped:
            break  # inline empty mapping, no children
        continue
    if in_paths:
        if stripped and not stripped[0].isspace():
            break
        m = re.match(r'^(\s+)(?:"(/[^"]*)"|\'(/[^\']*)\'|(/[^:"\']*)):', stripped)
        if m:
            indent = m.group(1)
            if paths_indent is None:
                paths_indent = indent
            if indent == paths_indent:
                count += 1

print(count)
PYEOF
}

# count_capture_pages counts the number of distinct PAGES visited in a
# capture, not the number of raw captured request records (LAB-4678,
# pkg/crawl/doc.go). MaxPages caps pages (distinct URLs visited) rather than
# captured requests, because a single SPA page can fire dozens of XHR/fetch
# calls that all count as one page. pkg/crawl/engine.go's visitPage opens a
# fresh tab per page on the rod (headless browser) backend, so the browser
# also emits that page's sub-resource requests (e.g. a 200 /favicon.ico) into
# the capture — inflating a raw record count well past the page budget even
# though the budget itself (pageBudgetReached, reserved under a mutex before
# each visit) was enforced exactly. pkg/crawl's own
# TestCrawlerContract_RespectsMaxPages test counts pages the same way for the
# same reason, explicitly excluding sub-resources so the counter is
# comparable across both the http and rod backends. This was the CI failure
# in PR #187 ("Max-pages limit: captured 20 requests (limit=10, allowed
# <=15)"): the test was counting raw capture records against a page budget.
#
# Discriminator: ObservedRequest carries a page_url field
# (pkg/crawl/types.go:37) that the browser backend sets on every captured
# exchange to the page it was observed on (pkg/crawl/network.go:154-161), so
# distinct page_url values are exactly the visited-page set. The net/http
# backend emits no page_url at all (one record per page, source=http), so
# fall back to counting distinct url values there.
#
# Invariant (PR #187 review finding CodeRabbit r3676134141): any
# structurally invalid capture yields "?", which assert_max_pages rejects
# via its ^[0-9]+$ guard — so a broken capture can never satisfy the
# max-pages assertion. This includes non-list top-level JSON (object,
# string, number, null) and a non-empty list from which zero pages could be
# derived (no element is a dict, or no element carries page_url or url —
# url is a required ObservedRequest field per pkg/crawl/types.go, so a
# non-empty capture always yields at least one). Only a genuinely empty
# list ([]) yields "0", since that's a structurally valid capture meaning
# "zero requests captured" and 0 pages does not exceed the cap.
# Usage: count_capture_pages <capture_file>
count_capture_pages() {
    local capture_file=$1
    python3 - "$capture_file" << 'PYEOF'
import json, sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    print("?")
    sys.exit(0)

if not isinstance(data, list):
    print("?")
    sys.exit(0)

page_urls = {r.get("page_url") for r in data if isinstance(r, dict) and r.get("page_url")}
if page_urls:
    print(len(page_urls))
    sys.exit(0)

urls = {r.get("url") for r in data if isinstance(r, dict) and r.get("url")}
if urls:
    print(len(urls))
    sys.exit(0)

if len(data) == 0:
    print(0)
else:
    print("?")
PYEOF
}

# validate_paths_absent fails if any forbidden path appears as a top-level
# key in the OpenAPI spec. Matching convention per forbidden value F:
#   - F ending in "/"  → SUBTREE match: flags the root and any descendant
#                        (e.g. "/api/missing/" flags "/api/missing" and
#                        "/api/missing/{id}/gone").
#   - F without "/"    → EXACT match only (e.g. "/api/users" flags the bare
#                        receiver literal but NOT "/api/users/{id}/orders").
# Used to assert that paths which must be filtered out (404 controls, bare
# receiver literals) did not leak into the generated spec.
# Usage: validate_paths_absent <spec_file> <forbidden_path>...
validate_paths_absent() {
    local spec_file=$1
    shift
    local result rc=0
    result=$(python3 - "$spec_file" "$@" << 'PYEOF'
import sys, re

spec_file = sys.argv[1]
forbidden = sys.argv[2:]

with open(spec_file) as f:
    content = f.read()

keys = []
in_paths = False
paths_indent = None
for line in content.split("\n"):
    stripped = line.rstrip()
    if re.match(r"^paths:\s*$", stripped):
        in_paths = True
        continue
    if in_paths:
        if stripped and not stripped[0].isspace():
            break
        m = re.match(r'^(\s+)(?:"(/[^"]*)"|\'(/[^\']*)\'|(/[^:"\']*)):', stripped)
        if m:
            indent = m.group(1)
            if paths_indent is None:
                paths_indent = indent
            if indent == paths_indent:
                keys.append(m.group(2) or m.group(3) or m.group(4))


def is_forbidden(k, fb):
    if fb.endswith("/"):
        root = fb.rstrip("/")
        return k == root or k.startswith(root + "/")
    return k == fb


bad = sorted({k for k in keys for fb in forbidden if is_forbidden(k, fb)})
if bad:
    print("LEAKED: " + ", ".join(bad))
    sys.exit(1)
print("OK: none of %d forbidden path(s) present" % len(forbidden))
PYEOF
    ) || rc=$?
    if [ $rc -ne 0 ]; then
        log_fail "Forbidden paths present in spec: ${result#LEAKED: }"
        return 1
    fi
    log_ok "${result}"
    return 0
}

# assert_within_depth checks a depth-limited crawl stayed inside its --depth
# budget AND actually followed links past the seed (LAB-3890 T3, gap B2).
# Extracted from test_crawl_depth so validate_test.sh can lock the boundary
# logic (PR #187 review finding TEST-004).
#
# Both counts are recovered by string surgery on one line of python stdout in
# the caller, so a change to that print format yields garbage rather than a
# number. The inline version guarded only reached_depth against the "?"
# sentinel; here BOTH sides must be numeric or the assertion hard-fails.
# Usage: assert_within_depth <label> <beyond_count> <reached_count>
assert_within_depth() {
    local label=$1 beyond=$2 reached=$3

    if ! [[ $beyond =~ ^[0-9]+$ ]]; then
        log_fail "${label}: beyond-depth count is not a number: '${beyond}' (depth-count extraction failed)"
        return 1
    fi
    if ! [[ $reached =~ ^[0-9]+$ ]]; then
        log_fail "${label}: reached-depth count is not a number: '${reached}' (depth-count extraction failed)"
        return 1
    fi
    if [ "$beyond" -ne 0 ]; then
        log_fail "${label}: found ${beyond} URL(s) beyond the requested depth — --depth not enforced"
        return 1
    fi
    if [ "$reached" -eq 0 ]; then
        log_fail "${label}: crawl never got past the seed — under-crawl / premature stop"
        return 1
    fi
    return 0
}

# assert_max_pages checks a crawl honoured its --max-pages cap (LAB-3890 T3,
# gap B2). Extracted from test_crawl_depth (PR #187 review finding TEST-004).
#
# This used to allow a margin (page_count <= limit + margin) on the theory
# that in-flight requests could overshoot the cap. That tolerance is gone: it
# no longer models anything real. count_capture_pages counts visited PAGES,
# not raw requests, and pageBudgetReached (pkg/crawl/engine.go) compares and
# increments the visited count inside a single mutex-guarded critical
# section, so the number of visited pages can never exceed MaxPages. CI run
# 30469344133 confirms this empirically: "[OK] Max-pages limit: visited 10
# page(s) (limit=10)" — the crawler lands exactly on the cap, zero overshoot.
# Keeping a vestigial margin only invites it being silently widened again
# (PR #187 review finding, outside-diff L836-L845).
# Usage: assert_max_pages <label> <page_count> <limit>
assert_max_pages() {
    local label=$1 page_count=$2 limit=$3

    if ! [[ $page_count =~ ^[0-9]+$ ]]; then
        log_fail "${label}: page count is not a number: '${page_count}' (capture read failed)"
        return 1
    fi
    if [ "$page_count" -gt "$limit" ]; then
        log_fail "${label}: visited ${page_count} page(s) (limit=${limit}) — --max-pages not enforced"
        return 1
    fi
    return 0
}
