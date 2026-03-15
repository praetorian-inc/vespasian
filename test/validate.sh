#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Shared validation functions for vespasian live tests.
# Source this file from run-live-tests.sh.

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
    if re.match(r"^paths:\s*$", stripped):
        in_paths = True
        continue
    if in_paths:
        # Another top-level key ends paths section
        if stripped and not stripped[0].isspace():
            break
        # Detect the indent of the first child to know the path indent level
        m = re.match(r'^(\s+)["\']?(/[^:"\']*)["\']?:', stripped)
        if m:
            indent = m.group(1)
            if paths_indent is None:
                paths_indent = indent
            # Only match paths at the same indent level (not nested keys)
            if indent == paths_indent:
                found_paths.append(m.group(2))

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

# validate_openapi_structure checks that the spec file has required OpenAPI fields.
# Usage: validate_openapi_structure <spec_file>
validate_openapi_structure() {
    local spec_file=$1

    if [ ! -f "$spec_file" ]; then
        log_fail "Spec file not found: $spec_file"
        return 1
    fi

    local result
    result=$(python3 - "$spec_file" << 'PYEOF'
import sys

with open(sys.argv[1]) as f:
    content = f.read()

required = ["openapi:", "info:", "paths:"]
missing = [r for r in required if r not in content]
if missing:
    print("MISSING fields: " + ", ".join(missing))
    sys.exit(1)
print("OK: valid OpenAPI structure")
PYEOF
    )

    if [ $? -ne 0 ]; then
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

    local result
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
    )

    if [ $? -ne 0 ]; then
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

    local result
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
    )

    if [ $? -ne 0 ]; then
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

    local result
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
    )

    if [ $? -ne 0 ]; then
        log_fail "Import validation: $result"
        return 1
    fi
    log_ok "Import validation: $result"
    return 0
}

# validate_soap_operations checks that WSDL output contains expected operations.
# Usage: validate_soap_operations <wsdl_file> <expected_json>
validate_soap_operations() {
    local wsdl_file=$1
    local expected_json=$2

    if [ ! -f "$wsdl_file" ]; then
        log_fail "WSDL file not found: $wsdl_file"
        return 1
    fi

    local result
    result=$(python3 - "$wsdl_file" "$expected_json" << 'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    content = f.read()

with open(sys.argv[2]) as f:
    expected = json.load(f)

missing = []
for op in expected["operations"]:
    if op not in content:
        missing.append(op)

if missing:
    print("MISSING operations: " + ", ".join(missing))
    sys.exit(1)

print("OK: all %d operations found" % len(expected["operations"]))
PYEOF
    )

    if [ $? -ne 0 ]; then
        log_fail "SOAP operations: $result"
        return 1
    fi
    log_ok "SOAP operations: $result"
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

    local result
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
    )

    if [ $? -ne 0 ]; then
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
    if re.match(r"^paths:\s*$", stripped):
        in_paths = True
        continue
    if in_paths:
        if stripped and not stripped[0].isspace():
            break
        m = re.match(r'^(\s+)["\']?(/[^:"\']*)["\']?:', stripped)
        if m:
            indent = m.group(1)
            if paths_indent is None:
                paths_indent = indent
            if indent == paths_indent:
                count += 1

print(count)
PYEOF
}
