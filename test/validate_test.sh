#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Regression test for the real-parser spec validators in test/validate.sh
# (LAB-3890 T1). These validators previously used grep / substring matching,
# so a malformed spec that merely *contained* the right strings passed:
#
#   * validate_openapi_structure greps for top-level "openapi:"/"info:"/"paths:"
#   * validate_soap_operations   did `if op not in content` (substring):
#                                expected "GetUser" false-passed on "GetUserList"
#   * validate_graphql_structure checked for the literals "type Query {" + "}"
#
# This test asserts the CORRECT (hardened) behaviour: valid specs pass, and
# every malformed / substring-trap fixture is REJECTED. Run against the old
# validators it fails (the false-passes); against the new parser-backed
# validators it passes.
#
# assert_reject requires BOTH a non-zero return code AND that the captured
# output contains an expected substring naming the real rejection reason
# (LAB-3890 TEST-005). A bare non-zero check cannot tell "rejected because the
# fixture is malformed" apart from "rejected because a prerequisite is missing
# or the validator is universally broken" — at the PR #187 review head, with
# xmllint absent, validate_soap_operations returned 1 for EVERY input, so all
# three WSDL reject cases printed "PASS (rejected invalid)" while proving
# nothing.
#
# Needs: node + test/spec-validators deps installed (npm ci), and python3.
# No Go build or live services required — runs in the offline CI job, in its
# own un-gated `validator-regression` job (see .github/workflows/live-tests.yml).
#
#   ./test/validate_test.sh

set -uo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "${THIS_DIR}/common.sh"
# shellcheck source=/dev/null
source "${THIS_DIR}/validate.sh"

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

PASS=0
FAIL=0

# assert_ok  <label> <function> <args...>  -> expects return code 0
assert_ok() {
    local label=$1; shift
    if "$@" >/dev/null 2>&1; then
        log_ok "PASS (accepted valid): ${label}"
        PASS=$((PASS + 1))
    else
        log_fail "FAIL (rejected valid): ${label}"
        FAIL=$((FAIL + 1))
    fi
}

# assert_reject <label> <expected_substring> <function> <args...>
#   -> expects a non-zero return code AND that the combined stdout+stderr
#      contains <expected_substring>, so a reject only counts as PASS when it
#      is rejected for the reason under test (LAB-3890 TEST-005).
#
# Distinguishes two failure modes in the log:
#   - rc == 0                        : "false-passed invalid" (accepted junk)
#   - rc != 0, substring not found   : "rejected for the WRONG reason" (a
#                                       broken/missing prerequisite or a
#                                       universally-failing validator would
#                                       otherwise print a false PASS here)
assert_reject() {
    local label=$1 expected_substring=$2; shift 2
    local output rc=0
    output=$("$@" 2>&1) || rc=$?

    if [ "$rc" -eq 0 ]; then
        log_fail "FAIL (false-passed invalid): ${label}"
        FAIL=$((FAIL + 1))
        return
    fi

    if printf '%s' "$output" | grep -qF -- "$expected_substring"; then
        log_ok "PASS (rejected invalid): ${label}"
        PASS=$((PASS + 1))
    else
        log_fail "FAIL (rejected for the WRONG reason): ${label}
  expected substring: ${expected_substring}
  actual output:      ${output}"
        FAIL=$((FAIL + 1))
    fi
}

# ──────────────────────────────────────────────────────────────
# OpenAPI
# ──────────────────────────────────────────────────────────────
log_header "validate_openapi_structure"

assert_ok "real generated 3.0.3 spec" \
    validate_openapi_structure "${THIS_DIR}/rest-api/expected-spec.yaml"

# Has the three magic top-level keys, but info is a string and the operation
# is a string — structurally invalid OpenAPI.
cat > "${WORK_DIR}/openapi-magic-keys-broken.yaml" <<'EOF'
openapi: 3.0.3
info: "should be an object"
paths:
  /users:
    get: "should be an operation object"
EOF
assert_reject "magic keys present but structurally broken" "INVALID:" \
    validate_openapi_structure "${WORK_DIR}/openapi-magic-keys-broken.yaml"

# Junk that contains the magic words but is not a valid document.
printf 'openapi info paths\nnot yaml at all: : :\n' > "${WORK_DIR}/openapi-junk.yaml"
assert_reject "junk text containing magic words" "INVALID:" \
    validate_openapi_structure "${WORK_DIR}/openapi-junk.yaml"

# Nonexistent spec file must be reported as such, not confused with a parser
# failure.
assert_reject "nonexistent OpenAPI spec file" "Spec file not found" \
    validate_openapi_structure "${WORK_DIR}/does-not-exist-openapi.yaml"

# Two operations both declaring operationId: dup. swagger-parser's own
# semantic pass is a no-op for OpenAPI 3.x (never checks this), so this is the
# validator's own explicit findDuplicateOperationId() check under test.
cat > "${WORK_DIR}/openapi-dup-operationid.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: Test
  version: "1.0.0"
paths:
  /a:
    get:
      operationId: dup
      responses:
        '200':
          description: ok
  /b:
    get:
      operationId: dup
      responses:
        '200':
          description: ok
EOF
assert_reject "duplicate operationId across two paths" "duplicate operationId" \
    validate_openapi_structure "${WORK_DIR}/openapi-dup-operationid.yaml"

# External $ref: resolve.external:false stops swagger-parser from fetching it,
# which also means it stops being an error at all unless the validator flags
# it explicitly (SEC-FE-002).
cat > "${WORK_DIR}/openapi-external-ref.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: Test
  version: "1.0.0"
paths:
  /a:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                $ref: './no-such-file.yaml#/X'
EOF
assert_reject "external \$ref to a file outside the spec" "external \$ref not permitted" \
    validate_openapi_structure "${WORK_DIR}/openapi-external-ref.yaml"

# A legitimate INTERNAL $ref must still be accepted — the external-ref walker
# must not be "fixed" by rejecting every $ref.
cat > "${WORK_DIR}/openapi-internal-ref.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: Test
  version: "1.0.0"
paths:
  /a:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Foo'
components:
  schemas:
    Foo:
      type: object
      properties:
        bar:
          type: string
EOF
assert_ok "legitimate internal \$ref to components/schemas" \
    validate_openapi_structure "${WORK_DIR}/openapi-internal-ref.yaml"

# ──────────────────────────────────────────────────────────────
# SOAP / WSDL operations
# ──────────────────────────────────────────────────────────────
log_header "validate_soap_operations"

assert_ok "real generated WSDL, exact operations" \
    validate_soap_operations "${THIS_DIR}/soap-service/service.wsdl" \
    "${THIS_DIR}/soap-service/expected-paths.json"

# Substring trap: WSDL defines only GetUserList; expecting GetUser must FAIL
# (the old validator false-passed because "GetUser" is a substring of
# "GetUserList").
cat > "${WORK_DIR}/substring.wsdl" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<definitions name="S" targetNamespace="urn:s"
             xmlns="http://schemas.xmlsoap.org/wsdl/">
  <portType name="P">
    <operation name="GetUserList"/>
  </portType>
</definitions>
EOF
printf '{"operations":["GetUser"]}' > "${WORK_DIR}/expect-getuser.json"
assert_reject "expected GetUser, WSDL only has GetUserList (substring trap)" "MISSING operations" \
    validate_soap_operations "${WORK_DIR}/substring.wsdl" "${WORK_DIR}/expect-getuser.json"

# Comment trap: operation name appears only in a comment, not as an element.
cat > "${WORK_DIR}/comment.wsdl" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<definitions name="S" targetNamespace="urn:s"
             xmlns="http://schemas.xmlsoap.org/wsdl/">
  <!-- GetUser is planned but not implemented -->
  <portType name="P">
    <operation name="ListUsers"/>
  </portType>
</definitions>
EOF
assert_reject "expected GetUser present only in an XML comment" "MISSING operations" \
    validate_soap_operations "${WORK_DIR}/comment.wsdl" "${WORK_DIR}/expect-getuser.json"

# Zero-operation portType: the empty-extraction path. Most likely way a
# future refactor of the extraction pipeline breaks silently — an empty
# actual_ops set must still correctly report every expected op as missing,
# not short-circuit into a false pass.
cat > "${WORK_DIR}/zero-op-porttype.wsdl" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<definitions name="S" targetNamespace="urn:s"
             xmlns="http://schemas.xmlsoap.org/wsdl/">
  <portType name="P"></portType>
</definitions>
EOF
assert_reject "zero-operation portType with non-empty expected operations" "MISSING operations" \
    validate_soap_operations "${WORK_DIR}/zero-op-porttype.wsdl" "${WORK_DIR}/expect-getuser.json"

# Malformed XML must be rejected outright.
printf '<definitions><portType><operation name="GetUser">\n' > "${WORK_DIR}/malformed.wsdl"
printf '{"operations":["GetUser"]}' > "${WORK_DIR}/expect-getuser2.json"
assert_reject "malformed (non-well-formed) WSDL" "not well-formed XML" \
    validate_soap_operations "${WORK_DIR}/malformed.wsdl" "${WORK_DIR}/expect-getuser2.json"

# Nonexistent WSDL file must be reported as such.
assert_reject "nonexistent WSDL file" "WSDL file not found" \
    validate_soap_operations "${WORK_DIR}/does-not-exist.wsdl" "${WORK_DIR}/expect-getuser.json"

# ──────────────────────────────────────────────────────────────
# GraphQL SDL
# ──────────────────────────────────────────────────────────────
log_header "validate_graphql_structure"

assert_ok "real generated SDL" \
    validate_graphql_structure "${THIS_DIR}/graphql-server/expected-spec.graphql"

# Literals present, length > 50, but references an undefined type.
cat > "${WORK_DIR}/bad.graphql" <<'EOF'
type Query {
  user(id: ID!): NoSuchType
}
# padding padding padding padding padding padding
EOF
assert_reject "'type Query {' + '}' present but references unknown type" "INVALID:" \
    validate_graphql_structure "${WORK_DIR}/bad.graphql"

# Junk containing the magic literals.
printf 'type Query { a closing brace } but not valid graphql whatsoever here now\n' \
    > "${WORK_DIR}/junk.graphql"
assert_reject "junk text containing 'type Query {' and '}'" "INVALID:" \
    validate_graphql_structure "${WORK_DIR}/junk.graphql"

# Nonexistent SDL file must be reported as such.
assert_reject "nonexistent GraphQL SDL file" "SDL file not found" \
    validate_graphql_structure "${WORK_DIR}/does-not-exist.graphql"

# ──────────────────────────────────────────────────────────────
# _ensure_spec_validators
# ──────────────────────────────────────────────────────────────
log_header "_ensure_spec_validators"

# _test_missing_spec_validator_deps runs _ensure_spec_validators against an
# empty deps directory inside an explicit subshell, so the SPEC_VALIDATORS_DIR
# override CANNOT leak into the rest of this script's run.
_test_missing_spec_validator_deps() {
    local empty_dir=$1
    (
        SPEC_VALIDATORS_DIR="$empty_dir"
        _ensure_spec_validators
    )
}
EMPTY_DEPS_DIR="${WORK_DIR}/empty-spec-validators-deps"
mkdir -p "${EMPTY_DEPS_DIR}"
assert_reject "missing spec-validator node_modules gives an actionable npm ci message" "npm ci" \
    _test_missing_spec_validator_deps "${EMPTY_DEPS_DIR}"

# ──────────────────────────────────────────────────────────────
# SPEC_VALIDATOR_MAX_BYTES (too-large rejection path)
# ──────────────────────────────────────────────────────────────
log_header "SPEC_VALIDATOR_MAX_BYTES"

# CodeRabbit nitpick (PR #187): the too-large rejection branch in both
# validate-openapi.mjs and validate-graphql.mjs was untestable without
# generating a multi-megabyte fixture. SPEC_VALIDATOR_MAX_BYTES lets this
# exercise that branch cheaply against the real (small) fixtures instead.
#
# Same subshell-wrapper pattern as _test_missing_spec_validator_deps above:
# each wrapper runs in an explicit subshell so `export SPEC_VALIDATOR_MAX_BYTES`
# CANNOT leak into the rest of this script's run.
_test_tiny_max_bytes_openapi() {
    local spec_file=$1
    (
        export SPEC_VALIDATOR_MAX_BYTES=10
        validate_openapi_structure "$spec_file"
    )
}
_test_tiny_max_bytes_graphql() {
    local sdl_file=$1
    (
        export SPEC_VALIDATOR_MAX_BYTES=10
        validate_graphql_structure "$sdl_file"
    )
}
_test_generous_max_bytes_openapi() {
    local spec_file=$1
    (
        export SPEC_VALIDATOR_MAX_BYTES=10485760
        validate_openapi_structure "$spec_file"
    )
}
_test_generous_max_bytes_graphql() {
    local sdl_file=$1
    (
        export SPEC_VALIDATOR_MAX_BYTES=10485760
        validate_graphql_structure "$sdl_file"
    )
}

assert_reject "tiny SPEC_VALIDATOR_MAX_BYTES rejects the real OpenAPI fixture as too large" \
    "too large" \
    _test_tiny_max_bytes_openapi "${THIS_DIR}/rest-api/expected-spec.yaml"

assert_reject "tiny SPEC_VALIDATOR_MAX_BYTES rejects the real GraphQL fixture as too large" \
    "too large" \
    _test_tiny_max_bytes_graphql "${THIS_DIR}/graphql-server/expected-spec.graphql"

# A generous override must not trivially "pass" by rejecting everything —
# both real fixtures must still be accepted under it.
assert_ok "generous SPEC_VALIDATOR_MAX_BYTES still accepts the real OpenAPI fixture" \
    _test_generous_max_bytes_openapi "${THIS_DIR}/rest-api/expected-spec.yaml"
assert_ok "generous SPEC_VALIDATOR_MAX_BYTES still accepts the real GraphQL fixture" \
    _test_generous_max_bytes_graphql "${THIS_DIR}/graphql-server/expected-spec.graphql"

# The override must not leak into this script's own environment.
if [ -n "${SPEC_VALIDATOR_MAX_BYTES+x}" ]; then
    log_fail "FAIL (env leak): SPEC_VALIDATOR_MAX_BYTES leaked into the parent shell: '${SPEC_VALIDATOR_MAX_BYTES}'"
    FAIL=$((FAIL + 1))
else
    log_ok "PASS (no env leak): SPEC_VALIDATOR_MAX_BYTES is unset in the parent shell"
    PASS=$((PASS + 1))
fi

# ──────────────────────────────────────────────────────────────
# assert_no_panic
# ──────────────────────────────────────────────────────────────
log_header "assert_no_panic"

# Locks the panic-detection regex extracted from test_import_malformed (gap B3).
# A broken pattern would silently downgrade the importer panic check to a no-op.
assert_ok "clean graceful error output" \
    assert_no_panic "graceful" "Error: failed to parse burp XML: unexpected EOF"
assert_ok "empty output" \
    assert_no_panic "empty" ""
assert_reject "output containing a Go panic" "PANICKED" \
    assert_no_panic "panicked" "panic: runtime error: index out of range [3] with length 0"
assert_reject "output containing a goroutine stack trace" "PANICKED" \
    assert_no_panic "stacktrace" "goroutine 1 [running]:
main.main()
	/src/main.go:42 +0x1d"

# Specificity: the regex is case-insensitive and colon-anchored. These pin
# that a bare "panic" or "goroutine" word must NOT fire, and that the
# case-insensitive match on "panic:" is intentional — without these, someone
# "simplifying" the pattern to a bare `panic` or `goroutine` match would turn
# every graceful importer error into a spurious failure and no test would
# object.
assert_ok "the word 'panic' without a colon must not fire" \
    assert_no_panic "recovered-msg" "recovered from panic in handler"
assert_ok "'goroutine' without a '[running]' trace must not fire" \
    assert_no_panic "goroutine-leak-msg" "goroutine leak detected"
assert_reject "case-insensitive PANIC: must still fire" "PANICKED" \
    assert_no_panic "case-insensitive" "PANIC: runtime error"

# ──────────────────────────────────────────────────────────────
# assert_ssrf_rejected
# ──────────────────────────────────────────────────────────────
log_header "assert_ssrf_rejected"

GENUINE_SSRF_REJECTION='vespasian: error: crawl failed: seed URL rejected by frontier (scope, SSRF, or parse): http://127.0.0.1:9; if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), pass --dangerous-allow-private'
assert_ok "genuine frontier rejection for the seed under test" \
    assert_ssrf_rejected "genuine" "http://127.0.0.1:9" "$GENUINE_SSRF_REJECTION"

# The old inline check grepped case-insensitively for
# 'ssrf|private|rejected by frontier|dangerous-allow-private'. kong is built
# with kong.UsageOnError(), so ANY parse error (e.g. a renamed subcommand or
# flag) prints this usage block, which lists --dangerous-allow-private and its
# help text — and would have satisfied that old grep with the gate never
# having run. This is the whole point of the finding: the block must be
# REJECTED, not accepted.
KONG_USAGE_BLOCK='Usage: vespasian <command> [flags]

Flags:
  -h, --help                      Show context-sensitive help.
      --dangerous-allow-private    Disable SSRF protection for crawling, allowing private/localhost targets (localhost, 127.0.0.1, RFC1918, link-local).

Commands:
  crawl <url>    Crawl a target and capture traffic
  scan <url>     Scan a target end-to-end

Run "vespasian <command> --help" for more information on a command.'
assert_reject "kong usage block containing --dangerous-allow-private must be rejected" \
    "kong printed its usage banner" \
    assert_ssrf_rejected "kong-usage" "http://127.0.0.1:9" "$KONG_USAGE_BLOCK"

# Frontier phrase present but names a DIFFERENT seed than the one under test.
WRONG_SEED_REJECTION='vespasian: error: crawl failed: seed URL rejected by frontier (scope, SSRF, or parse): http://10.0.0.5:80; if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), pass --dangerous-allow-private'
assert_reject "frontier phrase present but names a different seed" \
    "did not name the seed" \
    assert_ssrf_rejected "wrong-seed" "http://127.0.0.1:9" "$WRONG_SEED_REJECTION"

# An unrelated error must not be mistaken for an SSRF rejection.
assert_reject "unrelated error is not an SSRF rejection" \
    "output has no frontier rejection" \
    assert_ssrf_rejected "unrelated" "http://127.0.0.1:9" "Error: connection refused"

# ──────────────────────────────────────────────────────────────
# assert_within_depth
# ──────────────────────────────────────────────────────────────
log_header "assert_within_depth"

assert_ok "correct crawl: within depth budget, reached beyond the seed" \
    assert_within_depth "ok-depth" 0 5

assert_reject "over-crawl: URLs found beyond the requested depth" \
    "--depth not enforced" \
    assert_within_depth "over-depth" 2 5

assert_reject "under-crawl: never reached past the seed" \
    "under-crawl" \
    assert_within_depth "under-depth" 0 0

# Unparsable '?' must be rejected on BOTH sides — the old inline code guarded
# only the reached side, so the beyond side is what this pins.
assert_reject "unparsable beyond-depth count ('?')" \
    "beyond-depth count is not a number" \
    assert_within_depth "unparsable-beyond" "?" 5

assert_reject "unparsable reached-depth count ('?')" \
    "reached-depth count is not a number" \
    assert_within_depth "unparsable-reached" 0 "?"

# ──────────────────────────────────────────────────────────────
# assert_max_pages
# ──────────────────────────────────────────────────────────────
log_header "assert_max_pages"

# Production value: limit=10. No margin — the cap is enforced exactly
# (PR #187 review finding, outside-diff L836-L845; see assert_max_pages
# comment in validate.sh for why the margin was removed).
assert_ok "at the limit (10) is accepted" \
    assert_max_pages "at-limit" 10 10

assert_reject "one over the limit (11) is rejected" \
    "--max-pages not enforced" \
    assert_max_pages "over-limit" 11 10

assert_ok "comfortably under the limit (3) is accepted" \
    assert_max_pages "under-limit" 3 10

assert_reject "unparsable page count ('?')" \
    "page count is not a number" \
    assert_max_pages "unparsable-count" "?" 10

# assert_count <label> <expected> <function> <args...>
#   -> runs <function> with <args...>, captures its stdout, and compares it
#      (trimmed of a trailing newline) against <expected>. count_capture_pages
#      communicates its result via printed stdout rather than a return code,
#      so assert_ok/assert_reject (which only inspect rc / combined output)
#      don't fit; this is the dedicated stdout-comparison counterpart.
assert_count() {
    local label=$1 expected=$2; shift 2
    local actual
    actual=$("$@" 2>/dev/null)

    if [ "$actual" = "$expected" ]; then
        log_ok "PASS (count matches): ${label}"
        PASS=$((PASS + 1))
    else
        log_fail "FAIL (count mismatch): ${label}
  expected: ${expected}
  actual:   ${actual}"
        FAIL=$((FAIL + 1))
    fi
}

# ──────────────────────────────────────────────────────────────
# count_capture_pages
# ──────────────────────────────────────────────────────────────
log_header "count_capture_pages"

# rod-style capture: 10 distinct page_url values but 20 records (each page
# contributes a navigation record plus a /favicon.ico sub-resource record
# sharing the same page_url). This is the exact CI scenario from PR #187 —
# the single most important case here.
python3 - "${WORK_DIR}/rod-style-capture.json" << 'PYEOF'
import json, sys

records = []
for i in range(10):
    page_url = "http://example.test/page%d" % i
    records.append({"url": page_url, "page_url": page_url, "source": "rod"})
    records.append({"url": page_url + "/favicon.ico", "page_url": page_url, "source": "rod"})

with open(sys.argv[1], "w") as f:
    json.dump(records, f)
PYEOF
assert_count "rod-style capture: 10 pages, 20 records (navigation + favicon per page)" \
    "10" \
    count_capture_pages "${WORK_DIR}/rod-style-capture.json"

# net/http-style capture: no page_url key at all, 10 distinct urls.
python3 - "${WORK_DIR}/http-style-capture.json" << 'PYEOF'
import json, sys

records = [{"url": "http://example.test/page%d" % i, "source": "http"} for i in range(10)]

with open(sys.argv[1], "w") as f:
    json.dump(records, f)
PYEOF
assert_count "net/http-style capture: 10 records, no page_url key, 10 distinct urls" \
    "10" \
    count_capture_pages "${WORK_DIR}/http-style-capture.json"

# Duplicate urls, no page_url: must count distinct urls, not records.
python3 - "${WORK_DIR}/duplicate-urls-capture.json" << 'PYEOF'
import json, sys

records = [{"url": "http://example.test/same"} for _ in range(5)]

with open(sys.argv[1], "w") as f:
    json.dump(records, f)
PYEOF
assert_count "duplicate urls, no page_url: distinct count not record count" \
    "1" \
    count_capture_pages "${WORK_DIR}/duplicate-urls-capture.json"

# Empty list.
printf '[]' > "${WORK_DIR}/empty-capture.json"
assert_count "empty list" \
    "0" \
    count_capture_pages "${WORK_DIR}/empty-capture.json"

# Malformed JSON.
printf '{not valid json' > "${WORK_DIR}/malformed-capture.json"
assert_count "malformed JSON" \
    "?" \
    count_capture_pages "${WORK_DIR}/malformed-capture.json"

# Not a list (object). A structurally invalid capture must never satisfy
# assert_max_pages by masquerading as "0 pages" (PR #187 review finding
# CodeRabbit r3676134141) — it must yield "?", which assert_max_pages
# rejects via its ^[0-9]+$ guard.
printf '{}' > "${WORK_DIR}/not-a-list-capture.json"
assert_count "not a list (object)" \
    "?" \
    count_capture_pages "${WORK_DIR}/not-a-list-capture.json"

# Not a list (array of scalars, non-empty). Same defect class: a non-empty
# list with no dict elements yields zero derivable pages, so it must be
# rejected as "?" rather than silently reported as "0".
printf '["a", "b"]' > "${WORK_DIR}/not-a-list-of-dicts-capture.json"
assert_count "not a list of dicts (array of scalars)" \
    "?" \
    count_capture_pages "${WORK_DIR}/not-a-list-of-dicts-capture.json"

# Not a list (string).
printf '"nope"' > "${WORK_DIR}/not-a-list-string-capture.json"
assert_count "not a list (string)" \
    "?" \
    count_capture_pages "${WORK_DIR}/not-a-list-string-capture.json"

# Not a list (number).
printf '42' > "${WORK_DIR}/not-a-list-number-capture.json"
assert_count "not a list (number)" \
    "?" \
    count_capture_pages "${WORK_DIR}/not-a-list-number-capture.json"

# Not a list (null).
printf 'null' > "${WORK_DIR}/not-a-list-null-capture.json"
assert_count "not a list (null)" \
    "?" \
    count_capture_pages "${WORK_DIR}/not-a-list-null-capture.json"

# Non-empty list of dicts, but no record carries url or page_url: not a
# capture at all (url is a required ObservedRequest field), so zero
# derivable pages must be reported as "?", not "0".
printf '[{"method":"GET"},{"method":"POST"}]' > "${WORK_DIR}/no-url-field-capture.json"
assert_count "non-empty list of dicts, no url/page_url field on any record" \
    "?" \
    count_capture_pages "${WORK_DIR}/no-url-field-capture.json"

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
echo ""
if [ "${FAIL}" -eq 0 ]; then
    log_ok "validate.sh regression: ${PASS} passed, 0 failed"
    exit 0
else
    log_fail "validate.sh regression: ${PASS} passed, ${FAIL} failed"
    exit 1
fi
