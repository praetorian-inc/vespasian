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

# Production values: limit=10, margin=5.
assert_ok "at the margin (15) is accepted" \
    assert_max_pages "at-margin" 15 10 5

assert_reject "over the margin (16) is rejected" \
    "--max-pages not enforced" \
    assert_max_pages "over-margin" 16 10 5

assert_reject "unparsable page count ('?')" \
    "page count is not a number" \
    assert_max_pages "unparsable-count" "?" 10 5

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
