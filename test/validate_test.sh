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
# Needs: node + test/spec-validators deps installed (npm ci), and xmllint.
# No Go build or live services required — runs in the offline CI job.
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

# assert_reject <label> <function> <args...>  -> expects non-zero return code
assert_reject() {
    local label=$1; shift
    if "$@" >/dev/null 2>&1; then
        log_fail "FAIL (false-passed invalid): ${label}"
        FAIL=$((FAIL + 1))
    else
        log_ok "PASS (rejected invalid): ${label}"
        PASS=$((PASS + 1))
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
assert_reject "magic keys present but structurally broken" \
    validate_openapi_structure "${WORK_DIR}/openapi-magic-keys-broken.yaml"

# Junk that contains the magic words but is not a valid document.
printf 'openapi info paths\nnot yaml at all: : :\n' > "${WORK_DIR}/openapi-junk.yaml"
assert_reject "junk text containing magic words" \
    validate_openapi_structure "${WORK_DIR}/openapi-junk.yaml"

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
assert_reject "expected GetUser, WSDL only has GetUserList (substring trap)" \
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
assert_reject "expected GetUser present only in an XML comment" \
    validate_soap_operations "${WORK_DIR}/comment.wsdl" "${WORK_DIR}/expect-getuser.json"

# Malformed XML must be rejected outright.
printf '<definitions><portType><operation name="GetUser">\n' > "${WORK_DIR}/malformed.wsdl"
printf '{"operations":["GetUser"]}' > "${WORK_DIR}/expect-getuser2.json"
assert_reject "malformed (non-well-formed) WSDL" \
    validate_soap_operations "${WORK_DIR}/malformed.wsdl" "${WORK_DIR}/expect-getuser2.json"

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
assert_reject "'type Query {' + '}' present but references unknown type" \
    validate_graphql_structure "${WORK_DIR}/bad.graphql"

# Junk containing the magic literals.
printf 'type Query { a closing brace } but not valid graphql whatsoever here now\n' \
    > "${WORK_DIR}/junk.graphql"
assert_reject "junk text containing 'type Query {' and '}'" \
    validate_graphql_structure "${WORK_DIR}/junk.graphql"

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
