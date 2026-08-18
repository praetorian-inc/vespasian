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
# shellcheck source=/dev/null
source "${THIS_DIR}/form-spec-asserts.sh"

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

# A syntactically valid SDL with no Query root type must be rejected — the
# no-Query-root branch of validateSchema() (validate-graphql.mjs) previously
# had no regression case (PR #187 review finding TEST-013).
cat > "${WORK_DIR}/no-query-root.graphql" <<'EOF'
type Foo {
  a: String
}
EOF
assert_reject "valid SDL with no Query root type" "Query root type must be provided" \
    validate_graphql_structure "${WORK_DIR}/no-query-root.graphql"

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

# Baseline SPEC_VALIDATOR_MAX_BYTES BEFORE any wrapper runs. It is a supported
# override both validators read, so a CI job or developer may legitimately have
# it exported in the parent shell. The leak check at the end of this section
# compares against this baseline (set/unset status + value) so that "a wrapper's
# `export` escaped its subshell" (a real leak) is told apart from "the caller
# already had it set" (fine) — the ${VAR+x} form alone flagged the latter as a
# spurious leak (LAB-3890 TEST-002).
if [ -n "${SPEC_VALIDATOR_MAX_BYTES+x}" ]; then
    BASELINE_MAX_BYTES_SET=1
    BASELINE_MAX_BYTES_VAL="$SPEC_VALIDATOR_MAX_BYTES"
else
    BASELINE_MAX_BYTES_SET=0
    BASELINE_MAX_BYTES_VAL=
fi

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

# The wrappers must leave SPEC_VALIDATOR_MAX_BYTES exactly as the caller had it
# — same set/unset status, and if set the same value. Comparing against the
# baseline captured above (not merely "is it set now?") means a caller that
# legitimately exported the override is not misreported as a leak; only a value
# the wrappers themselves changed counts as one (LAB-3890 TEST-002).
if [ -n "${SPEC_VALIDATOR_MAX_BYTES+x}" ]; then
    NOW_MAX_BYTES_SET=1
    NOW_MAX_BYTES_VAL="$SPEC_VALIDATOR_MAX_BYTES"
else
    NOW_MAX_BYTES_SET=0
    NOW_MAX_BYTES_VAL=
fi
if [ "$NOW_MAX_BYTES_SET" = "$BASELINE_MAX_BYTES_SET" ] && [ "$NOW_MAX_BYTES_VAL" = "$BASELINE_MAX_BYTES_VAL" ]; then
    log_ok "PASS (no env leak): SPEC_VALIDATOR_MAX_BYTES matches its pre-test baseline (set=${BASELINE_MAX_BYTES_SET})"
    PASS=$((PASS + 1))
else
    log_fail "FAIL (env leak): SPEC_VALIDATOR_MAX_BYTES changed across the wrappers — baseline set=${BASELINE_MAX_BYTES_SET} val='${BASELINE_MAX_BYTES_VAL}', now set=${NOW_MAX_BYTES_SET} val='${NOW_MAX_BYTES_VAL}'"
    FAIL=$((FAIL + 1))
fi

# ──────────────────────────────────────────────────────────────
# SPEC_VALIDATOR_TIMEOUT (validator wall-clock bound / YAML alias bomb)
# ──────────────────────────────────────────────────────────────
log_header "SPEC_VALIDATOR_TIMEOUT"

# Baseline SPEC_VALIDATOR_TIMEOUT BEFORE any wrapper runs, mirroring the
# SPEC_VALIDATOR_MAX_BYTES baseline above: it is a supported override a CI job or
# developer may legitimately have exported, so the leak check at the end of this
# section compares set/unset status + value against THIS baseline (not merely "is
# it set now?"), telling a real escaped `export` apart from a pre-set caller env
# (mirrors LAB-3890 TEST-002 for MAX_BYTES).
if [ -n "${SPEC_VALIDATOR_TIMEOUT+x}" ]; then
    BASELINE_TIMEOUT_SET=1
    BASELINE_TIMEOUT_VAL="$SPEC_VALIDATOR_TIMEOUT"
else
    BASELINE_TIMEOUT_SET=0
    BASELINE_TIMEOUT_VAL=
fi

# SEC-FE-003 (PR #187 review): js-yaml applies no alias-expansion cap, so a
# YAML anchor bomb makes swagger-parser expand unbounded and — without a
# wall-clock bound — eventually return 0 for a "valid" spec after burning the
# CI job's whole timeout as an opaque kill. _run_spec_validator now runs each
# validator under `timeout`/`gtimeout` and rewrites exit 124 into an explicit
# "validator timed out after Ns" failure. Same explicit-subshell wrapper as the
# SPEC_VALIDATOR_MAX_BYTES cases above, so `export SPEC_VALIDATOR_TIMEOUT`
# cannot leak into the rest of this run.
_test_validator_timeout_openapi() {
    local spec_file=$1
    (
        export SPEC_VALIDATOR_TIMEOUT=3
        validate_openapi_structure "$spec_file"
    )
}

# Accept side (TEST-010): a real spec must still validate under an explicit
# SPEC_VALIDATOR_TIMEOUT override — the bomb reject below only proves the
# wall-clock bound fires, not that normal specs survive it. Unconditional (not
# inside the timeout-binary guard): a valid spec validates whether or not a
# timeout binary is present, exercising _run_spec_validator's non-124 path.
assert_ok "a real OpenAPI spec still validates under an explicit SPEC_VALIDATOR_TIMEOUT" \
    _test_validator_timeout_openapi "${THIS_DIR}/rest-api/expected-spec.yaml"

# TEST-014: every case in this section pins an explicit SPEC_VALIDATOR_TIMEOUT=3,
# so validate.sh's SHIPPED DEFAULT (`${SPEC_VALIDATOR_TIMEOUT:-30}`) is never
# exercised — rewriting the default to `:-0` (GNU `timeout 0` disables the bound
# entirely, so the alias bomb would hang unbounded) or to an absurd `:-99999` (far
# past the CI job's ~5-min kill, so the bound never fires as a diagnosable failure)
# leaves this whole suite green. Re-source validate.sh with SPEC_VALIDATOR_TIMEOUT
# UNSET in a subshell to observe the default it ships, and assert it is a positive,
# sub-CI-budget integer: >0 so `timeout N` actually bounds the run, and <300 so the
# bound trips before the ~5-min job kill turns it into an opaque hang (SEC-FE-003).
_default_spec_validator_timeout() {
    (
        unset SPEC_VALIDATOR_TIMEOUT
        # shellcheck source=/dev/null
        source "${THIS_DIR}/validate.sh"
        printf '%s' "${SPEC_VALIDATOR_TIMEOUT}"
    )
}
_assert_default_timeout_sane() {
    local def
    def="$(_default_spec_validator_timeout)"
    case "$def" in
        ''|*[!0-9]*)
            printf 'default SPEC_VALIDATOR_TIMEOUT is not a positive integer: %s\n' "$def" >&2
            return 1
            ;;
    esac
    if [ "$def" -gt 0 ] && [ "$def" -lt 300 ]; then
        return 0
    fi
    printf 'default SPEC_VALIDATOR_TIMEOUT out of bounds (0 < n < 300): %s\n' "$def" >&2
    return 1
}
assert_ok "validate.sh ships a positive, sub-CI-budget default SPEC_VALIDATOR_TIMEOUT" \
    _assert_default_timeout_sane

# A sub-1 KiB billion-laughs / alias bomb: 9 anchors a–i — a is a 9-element list
# of scalars and b–i are each 9-element lists of references to the level below,
# so the deepest anchor expands to 9^9 nodes while the file itself stays tiny.
# Inline in WORK_DIR like every other fixture here.
cat > "${WORK_DIR}/alias-bomb.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: alias bomb
  version: "1.0.0"
paths: {}
components:
  schemas:
    a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
    b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
    c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
    d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]
    e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]
    f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]
    g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]
    h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]
    i: &i [*h, *h, *h, *h, *h, *h, *h, *h, *h]
EOF

# TEST-002 (PR #208): the alias-bomb case above anchors only on the CONFIGURED
# value being interpolated into the MESSAGE. It cannot distinguish a build whose
# enforced `timeout` bound tracks SPEC_VALIDATOR_TIMEOUT from a mutant that
# hardcodes the bound argument (e.g. `timeout 30`) while leaving ${...}
# interpolation intact — the bomb never terminates, so both time out and both
# print the configured value. Bind the ENFORCED bound directly: a fixed 3s sleeper
# validator, driven once with a 1s override (must trip, and name "1s") and once
# with a 10s override (must finish). Any constant-bound mutant fails one of the
# pair. Ignores its input arg like a real validator would where the timeout fires
# before parsing. No top-level await, so it runs on any node.
cat > "${WORK_DIR}/sleeper-validator.mjs" <<'EOF'
// Keeps the event loop alive ~3s, then exits 0. See validate_test.sh TEST-002.
setTimeout(() => process.exit(0), 3000);
EOF
printf 'openapi: 3.0.3\n' > "${WORK_DIR}/sleeper-input.yaml"

# Same explicit-subshell wrapper as _test_validator_timeout_openapi, so the
# `export SPEC_VALIDATOR_TIMEOUT` cannot leak into the rest of this run (the
# end-of-section leak check still brackets these). Calls _run_spec_validator
# directly with the sleeper script rather than a real validator.
_run_sleeper_under_timeout() {
    local bound=$1
    (
        export SPEC_VALIDATOR_TIMEOUT="$bound"
        _run_spec_validator "${WORK_DIR}/sleeper-validator.mjs" "${WORK_DIR}/sleeper-input.yaml"
    )
}

# The bomb can only be bounded where a timeout binary exists.
# _run_spec_validator falls back to running the validator UNWRAPPED when neither
# timeout nor gtimeout is present (validate.sh), so on such a host this case
# would hang the whole suite — guard it and skip loudly instead. A stock macOS
# dev box has neither; the CI validator-regression job runs on ubuntu, where
# `timeout` is present.
if command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1; then
    # Anchor on the CONFIGURED value (3s), not just "timed out": _run_spec_validator
    # interpolates ${SPEC_VALIDATOR_TIMEOUT} into this message (validate.sh), so a
    # mutation that makes it ignore the env var (hardcode a different bound) no
    # longer prints "3s" and this reject flips red — killing the surviving mutant
    # that the loose "validator timed out after" anchor left green (TEST-016).
    assert_reject "YAML alias bomb trips the validator wall-clock bound at the configured 3s" \
        "validator timed out after 3s" \
        _test_validator_timeout_openapi "${WORK_DIR}/alias-bomb.yaml"

    # TEST-002 (PR #208): bind the ENFORCED wall-clock bound to the env var, not
    # merely its interpolation into the message. A 1s override MUST trip the 3s
    # sleeper — and the message must name "1s", killing a message-only mutant that
    # echoed a hardcoded "3s" — while a 10s override MUST let the same sleeper
    # finish (rc 0), proving the bound tracks the value rather than always-tripping.
    # A constant-bound mutant fails one side: `timeout 30` finishes under the 1s
    # case (reject sees rc 0), `timeout 1` trips under the 10s case (ok sees a
    # timeout).
    assert_reject "a 1s SPEC_VALIDATOR_TIMEOUT trips the enforced bound on a 3s validator (names the configured 1s)" \
        "validator timed out after 1s" \
        _run_sleeper_under_timeout 1
    assert_ok "a 10s SPEC_VALIDATOR_TIMEOUT lets the same 3s validator finish (bound tracks the value, not always-trip)" \
        _run_sleeper_under_timeout 10
else
    # TEST-012: do not let the skip silently reduce the pass count in CI. The
    # un-gated validator-regression job runs on ubuntu where /usr/bin/timeout
    # exists, so CI stays green; a future runner that drops coreutils goes red
    # instead of quietly dropping this regression case.
    if [ "${CI:-}" = "true" ]; then
        log_fail "FAIL (no timeout/gtimeout binary in CI): cannot bound the validator, so the SPEC_VALIDATOR_TIMEOUT alias-bomb regression case did not run"
        FAIL=$((FAIL + 1))
    else
        log_warn "no timeout/gtimeout binary — skipping SPEC_VALIDATOR_TIMEOUT alias-bomb case (cannot bound the validator on this host)"
    fi
fi

# The wrappers must leave SPEC_VALIDATOR_TIMEOUT exactly as the caller had it —
# same set/unset status, and if set the same value. Compare against the baseline
# captured at the top of this section (not merely "is it set now?"), so a caller
# that legitimately exported the override is not misreported as a leak; only a
# value the wrappers themselves changed counts (mirrors the MAX_BYTES leak check).
if [ -n "${SPEC_VALIDATOR_TIMEOUT+x}" ]; then
    NOW_TIMEOUT_SET=1
    NOW_TIMEOUT_VAL="$SPEC_VALIDATOR_TIMEOUT"
else
    NOW_TIMEOUT_SET=0
    NOW_TIMEOUT_VAL=
fi
if [ "$NOW_TIMEOUT_SET" = "$BASELINE_TIMEOUT_SET" ] && [ "$NOW_TIMEOUT_VAL" = "$BASELINE_TIMEOUT_VAL" ]; then
    log_ok "PASS (no env leak): SPEC_VALIDATOR_TIMEOUT matches its pre-test baseline (set=${BASELINE_TIMEOUT_SET})"
    PASS=$((PASS + 1))
else
    log_fail "FAIL (env leak): SPEC_VALIDATOR_TIMEOUT changed across the wrappers — baseline set=${BASELINE_TIMEOUT_SET} val='${BASELINE_TIMEOUT_VAL}', now set=${NOW_TIMEOUT_SET} val='${NOW_TIMEOUT_VAL}'"
    FAIL=$((FAIL + 1))
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

# Lower bound (TEST-020): the upper bound alone greened on an empty/1-page
# crawl. Default floor (min_pages=1) rejects a 0-page capture; an explicit
# floor rejects a crawl that stopped at the seed.
assert_reject "empty crawl (0 pages) is rejected by the default floor" \
    "expected at least" \
    assert_max_pages "under-crawl-default" 0 10

assert_reject "one page under an explicit floor of 2 is rejected" \
    "expected at least" \
    assert_max_pages "under-crawl-floor" 1 10 2

assert_ok "at an explicit floor of 2 is accepted" \
    assert_max_pages "at-floor" 2 10 2

# TEST-009: a non-numeric floor must be rejected. Input 5/10/abc: page_count=5
# passes its own numeric guard, so only the min_pages guard can fire here. Anchor
# on the arm-specific "floor (min_pages) is not a number" rather than the bare
# "not a number" the page-count arm also emits, so a regression that fired the
# wrong numeric guard would be caught instead of passing on the shared substring.
assert_reject "non-numeric floor is rejected" \
    "floor (min_pages) is not a number" \
    assert_max_pages "bad-floor" 5 10 abc

# ──────────────────────────────────────────────────────────────
# assert_exact_path_count
# ──────────────────────────────────────────────────────────────
log_header "assert_exact_path_count"

# Locks the exact-count guard extracted from the inline rest-api / scan-rest
# checks in run-live-tests.sh (TEST-003): equal counts accepted, any mismatch
# rejected with "expected exactly", and a non-numeric count hard-failed instead
# of silently string-compared.
assert_ok "exact path count: equal counts accepted" \
    assert_exact_path_count "count-equal" 5 5
assert_reject "exact path count: actual over expected is rejected" \
    "expected exactly" \
    assert_exact_path_count "count-over" 6 5
assert_reject "exact path count: actual under expected is rejected" \
    "expected exactly" \
    assert_exact_path_count "count-under" 4 5
assert_reject "exact path count: non-numeric actual is rejected" \
    "path count is not a number: '?' (capture read failed)" \
    assert_exact_path_count "count-nan" "?" 5
assert_reject "exact path count: non-numeric expected is rejected" \
    "expected path count is not a number" \
    assert_exact_path_count "count-expected-nan" 5 ""

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

# Mixed-backend capture (PR #187 LAB-3890 TEST-001): a single capture that
# mixes rod-style records (carry page_url) with net/http-style records (carry
# only url). The page count is the union of distinct page identities across
# BOTH keys — page_url preferred per record, url the fallback when a record has
# no page_url. The pre-fix logic returned the distinct page_url count whenever
# ANY page_url existed, silently dropping every url-only page (an undercount —
# the false-PASS direction for assert_max_pages). A page named by a page_url in
# one record and by a url in another must de-dup to a single page.
#   p1, p2   -> page_url only                     (2 pages)
#   p3, p4   -> url only                          (2 pages)
#   shared   -> once via page_url, once via url   (coincide -> 1 page)
# => 5 distinct pages across 6 records.
python3 - "${WORK_DIR}/mixed-backend-capture.json" << 'PYEOF'
import json, sys

records = [
    {"page_url": "http://example.test/p1"},
    {"page_url": "http://example.test/p2"},
    {"url": "http://example.test/p3"},
    {"url": "http://example.test/p4"},
    {"page_url": "http://example.test/shared"},
    {"url": "http://example.test/shared"},
]

with open(sys.argv[1], "w") as f:
    json.dump(records, f)
PYEOF
assert_count "mixed backend: page_url-only + url-only records, union de-duped across both keys" \
    "5" \
    count_capture_pages "${WORK_DIR}/mixed-backend-capture.json"

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
# validate_path_coverage — total_paths parity guard (TEST-005)
# ──────────────────────────────────────────────────────────────
log_header "validate_path_coverage total_paths parity"

# validate_path_coverage now self-checks that a fixture's total_paths equals
# len(paths) (PR #187 review finding TEST-005). Prove all three branches
# offline: matching key passes, mismatched key is rejected, absent key is
# accepted (the guard is opt-in per fixture).
cat > "${WORK_DIR}/cov-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /a:
    get:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/cov-ok.json" <<'EOF'
{"paths": {"/a": ["GET"]}, "total_paths": 1}
EOF
cat > "${WORK_DIR}/cov-mismatch.json" <<'EOF'
{"paths": {"/a": ["GET"]}, "total_paths": 5}
EOF
cat > "${WORK_DIR}/cov-nokey.json" <<'EOF'
{"paths": {"/a": ["GET"]}}
EOF

assert_ok "total_paths matches len(paths)" \
    validate_path_coverage "${WORK_DIR}/cov-spec.yaml" "${WORK_DIR}/cov-ok.json"

assert_reject "total_paths disagrees with len(paths)" "PARITY MISMATCH" \
    validate_path_coverage "${WORK_DIR}/cov-spec.yaml" "${WORK_DIR}/cov-mismatch.json"

assert_ok "absent total_paths key is accepted (opt-in guard)" \
    validate_path_coverage "${WORK_DIR}/cov-spec.yaml" "${WORK_DIR}/cov-nokey.json"

# ──────────────────────────────────────────────────────────────
# POST-form spec asserts — offline regression net (LAB-5611 / TEST-006)
# ──────────────────────────────────────────────────────────────
log_header "POST-form spec asserts (assert_post_get_operations / assert_form_body_fields)"

# TEST-006 wired assert_post_get_operations and assert_form_body_fields into the
# live 'test' job only, which the skip-live-tests label can bypass. Both helpers
# are ~90 lines of hand-rolled YAML-parsing python; a parser regression that made
# either silently always-succeed would slip past the ungated net. These offline
# cases exercise the REAL helpers (sourced from form-spec-asserts.sh, the same
# code the live runner calls) against hand-crafted spec + expected-paths
# fixtures, locking their parsing logic outside the label gate.

# --- assert_post_get_operations --------------------------------------------
# Positive control: a POST-only action (post op present, no get op) passes.
cat > "${WORK_DIR}/pgo-ok-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/pgo-expected.json" <<'EOF'
{"post_form_paths": ["/api/login"]}
EOF
assert_ok "assert_post_get_operations accepts a POST-only action" \
    assert_post_get_operations "${WORK_DIR}/pgo-ok-spec.yaml" "${WORK_DIR}/pgo-expected.json"

# Reject: a GET operation on a POST-only action (404/confidence-filter regressed).
cat > "${WORK_DIR}/pgo-get-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    get:
      responses:
        '200':
          description: ok
    post:
      responses:
        '200':
          description: ok
EOF
assert_reject "assert_post_get_operations rejects a GET on a POST-only action" \
    "unexpected GET operation on POST-only action" \
    assert_post_get_operations "${WORK_DIR}/pgo-get-spec.yaml" "${WORK_DIR}/pgo-expected.json"

# Reject: the POST operation is missing entirely.
cat > "${WORK_DIR}/pgo-nopost-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    put:
      responses:
        '200':
          description: ok
EOF
assert_reject "assert_post_get_operations rejects a spec missing the POST operation" \
    "expected POST operation" \
    assert_post_get_operations "${WORK_DIR}/pgo-nopost-spec.yaml" "${WORK_DIR}/pgo-expected.json"

# Reject: an expected form-action path is absent from the spec entirely.
cat > "${WORK_DIR}/pgo-absent-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/pgo-absent.json" <<'EOF'
{"post_form_paths": ["/api/absent"]}
EOF
assert_reject "assert_post_get_operations rejects an expected path absent from the spec" \
    "path not present in spec" \
    assert_post_get_operations "${WORK_DIR}/pgo-absent-spec.yaml" "${WORK_DIR}/pgo-absent.json"

# --- assert_form_body_fields -----------------------------------------------
# Positive control: each form's fields resolve under its OWN distinct schema.
cat > "${WORK_DIR}/fbf-ok-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/LoginBody'
      responses:
        '200':
          description: ok
  /api/register:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/RegisterBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    LoginBody:
      type: object
      properties:
        username:
          type: string
        password:
          type: string
    RegisterBody:
      type: object
      properties:
        username:
          type: string
        email:
          type: string
EOF
cat > "${WORK_DIR}/fbf-ok.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username", "password"], "/api/register": ["username", "email"]}}
EOF
assert_ok "assert_form_body_fields accepts fields under each form's own distinct schema" \
    assert_form_body_fields "${WORK_DIR}/fbf-ok-spec.yaml" "${WORK_DIR}/fbf-ok.json"

# Reject: a POST body missing an expected field.
cat > "${WORK_DIR}/fbf-missing-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/LoginBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    LoginBody:
      type: object
      properties:
        username:
          type: string
EOF
cat > "${WORK_DIR}/fbf-login-only.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username", "password"]}}
EOF
assert_reject "assert_form_body_fields rejects a POST body missing an expected field" \
    "request-body missing field(s)" \
    assert_form_body_fields "${WORK_DIR}/fbf-missing-spec.yaml" "${WORK_DIR}/fbf-login-only.json"

# Reject: two forms collapsed onto one shared request-body schema (distinctness guard).
cat > "${WORK_DIR}/fbf-shared-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/SharedBody'
      responses:
        '200':
          description: ok
  /api/register:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/SharedBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    SharedBody:
      type: object
      properties:
        username:
          type: string
        password:
          type: string
        email:
          type: string
EOF
assert_reject "assert_form_body_fields rejects two forms sharing one request-body schema" \
    "share request-body schema" \
    assert_form_body_fields "${WORK_DIR}/fbf-shared-spec.yaml" "${WORK_DIR}/fbf-ok.json"

# Reject: the expected path is absent from the spec entirely ("path not found").
cat > "${WORK_DIR}/fbf-nopath-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/LoginBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    LoginBody:
      type: object
      properties:
        username:
          type: string
EOF
cat > "${WORK_DIR}/fbf-absent-path.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/absent": ["username"]}}
EOF
assert_reject "assert_form_body_fields rejects an expected path absent from the spec" \
    "path not found" \
    assert_form_body_fields "${WORK_DIR}/fbf-nopath-spec.yaml" "${WORK_DIR}/fbf-absent-path.json"

# Reject: the POST operation exists but carries no requestBody ("no requestBody").
cat > "${WORK_DIR}/fbf-norb-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/fbf-norb.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username"]}}
EOF
assert_reject "assert_form_body_fields rejects a POST operation with no requestBody" \
    "no requestBody" \
    assert_form_body_fields "${WORK_DIR}/fbf-norb-spec.yaml" "${WORK_DIR}/fbf-norb.json"

# --- body_fields_for_path parser-arm coverage (LAB-5611 review follow-up) ------
# The fbf-* cases above lock the $ref-resolved happy path plus path-not-found and
# no-requestBody. These lock the remaining body_fields_for_path arms so a parser
# regression in any of them is caught by the ungated validator-regression job,
# not only the label-gated live 'test' run.

# Reject: the path exists but carries no POST operation (only a GET).
cat > "${WORK_DIR}/fbf-nopost-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    get:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/fbf-nopost.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username"]}}
EOF
assert_reject "assert_form_body_fields rejects a path with no POST operation" \
    "no POST operation" \
    assert_form_body_fields "${WORK_DIR}/fbf-nopost-spec.yaml" "${WORK_DIR}/fbf-nopost.json"

# Positive control: an INLINE request-body schema (properties block, no $ref).
# Every other fbf fixture uses a $ref, so this is the only case locking the
# inline parse path; the real rest-api spec may express a urlencoded body inline.
cat > "${WORK_DIR}/fbf-inline-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/subscribe:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                email:
                  type: string
                name:
                  type: string
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/fbf-inline.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/subscribe": ["email", "name"]}}
EOF
assert_ok "assert_form_body_fields accepts fields under an inline request-body schema" \
    assert_form_body_fields "${WORK_DIR}/fbf-inline-spec.yaml" "${WORK_DIR}/fbf-inline.json"

# Reject: the request-body ref points at a components schema that does not exist.
cat > "${WORK_DIR}/fbf-refmissing-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/MissingBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    LoginBody:
      type: object
      properties:
        username:
          type: string
EOF
cat > "${WORK_DIR}/fbf-refmissing.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username"]}}
EOF
assert_reject "assert_form_body_fields rejects a request-body ref to an absent schema" \
    "schema MissingBody not found" \
    assert_form_body_fields "${WORK_DIR}/fbf-refmissing-spec.yaml" "${WORK_DIR}/fbf-refmissing.json"

# Reject: a POST requestBody whose schema resolves to no properties at all.
cat > "${WORK_DIR}/fbf-noprops-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/fbf-noprops.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username"]}}
EOF
assert_reject "assert_form_body_fields rejects a request-body schema with no properties" \
    "no request-body schema properties" \
    assert_form_body_fields "${WORK_DIR}/fbf-noprops-spec.yaml" "${WORK_DIR}/fbf-noprops.json"

# Reject (TEST-001, mutation-testing follow-up on the PR #208 re-review): the
# expected fields live under a SIBLING media type (application/json), while the
# application/x-www-form-urlencoded body carries no matching schema. A urlencoded
# form contract must NOT be satisfied by a JSON sibling's fields — before the
# media-type scoping fix, body_fields_for_path scanned the whole requestBody block
# and false-passed here. Scoped to urlencoded, the empty urlencoded schema reaches
# "no request-body schema properties".
cat > "${WORK_DIR}/fbf-json-sibling-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
          application/json:
            schema:
              $ref: '#/components/schemas/LoginBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    LoginBody:
      type: object
      properties:
        username:
          type: string
        password:
          type: string
EOF
cat > "${WORK_DIR}/fbf-json-sibling.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username", "password"]}}
EOF
assert_reject "assert_form_body_fields rejects fields carried only by a non-urlencoded (application/json) sibling body" \
    "no request-body schema properties" \
    assert_form_body_fields "${WORK_DIR}/fbf-json-sibling-spec.yaml" "${WORK_DIR}/fbf-json-sibling.json"

# Reject (TEST-003, mutation-testing follow-up on the PR #208 re-review): the
# resolved urlencoded schema carries a FOREIGN field (email) beyond the expected
# set {username, password}. The old subset-only check (`missing = expected - got`)
# false-passed any superset; the exact-set check rejects the unexpected field.
cat > "${WORK_DIR}/fbf-extra-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: '#/components/schemas/LoginBody'
      responses:
        '200':
          description: ok
components:
  schemas:
    LoginBody:
      type: object
      properties:
        username:
          type: string
        password:
          type: string
        email:
          type: string
EOF
cat > "${WORK_DIR}/fbf-extra.json" <<'EOF'
{"post_form_body_fields_by_path": {"/api/login": ["username", "password"]}}
EOF
assert_reject "assert_form_body_fields rejects a urlencoded schema carrying a foreign field beyond the expected set" \
    "request-body has unexpected field(s)" \
    assert_form_body_fields "${WORK_DIR}/fbf-extra-spec.yaml" "${WORK_DIR}/fbf-extra.json"

# ──────────────────────────────────────────────────────────────
# assert_path_methods — offline regression net (LAB-5611 / TEST-001, PR #208)
# ──────────────────────────────────────────────────────────────
log_header "assert_path_methods (per-path {get,post} method-set lock)"

# assert_path_methods is wired into the live test_rest_api/test_scan_rest only,
# which skip-live-tests can bypass. Exercise the REAL helper offline against
# hand-crafted spec + expected fixtures so its parsing/comparison can't silently
# regress outside the label gate.

# Positive: GET-only declaration matches a GET-only spec, AND a {id}-vs-{userId}
# parameterized path matches positionally (proves param-tolerant matching).
cat > "${WORK_DIR}/apm-ok-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    get:
      responses:
        '200':
          description: ok
  /api/users/{userId}:
    get:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/apm-ok.json" <<'EOF'
{"paths": {"/api/login": ["GET"], "/api/users/{id}": ["GET"]}}
EOF
assert_ok "assert_path_methods accepts GET-only decls (and matches {id} vs {userId} positionally)" \
    assert_path_methods "${WORK_DIR}/apm-ok-spec.yaml" "${WORK_DIR}/apm-ok.json"

# Positive: a GET+POST declaration (scan-style) matches a GET+POST spec.
cat > "${WORK_DIR}/apm-getpost-spec.yaml" <<'EOF'
openapi: 3.0.3
info:
  title: t
  version: "1.0.0"
paths:
  /api/login:
    get:
      responses:
        '200':
          description: ok
    post:
      responses:
        '200':
          description: ok
EOF
cat > "${WORK_DIR}/apm-getpost.json" <<'EOF'
{"paths": {"/api/login": ["GET", "POST"]}}
EOF
assert_ok "assert_path_methods accepts a GET+POST declaration matching the spec" \
    assert_path_methods "${WORK_DIR}/apm-getpost-spec.yaml" "${WORK_DIR}/apm-getpost.json"

# Reject: fixture declares GET+POST but the spec dropped POST (scan-drops-POST regression).
assert_reject "assert_path_methods rejects a spec missing a declared POST" \
    "method mismatch" \
    assert_path_methods "${WORK_DIR}/apm-ok-spec.yaml" "${WORK_DIR}/apm-getpost.json"

# Reject: fixture declares GET-only but the spec emitted POST too
# (two-stage-emits-POST regression — the exact case TEST-001 names).
cat > "${WORK_DIR}/apm-getonly.json" <<'EOF'
{"paths": {"/api/login": ["GET"]}}
EOF
assert_reject "assert_path_methods rejects an unexpected POST on a GET-only decl" \
    "method mismatch" \
    assert_path_methods "${WORK_DIR}/apm-getpost-spec.yaml" "${WORK_DIR}/apm-getonly.json"

# Reject: a declared path is absent from the spec entirely.
cat > "${WORK_DIR}/apm-absent.json" <<'EOF'
{"paths": {"/api/absent": ["GET"]}}
EOF
assert_reject "assert_path_methods rejects a declared path absent from the spec" \
    "path not present in spec" \
    assert_path_methods "${WORK_DIR}/apm-ok-spec.yaml" "${WORK_DIR}/apm-absent.json"

# Reject (loud guard): a fixture verb outside the tracked {get,post} universe must
# fail with a widen-the-helper message, never be silently ignored.
cat > "${WORK_DIR}/apm-untracked.json" <<'EOF'
{"paths": {"/api/login": ["PUT"]}}
EOF
assert_reject "assert_path_methods rejects a fixture verb outside {get,post} (loud guard)" \
    "outside the asserted {get,post} universe" \
    assert_path_methods "${WORK_DIR}/apm-ok-spec.yaml" "${WORK_DIR}/apm-untracked.json"

# ──────────────────────────────────────────────────────────────
# rest-api fixture parity (cross-file lockstep + per-fixture invariants)
# ──────────────────────────────────────────────────────────────
log_header "rest-api fixture parity (cross-file lockstep + per-fixture invariants)"

# Offline enforcement of the rest-api fixtures' lockstep + internal invariants,
# python3-only (no node, no live services, no Go build). Moved here from
# test-runner-args.sh, which runs only in the label-gated `test` job, so
# `skip-live-tests` disabled the old parity check; validate_test.sh runs in the
# un-gated validator-regression job. TEST-006: the two fixtures declare
# paths/total_paths/post_form_paths/post_form_body_fields_by_path identical on
# purpose ("EDIT BOTH FILES") — assert cross-file equality, order-insensitive.
# TEST-005: per fixture, total_paths == len(paths); post_form_paths non-empty;
# every post_form_paths entry is a key of paths; every
# post_form_body_fields_by_path key is in post_form_paths with a non-empty field
# list. TEST-007: capture stderr too and print a self-describing, fixture-named
# message. TEST-008: label by os.path.basename, never the absolute argv path.
#
# _assert_fixture_parity prints its verdict to stdout and returns 0/1 with NO
# internal log_ok/log_fail, so the real pair drives assert_ok and the synthetic
# negative controls drive assert_reject — each increments the counter once.
_assert_fixture_parity() {
    # $1 = fixture A path, $2 = fixture B path
    local out rc=0
    out=$(python3 - "$1" "$2" 2>&1 <<'PY'
import sys, json, os

def load(p):
    with open(p) as f:
        return json.load(f)

a_path, b_path = sys.argv[1], sys.argv[2]
a_name, b_name = os.path.basename(a_path), os.path.basename(b_path)
problems = []

def check_one(name, d):
    paths = d.get("paths", {})
    tp = d.get("total_paths")
    if tp != len(paths):
        problems.append("%s: total_paths=%r != len(paths)=%d" % (name, tp, len(paths)))
    pfp = d.get("post_form_paths", [])
    if not pfp:
        problems.append("%s: post_form_paths is empty or missing" % name)
    for p in pfp:
        if p not in paths:
            problems.append("%s: post_form_paths entry %r is not a key of paths" % (name, p))
    bf = d.get("post_form_body_fields_by_path", {})
    for k, fields in bf.items():
        if k not in pfp:
            problems.append("%s: post_form_body_fields_by_path key %r not in post_form_paths" % (name, k))
        if not fields:
            problems.append("%s: post_form_body_fields_by_path[%r] field list is empty" % (name, k))

try:
    a = load(a_path); b = load(b_path)
except Exception as e:
    print("fixture parity: could not load fixtures (%s / %s): %s" % (a_name, b_name, e))
    sys.exit(1)

check_one(a_name, a)
check_one(b_name, b)

# Cross-file lockstep (order-insensitive on lists).
def norm(d):
    return {
        "paths": sorted((d.get("paths") or {}).keys()),
        "total_paths": d.get("total_paths"),
        "post_form_paths": sorted(d.get("post_form_paths") or []),
        "post_form_body_fields_by_path": {k: sorted(v) for k, v in (d.get("post_form_body_fields_by_path") or {}).items()},
    }
if norm(a) != norm(b):
    problems.append("cross-file lockstep broken between %s and %s (paths/total_paths/post_form_paths/post_form_body_fields_by_path must be identical)" % (a_name, b_name))

if problems:
    print("fixture parity FAILED: " + "; ".join(problems))
    sys.exit(1)
print("fixture parity OK: %s and %s are in lockstep and internally consistent" % (a_name, b_name))
sys.exit(0)
PY
    ) || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "fixture parity: ${out:-python3 failed with no output}"
        return 1
    fi
    echo "${out}"
    return 0
}

assert_ok "rest-api fixtures are in lockstep and internally consistent" \
    _assert_fixture_parity "${THIS_DIR}/rest-api/expected-paths.json" "${THIS_DIR}/rest-api/scan-expected-paths.json"

# Negative control 1: cross-file divergence (an extra path in A) is rejected.
cat > "${WORK_DIR}/parity-a.json" <<'EOF'
{"paths": {"/api/x": ["GET"], "/api/extra": ["GET"]}, "total_paths": 2,
 "post_form_paths": ["/api/x"], "post_form_body_fields_by_path": {"/api/x": ["f"]}}
EOF
cat > "${WORK_DIR}/parity-b.json" <<'EOF'
{"paths": {"/api/x": ["GET"]}, "total_paths": 1,
 "post_form_paths": ["/api/x"], "post_form_body_fields_by_path": {"/api/x": ["f"]}}
EOF
assert_reject "fixture parity rejects cross-file path divergence" \
    "lockstep broken" \
    _assert_fixture_parity "${WORK_DIR}/parity-a.json" "${WORK_DIR}/parity-b.json"

# Negative control 2: an intra-file invariant violation (a post_form_paths entry
# that is not a key of paths) is rejected. Same file for both args so the
# cross-file check passes and the intra-file check is what fires.
cat > "${WORK_DIR}/parity-bad-a.json" <<'EOF'
{"paths": {"/api/x": ["GET"]}, "total_paths": 1,
 "post_form_paths": ["/api/ghost"], "post_form_body_fields_by_path": {"/api/ghost": ["f"]}}
EOF
assert_reject "fixture parity rejects a post_form_paths entry absent from paths" \
    "not a key of paths" \
    _assert_fixture_parity "${WORK_DIR}/parity-bad-a.json" "${WORK_DIR}/parity-bad-a.json"

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
