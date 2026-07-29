#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Regression self-test for the Chrome/Chromium preflight probe in
# setup-live-targets.sh (LAB-3893). Plain bash, no test framework: creates
# fake browser binaries, overrides CHROME_CANDIDATES, sources the setup
# script (the BASH_SOURCE guard means main() does not run), then exercises
# detect_chrome_binary against each scenario.
#
# Usage: bash test/preflight-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_SCRIPT="${SCRIPT_DIR}/setup-live-targets.sh"

pass_count=0
fail_count=0

assert_eq() {
    local desc=$1 expected=$2 actual=$3
    if [ "$expected" = "$actual" ]; then
        echo "PASS: ${desc}"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: ${desc} (expected [${expected}], got [${actual}])"
        fail_count=$((fail_count + 1))
    fi
}

# ── Fixture setup ──────────────────────────────────────────────
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "${FIXTURE_DIR}"' EXIT

# A working "browser": prints a version string and exits 0.
mkdir -p "${FIXTURE_DIR}/bin"
WORKING_BROWSER="${FIXTURE_DIR}/bin/google-chrome"
cat > "${WORKING_BROWSER}" <<'EOF'
#!/bin/bash
echo "Fake Chrome 999.0.0.0"
exit 0
EOF
chmod +x "${WORKING_BROWSER}"

# A snap-stub "browser": present, executable, but fails at runtime — path
# contains /snap/ so it matches the snap-hint case in check_prerequisites.
mkdir -p "${FIXTURE_DIR}/snap/bin"
SNAP_STUB="${FIXTURE_DIR}/snap/bin/chromium-browser"
cat > "${SNAP_STUB}" <<'EOF'
#!/bin/bash
echo "chromium-browser requires the chromium snap to be installed" >&2
exit 1
EOF
chmod +x "${SNAP_STUB}"

# A generically-broken "browser": present, executable, fails at runtime, but
# its path matches NONE of the snap-hint globs (not under /snap/, not named
# chromium*). Exercises the generic "failed to run" arm of check_prerequisites.
GENERIC_BROKEN="${FIXTURE_DIR}/bin/broken-chrome"
cat > "${GENERIC_BROKEN}" <<'EOF'
#!/bin/bash
echo "broken-chrome: error while loading shared libraries" >&2
exit 127
EOF
chmod +x "${GENERIC_BROKEN}"

# NOTE: CHROME_CANDIDATES is defined in common.sh, which setup-live-targets.sh
# sources unconditionally at top level (not inside main()), so any override must
# happen AFTER sourcing — source first, then override, then call
# detect_chrome_binary.

# ── Case a: working browser present ────────────────────────────
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${WORKING_BROWSER}" "${SNAP_STUB}")
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
rc_a=$(echo "${result}" | sed -n '1p')
out_a=$(echo "${result}" | sed -n '2p')
assert_eq "case a: working browser exit code is 0" "0" "${rc_a}"
assert_eq "case a: working browser path echoed" "${WORKING_BROWSER}" "${out_a}"

# ── Case b: only a snap-stub present ───────────────────────────
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}")
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
rc_b=$(echo "${result}" | sed -n '1p')
out_b=$(echo "${result}" | sed -n '2p')
assert_eq "case b: snap-stub exit code is 2" "2" "${rc_b}"
assert_eq "case b: snap-stub path echoed" "${SNAP_STUB}" "${out_b}"

# case b (continued): exercise check_prerequisites' ACTUAL message selection.
# Run it with only the stub candidate and confirm it emits the snap-stub hint
# (not the generic "failed to run" message). This drives the real case
# statement, so a regression that narrows/reorders the snap pattern or swaps
# in the generic hint would fail here. Runs in a subshell because
# check_prerequisites calls `exit 1` when a prerequisite is missing.
msg_out=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}")
        set +e
        check_prerequisites 2>&1
    )
) || true   # check_prerequisites exits 1 (chrome missing); we only want its output
if printf '%s' "${msg_out}" | grep -q "snap stub"; then
    echo "PASS: case b: check_prerequisites emits the snap-stub hint"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case b: check_prerequisites did not emit the snap-stub hint"
    fail_count=$((fail_count + 1))
fi

# ── Case c: nothing runnable (all candidates missing) ──────────
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${FIXTURE_DIR}/bin/does-not-exist" "${FIXTURE_DIR}/nope")
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
rc_c=$(echo "${result}" | sed -n '1p')
out_c=$(echo "${result}" | sed -n '2p')
assert_eq "case c: nothing found exit code is 1" "1" "${rc_c}"
assert_eq "case c: nothing found stdout is empty" "" "${out_c}"

# ── Case d: broken candidate ordered BEFORE a working one ──────
# The real snap-stub scenario: `command -v` resolves the stub first and a
# working browser is only found later in the candidate list. Proves the loop
# SKIPS the non-runnable candidate and returns the later runnable one (rc 0),
# rather than stopping at the stub (rc 2). This is the branch case a cannot
# cover, since case a lists the working browser first.
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}" "${WORKING_BROWSER}")
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
rc_d=$(echo "${result}" | sed -n '1p')
out_d=$(echo "${result}" | sed -n '2p')
assert_eq "case d: stub-before-working exit code is 0" "0" "${rc_d}"
assert_eq "case d: stub-before-working selects the working browser" "${WORKING_BROWSER}" "${out_d}"

# ── Case e: present-but-broken NON-snap binary → generic hint ──
# Complements case b: a broken binary whose path matches none of the snap
# globs must get the generic "failed to run" hint, NOT the snap-stub hint.
# Guards the `*)` arm of check_prerequisites' case statement.
msg_out=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${GENERIC_BROKEN}")
        set +e
        check_prerequisites 2>&1
    )
) || true   # check_prerequisites exits 1 (chrome broken); we only want its output
if printf '%s' "${msg_out}" | grep -q "failed to run" && ! printf '%s' "${msg_out}" | grep -q "snap stub"; then
    echo "PASS: case e: non-snap broken binary gets the generic hint (not the snap hint)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case e: expected the generic 'failed to run' hint without snap-stub text"
    fail_count=$((fail_count + 1))
fi

# ── Case f: no timeout/gtimeout on PATH → bare-probe fallback ──
# Exercises chrome_runnable's degrade path (stock macOS ships neither
# timeout nor gtimeout). Restrict PATH to the fixture bin dir — which holds
# no timeout binary — so command -v timeout/gtimeout both miss and the bare
# `"$1" --version` branch runs. A working browser must still be detected.
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${WORKING_BROWSER}")
        PATH="${FIXTURE_DIR}/bin"   # no timeout/gtimeout here → force the fallback
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
rc_f=$(echo "${result}" | sed -n '1p')
out_f=$(echo "${result}" | sed -n '2p')
assert_eq "case f: no-timeout fallback still detects a working browser (rc 0)" "0" "${rc_f}"
assert_eq "case f: no-timeout fallback returns the working browser path" "${WORKING_BROWSER}" "${out_f}"

# ── Cases g-j: the browser gate is CONDITIONAL (LAB-5064) ───────
#
# A hard browser gate on every setup blocked work that provably needs no
# browser and, because it exits before write_config, took the browserless
# offline run down with it. check_prerequisites now takes <targets> <skip_start>
# and only treats a missing browser as fatal when the selection actually
# provisions a browser-backed target.
#
# These assert on the SEVERITY PREFIX of the browser diagnosis line itself
# ([FAIL] vs [WARN]), not on the script's global "Prerequisites check failed"
# epilogue. That epilogue is emitted when ANY prerequisite fails — go, python3,
# node — so asserting on it would couple these cases to whatever happens to be
# installed on the host: a non-fatal browser gate on a machine without python3
# still prints it. Reading the browser line's own prefix isolates the gate
# exactly, and makes the result independent of the rest of the checklist.

# Runs check_prerequisites with a given candidate list and echoes its output.
# Args after the first are forwarded to check_prerequisites verbatim, so the
# no-arg default is exercised too.
run_prereqs_with() {
    local candidate=$1; shift
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${candidate}")
        set +e
        check_prerequisites "$@" 2>&1
    ) || true
}

# Only a snap stub on PATH (rc==2: present but not runnable).
run_prereqs_with_stub_only() { run_prereqs_with "${SNAP_STUB}" "$@"; }
# No browser at all (rc==1) — the state a fresh devcontainer is in before
# install-chrome.sh runs, and a different arm of check_prerequisites.
run_prereqs_with_no_browser() { run_prereqs_with "${FIXTURE_DIR}/bin/does-not-exist" "$@"; }

# Extract the severity prefix of the browser diagnosis line. Both wordings are
# matched because the rc==2 and rc==1 arms emit different text.
browser_gate_level() {
    local output=$1
    if printf '%s' "${output}" | grep -qE '\[FAIL\].*(not runnable|Chrome/Chromium not found)'; then
        printf 'FAIL\n'
    elif printf '%s' "${output}" | grep -qE '\[WARN\].*(not runnable|Chrome/Chromium not found)'; then
        printf 'WARN\n'
    else
        printf 'NONE\n'
    fi
}

# expected_level is FAIL (gate is fatal) or WARN (gate degrades to a warning).
assert_gate() {
    local desc=$1 expected_level=$2 output=$3
    assert_eq "${desc}" "${expected_level}" "$(browser_gate_level "${output}")"
}

# Case g: a browser-backed target is selected → a broken browser is still fatal.
# This is the LAB-3893 guarantee; the conditional gate must not weaken it.
assert_gate "case g: browser-backed target keeps the browser gate fatal" \
    FAIL "$(run_prereqs_with_stub_only "rest-api" false)"

# Case h: grpc-server only. Its live test speaks gRPC reflection and never
# launches Chrome, so a browserless host must not block the setup.
out_h="$(run_prereqs_with_stub_only "grpc-server" false)"
assert_gate "case h: grpc-server-only setup does not require a browser" WARN "${out_h}"
# Non-fatal must not mean silent: the stub is still diagnosed, just at WARN.
# A developer who later switches to a browser-backed target needs to have seen
# that their /usr/bin/chromium-browser is a stub.
if printf '%s' "${out_h}" | grep -q "not runnable"; then
    echo "PASS: case h: broken browser still diagnosed, just non-fatally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case h: non-fatal gate silently swallowed the broken-browser diagnosis"
    fail_count=$((fail_count + 1))
fi

# Case i: --skip-start builds binaries and starts nothing, so it needs no
# browser REGARDLESS of target selection. Both rows below pass browser-backed
# targets and differ only in skip_start, which is what isolates its effect —
# an earlier revision passed skip_start=false on the first row, making it a
# silent duplicate of case g that asserted nothing about --skip-start.
assert_gate "case i: browser target WITHOUT --skip-start is fatal (baseline)" \
    FAIL "$(run_prereqs_with_stub_only "rest-api" false)"
assert_gate "case i: the same target WITH --skip-start is non-fatal" \
    WARN "$(run_prereqs_with_stub_only "rest-api" true)"

# Case j: the no-argument call (used by nothing in-tree, but the safe default)
# must keep the old strict behaviour — every target selected, gate fatal.
assert_gate "case j: no-arg check_prerequisites defaults to the strict gate" \
    FAIL "$(run_prereqs_with_stub_only)"

# ── Cases l-m: the rc==1 arm (NO browser at all) ───────────────
# Cases g-j all pin CHROME_CANDIDATES to the snap stub, which only exercises
# rc==2 ("present but not runnable"). A fresh devcontainer before
# install-chrome.sh runs is rc==1 ("nothing found") — a separate branch with its
# own fatal/non-fatal handling and its own message. Repeat the matrix there.
assert_gate "case l: absent browser + browser-backed target is fatal" \
    FAIL "$(run_prereqs_with_no_browser "rest-api" false)"
assert_gate "case l: absent browser + grpc-server-only is non-fatal" \
    WARN "$(run_prereqs_with_no_browser "grpc-server" false)"
assert_gate "case l: absent browser + --skip-start is non-fatal" \
    WARN "$(run_prereqs_with_no_browser "rest-api" true)"

# Case m: the rc==1 arm must steer users at the installer, not at
# `apt install chromium-browser` — on Ubuntu noble that package is the snap
# transitional stub, i.e. precisely the unrunnable binary this check exists to
# catch. Guards against the old advice creeping back.
out_m="$(run_prereqs_with_no_browser "rest-api" false)"
if printf '%s' "${out_m}" | grep -q "install-chrome.sh" && \
   ! printf '%s' "${out_m}" | grep -q "apt install chromium-browser"; then
    echo "PASS: case m: absent-browser hint points at install-chrome.sh, not the snap stub package"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case m: absent-browser hint is missing install-chrome.sh or still suggests chromium-browser"
    fail_count=$((fail_count + 1))
fi

# Case k: browser_required's mapping itself.
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        set +e
        browser_required "grpc-server"; echo "grpc=$?"
        browser_required "rest-api"; echo "rest=$?"
        browser_required "grpc-server,concat-spa"; echo "mixed=$?"
        browser_required "totally-unknown-target"; echo "unknown=$?"
    )
)
assert_eq "case k: grpc-server alone needs no browser" "grpc=1" "$(echo "${result}" | sed -n '1p')"
assert_eq "case k: rest-api needs a browser" "rest=0" "$(echo "${result}" | sed -n '2p')"
assert_eq "case k: a mixed list needs a browser" "mixed=0" "$(echo "${result}" | sed -n '3p')"
# Deliberately fail-OPEN, unlike targets_need_config's fail-closed default: an
# unknown name here only relaxes a warning, and main()'s build dispatch rejects
# the typo with "Unknown target" + exit 1 before anything is provisioned. Pinned
# so the asymmetry with its sibling is a recorded decision, not an accident.
assert_eq "case k: an unknown target does not force the browser gate (fails open)" \
    "unknown=1" "$(echo "${result}" | sed -n '4p')"

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "preflight-selftest: ${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
