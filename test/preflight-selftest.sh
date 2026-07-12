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

# NOTE: setup-live-targets.sh assigns CHROME_CANDIDATES unconditionally at
# top level (not inside main()), so any override must happen AFTER sourcing
# — sourcing first, then overriding, then calling detect_chrome_binary.

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

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "preflight-selftest: ${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
