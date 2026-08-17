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
skip_count=0
# Sum of the assertion counts each fired skip() call would otherwise have
# contributed (see the credit argument below). Lets the completion sentinel
# stay enforced even when a block legitimately skips, instead of going dark
# the moment skip_count is nonzero.
skip_credit=0
# TEST-006: flips to 1 immediately before the Summary section runs, matching
# install-chrome-selftest.sh and test-runner-args.sh. Every case here is a flat
# sequence under this script's own `set -euo pipefail`; a stray `exit 0` (or an
# errexit abort) anywhere above the summary would otherwise print PASS lines,
# no summary, and a green CI check for however many cases never ran. MEASURED
# on a scratch copy: injecting `exit 0` right after this block gave a bare
# `rm -rf` on the fixture dir and exit 0 — no FAIL, no summary — before this
# sentinel existed.
SUITE_COMPLETED=0

# Environment-dependent blocks call this instead of a bare `echo SKIP`.
#
# Takes a CREDIT: the number of assertions the skipped block would have made
# on a fully-equipped host. Without it the completion sentinel below had to
# disable itself whenever anything skipped, and every skip trigger in this
# file is ambient toolchain availability (Go, Python3, timeout/gtimeout) — on
# a host missing any of those, EXPECTED_ASSERTIONS stopped being checked at
# all, silently, on the exact kind of host most likely to differ from the
# author's. The credit lets the sentinel keep pass+fail+skip_credit pinned to
# EXPECTED_ASSERTIONS regardless of which arm ran, so deleting a case still
# fails the suite even on a degraded host. Credits were derived empirically —
# forcing each skip arm on a fully-equipped host and reading off exactly how
# many assertions vanished — not estimated from reading the block.
skip() {
    local credit=${2:-0}
    echo "SKIP: $1"
    skip_count=$((skip_count + 1))
    skip_credit=$((skip_credit + credit))
}

# Completion sentinel. Pinned to the assertion count of a fully-equipped run
# (nothing skipped). Enforced unconditionally: pass_count + fail_count +
# skip_credit must equal this total on EVERY host, degraded or not, because
# skip_credit already accounts for whatever a skipped block would have added.
# Deleting a case — on a full host OR a degraded one — changes this total and
# fails the suite, which is the regression this guards.
#
# Update deliberately when adding or removing an assertion, and update the
# matching skip() credit if the change touches an environment-gated block.
# 88 = 84 + case f1's 4 assertions (TEST-011: gtimeout arm coverage). Case f1
# synthesises its own fixture gtimeout rather than depending on ambient PATH,
# so it runs unconditionally on every host and needs no skip() credit.
#
# Round-15 review, TEST-001: 88 -> 90. MEASURED by running the suite, not
# derived. +2 for case f1b, which pins the PRODUCTION `${CHROME_PROBE_TIMEOUT:-2}`
# default — the value every real run uses and which nothing asserted, because
# both suites that could exercise the `:-` arm export the variable first. It
# reuses case f1's fixture gtimeout and so likewise needs no skip() credit.
EXPECTED_ASSERTIONS=90

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
# SEC-BE-006: pin the parent instead of inheriting $TMPDIR. This tree holds
# executable fixtures that get PATH-prepended and RUN, so an inherited TMPDIR
# pointing at a non-sticky directory a second local user can write to would let
# them rename it away between creation and use and choose the binaries this suite
# executes. /tmp's sticky bit is the property being relied on.
FIXTURE_DIR=$(TMPDIR=/tmp mktemp -d)
# INT/TERM as well as EXIT: a bash signal handler returns to the interrupted
# code, so without an explicit exit a Ctrl-C left the fixture tree in $TMPDIR.
#
# The completion sentinel is folded into THIS trap rather than registered as a
# second one (TEST-006): bash keeps a single EXIT trap, so a separate
# `trap ... EXIT` declared here would silently REPLACE this one and never
# fire — exactly the inert-assertion failure mode this suite exists to catch.
trap 'rm -rf "${FIXTURE_DIR}"; if [ "${SUITE_COMPLETED}" != 1 ]; then echo "preflight-selftest: FAIL — suite terminated before reaching the summary; results are incomplete" >&2; exit 1; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

# Pin the probe budget for the whole suite (TEST-014).
#
# Only cases f2/f3 used to pin it, so every OTHER case inherited whatever the
# ambient environment had. That is not hypothetical: `CHROME_PROBE_TIMEOUT=0.0001
# bash test/preflight-selftest.sh` drops this suite to 59/6 and install-chrome
# to 121/16, because a budget that small makes every real probe time out and
# report a healthy browser as "not runnable" — the exact LAB-3893 false positive
# the override exists to cure. The cases that deliberately vary the budget set
# it per-invocation, which still overrides this default.
export CHROME_PROBE_TIMEOUT=2

# ── Case a0: the PRODUCTION candidate list (TEST-005) ──────────
# Every other case in every suite OVERRIDES CHROME_CANDIDATES with fixtures, so
# the shipped list in common.sh was asserted nowhere: trimming it to a single
# `google-chrome` entry — deleting `chromium-browser`, the very snap-stub name
# LAB-3893 exists to diagnose — left all four suites green. This is the one case
# that reads the real array, so it must NOT override it.
prod_candidates=$(
    (
        # shellcheck source=common.sh
        source "${SCRIPT_DIR}/common.sh"
        printf '%s\n' "${CHROME_CANDIDATES[@]}"
    )
)
for required in google-chrome chromium-browser chromium /usr/bin/google-chrome /snap/bin/chromium; do
    if printf '%s\n' "${prod_candidates}" | grep -qxF -- "${required}"; then
        echo "PASS: case a0: production CHROME_CANDIDATES still contains '${required}'"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case a0: production CHROME_CANDIDATES lost '${required}' — detection coverage silently narrowed"
        fail_count=$((fail_count + 1))
    fi
done
# Order is load-bearing: google-chrome must be probed before chromium-browser,
# so a host with both prefers the real Chrome over Ubuntu's snap launcher stub.
if [ "$(printf '%s\n' "${prod_candidates}" | grep -nxF -- google-chrome | cut -d: -f1)" \
     -lt "$(printf '%s\n' "${prod_candidates}" | grep -nxF -- chromium-browser | cut -d: -f1)" ]; then
    echo "PASS: case a0: google-chrome is probed before chromium-browser"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case a0: candidate priority inverted — the snap stub would be preferred over real Chrome"
    fail_count=$((fail_count + 1))
fi

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

# ── Case e2: EVERY member of the snap-hint glob set (TEST-009) ──
#
# Cases b and e between them cover one glob member (*/snap/*) and the `*)` arm.
# The set is `*/snap/*|*/chromium-browser|*/chromium`, so the other two members
# were unasserted — mutation-proven: reducing the arm to `*/snap/*)` alone left
# this suite at 73/0/0, exit 0 with both case b and case e still green.
#
# That is not a cosmetic gap. `/usr/bin/chromium-browser` IS the Ubuntu snap
# launcher stub named in LAB-5064's own Evidence block and in its parent
# LAB-3893, and it does NOT live under /snap/. Losing that member sends a
# developer hitting the exact originating symptom to the generic "check
# permissions, missing shared libraries" hint instead of the actionable snap
# diagnosis — reintroducing the confusion LAB-3893 was filed to remove.
#
# Derived from the source, not hardcoded, so the test cannot drift from the arm
# it guards.
snap_glob=$(grep -oE '^\s+\*/snap/\*[^)]*\)' "${SETUP_SCRIPT}" | head -1 | tr -d ' )')
if [ -z "${snap_glob}" ]; then
    echo "FAIL: case e2: could not extract the snap-hint glob set from ${SETUP_SCRIPT} — the per-member assertions below are vacuous"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case e2: snap-hint glob set extracted from the source"
    pass_count=$((pass_count + 1))
    # Build a broken fixture whose PATH matches each glob member in turn, and
    # require the snap hint for every one of them.
    e2_missing=""
    IFS='|' read -r -a e2_globs <<<"${snap_glob}"
    for e2_glob in "${e2_globs[@]}"; do
        # Turn the glob into a concrete path: */snap/* -> <fix>/snap/x,
        # */chromium-browser -> <fix>/e2/chromium-browser, etc.
        case "${e2_glob}" in
            '*/snap/*') e2_dir="${FIXTURE_DIR}/e2-snap/snap"; e2_name="anything" ;;
            '*/'*)      e2_dir="${FIXTURE_DIR}/e2-${e2_glob##*/}"; e2_name="${e2_glob##*/}" ;;
            *)          continue ;;
        esac
        mkdir -p "${e2_dir}"
        e2_bin="${e2_dir}/${e2_name}"
        printf '#!/bin/bash\necho "stub" >&2\nexit 1\n' > "${e2_bin}"
        chmod +x "${e2_bin}"
        e2_out=$(
            (
                # shellcheck source=setup-live-targets.sh
                source "${SETUP_SCRIPT}"
                # shellcheck disable=SC2034  # consumed by detect_chrome_binary
                CHROME_CANDIDATES=("${e2_bin}")
                set +e
                check_prerequisites 2>&1
            )
        ) || true
        printf '%s' "${e2_out}" | grep -q "snap stub" || e2_missing="${e2_missing} ${e2_glob}"
    done
    if [ -n "${e2_missing}" ]; then
        echo "FAIL: case e2: glob member(s) no longer produce the snap-stub hint:${e2_missing}"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case e2: every snap-hint glob member (${snap_glob}) produces the snap-stub hint"
        pass_count=$((pass_count + 1))
    fi
    # Pin the member count too: deriving the set from the source means a deletion
    # shrinks the expectation and the evidence together, so the loop above would
    # pass vacuously on whatever survived.
    e2_count=${#e2_globs[@]}
    if [ "${e2_count}" -ge 3 ]; then
        echo "PASS: case e2: the snap-hint glob set still carries at least 3 members"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case e2: the snap-hint glob set shrank to ${e2_count} member(s) (expected >= 3) — /usr/bin/chromium-browser, the LAB-3893 snap stub, may no longer be diagnosed"
        fail_count=$((fail_count + 1))
    fi
fi

# ── Case e3: the FIRST broken stub is the one reported (TEST-012) ──
#
# detect_chrome_binary keeps `stub` set to the FIRST non-runnable candidate it saw
# and echoes that one on rc 2, so the diagnostic names the browser the operator most
# likely meant. Nothing asserted it: every existing case that lands on rc 2 supplies a
# single broken candidate, and case p discards stdout entirely, so the contract held
# only by construction. With two broken candidates, echoing the LAST one — a one-line
# change (`stub="$bin"` unconditionally) — was previously invisible.
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}" "${GENERIC_BROKEN}")
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
assert_eq "case e3: two broken candidates still report 'stub found, none runnable' (rc 2)" \
    "2" "$(echo "${result}" | sed -n '1p')"
assert_eq "case e3: the FIRST broken candidate is the one echoed, not the last" \
    "${SNAP_STUB}" "$(echo "${result}" | sed -n '2p')"

# ── Case e4: a runnable candidate wins even when listed after a stub (TEST-012) ──
# The other half of the same contract: the loop must keep looking past a stub rather
# than reporting the first thing it finds. Case a0 pins the production candidate
# ORDER (real Chrome ahead of the snap stub); this pins that the order is honoured
# even when a stub comes first.
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
assert_eq "case e4: a runnable candidate after a stub is still found (rc 0)" \
    "0" "$(echo "${result}" | sed -n '1p')"
assert_eq "case e4: the runnable candidate is echoed, not the earlier stub" \
    "${WORKING_BROWSER}" "$(echo "${result}" | sed -n '2p')"

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

# ── Case f0: the fallback REJECTS a broken browser (TEST-010) ───
#
# Case f above pins the fallback only in the direction where the browser works,
# so an accept-all fallback was indistinguishable from a correct one.
# Mutation-proven: replacing chrome_runnable's `"$1" --version >/dev/null 2>&1`
# with `return 0` left this suite at 73/0/0, exit 0. On a host with neither
# timeout nor gtimeout — stock macOS, the very platform the fallback exists for —
# that means a snap stub or an otherwise broken browser is reported RUNNABLE,
# which is precisely the LAB-3893 false positive this probe exists to prevent.
#
# Both polarities are now pinned, so the fallback has to discriminate rather than
# merely answer.
result=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${GENERIC_BROKEN}")
        PATH="${FIXTURE_DIR}/bin"   # no timeout/gtimeout here → force the fallback
        set +e
        out=$(detect_chrome_binary)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
)
rc_f0=$(echo "${result}" | sed -n '1p')
out_f0=$(echo "${result}" | sed -n '2p')
# rc 2 is detect_chrome_binary's "found a stub, nothing runnable" answer; the
# broken fixture is the only candidate, so it must be reported as the stub rather
# than as a working browser.
assert_eq "case f0: no-timeout fallback REJECTS a broken browser (rc 2, not 0)" "2" "${rc_f0}"
assert_eq "case f0: no-timeout fallback still echoes the stub path it rejected" "${GENERIC_BROKEN}" "${out_f0}"

# ── Case f1: the gtimeout arm (macOS + coreutils) actually runs ─
# TEST-011: chrome_runnable's `elif command -v gtimeout` was dead coverage —
# no case anywhere selects it. Measured: deleting both gtimeout lines from
# common.sh (the elif condition and `t=gtimeout`) left this suite green with
# no case failing. Cases f/f0 above force the BARE-probe fallback by emptying
# PATH of every timeout binary; every other case runs on this container,
# which has no gtimeout at all (`command -v gtimeout` -> empty), so ambient
# PATH can never reach the branch either. This case SYNTHESISES it instead of
# depending on the host: a subshell-scoped PATH pointing at a directory that
# holds ONLY a fixture `gtimeout` (plus a symlinked real `sleep`, needed by the
# fixture's watchdog and by the slow-browser fixture below — no real `timeout`
# anywhere on that PATH), so `command -v timeout` misses and chrome_runnable's
# `elif command -v gtimeout` hits.
#
# A fixture that is merely resolvable on PATH would pass even if
# chrome_runnable never executed it — the grep-shaped assertion this branch's
# review has rejected for eleven rounds. Two behavioural properties instead,
# mirroring what case f2 below pins for the `timeout` arm: (1) the fixture
# records every invocation to a marker file, so passing proves gtimeout was
# actually EXECUTED, not just present; (2) a slow browser under a tiny
# override must be killed with rc 124 — the exact status GNU timeout/gtimeout
# reserve for "I killed it".
GTIMEOUT_BIN_DIR="${FIXTURE_DIR}/gtimeout-only-bin"
mkdir -p "${GTIMEOUT_BIN_DIR}"
ln -s "$(command -v sleep)" "${GTIMEOUT_BIN_DIR}/sleep"
GTIMEOUT_MARKER="${FIXTURE_DIR}/gtimeout.invocations"
# TEST-001: a SECOND, independent marker recording the duration gtimeout was
# handed. Separate from GTIMEOUT_MARKER on purpose — case f1's four existing
# assertions read that one and must keep reading exactly what they did before.
GTIMEOUT_BUDGET_MARKER="${FIXTURE_DIR}/gtimeout.budget"

# Minimal `timeout`-alike: runs its argv in the background, races a watchdog
# `sleep` against it, and reports rc 124 if the watchdog wins — the same
# externally-observable contract as GNU timeout/gtimeout, just implemented in
# a few lines of bash instead of C.
cat > "${GTIMEOUT_BIN_DIR}/gtimeout" <<'EOF'
#!/bin/bash
[ -n "${GTIMEOUT_MARKER:-}" ] && printf 'invoked\n' >> "${GTIMEOUT_MARKER}"
[ -n "${GTIMEOUT_BUDGET_MARKER:-}" ] && printf '%s\n' "$1" >> "${GTIMEOUT_BUDGET_MARKER}"
duration="$1"
shift
"$@" &
cmdpid=$!
( sleep "${duration}"; kill -TERM "${cmdpid}" 2>/dev/null ) &
watchdog=$!
wait "${cmdpid}" 2>/dev/null
rc=$?
kill "${watchdog}" 2>/dev/null
wait "${watchdog}" 2>/dev/null
if [ "${rc}" -ge 128 ]; then
    exit 124
fi
exit "${rc}"
EOF
chmod +x "${GTIMEOUT_BIN_DIR}/gtimeout"

# Own slow-browser fixture rather than reusing f2's SLOW_BROWSER: f2's is only
# created inside its own `command -v timeout/gtimeout` guard below, so on a
# host that takes that guard's other arm it would not exist yet.
GTIMEOUT_SLOW_BROWSER="${FIXTURE_DIR}/bin/slow-chrome-f1"
cat > "${GTIMEOUT_SLOW_BROWSER}" <<'EOF'
#!/bin/bash
sleep 0.5
echo "Fake Slow Chrome (f1) 999.0.0.0"
exit 0
EOF
chmod +x "${GTIMEOUT_SLOW_BROWSER}"

probe_via_gtimeout() {
    local browser=$1 budget=$2
    (
        # shellcheck source=setup-live-targets.sh disable=SC1091
        source "${SETUP_SCRIPT}"
        PATH="${GTIMEOUT_BIN_DIR}"   # only the fixture gtimeout (+ sleep) — no timeout, no real gtimeout
        export GTIMEOUT_MARKER
        set +e
        CHROME_PROBE_TIMEOUT="${budget}" chrome_runnable "${browser}"
        printf '%s\n' "$?"
    )
}

: > "${GTIMEOUT_MARKER}"
rc_f1_pass=$(probe_via_gtimeout "${WORKING_BROWSER}" 10)
assert_eq "case f1: gtimeout arm detects a working browser (rc 0)" "0" "${rc_f1_pass}"
assert_eq "case f1: the fixture gtimeout was invoked to detect the working browser" \
    "invoked" "$(cat "${GTIMEOUT_MARKER}")"

: > "${GTIMEOUT_MARKER}"
rc_f1_kill=$(probe_via_gtimeout "${GTIMEOUT_SLOW_BROWSER}" 0.2)
assert_eq "case f1: CHROME_PROBE_TIMEOUT=0.2 kills the slow probe via gtimeout (rc 124)" \
    "124" "${rc_f1_kill}"
assert_eq "case f1: the fixture gtimeout was invoked to kill the slow probe" \
    "invoked" "$(cat "${GTIMEOUT_MARKER}")"

# ── Case f1b: the PRODUCTION default budget (TEST-001) ──────────────────────
#
# `chrome_probe_budget` reads `${CHROME_PROBE_TIMEOUT:-2}` (test/common.sh:104).
# That literal 2 is what every real developer run and every CI run uses, and
# until now NOTHING asserted it. Both suites that could exercise the `:-` arm
# export the variable suite-wide first (here at :144, install-chrome-selftest.sh
# at :55), and case f2 was deliberately moved onto an explicit override
# (rationale at 571-584 below). MUTATION-PROVEN: `:-2` -> `:-0.001` left all
# FOUR suites green while every real probe times out and a healthy browser is
# reported "not runnable" — the exact LAB-3893 false positive this code cures,
# on a path only the label-gated `test` job would ever notice.
#
# Asserts the budget VALUE handed to gtimeout, NOT elapsed wall-clock. Pinning
# the pass side to the 2s default by timing was already tried and removed for
# being load-sensitive on a throttled runner (see 571-584); reading the value
# out of the fixture is deterministic, cannot flake, and catches ANY change to
# the literal rather than only a large one.
probe_via_gtimeout_default_budget() {
    (
        # shellcheck source=setup-live-targets.sh disable=SC1091
        source "${SETUP_SCRIPT}"
        PATH="${GTIMEOUT_BIN_DIR}"   # only the fixture gtimeout (+ sleep)
        export GTIMEOUT_MARKER GTIMEOUT_BUDGET_MARKER
        unset CHROME_PROBE_TIMEOUT   # the production path: no override at all
        set +e
        chrome_runnable "$1"
        printf '%s\n' "$?"
    )
}

: > "${GTIMEOUT_MARKER}"
: > "${GTIMEOUT_BUDGET_MARKER}"
rc_f1b=$(probe_via_gtimeout_default_budget "${WORKING_BROWSER}")
assert_eq "case f1b: with CHROME_PROBE_TIMEOUT unset, the production default still detects a working browser (rc 0)" \
    "0" "${rc_f1b}"
assert_eq "case f1b: the un-overridden production budget reaches timeout as 2s — shrinking it makes every real probe time out and report a healthy browser as 'not runnable' (the LAB-3893 false positive)" \
    "2" "$(head -1 "${GTIMEOUT_BUDGET_MARKER}")"

# ── Case f2: CHROME_PROBE_TIMEOUT reaches the probe budget ─────
# chrome_runnable must honour CHROME_PROBE_TIMEOUT (a cold container mount can
# make a healthy browser's first exec slow). A "browser" that takes real
# wall-clock time to answer --version must (a) survive a comfortably large
# override and (b) be killed by a tiny one — proving the override actually
# reaches the timeout invocation, in both directions.
#
# The pass side is pinned to an EXPLICIT override (CHROME_PROBE_TIMEOUT=10),
# NOT the production default (hardcoded "2" in chrome_runnable, common.sh).
# An earlier version pinned the pass side to that literal default, which made
# the assertion load-sensitive: the fixture's sleep had to outlive bash/
# timeout process-startup jitter on a throttled CI runner while still fitting
# inside a fixed 2s ceiling it does not control (TEST-013). An explicit,
# generous override turns this into a RATIO assertion — budget far exceeds
# sleep — rather than an absolute-wall-clock one, so ordinary CI jitter cannot
# flip it. This does mean case f2 no longer pins the literal "2" default
# value itself; nothing else in this suite does either, and that value is a
# tuning constant, not part of the LAB-5064/LAB-3893 contract this file
# guards. Skipped when no timeout/gtimeout is on PATH (the bare-probe
# fallback has no budget to override; case f covers that path).
if command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1; then
    # 0.5s sleep against a 10s override below is a 20x margin, and against
    # the 0.2s kill override is a fixed 2.5x margin in the other direction
    # (sleep always takes >= 0.5s of real time regardless of CPU load, so
    # that side was never load-sensitive to begin with).
    SLOW_BROWSER="${FIXTURE_DIR}/bin/slow-chrome"
    cat > "${SLOW_BROWSER}" <<'EOF'
#!/bin/bash
sleep 0.5
echo "Fake Slow Chrome 999.0.0.0"
exit 0
EOF
    chmod +x "${SLOW_BROWSER}"

    probe_slow_browser() {
        (
            # shellcheck source=setup-live-targets.sh disable=SC1091
            source "${SETUP_SCRIPT}"
            set +e
            chrome_runnable "${SLOW_BROWSER}"
            printf '%s\n' "$?"
        )
    }

    assert_eq "case f2: slow browser passes when the override budget comfortably exceeds it" \
        "0" "$(CHROME_PROBE_TIMEOUT=10 probe_slow_browser)"
    # Assert rc 124 exactly — timeout/gtimeout's "I killed it" status. Any
    # other nonzero rc (125 invalid duration, the probe's own failure code)
    # would mean the probe failed for the wrong reason, not that the budget
    # was enforced.
    rc_f2=$(CHROME_PROBE_TIMEOUT=0.2 probe_slow_browser)
    if [ "${rc_f2}" = "124" ]; then
        echo "PASS: case f2: CHROME_PROBE_TIMEOUT=0.2 kills the slow probe (rc 124)"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case f2: expected timeout kill (rc 124), got rc ${rc_f2}"
        fail_count=$((fail_count + 1))
    fi
    # ── Case f3: a malformed budget must not condemn the browser ──
    # An unparseable CHROME_PROBE_TIMEOUT makes timeout(1) exit 125 WITHOUT
    # running the browser, which chrome_runnable would otherwise report as
    # "not runnable" — reintroducing the LAB-3893 false positive the override
    # exists to cure, and blaming the browser for a typo in an env var. The
    # value is validated and falls back to the 2s default with a warning.
    probe_working_browser() {
        (
            # shellcheck source=setup-live-targets.sh disable=SC1091
            source "${SETUP_SCRIPT}"
            set +e
            chrome_runnable "${WORKING_BROWSER}" 2>/dev/null
            printf '%s\n' "$?"
        )
    }
    # stderr is captured via a file rather than `2>&1 >/dev/null`: that ordering
    # reads backwards (it duplicates stdout's CURRENT target before /dev/null is
    # applied) and shellcheck flags it as SC2069. A file keeps the intent obvious.
    warn_of() {
        local errf="${FIXTURE_DIR}/f3.err"
        (
            # shellcheck source=setup-live-targets.sh disable=SC1091
            source "${SETUP_SCRIPT}"
            set +e
            chrome_runnable "${WORKING_BROWSER}" >/dev/null 2>"${errf}"
        )
        cat "${errf}"
    }
    # TEST-011: continuation lines and the loop keyword now sit at this block's own
    # indentation. The comment's 2nd and 3rd lines were at column 0 and the `for` was
    # too, while the loop BODY was indented 8 — which reads as though the loop is
    # outside the enclosing block when it is inside it.
    #
    # Boundary spellings matter here: an earlier zero-glob rejected 007, 00.1 and
    # 0.05 — all perfectly good budgets — while a plain `0` slipped through some
    # variants. Both directions are pinned: these must all still DETECT the browser.
    for bad in "abc" "-1" "2s" "1.2.3" "0" "00" "0.0" "0." "000.000" ".0" ""; do
        rc_f3=$(CHROME_PROBE_TIMEOUT="${bad}" probe_working_browser)
        assert_eq "case f3: CHROME_PROBE_TIMEOUT='${bad}' still detects a working browser" \
            "0" "${rc_f3}"
    done
    # An empty value means "unset" to :- and must stay silent; a malformed one
    # must say so, otherwise the fallback is invisible and the typo persists.
    assert_contains_f3() {
        local desc=$1 needle=$2 hay=$3
        if printf '%s' "${hay}" | grep -qF -- "${needle}"; then
            echo "PASS: ${desc}"; pass_count=$((pass_count + 1))
        else
            echo "FAIL: ${desc} (output did not contain [${needle}])"; fail_count=$((fail_count + 1))
        fi
    }
    assert_contains_f3 "case f3: a malformed budget warns and names the value" \
        "CHROME_PROBE_TIMEOUT=abc" "$(CHROME_PROBE_TIMEOUT=abc warn_of)"
    # '2s' and '0' deserve their own warning assertions. Without them their loop
    # iterations above could not fail: GNU timeout accepts a "2s" suffix and
    # treats 0 as "no timeout", so both would yield rc 0 whether validation
    # rejected them or not. Asserting the warning proves they were rejected HERE.
    assert_contains_f3 "case f3: a suffixed budget ('2s') is rejected by validation, not passed through" \
        "CHROME_PROBE_TIMEOUT=2s" "$(CHROME_PROBE_TIMEOUT=2s warn_of)"
    # Every zero spelling gets its own WARNING assertion, not just an rc check.
    # The rc-based loop above is vacuous for these: rc 0 holds whether the value
    # was rejected (budget falls back to 2) or passed straight through (GNU
    # timeout reads `00` as 0 = no timeout, and the fake browser answers
    # instantly either way). Mutation-proven — narrowing the validation to a
    # literal `0` left the `00` and `0.` rows green.
    for zero in "0" "00" "0." "0.0" "000.000" ".0"; do
        assert_contains_f3 "case f3: '${zero}' is recognised as a zero budget and refused" \
            "is zero" "$(CHROME_PROBE_TIMEOUT="${zero}" warn_of)"
    done
    # ...and the converse: leading-zero durations that are NOT zero must be
    # accepted silently. Rejecting them was a real over-reach in an earlier glob.
    for good in "007" "00.1" "0.05" ".5" "2.50"; do
        assert_eq "case f3: a valid budget '${good}' is accepted without warning" \
            "" "$(CHROME_PROBE_TIMEOUT="${good}" warn_of)"
    done
    assert_eq "case f3: an empty budget is treated as unset, no warning" \
        "" "$(CHROME_PROBE_TIMEOUT='' warn_of)"
else
    # Credit 27: measured by forcing this arm false on a fully-equipped host
    # and reading pass_count's drop (71 -> 44). Covers the f2 pass/kill pair,
    # the 11-value f3 detects-anyway loop, the 2 named-warning assertions, the
    # 6-value zero-spelling loop, the 5-value valid-budget loop, and the
    # empty-budget assertion.
    skip "case f2: no timeout/gtimeout on PATH — no probe budget to override" 27
fi

# ── Case p: _CHROME_BUDGET_WARNED dedups within ONE shell (TEST-002) ──
# The warn-once guard added alongside _CHROME_BUDGET_WARNED has no coverage
# anywhere: every existing budget-warning case above (f3's warn_of /
# probe_working_browser) sources the script in a FRESH subshell per
# invocation, so _CHROME_BUDGET_WARNED starts empty every time and the
# dedup path — printing the warning once per RUN rather than once per
# candidate probed — never executes. detect_chrome_binary's loop over
# CHROME_CANDIDATES is the only production call site that invokes
# chrome_runnable more than once in the SAME shell, so drive that loop
# directly, in one `source`, with three present-but-broken candidates and a
# single bad CHROME_PROBE_TIMEOUT for the whole loop. This case needs no
# timeout/gtimeout gate: chrome_runnable validates the budget before it
# checks for either, so the dedup path runs on every host.
warn_count_over_candidates() {
    local budget=$1 pattern=$2 errf="${FIXTURE_DIR}/p.err"
    (
        # shellcheck source=setup-live-targets.sh disable=SC1091
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}" "${GENERIC_BROKEN}" "${SNAP_STUB}")
        set +e
        CHROME_PROBE_TIMEOUT="${budget}" detect_chrome_binary >/dev/null 2>"${errf}"
    )
    grep -c "${pattern}" "${errf}"
}
assert_eq "case p: a malformed CHROME_PROBE_TIMEOUT warns exactly once across 3 probes in one shell" \
    "1" "$(warn_count_over_candidates "abc" "is not a usable timeout")"
assert_eq "case p: a zero CHROME_PROBE_TIMEOUT warns exactly once across 3 probes in one shell" \
    "1" "$(warn_count_over_candidates "0" "is zero, which disables the timeout")"

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

# ── Case k: browser_required's mapping itself ──────────────────
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

# A comma-splitting bug that word-split an UNQUOTED expansion would also glob,
# so a list containing * would expand against the cwd before being compared.
# Run from a directory that contains a file literally named like a browser
# target: if the split globs, "*" becomes "rest-api" and this returns 0.
glob_rc=$(
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        mkdir -p "${FIXTURE_DIR}/globdir" && : > "${FIXTURE_DIR}/globdir/rest-api"
        cd "${FIXTURE_DIR}/globdir" || exit 9
        set +e
        browser_required "*"
        printf '%s\n' "$?"
    )
)
assert_eq "case k: a glob in the target list is not expanded (stays unknown)" \
    "1" "${glob_rc}"

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

# ── Case n: main()'s CALL SITE, end to end ─────────────────────
# Cases g-m all invoke check_prerequisites directly with explicit arguments, so
# every one of them stayed green when main()'s call site was reverted to a bare
# `check_prerequisites` — reintroducing the exact browserless hard-fail LAB-5064
# exists to fix. Worse, case j asserts that the argument-less call MUST be fatal,
# so the suite actively certified the broken call site as correct.
#
# This case closes that by running main() itself. The build helpers are stubbed
# (no compilation, no network); everything up to and including the browser gate
# is the real code path.
#
# It has teeth in both directions: strip the arguments from the call site and the
# gate goes fatal, check_prerequisites exits 1, and BOTH the WARN assertion and
# the past-prereqs marker below fail.
PAST_PREREQS_MARKER="STUB-REACHED-BUILD-PHASE"

# check_prerequisites exits 1 on ANY failed prerequisite, not just the browser
# gate — go, python3 too. The marker and the "Prerequisites check failed"
# epilogue are therefore only readable as browser-gate signals on a host that
# has go and python3 (this suite's own README/CLAUDE.md claim that guard
# scripts "need no Go, Node, or Chrome" is about running the SUITE, not about
# what a non-fatal gate needs downstream of it in main()). Without this guard
# a python3-less host would see the browser gate behave correctly yet still
# fail these two assertions on an unrelated missing prerequisite (TEST-016) —
# a false RED, not a false green, but one that couples this un-gated
# preflight-selftest job to the runner image's toolchain. Gate the
# marker/epilogue checks on it and SKIP with a clear reason otherwise; the
# browser-severity assertions (assert_gate, above and below) are NOT gated
# because browser_gate_level reads only the browser diagnosis line and never
# depends on go/python3 being present.
HAS_NONBROWSER_PREREQS=true
if ! command -v go >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    HAS_NONBROWSER_PREREQS=false
fi

run_setup_main() {
    (
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}")
        # build_vespasian is the FIRST thing main() calls after the prerequisite
        # gate, so stubbing it with an immediate exit does double duty: it stands
        # in as the past-prereqs marker, and it makes this case incapable of
        # reaching the real build or service-start phases.
        #
        # That second property is not a nicety. An earlier revision stubbed only
        # build_vespasian and build_grpc_server without exiting, and when the
        # "browser gate never fatal" mutation let a rest-api setup through, the
        # test compiled Go and started live services from a scratch copy of the
        # tree. A test must stay inert under mutation, not just under the
        # behaviour it expects.
        build_vespasian() { log_ok "${PAST_PREREQS_MARKER}"; exit 0; }
        set +e
        main "$@" 2>&1
    ) || true
}

# ── Case n2: a browserless run REACHES write_config (TEST-013) ──
#
# Case n proves a browserless setup gets past the prerequisite gate, and that is where
# its stub exits. Nothing proved the run goes on to WRITE the config, which is the
# outcome AC2 actually promises: `run-live-tests.sh --group offline` must work on a
# fresh browserless checkout, and it loads ports and TARGETS_SETUP from
# .live-test-config. A browser gate that turned fatal LATER — past the gate but before
# write_config — would satisfy every other assertion in this file while leaving the
# offline group with nothing to load.
#
# NOT driven with --skip-start: that flag deliberately `exit 0`s after the build with
# "services not started", so a skip-start run legitimately never reaches write_config
# and asserting otherwise would be asserting a false contract. Instead the build and
# the service start are stubbed and main() is allowed to run through to the end.
# STATE_DIR is resolved at SOURCE time from SETUP_LIVE_TARGETS_STATE_DIR, so the
# override is exported before sourcing rather than set afterwards.
n2_state="${FIXTURE_DIR}/n2-state"
mkdir -p "${n2_state}"
# stdout is not the outcome under test — the config FILE is — so it is kept on disk
# for inspection rather than captured into an unused variable (SC2034).
{
    (
        export SETUP_LIVE_TARGETS_STATE_DIR="${n2_state}"
        # shellcheck source=setup-live-targets.sh
        source "${SETUP_SCRIPT}"
        # shellcheck disable=SC2034  # consumed by detect_chrome_binary from the sourced script
        CHROME_CANDIDATES=("${SNAP_STUB}")
        build_vespasian()     { :; }
        build_grpc_server()   { :; }
        build_graphql_server() { :; }
        # Nothing is actually started: the port resolver reports a fixed port and the
        # starter is a no-op, so this case cannot leave a listener or a PID behind.
        # shellcheck disable=SC2034  # both are consumed by the sourced main(), not here
        resolve_port_or_die() { RESOLVED_PORT=19999; GRPC_SERVER_PORT=19999; }
        start_grpc_server()   { :; }
        cleanup_stale_state() { :; }
        # teardown_on_failure is armed by main() via an EXIT trap; with the starts
        # stubbed it has nothing to tear down, but disarm it so a stray failure in
        # this subshell cannot reach into the fixture tree.
        teardown_on_failure() { :; }
        set +e
        main --targets grpc-server 2>&1
    )
} > "${n2_state}/main.out" 2>&1 || true
if [ -f "${n2_state}/.live-test-config" ]; then
    echo "PASS: case n2: a browserless setup reaches write_config and leaves a config behind (AC2)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case n2: a browserless setup did NOT reach write_config — no .live-test-config was written, so 'run-live-tests.sh --group offline' has nothing to load on a browserless checkout (AC2)"
    fail_count=$((fail_count + 1))
fi
if grep -qE '^TARGETS_SETUP=' "${n2_state}/.live-test-config" 2>/dev/null; then
    echo "PASS: case n2: the config the browserless run wrote carries TARGETS_SETUP"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case n2: the browserless run's config has no TARGETS_SETUP line — run-live-tests.sh cannot tell which targets were provisioned"
    fail_count=$((fail_count + 1))
fi

# grpc-server speaks gRPC reflection and never launches a browser; --skip-start
# starts nothing at all. A browserless host must therefore get through setup.
out_n="$(run_setup_main --targets grpc-server --skip-start)"
assert_gate "case n: main() with a browserless grpc-server setup warns, not fails" \
    WARN "${out_n}"
# check_prerequisites exits 1 on a fatal gate, so the marker can only appear if
# the gate stayed non-fatal AND the run continued past it. Guarded on
# HAS_NONBROWSER_PREREQS — see the comment above PAST_PREREQS_MARKER.
if [ "${HAS_NONBROWSER_PREREQS}" = true ]; then
    if printf '%s' "${out_n}" | grep -qF "${PAST_PREREQS_MARKER}"; then
        echo "PASS: case n: the run proceeds past prerequisites into the build phase"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case n: the run did not get past prerequisites (browser gate still fatal?)"
        fail_count=$((fail_count + 1))
    fi
    if printf '%s' "${out_n}" | grep -q "Prerequisites check failed"; then
        echo "FAIL: case n: main() hard-failed prerequisites on a browserless grpc-server setup"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case n: main() did not hard-fail prerequisites"
        pass_count=$((pass_count + 1))
    fi
else
    # Credit 2: the marker-present and epilogue-absent assertions below.
    skip "case n: marker/epilogue assertions need go and python3 on PATH" 2
fi

# Case n (continued): isolate --skip-start AT THE CALL SITE against a
# browser-backed target (TEST-017). out_n above isolates the TARGETS argument
# (grpc-server has no browser target at all) but not skip_start: grpc-server
# is already outside BROWSER_TARGETS, so browser_required returns 1 and the
# gate degrades to WARN whether or not --skip-start is even passed — a
# mutation at setup-live-targets.sh's call site (main() forwarding
# `check_prerequisites "$targets" false` instead of "$skip_start") would leave
# out_n, out_n2 below, and every case g-m green. This row and out_n2 differ in
# EXACTLY ONE way — the presence of --skip-start against the same
# browser-backed rest-api target — mirroring case i's isolation of skip_start
# one level down, but through main() itself.
out_n3="$(run_setup_main --targets rest-api --skip-start)"
assert_gate "case n: main() forwards --skip-start for a browser-backed target (non-fatal)" \
    WARN "${out_n3}"
if [ "${HAS_NONBROWSER_PREREQS}" = true ]; then
    if printf '%s' "${out_n3}" | grep -qF "${PAST_PREREQS_MARKER}"; then
        echo "PASS: case n: --skip-start at the call site reaches the build phase"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case n: --skip-start at the call site did not reach the build phase"
        fail_count=$((fail_count + 1))
    fi
else
    # Credit 1: the single marker-reached-build-phase assertion below.
    skip "case n: --skip-start marker assertion needs go and python3 on PATH" 1
fi

# And the LAB-3893 half of the contract at the same call site: a browser-backed
# target through main() must STILL hard-fail. Without this, "make the gate
# conditional" could regress into "never gate" and the rows above would happily
# stay green. Asserting the marker is ABSENT is what catches that.
out_n2="$(run_setup_main --targets rest-api)"
assert_gate "case n: main() with a browser-backed target is still fatal" \
    FAIL "${out_n2}"
if printf '%s' "${out_n2}" | grep -q "Prerequisites check failed"; then
    echo "PASS: case n: a browser-backed setup still aborts at prerequisites"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case n: a browser-backed setup no longer aborts (LAB-3893 regression)"
    fail_count=$((fail_count + 1))
fi
if printf '%s' "${out_n2}" | grep -qF "${PAST_PREREQS_MARKER}"; then
    echo "FAIL: case n: a browser-backed setup got past the gate it should have failed"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case n: a browser-backed setup never reaches the build phase"
    pass_count=$((pass_count + 1))
fi

# ── Case o: the rc==0 arm — a runnable browser is actually present ────
# report_browser_prerequisite has three arms: rc==0 (browser found -> log_ok,
# return 0), rc==2 (present but not runnable) and rc==1 (nothing found).
# Cases g-n all pin CHROME_CANDIDATES to either the snap stub (rc==2, via
# run_prereqs_with_stub_only) or a missing path (rc==1, via
# run_prereqs_with_no_browser) — every one of them exercises a FAILURE arm of
# the browser probe. The rc==0 "browser found" arm — the one that runs on
# every correctly provisioned machine — was never fed to check_prerequisites
# anywhere in this suite (TEST-015). A mutation that condemns a healthy
# browser (e.g. replacing the rc==0 branch's `return 0` with a failure) would
# therefore leave every case in this file green.
#
# Reuses run_prereqs_with directly (not the stub/no-browser wrappers) with
# WORKING_BROWSER, against a browser-backed target with skip_start=false —
# the case most like a real developer's first run on a freshly provisioned
# host.
out_o="$(run_prereqs_with "${WORKING_BROWSER}" "rest-api" false)"
assert_gate "case o: a working browser leaves no [FAIL]/[WARN] browser diagnosis" \
    NONE "${out_o}"
if printf '%s' "${out_o}" | grep -q '\[OK\]' && \
   printf '%s' "${out_o}" | grep -qF "Browser: ${WORKING_BROWSER}"; then
    echo "PASS: case o: check_prerequisites logs the detected browser at [OK]"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case o: check_prerequisites did not log the detected browser at [OK]"
    fail_count=$((fail_count + 1))
fi
# A working browser must not, by itself, cause the run to hard-fail. Guarded
# on HAS_NONBROWSER_PREREQS for the same reason as case n's epilogue check
# (see the comment above PAST_PREREQS_MARKER): check_prerequisites exits 1 on
# ANY failed prerequisite, so on a go/python3-less host this line would print
# regardless of the browser arm's own (correct) behaviour, coupling this
# assertion to the runner image's toolchain the same way TEST-016 flagged.
if [ "${HAS_NONBROWSER_PREREQS}" = true ]; then
    if printf '%s' "${out_o}" | grep -q "Prerequisites check failed"; then
        echo "FAIL: case o: a working browser still hard-failed prerequisites"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case o: a working browser does not hard-fail prerequisites"
        pass_count=$((pass_count + 1))
    fi
else
    # Credit 1: the single epilogue-absence assertion below.
    skip "case o: epilogue-absence assertion needs go and python3 on PATH" 1
fi

# ── Summary ─────────────────────────────────────────────────────
SUITE_COMPLETED=1
echo ""
echo "preflight-selftest: ${pass_count} passed, ${fail_count} failed, ${skip_count} skipped"

# Assertion accounting (TEST-015 / TEST-013). Nothing may vanish on ANY host,
# degraded or not: pass + fail + skip_credit is pinned to EXPECTED_ASSERTIONS
# unconditionally, so deleting a case fails here even on a host where some
# blocks legitimately skip for want of Go, Python3, or timeout/gtimeout — the
# exact ambient-toolchain gap this suite's own skip triggers depend on, and
# which this repo's un-gated preflight-selftest CI job cannot be assumed to
# lack (GitHub's ubuntu-24.04 runner image ships Go and Python3 preinstalled
# regardless of whether a setup-go/setup-node step ran, so this job most
# likely takes the zero-skip arm in practice — but the pin no longer depends
# on that guess either way). When blocks were skipped the skip lines above say
# which and why; the NOTE below is informational, not a gate.
total=$((pass_count + fail_count))
if [ "$((total + skip_credit))" -ne "${EXPECTED_ASSERTIONS}" ]; then
    echo "FAIL: assertion accounting drift — expected ${EXPECTED_ASSERTIONS} assertions (pass+fail+skip_credit), saw $((total + skip_credit))."
    echo "      A case was added or removed without updating EXPECTED_ASSERTIONS, or a skip() credit is stale."
    exit 1
fi
if [ "${skip_count}" -gt 0 ]; then
    echo "NOTE: ${skip_count} block(s) skipped — this run did not exercise the full suite."
fi
[ "${fail_count}" -eq 0 ]
