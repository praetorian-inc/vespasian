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
# INT/TERM as well as EXIT: a bash signal handler returns to the interrupted
# code, so without an explicit exit a Ctrl-C left the fixture tree in $TMPDIR.
trap 'rm -rf "${FIXTURE_DIR}"' EXIT
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

# ── Case f2: CHROME_PROBE_TIMEOUT reaches the probe budget ─────
# The probe budget defaults to 2s but must honour CHROME_PROBE_TIMEOUT (a
# cold container mount can make a healthy browser's first exec slow). A
# "browser" that answers --version after ~1s passes under the default budget
# but must be killed under CHROME_PROBE_TIMEOUT=0.2 — if the override never
# reaches the timeout invocation, the slow probe still succeeds and the
# second assertion fails. Skipped when no timeout/gtimeout is on PATH (the
# bare-probe fallback has no budget to override; case f covers that path).
if command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1; then
    # 0.5s, not 1s. The fixture has to outlive the 0.2s override (so the kill
    # assertion is real) and comfortably fit inside the 2s default (so the
    # pass-side assertion is not a coin flip on a loaded CI box). At 1s the
    # pass side had only ~1s of headroom; at 0.5s it has ~1.5s while the kill
    # side keeps a 2.5x margin.
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

    # Pin the budget to its default for the first probe: the README tells
    # users to export CHROME_PROBE_TIMEOUT, and an ambient value below ~1s
    # would fail this assertion spuriously. (Empty means "unset" to :-.)
    assert_eq "case f2: slow browser passes under the default 2s budget" \
        "0" "$(CHROME_PROBE_TIMEOUT='' probe_slow_browser)"
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
    for bad in "abc" "-1" "2s" "1.2.3" "0" ""; do
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
    assert_contains_f3 "case f3: a zero budget is rejected (0 would disable the timeout)" \
        "CHROME_PROBE_TIMEOUT=0" "$(CHROME_PROBE_TIMEOUT=0 warn_of)"
    assert_eq "case f3: an empty budget is treated as unset, no warning" \
        "" "$(CHROME_PROBE_TIMEOUT='' warn_of)"
else
    echo "SKIP: case f2: no timeout/gtimeout on PATH — no probe budget to override"
fi

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

# grpc-server speaks gRPC reflection and never launches a browser; --skip-start
# starts nothing at all. A browserless host must therefore get through setup.
out_n="$(run_setup_main --targets grpc-server --skip-start)"
assert_gate "case n: main() with a browserless grpc-server setup warns, not fails" \
    WARN "${out_n}"
# check_prerequisites exits 1 on a fatal gate, so the marker can only appear if
# the gate stayed non-fatal AND the run continued past it.
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

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "preflight-selftest: ${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
