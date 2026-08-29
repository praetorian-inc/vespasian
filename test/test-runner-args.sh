#!/usr/bin/env bash
# Tests for run-live-tests.sh target group consistency and the --group flag,
# plus the setup-live-targets.sh run-guidance selector. Validates that the group
# arrays stay in sync with the case dispatch block, that --group resolves the
# correct target set (via --dry-run, no binary required), and that
# setup-complete guidance steers full vs partial setups correctly.
#
# Starts no live services and contacts no network. It is dry-run based with ONE
# deliberate exception: the "real offline run" block below invokes the runner for
# real to prove a browserless offline run needs no config file. That block pins
# VESPASIAN to a nonexistent path so it always exercises the binary-absent arm —
# otherwise the assertion would cover a different code path in CI (where this job
# runs before the build) than locally (where bin/vespasian exists). RESULTS_DIR is
# redirected into a temp dir so nothing is written into the repo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run-live-tests.sh"
PASS=0
FAIL=0
SKIP=0
SKIP_CREDIT=0
# A completion sentinel, matching install-chrome-selftest.sh. Without
# it an `exit 0` or an errexit abort part-way through this file printed a run of
# PASS lines, no summary, and a green CI check — the suite reporting success for
# the assertions it happened to reach before dying.
SUITE_COMPLETED=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1" >&2; }
# This suite gained one environmental arm (test/.results may already
# exist from a developer's own run-live-tests.sh run, since that is its default
# RESULTS_DIR). It takes a credit so the pin below stays exact instead of being
# switched off, which is the defect the review records against the sibling suite.
skip() { SKIP=$((SKIP + 1)); SKIP_CREDIT=$((SKIP_CREDIT + ${2:-0})); echo "  SKIP: $1"; }

# All temp configs live under one directory removed by a single EXIT trap, so
# they are cleaned up no matter where the script exits (including a `set -e`
# abort mid-assertion). A directory — not an in-shell array — is used precisely
# because new_tmp is called via command substitution ($(new_tmp)), whose
# subshell would discard any array registration; a filesystem dir created in the
# parent and torn down by the trap has no such scoping problem.
# Pin the parent instead of inheriting $TMPDIR. This tree holds
# executable fixtures that get PATH-prepended and RUN, so an inherited TMPDIR
# pointing at a non-sticky directory a second local user can write to would let
# them rename it away between creation and use and choose the binaries this suite
# executes. /tmp's sticky bit is the property being relied on.
TMPDIR_T="$(TMPDIR=/tmp mktemp -d)"
# The completion sentinel is folded into THIS trap rather than registered as a
# second one: bash keeps a single EXIT trap, so a separate `trap ... EXIT`
# declared earlier is silently REPLACED by this one and never fires. That is
# exactly the inert-assertion failure mode this suite exists to catch, so it is
# worth stating rather than leaving to be rediscovered.
trap 'rm -rf "$TMPDIR_T"; if [ "${SUITE_COMPLETED}" != 1 ]; then echo "test-runner-args: FAIL — suite terminated before reaching the summary; results are incomplete" >&2; exit 1; fi' EXIT
# INT/TERM too, matching the other selftests: a bash signal handler returns to
# the interrupted code, so without an explicit exit a Ctrl-C leaks the temp tree.
trap 'exit 130' INT
trap 'exit 143' TERM
new_tmp() { mktemp "$TMPDIR_T/cfg.XXXXXX"; }

# ── Source the target arrays and helper from the runner ──────────

source <(sed -n '/^OFFLINE_TARGETS=(/,/^)/p' "$RUNNER")
source <(sed -n '/^LIVE_TARGETS=(/,/^)/p' "$RUNNER")
source <(grep '^join_targets()' "$RUNNER")

# ── Source the setup-complete guidance selector from setup-live-targets.sh ──
# Extract ONLY ALL_TARGETS and run_tests_guidance() — never source the whole
# script, whose `main "$@"` at EOF would start live services. Mirrors the
# array/function extraction above and keeps the test hermetic.
SETUP="$SCRIPT_DIR/setup-live-targets.sh"
source <(grep '^ALL_TARGETS=' "$SETUP")
source <(sed -n '/^run_tests_guidance()/,/^}/p' "$SETUP")

# ── Extract case-dispatch targets from the runner ────────────────
# Capture every arm label inside the dispatch block (case "$target" in … esac),
# independent of where the test_* body sits. The previous approach required the
# label and its test_* call on the SAME line, so a multi-line arm —
#     new-target)
#         test_new_target
#         ;;
# a common bash style — was silently dropped from DISPATCH_TARGETS. That let an
# ungrouped multi-line target slip past the "every dispatch target is grouped"
# check below: the exact silent coverage drift this file exists to prevent.
# Anchoring on the dispatch case block captures the label whether the body is
# inline or on following lines. Uses only POSIX awk (2-arg match/substr/gsub/sub)
# so it behaves identically under BSD awk (dev macOS) and gawk (CI ubuntu).

mapfile -t DISPATCH_TARGETS < <(
    awk '
        /^[[:space:]]*case[[:space:]]+"?[$]target"?[[:space:]]+in/ { in_dispatch = 1; next }
        in_dispatch && /^[[:space:]]*esac/ { in_dispatch = 0; next }
        in_dispatch && match($0, /^[[:space:]]*[A-Za-z0-9_-]+\)/) {
            label = substr($0, RSTART, RLENGTH)
            gsub(/[[:space:]]/, "", label)
            sub(/\)$/, "", label)
            print label
        }
    ' "$RUNNER" | sort
)

# ungrouped_dispatch_targets prints any of the given targets that are absent
# from OFFLINE_TARGETS and LIVE_TARGETS. This is the real coverage check shared
# by the drift guard and its negative self-test, so a regression here trips
# both — not just a hand-written copy of the loop.
#
# There is deliberately no config-only tier any more. It existed for exactly one
# target, grpc-server, and its only effect was to exempt that target from the
# "every dispatch target is grouped" check — which is precisely why grpc-server
# ran on no PR for the life of the epic (LAB-5549). Requiring every dispatch
# target to name a group makes this guard strictly stronger, and means a future
# target cannot be added without deciding where it runs.
ungrouped_dispatch_targets() {
    local grouped=("${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}")
    local target
    for target in "$@"; do
        if ! printf '%s\n' "${grouped[@]}" | grep -qx "$target"; then
            printf '%s\n' "$target"
        fi
    done
}

# undispatched_group_members prints any of the given group members that have no
# case-dispatch entry in the runner. Shared by the drift guard's direction-(a)
# check and its negative self-test, so a regression trips both.
undispatched_group_members() {
    local target
    for target in "$@"; do
        if ! printf '%s\n' "${DISPATCH_TARGETS[@]}" | grep -qx "$target"; then
            printf '%s\n' "$target"
        fi
    done
}

# report_undispatched_group_members and report_ungrouped_dispatch_targets wrap
# each detection helper with the fail-emitting loop, so the drift guard AND its
# negative self-tests drive the SAME loop→fail() wiring rather than a copy. A
# regression that breaks that path (e.g. a dropped `fail` call) then trips the
# self-tests too, instead of leaving them green on a silently disabled guard.
report_undispatched_group_members() {
    local target
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        fail "Grouped target '$target' has no case-dispatch entry in run-live-tests.sh"
    done < <(undispatched_group_members "$@")
}

report_ungrouped_dispatch_targets() {
    local target
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        fail "Dispatch target '$target' is not in OFFLINE_TARGETS or LIVE_TARGETS"
    done < <(ungrouped_dispatch_targets "$@")
}

echo "=== Drift guard: groups vs case dispatch ==="
drift_fail_before=$FAIL

# Fidelity check: the guard is only as good as this extraction. A known target
# that always exists is the cheapest sentinel — it catches both an empty scrape
# and a regex that matches the wrong lines, either of which would let real drift
# pass unseen.
if printf '%s\n' "${DISPATCH_TARGETS[@]}" | grep -qx 'rest-api'; then
    pass "DISPATCH_TARGETS extraction captured case-block targets (sentinel: rest-api)"
else
    fail "DISPATCH_TARGETS extraction is broken/empty (sentinel 'rest-api' missing)"
fi

# Every group member must have a case-dispatch entry (direction a), so a target
# cannot be listed in a group while `--targets <it>` falls through to the
# unknown-target path. The call below is what enforces that: if the guarantee
# ever becomes false, `report_undispatched_group_members` emits the
# "in a group but has no case-dispatch entry" failure and this suite fails.
report_undispatched_group_members "${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}"

# Every dispatch target must be in a group (direction b).
report_ungrouped_dispatch_targets "${DISPATCH_TARGETS[@]}"

# No target should appear in both groups.
for target in "${OFFLINE_TARGETS[@]}"; do
    if printf '%s\n' "${LIVE_TARGETS[@]}" | grep -qx "$target"; then
        fail "'$target' appears in both OFFLINE_TARGETS and LIVE_TARGETS"
    fi
done

group_count=$(( ${#OFFLINE_TARGETS[@]} + ${#LIVE_TARGETS[@]} ))
dispatch_count=${#DISPATCH_TARGETS[@]}

# Belt-and-suspenders count assertion: with robust extraction the arm count must
# equal the grouped count exactly. This catches drift the per-target loops cannot
# — e.g. an accidental duplicate arm, or a target both grouped and extracted but
# miscounted — by comparing totals directly instead of per-target membership.
if [[ "$group_count" -ne "$dispatch_count" ]]; then
    fail "Coverage count mismatch: grouped (${group_count}) != dispatch (${dispatch_count})"
fi

if [[ "$FAIL" -eq "$drift_fail_before" ]]; then
    pass "Groups (${group_count}) cover all dispatch targets (${dispatch_count})"
fi

echo ""
echo "=== Absolute group-size anchors (AC#3: 21 offline + 11 live = 32) ==="

# Pin concrete group sizes as literals, independent of the sourced arrays. The
# behavioral --group tests derive expected from the same OFFLINE_TARGETS/
# LIVE_TARGETS under test, so a coordinated silent target drop shrinks expected
# and actual in lockstep and passes green. These literals encode the LAB-4773
# AC#3 contract — "all grouped targets still run", 32 of them as of LAB-5549 —
# so any such drop trips here.
# (LAB-3890 T2 added scan-rest; LAB-3269 added forms-target; LAB-4999 added the
# live-only no-download egress guard; LAB-5549 moved grpc-server out of the
# config-only tier and into LIVE_TARGETS: 21 offline + 11 live = 32 total.)
if [[ "${#OFFLINE_TARGETS[@]}" -eq 21 ]]; then
    pass "OFFLINE_TARGETS has exactly 21 members"
else
    fail "OFFLINE_TARGETS count drifted: expected 21, got ${#OFFLINE_TARGETS[@]}"
fi
if [[ "${#LIVE_TARGETS[@]}" -eq 11 ]]; then
    pass "LIVE_TARGETS has exactly 11 members"
else
    fail "LIVE_TARGETS count drifted: expected 11, got ${#LIVE_TARGETS[@]}"
fi
if [[ "$group_count" -eq 32 ]]; then
    pass "Grouped targets total 32 (AC#3: all 32 targets still run)"
else
    fail "Grouped-target total drifted: expected 32, got $group_count"
fi

echo ""
echo "=== Live group is startable by setup-live-targets.sh ==="

# grpc-server is in LIVE_TARGETS, so `--group live` now runs it on every PR with
# no TARGETS_SETUP or --targets override (LAB-5549). That only works because a
# bare `./test/setup-live-targets.sh` — exactly what live-tests.yml runs — starts
# it, which it does by defaulting --targets to ALL_TARGETS. If grpc-server were
# dropped from setup's ALL_TARGETS while staying in LIVE_TARGETS, the runner
# would probe a server nobody started and the target would fail on an unset
# port rather than on anything about gRPC. This pins that cross-script seam;
# ALL_TARGETS is sourced from setup-live-targets.sh above.
#
# Written as ONE assertion on every path, with a third arm, rather than as an
# `if in LIVE_TARGETS` wrapper with no else. Wrapped, this was the only assertion
# in the file whose EXISTENCE depended on the data it asserts about: drop
# grpc-server from LIVE_TARGETS and it emitted neither pass nor fail, so the
# accounting pin below failed with "a case was added or removed without updating
# EXPECTED_ASSERTIONS" — blaming test maintenance for a real coverage regression.
# The third arm names the actual cause instead.
if ! printf '%s\n' "${LIVE_TARGETS[@]}" | grep -qx 'grpc-server'; then
    fail "grpc-server left LIVE_TARGETS — this guard and the LAB-5549 rationale (gRPC runs by default) need revisiting"
elif printf '%s' "$ALL_TARGETS" | tr ',' '\n' | grep -qx 'grpc-server'; then
    pass "grpc-server is in LIVE_TARGETS and startable by setup-live-targets.sh"
else
    fail "grpc-server is in LIVE_TARGETS but absent from setup-live-targets.sh ALL_TARGETS"
fi

echo ""
echo "=== gRPC preflight probe arms (_probe_grpc_target) ==="

# _probe_grpc_target decides whether the whole live run aborts
# (preflight_test_host ends in `exit 1`), and its arms are mutually exclusive on
# tool availability, so on any given machine at most ONE of them ever executes:
# CI exercises whichever of grpcurl/nc/timeout the runner image happens to ship
# and the rest are dead in practice. That is the same environment-dependent,
# never-executed-where-it-matters shape LAB-5549 removed from the protoc gate, so
# it is not left to the runner image here. Each arm is driven with executable
# fixtures on a controlled PATH — the pattern the load_config value-validation
# block below already uses.
#
# The function text is extracted to a file BEFORE the PATH is restricted, because
# `sed` would not be resolvable inside the sandbox; `source` is a builtin and
# needs no PATH.
probe_fn=$(new_tmp)
sed -n '/^_probe_grpc_target()/,/^}/p' "$RUNNER" > "$probe_fn"

# The sandbox holds ONLY bash (needed by the /dev/tcp arm). Everything else the
# function looks for is absent unless a scenario dir supplies it, which is what
# makes "grpcurl absent" and "no bounded probe available" reachable at all — a
# real /usr/bin on PATH would supply the host's own nc or timeout and silently
# route every case into one arm.
probe_base="$TMPDIR_T/probe-base"
mkdir -p "$probe_base"
ln -s "$(command -v bash)" "$probe_base/bash"

# The stub RECORDS its argv before exiting. Without that the probe assertions
# below can only observe reachability and exit status, which leaves every
# timeout bound deletable undetected: dropping `-max-time`, dropping `-w`, or
# widening `budget` all keep the suite at its pin while removing the property
# the bounds exist to provide. The whole point of this probe is that it fails
# FAST, so the bound is the behaviour under test, not an implementation detail.
new_probe_dir() { # $1 = tool name, $2 = exit status
    local d
    d="$TMPDIR_T/probe-$1-$2"
    mkdir -p "$d"
    printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/argv-%s.log"\nexit %s\n' "$TMPDIR_T" "$1" "$2" > "$d/$1"
    chmod +x "$d/$1"
    printf '%s' "$d"
}
d_grpcurl_ok=$(new_probe_dir grpcurl 0)
d_grpcurl_fail=$(new_probe_dir grpcurl 1)
d_nc_ok=$(new_probe_dir nc 0)
# A real timeout replacement: drop the budget argument and exec the rest, so the
# /dev/tcp arm actually runs its `bash -c` payload.
# Delegates to the REAL timeout binary by absolute path so the fixture actually
# BOUNDS the probe. The earlier `shift; exec "$@"` form discarded the budget, so
# every assertion below ran unbounded: fine against a closed loopback port (which
# refuses instantly) but a hang against a filtered one, in the very block written
# to prove this probe cannot hang.
d_timeout="$TMPDIR_T/probe-timeout"
mkdir -p "$d_timeout"
_real_timeout=$(command -v timeout || true)
if [ -n "$_real_timeout" ]; then
    printf '#!/bin/sh\nexec %s "$@"\n' "$_real_timeout" > "$d_timeout/timeout"
else
    printf '#!/bin/sh\nshift\nexec "$@"\n' > "$d_timeout/timeout"
fi
chmod +x "$d_timeout/timeout"

# Runs _probe_grpc_target under a restricted PATH, echoing "rc=<status>" after
# the function's own output so both are assertable. `|| rc=$?` is required: this
# suite runs under `set -e`, so a returning-1 arm would otherwise abort the
# subshell before the status was printed.
run_probe() { # $1 = PATH, $2 = TEST_HOST, $3 = port
    (
        PATH="$1"
        export PATH
        source "$SCRIPT_DIR/common.sh"
        source "$probe_fn"
        declare -F _probe_grpc_target >/dev/null || { echo "SENTINEL_PROBE_MISSING"; exit 0; }
        TEST_HOST="$2"
        rc=0
        _probe_grpc_target "$3" || rc=$?
        echo "rc=$rc"
    ) 2>&1
}

# The fixture must actually BOUND, not just forward. Reverting it to the earlier
# `shift; exec "$@"` form changed no assertion, leaving the block that proves this
# probe cannot hang running unbounded itself.
if [ -n "$_real_timeout" ] && grep -q "exec $_real_timeout" "$d_timeout/timeout"; then
    pass "probe timeout fixture delegates to the real timeout binary (it bounds, not just forwards)"
elif [ -z "$_real_timeout" ]; then
    pass "probe timeout fixture: no timeout binary on this host, unbounded fallback is the documented degraded arm"
else
    fail "probe timeout fixture no longer execs the real timeout binary — the bounded-probe assertions below would run unbounded"
fi

# Guard the extraction itself: an empty or broken sed range would make every
# assertion below vacuous rather than failing.
if [[ "$(run_probe "$probe_base" localhost "")" == *SENTINEL_PROBE_MISSING* ]]; then
    fail "_probe_grpc_target extraction is broken/empty — the probe-arm assertions below are vacuous"
else
    pass "_probe_grpc_target sourced from run-live-tests.sh (probe-arm block)"
fi

# Arm 1: port unset. Mirrors _probe_target_host's contract — a target
# setup-live-targets.sh never configured is not a failure.
out=$(run_probe "$probe_base" localhost "")
if [[ "$out" == "rc=0" ]]; then
    pass "_probe_grpc_target: unset port returns 0 with no log output"
else
    fail "_probe_grpc_target: unset port expected bare 'rc=0', got: $out"
fi

# Arm 2: grpcurl present and answering.
out=$(run_probe "$d_grpcurl_ok:$probe_base" localhost 50051)
if [[ "$out" == *"grpc-server reachable at localhost:50051"* && "$out" == *"rc=0"* ]]; then
    pass "_probe_grpc_target: grpcurl success reports reachable and returns 0"
else
    fail "_probe_grpc_target: grpcurl success arm, got: $out"
fi

# The BOUND, not just the outcome. `-max-time` is the only thing making the
# grpcurl arm fail fast; deleting it leaves every reachability assertion above
# green while restoring the hang this probe exists to prevent.
# Adjacency, not mere presence: assert the value that FOLLOWS the flag. Two
# independent greps pass whenever a bare "5" appears anywhere else in argv, which
# is a latent hole rather than one this harness reaches today -- its fixtures use
# port 50051, so the loose form does catch a widened budget here. Pinned on
# adjacency anyway because the property under test is "the budget is 5", and a
# harness that later probed port 5 would silently stop testing it.
if [ "$(grep -A1 -x -- '-max-time' "$TMPDIR_T/argv-grpcurl.log" 2>/dev/null | tail -1)" = "5" ]; then
    pass "_probe_grpc_target: grpcurl arm passes -max-time 5 (bound is asserted, not just the outcome)"
else
    fail "_probe_grpc_target: grpcurl arm must pass '-max-time 5'; recorded argv: $(tr '\n' ' ' < "$TMPDIR_T/argv-grpcurl.log" 2>/dev/null)"
fi

# Arm 3: grpcurl present and refusing. grpcurl is authoritative when present —
# it must NOT fall through to the weaker nc/dev-tcp arms.
out=$(run_probe "$d_grpcurl_fail:$d_nc_ok:$probe_base" localhost 50051)
if [[ "$out" == *"grpc-server is unreachable at localhost:50051"* && "$out" == *"rc=1"* && "$out" != *"(nc)"* ]]; then
    pass "_probe_grpc_target: grpcurl failure returns 1 without falling through to nc"
else
    fail "_probe_grpc_target: grpcurl failure arm, got: $out"
fi

# Arm 4: no grpcurl, nc answers.
out=$(run_probe "$d_nc_ok:$probe_base" localhost 50051)
if [[ "$out" == *"grpc-server reachable at localhost:50051 (nc)"* && "$out" == *"rc=0"* ]]; then
    pass "_probe_grpc_target: nc success reports reachable via nc and returns 0"
else
    fail "_probe_grpc_target: nc success arm, got: $out"
fi

# Same reasoning as the grpcurl bound above: `-w` is what makes the nc arm
# finite. This is the arm CI actually takes when grpc-server is down, because
# ubuntu-24.04 ships nc but not grpcurl.
# Adjacency for the same reason as the grpcurl bound above.
if [ "$(grep -A1 -x -- '-w' "$TMPDIR_T/argv-nc.log" 2>/dev/null | tail -1)" = "5" ]; then
    pass "_probe_grpc_target: nc arm passes -w 5 (bound is asserted, not just the outcome)"
else
    fail "_probe_grpc_target: nc arm must pass '-w 5'; recorded argv: $(tr '\n' ' ' < "$TMPDIR_T/argv-nc.log" 2>/dev/null)"
fi

# Arm 5: nothing bounded available. This must FAIL rather than degrade to an
# unbounded connect — a preflight exists to fail fast, so a hang is strictly
# worse than a diagnosable failure (a deliberate divergence from the
# graceful-degrade precedent in setup-live-targets.sh's wait_for_grpc).
out=$(run_probe "$probe_base" localhost 50051)
if [[ "$out" == *"no bounded probe available for localhost:50051"* && "$out" == *"rc=1"* ]]; then
    pass "_probe_grpc_target: no bounded probe available fails and names the missing tools"
else
    fail "_probe_grpc_target: no-bounded-probe arm, got: $out"
fi

# The /dev/tcp arm's own failure outcome. Port 1 on loopback has no listener, so
# the connect fails without this suite starting anything -- the assertion stays
# hermetic. It pins the arm's `return 1`: flipping that to `return 0` makes an
# unreachable gRPC target report success and the whole preflight pointless, and
# without this assertion that mutation survives the entire suite.
out=$(run_probe "$d_timeout:$probe_base" 127.0.0.1 1)
if [[ "$out" == *"grpc-server is unreachable at 127.0.0.1:1"* && "$out" == *"rc=1"* ]]; then
    pass "_probe_grpc_target: /dev/tcp arm reports unreachable and returns 1 on a closed port"
else
    fail "_probe_grpc_target: /dev/tcp closed-port arm expected unreachable + rc=1, got: $out"
fi

# Arms 6-7: the /dev/tcp arm must not let TEST_HOST reach a shell PARSER.
# `bash -c` parses its argument as shell source, so an interpolated
# "${TEST_HOST}/${port}" would execute anything TEST_HOST carries. TEST_HOST is an
# env-only seam and the port is unvalidated when it comes from the environment, so
# neither value is screened before this call.
#
# The payload uses only the `printf` builtin and a redirect — no external command
# — because the sandbox PATH holds nothing else. A payload needing /usr/bin/touch
# would be inert here for the wrong reason and the assertion could never fail.
probe_marker="$TMPDIR_T/probe-injection-marker"
hostile_host="x/1; printf pwned > $probe_marker #"

# Positive control FIRST: prove the payload really does fire against the
# vulnerable interpolated form. Without this, the negative assertion below cannot
# be distinguished from a payload that never had a chance to run.
rm -f "$probe_marker"
( PATH="$d_timeout:$probe_base"; export PATH
  timeout 5 bash -c "echo > /dev/tcp/${hostile_host}/50051" ) >/dev/null 2>&1 || true
if [[ -f "$probe_marker" ]]; then
    pass "_probe_grpc_target: injection payload fires against the interpolated form (positive control — this assertion can fail)"
else
    fail "_probe_grpc_target: injection payload did not fire even against the interpolated form — the hostile-TEST_HOST assertion below would be vacuous"
fi

# The real assertion: the shipped function must NOT execute it.
rm -f "$probe_marker"
out=$(run_probe "$d_timeout:$probe_base" "$hostile_host" 50051)
if [[ ! -f "$probe_marker" ]]; then
    pass "_probe_grpc_target: hostile TEST_HOST is not executed by the /dev/tcp probe"
else
    fail "_probe_grpc_target: hostile TEST_HOST was EXECUTED by the /dev/tcp probe (command injection); output: $out"
fi
rm -f "$probe_marker"

echo ""
echo "=== Env-seam validation (TEST_HOST / GRPC_SERVER_PORT) ==="

# run-live-tests.sh refuses to run on a TEST_HOST that is not a plain hostname,
# IPv4 or bracketed IPv6, and on a GRPC_SERVER_PORT outside 1-65535. Both values
# flow into a curl URL, a grpcurl authority, an nc operand and a `bash -c` argv,
# so this seam is what keeps every one of those sinks fed only screened values.
# It shipped with no assertion at all: deleting the whole block left the suite
# green, which is the "guard that cannot fail" shape this file exists to prevent.
#
# Each case runs in its own `bash -c` subshell, so the seam's `exit 1` terminates
# that subshell and not this suite.
# Captures the STATUS as well as the message. Matching only the text pinned the
# wording, not the refusal: deleting `exit 1` from the seam left the message on
# stderr and the suite green, and that mutant is genuinely broken because the
# /dev/tcp argv comment now rests on the seam actually stopping the run.
seam_rc=0
seam_hostile=$(TEST_HOST='x/1; id #' bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) || seam_rc=$?
if [[ "$seam_hostile" == *"refusing to run"* ]] && [ "$seam_rc" -ne 0 ] && [[ "$seam_hostile" != *"targets="* ]]; then
    pass "env seam: TEST_HOST carrying shell metacharacters is refused (non-zero status, no target list)"
else
    fail "env seam: a TEST_HOST containing ';' and '#' must abort with non-zero status and emit no target list; rc=$seam_rc, got: $seam_hostile"
fi

# TEST-005: one payload pinned one character class. This payload ENDS in '#', so
# the trailing-character rule alone rejected it and the middle of the pattern was
# never exercised; and admitting a leading dash -- which the seam comment calls
# "the point of the second pattern" -- changed no assertion at all.
for seam_bad in '-X' 'a b' 'foo$(id)bar' 'ho`id`st'; do
    rc=0
    out=$(TEST_HOST="$seam_bad" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) || rc=$?
    if [[ "$out" == *"refusing to run"* ]] && [ "$rc" -ne 0 ]; then
        pass "env seam: TEST_HOST '${seam_bad}' is refused"
    else
        fail "env seam: TEST_HOST '${seam_bad}' must be refused; rc=$rc, got: $out"
    fi
done

# Accept-direction cases. A validator that rejects a documented value breaks every
# run that uses it, so both the devcontainer form and the bracketed IPv6 literal
# are pinned. Deleting the `\[[0-9A-Fa-f:]+\]` alternative from the seam pattern
# previously changed no assertion, so the documented IPv6 form could have been
# refused silently.
for seam_good in 'host.docker.internal' '127.0.0.1' '[::1]'; do
    if out=$(TEST_HOST="$seam_good" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) &&
       [[ "$out" != *"refusing to run"* && "$out" == *"targets="* ]]; then
        pass "env seam: documented TEST_HOST '${seam_good}' is accepted"
    else
        fail "env seam: TEST_HOST '${seam_good}' must be accepted — the validator cannot reject a documented value; got: $out"
    fi
done

# host_bare strips the brackets a bracketed IPv6 literal carries, because nc and
# bash's /dev/tcp take a bare host and REJECT them while curl and grpcurl require
# them. Deleting the stripping changed no assertion, so this drives the real
# function and asserts the probe reports the BARE form.
# Asserted on the RECORDED ARGV, not the log line: the log deliberately echoes the
# operator's TEST_HOST verbatim (brackets and all) so the diagnostic names what
# they set, while the stripping applies only to what reaches the bare-host
# consumers. Matching the log would pin the wrong surface.
rm -f "$TMPDIR_T/argv-nc.log"
run_probe "$d_nc_ok:$probe_base" '[::1]' 50051 >/dev/null
if grep -qx -- '::1' "$TMPDIR_T/argv-nc.log" 2>/dev/null; then
    pass "_probe_grpc_target: bracketed IPv6 TEST_HOST reaches nc as the bare '::1' it accepts"
else
    fail "_probe_grpc_target: TEST_HOST='[::1]' must reach nc as '::1' (nc rejects brackets); recorded argv: $(tr '\n' ' ' < "$TMPDIR_T/argv-nc.log" 2>/dev/null)"
fi

# Four cases, not one. With only 99999 pinned, deleting BOTH the `^[0-9]{1,5}$`
# shape check and the `-lt 1` bound left the suite green while admitting 0, -1 and
# abc into a curl URL and into grpcurl/nc argv.
for seam_port_bad in 99999 0 -1 abc; do
    rc=0
    out=$(GRPC_SERVER_PORT="$seam_port_bad" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) || rc=$?
    if [[ "$out" == *"refusing to run"* ]] && [ "$rc" -ne 0 ]; then
        pass "env seam: GRPC_SERVER_PORT '${seam_port_bad}' is refused"
    else
        fail "env seam: GRPC_SERVER_PORT '${seam_port_bad}' must be refused; rc=$rc, got: $out"
    fi
done

echo ""
echo "=== AC4 compile check is unconditional (LAB-5549's whole point) ==="

# LAB-5549 exists because the AC4 compile assertion was gated on
# `command -v protoc` and therefore passed by NEVER RUNNING. Removing that gate
# is the deliverable, so the property worth pinning is not "the check works" but
# "the check cannot opt itself out again". Both regressions below are one-line
# edits that leave every other assertion in this suite green.
# Whole comment LINES are dropped; a `#` inside a code line is left alone. The
# block's own comments narrate the removed `command -v protoc` gate at length, so
# matching raw text reports that history as a live gate -- this assertion failed
# on a correct tree the first time it ran. But truncating each line at its first
# `#` over-corrects: a gate written as `... "#" ... || ! command -v protoc` would
# be silently erased along with the comment, hiding exactly what this checks for.
# `|| true` is load-bearing: grep exits 1 when it filters everything out, and
# under `set -e` a failing command substitution aborts the whole suite. Without
# it a broken sed anchor killed the run mid-file -- the completion sentinel
# caught it, but reported "terminated before reaching the summary" instead of the
# real cause, which is the misattributed-diagnostic failure this file warns about
# elsewhere. With it, a broken anchor becomes the counted failure below.
ac4_block=$(sed -n '/# AC4 (LAB-2778)/,/^    local expected_count/p' "$RUNNER" | grep -vE '^[[:space:]]*#' || true)

# Fidelity sentinel, matching the four sibling extractions in this file. Without
# it an anchor that stops matching yields an EMPTY block, and assertion (a) below
# -- which passes when it finds no capability gate -- passes vacuously on nothing.
if [ -n "$ac4_block" ] && printf '%s' "$ac4_block" | grep -q 'proto-validate'; then
    pass "AC4 block extracted from run-live-tests.sh (assertions below are non-vacuous)"
else
    fail "AC4 block extraction is broken/empty — the two assertions below would pass vacuously; fix the sed anchors rather than deleting them"
fi

# (a) BEHAVIOURAL, not textual. Three earlier revisions of this check grepped the
# block's source and mis-fired every time: first matching `command -v protoc`
# inside the comments that narrate its removal, then over-correcting by truncating
# each line at its first `#` (which would erase a real gate written beside one),
# and then going red on a harmless trailing comment. The property is not "the text
# contains no gate" -- it is "the compile assertion evaluates on a host with no
# protoc", which is exactly CI's state. So run it there.
#
# A stripped PATH holding only the interpreters and go makes protoc genuinely
# absent regardless of this host, then a deliberately MALFORMED spec must be
# reported as a failure. A reintroduced `command -v protoc ||` gate short-circuits
# and reports success instead, which this catches on any host.
# Drives the AC4 BLOCK ITSELF, on a PATH where protoc is genuinely absent. The
# first attempt at this ran the validator binary directly, which tests the wrong
# subject: the gate would live in the SHELL, so mutating the shell changed nothing
# and the mutation survived. Extract the block, stub the loggers, feed it a
# MALFORMED spec, and assert it counts a failure. A reintroduced
# `! command -v protoc ||` short-circuits to success on a protoc-absent host,
# which is precisely CI's state.
# Driven with a STUB validator, not the real toolchain. The property under test is
# the BLOCK's control flow -- does it invoke the validator, and does it count the
# result -- not whether protocompile works, which test/proto-validate's own unit
# tests and ci.yml's proto-validate-tests job already cover.
#
# That distinction is load-bearing for WHERE this suite runs. Requiring a real
# `go run` put a Go toolchain AND a module-proxy fetch inside live-tests.yml's
# `preflight-selftest` job, which has no setup-go and whose documented property is
# that these suites need "no Go, Node, or Chrome" (AGENTS.md). Measured: with
# GOPROXY=off and an empty module cache the real-toolchain form FAILED, and the
# LAB-4732 egress audit->block flip would have made that CI's steady state, with a
# message blaming run-live-tests.sh.
#
# The stub is also STRICTLY STRONGER: it records that it was CALLED, so the
# round-4 vacuity (the block failing before ever reaching the validator) is caught
# directly rather than inferred from an exit status.
# WRAPPED IN A FUNCTION. The block declares `local spec_abs`, and `local` outside a
# function is a hard error: sourced at top level that assignment failed, the
# compound command died before the validator was reached, and failures=1 came back
# for every input -- so a single-direction assertion passed vacuously. That was the
# round-4 defect in this very guard.
ac4_fn=$(new_tmp)
{
    printf '_ac4_block() {\n'
    sed -n '/# AC4 (LAB-2778)/,/^    local expected_count/p' "$RUNNER" | sed '$d'
    printf '}\n'
} > "$ac4_fn"

# Guard the extraction: a broken end anchor would otherwise wrap ~1000 lines of the
# runner into the function and source it.
if [ -s "$ac4_fn" ] && grep -q 'proto-validate' "$ac4_fn" && [ "$(wc -l < "$ac4_fn")" -lt 120 ]; then
    pass "AC4 block extracted and wrapped for execution (bounded, non-empty)"
else
    fail "AC4 block extraction is empty, oversized ($(wc -l < "$ac4_fn") lines), or missing its proto-validate call — the behavioural assertions below cannot be trusted"
fi

ac4_bin="$TMPDIR_T/ac4-bin"; mkdir -p "$ac4_bin"
for _t in sh bash sed grep dirname basename cat rm mkdir uname env tr printf; do
    _p=$(command -v "$_t" 2>/dev/null) && ln -sf "$_p" "$ac4_bin/$_t"
done
# Fake `go`: records its argv, then exits with the status in AC4_STUB_RC.
cat > "$ac4_bin/go" <<'AC4GO'
#!/bin/sh
printf '%s\n' "$*" >> "$AC4_STUB_LOG"
exit "${AC4_STUB_RC:-0}"
AC4GO
chmod +x "$ac4_bin/go"

ac4_dir="$TMPDIR_T/ac4-run"; mkdir -p "$ac4_dir"
ac4_stub_log="$TMPDIR_T/ac4-stub.log"

ac4_run() { # $1 = stub exit status
    : > "$ac4_stub_log"
    printf 'syntax = "proto3";\nmessage M { string a = 1; }\n' > "$ac4_dir/spec.proto"
    PATH="$ac4_bin" AC4_ROOT="$SCRIPT_DIR/.." AC4_DIR="$ac4_dir" AC4_FN="$ac4_fn" \
    AC4_STUB_RC="$1" AC4_STUB_LOG="$ac4_stub_log" \
    "$ac4_bin/bash" -c '
        log_ok(){ printf "OK:%s\n" "$1"; }
        log_fail(){ printf "FAIL:%s\n" "$1"; }
        log_info(){ printf "INFO:%s\n" "$1"; }
        failures=0
        PROJECT_ROOT="$AC4_ROOT"
        target_dir="$AC4_DIR"
        spec_file="$AC4_DIR/spec.proto"
        source "$AC4_FN"
        _ac4_block
        printf "failures=%s\n" "$failures"
    ' 2>&1 || true
}

ac4_pass_out=$(ac4_run 0); ac4_pass_log=$(cat "$ac4_stub_log" 2>/dev/null)
ac4_fail_out=$(ac4_run 1)

# The validator must actually be INVOKED. This is the anti-vacuity property: the
# round-4 guard failed before reaching it and still reported failures=1.
if printf '%s' "$ac4_pass_log" | grep -q 'run \.'; then
    pass "AC4 block actually invokes the proto validator (\`go run .\` observed, not inferred)"
else
    fail "AC4 block never invoked the validator — the compile assertion is not running at all. Stub log: [$ac4_pass_log]"
fi

# And it must COUNT the result in both directions.
if [[ "$ac4_pass_out" == *"failures=0"* ]] && [[ "$ac4_fail_out" == *"failures=1"* ]]; then
    pass "AC4 block counts the validator's verdict: success -> failures=0, failure -> failures=1"
else
    fail "AC4 block must map the validator's exit status onto failures (0 and 1). success=[$ac4_pass_out] failure=[$ac4_fail_out]"
fi

# (b) Every non-success arm must count a failure. A branch that neither compiles
# nor increments `failures` reports PASS with AC4 never evaluated -- the same
# false green as the protoc gate, triggered by artifact content instead. The
# multi-file `// ---` arm is the one that changed skip->fail; log_info alone
# there would silently restore the hole.
multifile_arm=$(printf '%s' "$ac4_block" | sed -n "/grep -q /,/elif/p")
if printf '%s' "$multifile_arm" | grep -q 'failures=$((failures + 1))'; then
    pass "AC4 multi-file '// ---' arm counts a failure (cannot report PASS with the compile check unevaluated)"
else
    fail "AC4 multi-file '// ---' arm does not increment failures — a multi-file spec would report PASS with AC4 never evaluated"
fi

echo ""
echo "=== gRPC preflight case-block dispatch (preflight_test_host) ==="

# grpc-server and concat-spa were arms of the SAME `case ',${targets},' in`
# statement, and `case` stops at the first matching arm — so any run selecting
# both probed gRPC and silently SKIPPED concat-spa's /healthz probe. Harmless
# only while grpc-server was config-only; moving it into LIVE_TARGETS made that
# skip permanent for every `--group live` run. Splitting the arms into separate
# `case` statements fixed it, and this pins the fix.
#
# The failure mode is silent by construction — a skipped probe produces no output
# and no failure — which is why it survived from PR #159 until LAB-5549. It
# recurs the moment anyone adds a target by appending an arm to an existing
# `case` instead of opening a new one, so the guard is on the dispatch, not on
# grpc-server specifically.
preflight_fn=$(new_tmp)
sed -n '/^preflight_test_host()/,/^}/p' "$RUNNER" > "$preflight_fn"

run_preflight() { # $1 = targets list
    (
        source "$SCRIPT_DIR/common.sh"
        source "$preflight_fn"
        declare -F preflight_test_host >/dev/null || { echo "SENTINEL_PREFLIGHT_MISSING"; exit 0; }
        # Stubs record the call instead of touching the network. $3 is the target
        # name _probe_target_host is passed; the gRPC probe takes only a port.
        _probe_target_host() { echo "PROBED:$3"; return 0; }
        _probe_grpc_target() { echo "PROBED:grpc-server"; return 0; }
        REST_API_PORT=1
        SOAP_SERVICE_PORT=2
        GRAPHQL_SERVER_PORT=3
        GRPC_SERVER_PORT=4
        CONCAT_SPA_PORT=5
        FORMS_TARGET_PORT=6
        preflight_test_host "$1" || true
    ) 2>&1
}

if [[ "$(run_preflight grpc-server)" == *SENTINEL_PREFLIGHT_MISSING* ]]; then
    fail "preflight_test_host extraction is broken/empty — the dispatch assertions below are vacuous"
else
    pass "preflight_test_host sourced from run-live-tests.sh (case-dispatch block)"
fi

# The exact co-selection that was broken: both probes must fire.
out=$(run_preflight "grpc-server,concat-spa")
if [[ "$out" == *"PROBED:grpc-server"* && "$out" == *"PROBED:concat-spa"* ]]; then
    pass "preflight_test_host: grpc-server and concat-spa co-selected both probe (no shared case arm)"
else
    fail "preflight_test_host: co-selecting grpc-server,concat-spa must probe both, got: $out"
fi

# Generalised: selecting the whole live group must fire every case block, so a
# future target folded into an existing arm is caught even if it is not
# concat-spa.
out=$(run_preflight "$(join_targets "${LIVE_TARGETS[@]}")")
missing_probes=""
for expected_probe in rest-api soap-service graphql-server grpc-server concat-spa forms-target; do
    [[ "$out" == *"PROBED:${expected_probe}"* ]] || missing_probes="${missing_probes} ${expected_probe}"
done
if [[ -z "$missing_probes" ]]; then
    pass "preflight_test_host: --group live selection fires every target's probe"
else
    fail "preflight_test_host: --group live selection skipped probe(s):${missing_probes}; got: $out"
fi

echo ""
echo "=== Drift guard self-test (negative case) ==="

# Drive the REAL guard loop (report_*), not just the detection helper, against a
# synthetic input containing a target absent from every group. This exercises
# the full loop→fail() wiring the guard relies on, so a regression that breaks
# it (a dropped `fail`, a deleted loop) also fails here instead of leaving the
# guard silently disabled. Run in $(...) so the synthetic fail() increments the
# subshell's FAIL, not the real counter; assert on the captured output.
phantom_dispatch_output="$(report_ungrouped_dispatch_targets "${DISPATCH_TARGETS[@]}" "phantom-target" 2>&1)"
if printf '%s\n' "$phantom_dispatch_output" | grep -q "phantom-target"; then
    pass "Drift guard loop fails on ungrouped dispatch target (phantom-target)"
else
    fail "Drift guard loop did NOT fail on ungrouped dispatch target"
fi

# Direction (a): same, for a group member with no dispatch entry.
phantom_member_output="$(report_undispatched_group_members "${OFFLINE_TARGETS[@]}" "phantom-group-member" 2>&1)"
if printf '%s\n' "$phantom_member_output" | grep -q "phantom-group-member"; then
    pass "Drift guard loop fails on group member without a dispatch entry (phantom-group-member)"
else
    fail "Drift guard loop did NOT fail on group member without a dispatch entry"
fi

echo ""
echo "=== Target group construction ==="

# --group all must resolve to a duplicate-free list. Drive the REAL runner via
# --dry-run (not a local reconstruction) so this guards the production all)
# path. With TARGETS_SETUP empty the runner does not dedup, so an accidental
# repeated entry within OFFLINE_TARGETS/LIVE_TARGETS would surface here — the
# one duplicate case the disjoint-groups and behavioral-all checks cannot see.
tmpconfig_all=$(new_tmp)
echo "TARGETS_SETUP=" > "$tmpconfig_all"
all=$(env CONFIG_FILE="$tmpconfig_all" bash -c "source '$RUNNER' --group all --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
dup_count=$(echo "$all" | tr ',' '\n' | sort | uniq -d | wc -l | tr -d ' ')
if [[ -z "$all" ]]; then
    fail "--group all: runner produced no target list (empty output)"
elif [[ "$dup_count" -eq 0 ]]; then
    pass "--group all: no duplicates"
else
    fail "--group all: found $dup_count duplicate(s)"
fi

# TARGETS_SETUP merge deduplicates correctly (behavioral via --dry-run).
tmpconfig_setup=$(new_tmp)
echo "TARGETS_SETUP=grpc-server,rest-api" > "$tmpconfig_setup"
setup_output=$(env CONFIG_FILE="$tmpconfig_setup" bash -c "source '$RUNNER' --group all --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true

grpc_count=$( { echo "$setup_output" | tr ',' '\n' | grep -cx 'grpc-server' || true; } )
if [[ "$grpc_count" -eq 1 ]]; then
    pass "TARGETS_SETUP merge: grpc-server appears exactly once"
else
    fail "TARGETS_SETUP merge: grpc-server count=$grpc_count, expected 1"
fi

rest_count=$( { echo "$setup_output" | tr ',' '\n' | grep -cx 'rest-api' || true; } )
if [[ "$rest_count" -eq 1 ]]; then
    pass "TARGETS_SETUP merge: rest-api deduplicated (appears once)"
else
    fail "TARGETS_SETUP merge: rest-api count=$rest_count, expected 1"
fi

# Order matters (AC#3): TARGETS_SETUP is prepended and dedup keeps the first
# occurrence, so the resolved list must START with the setup targets in order.
# Counts alone would miss an append-instead-of-prepend or keep-last regression.
if [[ "$setup_output" == "grpc-server,rest-api,"* ]]; then
    pass "TARGETS_SETUP merge: setup targets prepended in order"
else
    fail "TARGETS_SETUP merge: expected leading 'grpc-server,rest-api,', got '$setup_output'"
fi

# --group all is ADDITIVE, never restrictive: a subset-looking TARGETS_SETUP
# (e.g. a single service) must NOT narrow the resolved live set — every
# LIVE_TARGETS member is still present. Pins the LAB-4773 decision that subset
# selection is done via --targets, not TARGETS_SETUP.
tmpconfig_subset=$(new_tmp)
echo "TARGETS_SETUP=rest-api" > "$tmpconfig_subset"
subset_output=$(env CONFIG_FILE="$tmpconfig_subset" bash -c "source '$RUNNER' --group all --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
missing_live=""
for t in "${LIVE_TARGETS[@]}"; do
    printf '%s\n' "$subset_output" | tr ',' '\n' | grep -qx "$t" || missing_live="$missing_live $t"
done
if [[ -z "$missing_live" ]]; then
    pass "--group all: TARGETS_SETUP is additive (subset value does not drop live targets)"
else
    fail "--group all: subset TARGETS_SETUP dropped live target(s):$missing_live"
fi

# TARGETS_SETUP applies ONLY to the "all" group. --group offline / --group live
# must ignore it entirely.
#
# TARGETS_SETUP is passed in the ENVIRONMENT, not via CONFIG_FILE. Two reasons,
# both of which made the previous form of this check unable to fail:
#   1. --group offline/live --dry-run deliberately does not call load_config
#      (see the runner's load_config guard), so a TARGETS_SETUP written to a
#      config file is never set on this path and resolve_targets is handed an
#      empty value no matter what it does with it.
#   2. The probe value was grpc-server, which is now itself a member of
#      LIVE_TARGETS (LAB-5549) — so even had it been set, a leak into
#      --group live would have been indistinguishable from correct output.
# Setting it in the environment reaches the same global that load_config's
# `declare -g` would, and a sentinel in neither group keeps both halves
# discriminating. Verified by mutation: adding the "all" arm's TARGETS_SETUP
# prepend to the live arm fails this assertion.
#
# CONFIG_FILE is ALSO pinned to an empty fixture, so the sentinel survives
# whether or not load_config runs on this path. Reason 1 above is a property of
# the runner (--dry-run returns before the `targets_need_config` → load_config
# call), not of this test, and nothing here asserts it. Left unpinned, the day
# that gating changes load_config's `declare -g TARGETS_SETUP` would overwrite
# the sentinel from whatever real .live-test-config happens to exist on the
# machine — in CI, one naming rest-api,soap-service,graphql-server,grpc-server,
# every one of them a group member — the comparison would pass for the wrong
# reason, and this assertion would be unable to fail again. Every sibling config
# assertion in this file pins CONFIG_FILE to a new_tmp fixture for the same
# reason (see the --group all subset check above).
scoped_cfg=$(new_tmp)
: > "$scoped_cfg"
scoped_offline=$(env CONFIG_FILE="$scoped_cfg" TARGETS_SETUP=phantom-setup-target bash -c "source '$RUNNER' --group offline --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
scoped_live=$(env CONFIG_FILE="$scoped_cfg" TARGETS_SETUP=phantom-setup-target bash -c "source '$RUNNER' --group live --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
if [[ "$scoped_offline" == "$(join_targets "${OFFLINE_TARGETS[@]}")" && "$scoped_live" == "$(join_targets "${LIVE_TARGETS[@]}")" ]]; then
    pass "TARGETS_SETUP ignored for --group offline/live (sentinel absent from both)"
else
    fail "TARGETS_SETUP leaked into --group offline/live: offline='$scoped_offline' live='$scoped_live'"
fi

echo ""
echo "=== join_targets helper ==="

arr=(a b c)
result="$(join_targets "${arr[@]}")"
if [[ "$result" == "a,b,c" ]]; then
    pass "join_targets: 'a,b,c'"
else
    fail "join_targets: expected 'a,b,c', got '$result'"
fi

result="$(join_targets "only")"
if [[ "$result" == "only" ]]; then
    pass "join_targets single: 'only'"
else
    fail "join_targets single: expected 'only', got '$result'"
fi

echo ""
echo "=== Argument validation ==="

# Invalid --group value exits non-zero with the expected error message.
tmpconfig=$(new_tmp)
echo "TARGETS_SETUP=" > "$tmpconfig"
invalid_output=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group bogus" 2>&1) && rc=0 || rc=$?
if [[ "$invalid_output" == *"Unknown group"* && "$invalid_output" == *"Usage:"* && "$rc" -ne 0 ]]; then
    pass "Invalid --group: rejected non-zero with 'Unknown group' message"
else
    fail "Invalid --group: expected non-zero exit + 'Unknown group' (rc=$rc), got: $invalid_output"
fi

# --group without a value exits non-zero with the expected error message.
tmpconfig=$(new_tmp)
echo "TARGETS_SETUP=" > "$tmpconfig"
novalue_output=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group" 2>&1) && rc=0 || rc=$?
if [[ "$novalue_output" == *"--group requires a value"* && "$rc" -ne 0 ]]; then
    pass "--group (no value): rejected non-zero with '--group requires a value'"
else
    fail "--group (no value): expected non-zero exit + '--group requires a value' (rc=$rc), got: $novalue_output"
fi

# --targets without a value exits non-zero with the expected error message.
tmpconfig=$(new_tmp)
echo "TARGETS_SETUP=" > "$tmpconfig"
novalue_output=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --targets" 2>&1) && rc=0 || rc=$?
if [[ "$novalue_output" == *"--targets requires a value"* && "$rc" -ne 0 ]]; then
    pass "--targets (no value): rejected non-zero with '--targets requires a value'"
else
    fail "--targets (no value): expected non-zero exit + '--targets requires a value' (rc=$rc), got: $novalue_output"
fi

echo ""
echo "=== Behavioral --group resolution (via --dry-run) ==="

# These tests invoke the runner with --dry-run to verify the actual
# group-resolution code path without requiring a binary or running tests.

tmpconfig=$(new_tmp)
echo "TARGETS_SETUP=" > "$tmpconfig"

# --group offline resolves to exactly OFFLINE_TARGETS.
expected_offline="$(join_targets "${OFFLINE_TARGETS[@]}")"
actual_offline=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
if [[ "$actual_offline" == "$expected_offline" ]]; then
    pass "--group offline resolves to OFFLINE_TARGETS (${#OFFLINE_TARGETS[@]} targets)"
else
    fail "--group offline: expected '$expected_offline', got '$actual_offline'"
fi

# --group live resolves to exactly LIVE_TARGETS.
expected_live="$(join_targets "${LIVE_TARGETS[@]}")"
actual_live=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group live --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
if [[ "$actual_live" == "$expected_live" ]]; then
    pass "--group live resolves to LIVE_TARGETS (${#LIVE_TARGETS[@]} targets)"
else
    fail "--group live: expected '$expected_live', got '$actual_live'"
fi

# --group all (default) resolves to OFFLINE + LIVE.
expected_all="$(join_targets "${OFFLINE_TARGETS[@]}"),$(join_targets "${LIVE_TARGETS[@]}")"
actual_all=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
if [[ "$actual_all" == "$expected_all" ]]; then
    pass "--group all resolves to OFFLINE + LIVE ($(echo "$expected_all" | tr ',' '\n' | wc -l | tr -d ' ') targets)"
else
    fail "--group all: expected '$expected_all', got '$actual_all'"
fi

# --targets overrides --group.
actual_override=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --targets rest-api --group offline --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
if [[ "$actual_override" == "rest-api" ]]; then
    pass "--targets overrides --group: resolved to 'rest-api' only"
else
    fail "--targets overrides --group: expected 'rest-api', got '$actual_override'"
fi


echo ""
echo "=== --dry-run needs no config for offline/live/--targets ==="

# offline/live resolution reads only OFFLINE_TARGETS/LIVE_TARGETS — never the
# config — so --dry-run for those groups (and for an explicit --targets list)
# must succeed on a fresh checkout with no .live-test-config. Point CONFIG_FILE
# at a path that does not exist to prove the runner does not require it.
noconfig="$SCRIPT_DIR/.nonexistent-live-test-config.$$"
rm -f "$noconfig" 2>/dev/null || true

nc_offline=$(env CONFIG_FILE="$noconfig" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) && nc_rc=0 || nc_rc=$?
nc_offline_targets=$(printf '%s\n' "$nc_offline" | sed -n 's/^targets=//p')
if [[ "$nc_rc" -eq 0 && "$nc_offline_targets" == "$(join_targets "${OFFLINE_TARGETS[@]}")" ]]; then
    pass "--group offline --dry-run: succeeds without a config file"
else
    fail "--group offline --dry-run (no config): rc=$nc_rc, targets='$nc_offline_targets'"
fi

nc_live=$(env CONFIG_FILE="$noconfig" bash -c "source '$RUNNER' --group live --dry-run" 2>&1) && nc_rc=0 || nc_rc=$?
nc_live_targets=$(printf '%s\n' "$nc_live" | sed -n 's/^targets=//p')
if [[ "$nc_rc" -eq 0 && "$nc_live_targets" == "$(join_targets "${LIVE_TARGETS[@]}")" ]]; then
    pass "--group live --dry-run: succeeds without a config file"
else
    fail "--group live --dry-run (no config): rc=$nc_rc, targets='$nc_live_targets'"
fi

nc_explicit=$(env CONFIG_FILE="$noconfig" bash -c "source '$RUNNER' --targets rest-api --dry-run" 2>&1) && nc_rc=0 || nc_rc=$?
nc_explicit_targets=$(printf '%s\n' "$nc_explicit" | sed -n 's/^targets=//p')
if [[ "$nc_rc" -eq 0 && "$nc_explicit_targets" == "rest-api" ]]; then
    pass "--targets --dry-run: succeeds without a config file"
else
    fail "--targets --dry-run (no config): rc=$nc_rc, targets='$nc_explicit_targets'"
fi

# The default 'all' group folds in config-driven TARGETS_SETUP, so it still
# requires a config even under --dry-run. Pin that this remains intentional.
nc_all=$(env CONFIG_FILE="$noconfig" bash -c "source '$RUNNER' --group all --dry-run" 2>&1) && nc_rc=0 || nc_rc=$?
if [[ "$nc_rc" -ne 0 && "$nc_all" == *"Config file not found"* ]]; then
    pass "--group all --dry-run: still requires config (TARGETS_SETUP is config-driven)"
else
    fail "--group all --dry-run (no config): expected non-zero + 'Config file not found', rc=$nc_rc"
fi

echo ""
echo "=== A REAL offline run needs no config (LAB-5064) ==="

# The block above only covers --dry-run. LAB-5064 is about the REAL run: on a
# browserless host setup-live-targets.sh used to exit at the Chrome preflight
# before writing .live-test-config, which took the service-free offline group
# down with it even though it needs no ports at all. Guard both halves of the
# fix — the predicate, and the runner actually honouring it.

source <(sed -n '/^targets_need_config()/,/^}/p' "$RUNNER")

# Fidelity sentinel, matching the one guarding the run_tests_guidance
# extraction above. Without it a broken/empty sed range leaves
# targets_need_config UNDEFINED and every call returns 127 — which the
# inverted-polarity offline row below reads as success, so it passes
# VACUOUSLY while the remaining rows fail confusingly. Verified by sabotaging
# the range. Assert the function exists before asserting what it does.
if declare -F targets_need_config >/dev/null; then
    pass "targets_need_config sourced from run-live-tests.sh"
else
    fail "targets_need_config was not sourced (extraction broken/empty)"
fi

if targets_need_config "$(join_targets "${OFFLINE_TARGETS[@]}")"; then
    fail "targets_need_config: offline group wrongly reported as needing config"
else
    pass "targets_need_config: offline group needs no config"
fi

if targets_need_config "import-burp,rest-api"; then
    pass "targets_need_config: a mixed list needs config (live member present)"
else
    fail "targets_need_config: mixed list wrongly reported as config-free"
fi

if targets_need_config "$(join_targets "${LIVE_TARGETS[@]}")"; then
    pass "targets_need_config: live group needs config"
else
    fail "targets_need_config: live group wrongly reported as config-free"
fi

# An unrecognised target must FAIL CLOSED — treated as needing config, so a typo
# surfaces as a missing-config error instead of silently running against
# hardcoded default ports.
if targets_need_config "totally-unknown-target"; then
    pass "targets_need_config: unknown target fails closed (needs config)"
else
    fail "targets_need_config: unknown target wrongly reported as config-free"
fi

# A comma-split that word-split an UNQUOTED expansion would also GLOB, so a
# list containing * would expand against the cwd before comparison. Run from a
# directory holding a file named after a real offline target: if the split
# globs, "*" becomes "import-burp" and this wrongly reports config-free.
globdir="$TMPDIR_T/globdir"
mkdir -p "$globdir" && : > "$globdir/import-burp"
if (cd "$globdir" && targets_need_config "*"); then
    pass "targets_need_config: a glob is not expanded (stays unknown, fails closed)"
else
    fail "targets_need_config: '*' was glob-expanded against the cwd"
fi

# Every case above drives the predicate with a WHOLE group list
# (join_targets of a real array) or a target that shares no characters with any
# real one ("totally-unknown-target"). None feeds a bare SUBSTRING of a real
# offline target name, so replacing the whole-word match
# (`case " ${OFFLINE_TARGETS[*]} " in *" ${target} "*)`) with an unbounded
# substring match (dropping the space delimiters) would still classify every
# case above identically — and "import" IS a literal substring of
# "import-burp" et al., so a substring match would wrongly call it offline.
# Verified by mutation: dropping the bounding spaces on both sides of the case
# pattern left this suite at 117/0, exit 0.
if targets_need_config "import"; then
    pass "targets_need_config: 'import' (substring of import-burp/-har/...) is NOT treated as a match — fails closed"
else
    fail "targets_need_config: 'import' was matched as if it were a real target — whole-word anchoring lost (substring match regressed)"
fi

# The case pattern's `" ${target} "` is deliberately quoted so a
# glob-metacharacter-bearing target value is matched LITERALLY rather than as
# a wildcard (see the function's own comment on the here-string vs IFS split).
# That quoting is untested: a target that is a real offline target name with a
# trailing '*' appended is not itself a member of OFFLINE_TARGETS, so it must
# still fail closed — UNLESS the quoting around ${target} in the case pattern
# is dropped, in which case the '*' becomes an active wildcard and the pattern
# matches "generate-rest" (a real member) through it. Verified by mutation:
# removing the quotes around ${target} in the case pattern left this suite at
# 117/0, exit 0 (this specific assertion flipped from PASS to FAIL).
if targets_need_config "generate-rest*"; then
    pass "targets_need_config: 'generate-rest*' (glob-bearing, not a real target) fails closed — target is matched literally, not as a wildcard"
else
    fail "targets_need_config: 'generate-rest*' was wrongly treated as config-free — a glob character in the target value acted as a wildcard"
fi

# Behavioral: a real (non-dry-run) offline selection must get PAST config
# loading. Asserted as the absence of the config error rather than a specific
# exit code, because how far the run then gets legitimately differs by
# environment — in CI this guard runs before setup-go, so it stops at the
# missing vespasian binary; locally the binary exists and the importer test
# actually runs. Either way, reaching that point proves no config was demanded.
# One tiny importer target keeps it fast in both.
#
# RESULTS_DIR is redirected into the throwaway temp dir: locally this really
# does execute an importer, and without the override it would write into the
# repo's test/.results/ — a side effect this file's header disclaims ("Does NOT
# run actual live tests").
# VESPASIAN is pinned to a path that cannot exist so this always lands on the
# binary-absent arm. Without the pin the assertion below covered the binary check
# in CI and the target dispatch locally — two different code paths behind one
# green result, and neither environment tested what the other did.
#
# Record whether the repo's own test/.results pre-exists BEFORE either real-run
# block below, so the isolation assertion after them cannot be confused by a
# leftover from an unrelated prior run (e.g. a developer's `make test`).
results_dir_pre_existing=false
[[ -e "$SCRIPT_DIR/.results" ]] && results_dir_pre_existing=true

real_offline=$(env CONFIG_FILE="$noconfig" RESULTS_DIR="$TMPDIR_T/results" \
    VESPASIAN="$TMPDIR_T/no-such-vespasian-binary" \
    bash -c "source '$RUNNER' --targets import-empty --no-build" 2>&1) || true
if [[ "$real_offline" == *"Config file not found"* ]]; then
    fail "real offline run demanded a config: $(printf '%s' "$real_offline" | head -3)"
else
    pass "real offline run (--targets import-empty) proceeds without a config file"
fi

# The check above is negative-only, so ANY unrelated early failure would satisfy
# it. Pair it with a positive marker proving the run actually got as far as the
# post-config stage. With VESPASIAN pinned absent, that marker is the binary
# check — deterministically, in every environment.
#
# The message must name the EXACT overridden path, not merely contain "vespasian
# binary not found". A substring-only match is satisfied just as well
# by the default ${PROJECT_ROOT}/bin/vespasian path, which is what a broken
# VESPASIAN="${VESPASIAN:-...}" indirection (dropped back to a plain assignment
# that ignores the env override) would report instead — in CI (no build) that
# message differs only in the path, so only pinning the exact path proves the
# override, rather than ambient binary absence, is what produced this failure.
if [[ "$real_offline" == *"vespasian binary not found at $TMPDIR_T/no-such-vespasian-binary"* ]]; then
    pass "real offline run reached the post-config stage; VESPASIAN override honoured (exact overridden path in failure message)"
else
    fail "real offline run failed before reaching post-config, or the VESPASIAN override was not honoured: $(printf '%s' "$real_offline" | head -3)"
fi

# The mirror image of the two assertions above, and the one that gives them
# teeth. Everything so far proves an OFFLINE target does not demand a config;
# nothing proved a LIVE target still does. Deleting the conditional load_config
# call site entirely therefore left all of these green — the guard was
# unpinned in the one direction that matters, because a runner that never loads
# config passes every "no config demanded" assertion by construction.
live_needs_config=$(env CONFIG_FILE="$noconfig" RESULTS_DIR="$TMPDIR_T/results" \
    VESPASIAN="$TMPDIR_T/no-such-vespasian-binary" \
    bash -c "source '$RUNNER' --targets rest-api --no-build" 2>&1) || true
if [[ "$live_needs_config" == *"Config file not found"* ]]; then
    pass "live target still demands a config file (load_config call site is wired)"
else
    fail "live target did NOT demand a config — the conditional load_config call site is gone: $(printf '%s' "$live_needs_config" | head -3)"
fi
# Negative companion: it must fail AT the config check, not sail past it to the
# binary check. Otherwise a runner that loads config too late would still pass.
if [[ "$live_needs_config" == *"vespasian binary not found"* ]]; then
    fail "live target reached the binary check despite a missing config — config is loaded too late"
else
    pass "live target stops at the config check, before the binary check"
fi

# The header claims RESULTS_DIR "is redirected into a temp dir so nothing is
# written into the repo." Nothing above pins that: both real-run blocks pass
# RESULTS_DIR="$TMPDIR_T/results" as an env override, but if run-live-tests.sh
# ever reverted its RESULTS_DIR="${RESULTS_DIR:-...}" indirection back to a
# plain assignment, the override would be silently discarded and the
# real_offline block (which reaches `mkdir -p "$RESULTS_DIR"` before the
# binary-absent exit) would create test/.results inside this repo checkout —
# invisible to `git status` because test/.results is gitignored.
# This check used to be one-shot, and it disabled itself in exactly
# the state where the regression is present. The first arm emitted a bare `echo`
# — neither pass nor fail — so it silently REMOVED itself from the count instead
# of reporting anything. Measured sequence: on a clean tree the check passes
# (110/0); applying the exact regression it guards correctly fails (109 passed,
# 1 failed); but that failing run CREATES test/.results, nothing removes it (the
# EXIT trap clears only $TMPDIR_T), so every later run takes the silent arm and
# reports "109 passed, 0 failed" with the regression still in place. The only
# surviving signal was the accounting sentinel's "A case was added or removed
# without updating EXPECTED_ASSERTIONS", which blames test maintenance for a
# live production regression and whose obvious remedy — bumping the pin to 109 —
# deletes the coverage permanently. test/.results is gitignored, so nothing cues
# a developer to remove it.
#
# Two changes make it repeatable: every arm now emits a COUNTED outcome, and the
# failing arm removes the directory the real-run block just created so the next
# run measures the code rather than the debris. The pre-existing arm is a
# credited skip, not a silent echo, so the accounting stays exact either way.
if $results_dir_pre_existing; then
    skip "RESULTS_DIR isolation check: $SCRIPT_DIR/.results pre-existed before this run (not created by it)" 1
elif [[ -e "$SCRIPT_DIR/.results" ]]; then
    fail "RESULTS_DIR override was not honoured — test/.results was created in the repo checkout by the real-run block"
    # Created by THIS suite's real-run block, so removing it is safe and is what
    # keeps the check from being permanently disabled on this checkout.
    rm -rf "$SCRIPT_DIR/.results"
else
    pass "RESULTS_DIR override honoured — no test/.results written into the repo checkout by the real-run block"
fi

# ── Unknown-flag rejection ──────────────────────────────────────
#
# run-live-tests.sh's parse loop has a catch-all that names the offending option,
# prints usage and exits 1 — and NO suite asserted it. Replacing the catch-all
# with `*) shift ;;` left this suite at 110/0, rc 0: a typo'd flag would then be
# silently ignored and the run would proceed with the WRONG target selection
# while reporting success, which for `--group offline` vs `--group live` is the
# difference between running the browser tests and not.
#
# Both sibling suites already pin this for their own script
# (install-chrome-selftest case b, setup-live-targets_test Test 14 (parse_args
# unknown option)), so this was
# the one un-pinned parser of the three. Driven behaviourally against the real
# script rather than by grepping its source: the flag reaches a real parse loop
# and the process really exits, so there is no source-vs-behaviour gap to hide in.
# The exit code is asserted TOGETHER with the diagnostic, not separately. Measured
# while building this check: replacing the catch-all with `*) shift ;;` still gave
# rc 1, because the run then proceeded and died later for an unrelated reason (no
# vespasian binary). A standalone `rc == 1` assertion therefore passes for the
# wrong reason under the very mutation it exists to catch. The conjunction cannot:
# only the real catch-all produces rc 1 AND names the flag.
unknown_out=$(bash "$RUNNER" --not-a-real-flag 2>&1) && unknown_rc=0 || unknown_rc=$?
unknown_named=false
case "$unknown_out" in
    *"Unknown option: --not-a-real-flag"*) unknown_named=true ;;
esac
if [[ "$unknown_rc" -eq 1 ]] && $unknown_named; then
    pass "run-live-tests.sh rejects an unknown flag: exit 1 AND names the offending option"
else
    fail "run-live-tests.sh did not reject an unknown flag (rc $unknown_rc, named=$unknown_named) — a typo'd flag is silently ignored and the run proceeds with the wrong target selection"
fi
# ── The ambient-VESPASIAN override notice ──────────────────────────────────
#
# run-live-tests.sh honours a VESPASIAN already present in the environment and
# warns that every crawl/generate in the run will use THAT binary rather than
# the one under ${PROJECT_ROOT}/bin. None of the three pieces — the capture, the
# guard, or the message — had any assertion in any suite: deleting all three
# left every suite green, and a run under an ambient override then reported
# results for an arbitrary binary with nothing in the output saying so, which is
# what makes a green live-test run unfalsifiable.
#
# Driven through the same invocation as the unknown-flag check above. The notice
# is emitted immediately after common.sh is sourced, which is BEFORE the parse
# loop rejects the flag, so one extra run with VESPASIAN set captures it without
# needing a working binary or any live target.
override_path=/tmp/vespasian-ambient-override-probe
override_out=$(VESPASIAN="$override_path" bash "$RUNNER" --not-a-real-flag 2>&1 || true)
case "$override_out" in
    *"VESPASIAN was set in the environment"*)
        pass "run-live-tests.sh announces an ambient VESPASIAN override" ;;
    *)  fail "run-live-tests.sh did not announce an ambient VESPASIAN override — the run silently uses a binary the operator did not build, and the output says nothing about it" ;;
esac
# The PATH, not just the fact. A notice that says an override is in effect
# without naming it leaves the operator unable to tell which binary produced
# the results, which is the only actionable part of the warning.
case "$override_out" in
    *"$override_path"*)
        pass "the override notice names the overriding path, so the operator can see which binary ran" ;;
    *)  fail "the override notice does not name the overriding path — it reports that SOME override is active without saying which binary the results came from" ;;
esac
# And the negative: absent from the run WITHOUT the override. The unknown-flag
# capture above is that run, so this needs no third invocation. Without this,
# an unconditional notice — the guard at :184 deleted, the message left behind —
# satisfies both assertions above while telling every normal run it is using a
# binary it is not.
case "$unknown_out" in
    *"VESPASIAN was set in the environment"*)
        fail "the override notice fired on a run with no ambient VESPASIAN — it is unconditional, so it now misreports every normal run" ;;
    *)  pass "the override notice stays silent when VESPASIAN is not set in the environment" ;;
esac

# Matched without a leading path: usage() prints "Usage: $0", so the text varies
# with how the script was invoked (relative here, absolute via $RUNNER). Anchoring
# on the basename plus "[options]" is invocation-independent.
case "$unknown_out" in
    *"run-live-tests.sh [options]"*)
        pass "run-live-tests.sh prints usage when rejecting an unknown flag" ;;
    *)
        fail "run-live-tests.sh no longer prints usage when rejecting an unknown flag" ;;
esac

echo ""
echo "=== Browser probe shared with common.sh ==="
# chrome_available gates the rod-backed targets. It must use the SHARED
# detect_chrome_binary probe from common.sh, which actually runs the candidate,
# not a bare `command -v`: on a stock devcontainer /usr/bin/chromium-browser is a
# snap launcher stub that resolves fine and then fails at launch, so a
# presence-only probe attempted the crawl and failed inside it instead of
# skipping with a reason. Sharing the probe is also what keeps the runner, the
# setup preflight and install-chrome.sh from disagreeing about whether this host
# has a usable browser.
#
# This is a DRIFT guard, in the same spirit as the target-group check above.
# Both greps below are structural: they are satisfied by a body that calls
# detect_chrome_binary and throws the answer away, e.g.
# `detect_chrome_binary >/dev/null 2>&1; return 0`. Make the RESULT
# load-bearing by extracting chrome_available the same way targets_need_config
# is above — a sed range over the source, not the whole runner (which calls
# `main "$@"` unguarded) — and driving it against a fixture CHROME_CANDIDATES.
chrome_avail_body=$(awk '/^chrome_available\(\) \{/,/^\}/' "$RUNNER")
# Strip comment lines before grepping, the same way the workflow
# step-list guards below strip them. Grepping the raw body was a false
# certification: re-implementing the probe inline and leaving
# "previously delegated to detect_chrome_binary" in a comment kept this printing
# "chrome_available delegates to …" while the delegation was gone. Mutation-proven
# — the inline re-implementation left the suite at 112/0, exit 0, and the three
# BEHAVIOURAL polarity checks below passed too, because an inline copy reproduces
# the shared probe's behaviour on these fixtures while no longer BEING it. That is
# what makes the comment strip load-bearing rather than cosmetic: behaviour alone
# cannot distinguish delegation from duplication.
chrome_avail_code=$(printf '%s\n' "$chrome_avail_body" | grep -vE '^[[:space:]]*#')
if printf '%s' "$chrome_avail_code" | grep -q 'detect_chrome_binary'; then
    pass "chrome_available delegates to common.sh's detect_chrome_binary"
else
    fail "chrome_available no longer uses detect_chrome_binary — the runner's browser probe has drifted from the shared one"
fi
# Broadened past `command -v`: `type -P` and `which` resolve a name exactly the
# same way, so pinning one spelling let the other reintroduce the presence-only
# probe this check exists to refuse.
if printf '%s' "$chrome_avail_code" | grep -qE '(command -v|type -P|which)[[:space:]]+.*(google-chrome|chromium|chromium-browser)'; then
    fail "chrome_available reintroduced a presence-only probe (command -v/type -P/which — snap stubs pass it)"
else
    pass "chrome_available carries no presence-only browser check"
fi
# And that it still resolves candidates from the SHARED list rather than a local
# one. An inline loop over its own hardcoded names is drift even when it delegates
# the runnability probe, because the two scripts then disagree about WHICH
# browsers to consider.
if printf '%s' "$chrome_avail_code" | grep -qE 'CHROME_CANDIDATES'; then
    fail "chrome_available iterates CHROME_CANDIDATES itself — resolution belongs to detect_chrome_binary, not the runner"
else
    pass "chrome_available does not re-implement candidate resolution"
fi
# POSITION, not just presence. All three pins above are per-line, and each of
# them is evaded by the same mutation: a presence-only FAST PATH spread across
# more than one line, ahead of the delegation.
#
#     chrome_available() {
#         for b in google-chrome chromium chromium-browser; do
#             command -v "$b" >/dev/null 2>&1 && return 0
#         done
#         detect_chrome_binary >/dev/null 2>&1 || [ -d "$HOME/.cache/rod/browser" ]
#     }
#
# The delegation pin passes (the call is still there). The presence-only pin
# passes: its regex needs a browser NAME on the same line as `command -v`, and
# here the names are on the `for` line while the probe reads "$b". The
# CHROME_CANDIDATES pin passes: this list is local. And the behavioural polarity
# checks below pass too, because on a host WITH a runnable browser both routes
# answer yes. What has actually happened is that a snap stub — the entire reason
# this probe is shared — now returns 0 before detect_chrome_binary is consulted.
#
# What no per-line pin can see is ORDER, so pin that instead: the FIRST
# executable statement of the body must be the detect_chrome_binary call. A fast
# path has to go somewhere, and every position that neuters the delegation is
# before it.
chrome_avail_first=$(printf '%s\n' "$chrome_avail_code" \
    | sed -e '1d' -e '/^[[:space:]]*$/d' \
    | head -1 \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
if [[ -z "$chrome_avail_first" ]]; then
    fail "could not read chrome_available's first statement — the ordering pin below would be vacuous"
elif [[ "$chrome_avail_first" == detect_chrome_binary* ]]; then
    pass "chrome_available's FIRST statement is the detect_chrome_binary call (no probe runs ahead of the shared one)"
else
    fail "chrome_available's first statement is [${chrome_avail_first}], not the detect_chrome_binary call — something answers ahead of the shared probe, and a multi-line presence-only fast path there passes all three text pins above while letting a snap stub report a usable browser"
fi

# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"
source <(sed -n '/^chrome_available() {/,/^}/p' "$RUNNER")

# Fidelity sentinel, matching the ones guarding the other function extractions
# in this file: a broken/empty sed range would leave chrome_available
# UNDEFINED, and calling it would then error under `set -e` rather than
# silently misreport — but assert presence explicitly so that failure mode is
# named instead of a confusing abort deeper in the behavioral checks below.
if declare -F chrome_available >/dev/null; then
    pass "chrome_available sourced from run-live-tests.sh"
else
    fail "chrome_available was not sourced (extraction broken/empty)"
fi

chrome_fixture_dir="$TMPDIR_T/chrome-fixture"
mkdir -p "$chrome_fixture_dir/bin" "$chrome_fixture_dir/home"

# A working "browser": prints a version string and exits 0 (mirrors
# preflight-selftest.sh's fixture).
chrome_working_browser="$chrome_fixture_dir/bin/google-chrome"
cat > "$chrome_working_browser" <<'EOF'
#!/bin/bash
echo "Fake Chrome 999.0.0.0"
exit 0
EOF
chmod +x "$chrome_working_browser"

# A present-but-not-runnable "browser": the LAB-3893 snap-stub failure mode.
chrome_broken_browser="$chrome_fixture_dir/bin/broken-chrome"
cat > "$chrome_broken_browser" <<'EOF'
#!/bin/bash
echo "broken-chrome: not runnable" >&2
exit 127
EOF
chmod +x "$chrome_broken_browser"

# Positive polarity: a working candidate reports available.
if (
    CHROME_CANDIDATES=("$chrome_working_browser")
    HOME="$chrome_fixture_dir/home"
    chrome_available
); then
    pass "chrome_available: reports available with a runnable candidate"
else
    fail "chrome_available: expected available (rc 0) with a runnable candidate"
fi

# Negative polarity — the one a `detect_chrome_binary >/dev/null 2>&1; return 0`
# mutation defeats: only a non-runnable candidate, and HOME pointed at a
# directory with no .cache/rod/browser fallback.
if (
    CHROME_CANDIDATES=("$chrome_broken_browser")
    HOME="$chrome_fixture_dir/home"
    chrome_available
); then
    fail "chrome_available: expected unavailable (rc 1) with only a non-runnable candidate and no rod cache"
else
    pass "chrome_available: reports unavailable with only a non-runnable candidate and no rod cache"
fi

# The rod-cache FALLBACK arm. The two polarities above both leave
# $HOME without a rod cache, so the `|| [ -d "$HOME/.cache/rod/browser" ]` half
# of chrome_available was never the deciding term: deleting it entirely kept
# this suite green. That arm is what lets a host whose only browser is one
# go-rod downloaded itself — not on PATH, so invisible to CHROME_CANDIDATES —
# still run the rod-backed targets instead of skipping them, which is the
# difference between AC3 executing and AC3 quietly SKIPping.
mkdir -p "$chrome_fixture_dir/home-rod/.cache/rod/browser"
if (
    CHROME_CANDIDATES=("$chrome_broken_browser")
    HOME="$chrome_fixture_dir/home-rod"
    chrome_available
); then
    pass "chrome_available: a rod-downloaded browser counts as available even with no runnable candidate"
else
    fail "chrome_available: expected available (rc 0) via the rod-cache fallback with a rod cache present"
fi

echo ""
echo "=== print_summary: RESULTS_DIR is data, not format ==="
# This PR converts print_summary's RESULTS_DIR line from `echo -e` to
# `printf '%s'`, with an explicit rationale: RESULTS_DIR is env-overridable, so
# it is data, not format, and must not have backslash escapes interpreted.
# Nothing exercised print_summary at all before this. common.sh is already
# sourced above (chrome_available block); extract print_summary the same way
# targets_need_config/load_config are extracted.
source <(sed -n '/^print_summary() {/,/^}/p' "$RUNNER")

if declare -F print_summary >/dev/null; then
    pass "print_summary sourced from run-live-tests.sh"
else
    fail "print_summary was not sourced (extraction broken/empty)"
fi

# Empty TEST_STATUS (and friends) so the per-target loop body never runs —
# only the Total/Results lines under test are exercised. These associative
# arrays are declared globally in run-live-tests.sh; declare fresh ones here
# since only print_summary's body, not the whole file, was sourced.
summary_out=$(
    declare -A TEST_STATUS=() TEST_ENDPOINTS=() TEST_EXPECTED=() TEST_DURATION=()
    RESULTS_DIR='/tmp/x\e[31m'
    print_summary
) || true
if printf '%s' "$summary_out" | grep -qF '\e[31m'; then
    pass "print_summary: RESULTS_DIR backslash escape stays literal (printf %s, not echo -e)"
else
    fail "print_summary: RESULTS_DIR backslash escape was interpreted — expected literal '\\e[31m' in: $summary_out"
fi

echo ""
echo "=== print_summary: all-skipped-is-not-a-pass gate (AC3) ==="
# The block above declares EMPTY TEST_STATUS/TEST_ENDPOINTS/TEST_EXPECTED/
# TEST_DURATION arrays precisely so the per-target loop never runs — which
# also makes total_pass=0 AND total_skip=0, so the AC3 gate's own
# `total_skip -gt 0` condition is false and it is never entered. Drive
# print_summary with a POPULATED array so all three arms of the gate are
# actually exercised: an all-skipped run must fail, the documented escape
# hatch must turn that into a pass, and a legitimate partial skip (something
# else in the run actually passed) must not be caught by the gate at all.

# Arm 1: every selected target skipped, nothing else ran — must fail.
all_skip_rc=0
all_skip_out=$(
    declare -A TEST_STATUS=([rest-api]=SKIP) TEST_ENDPOINTS=([rest-api]=-) TEST_EXPECTED=([rest-api]=-) TEST_DURATION=([rest-api]=0)
    RESULTS_DIR="$TMPDIR_T/results"
    print_summary
) || all_skip_rc=$?
if [[ "$all_skip_rc" -ne 0 ]] && printf '%s' "$all_skip_out" | grep -q "nothing executed"; then
    pass "print_summary: an all-skipped run fails ('nothing executed') — AC3 gate fires"
else
    fail "print_summary: an all-skipped run did not fail as expected (rc=$all_skip_rc): $all_skip_out"
fi

# Arm 2: the documented escape hatch converts the same all-skipped input to a
# pass, and is exercised at all (it has no test anywhere else in this repo).
allow_no_exec_rc=0
allow_no_exec_out=$(
    declare -A TEST_STATUS=([rest-api]=SKIP) TEST_ENDPOINTS=([rest-api]=-) TEST_EXPECTED=([rest-api]=-) TEST_DURATION=([rest-api]=0)
    RESULTS_DIR="$TMPDIR_T/results"
    LIVE_TESTS_ALLOW_NO_EXECUTION=1
    print_summary
) || allow_no_exec_rc=$?
if [[ "$allow_no_exec_rc" -eq 0 ]]; then
    pass "print_summary: LIVE_TESTS_ALLOW_NO_EXECUTION=1 turns an all-skipped run into success"
else
    fail "print_summary: LIVE_TESTS_ALLOW_NO_EXECUTION=1 did not accept an all-skipped run (rc=$allow_no_exec_rc): $allow_no_exec_out"
fi

# Arm 3: a legitimate PARTIAL skip — something else in the same run actually
# passed — must NOT be caught by the all-skipped gate.
partial_skip_rc=0
partial_skip_out=$(
    declare -A TEST_STATUS=([a]=PASS [b]=SKIP) TEST_ENDPOINTS=([a]=1 [b]=-) TEST_EXPECTED=([a]=1 [b]=-) TEST_DURATION=([a]=0 [b]=0)
    RESULTS_DIR="$TMPDIR_T/results"
    print_summary
) || partial_skip_rc=$?
if [[ "$partial_skip_rc" -eq 0 ]]; then
    pass "print_summary: a partial skip (one PASS, one SKIP) still succeeds"
else
    fail "print_summary: a legitimate partial skip was wrongly failed by the all-skipped gate (rc=$partial_skip_rc): $partial_skip_out"
fi

echo ""
echo "=== Setup-complete guidance (setup-live-targets.sh) ==="

# Drive the REAL run_tests_guidance selector (sourced above, not a copy) for
# both arms. This is the one behavior in setup-live-targets.sh that steers a
# user away from a bare `all` run after a partial setup; nothing else exercises
# it. Assert both the presence of the correct steering AND the absence of the
# wrong arm's line, so a swapped/broken branch trips loudly.

# Fidelity sentinel: an empty/broken extraction would make every assertion below
# vacuous, so prove the function was actually sourced before trusting it.
if declare -F run_tests_guidance >/dev/null; then
    pass "run_tests_guidance sourced from setup-live-targets.sh"
else
    fail "run_tests_guidance was not sourced (extraction broken/empty)"
fi

# Full setup (targets == ALL_TARGETS): bare run, and NO --targets/--group steering.
full_guidance="$(run_tests_guidance "$ALL_TARGETS")"
if [[ "$full_guidance" == *"Run tests with: ./test/run-live-tests.sh"* ]] \
   && [[ "$full_guidance" != *"--targets"* ]] \
   && [[ "$full_guidance" != *"--group offline"* ]]; then
    pass "guidance (full setup): bare run, no --targets/--group steering"
else
    fail "guidance (full setup): expected bare run only, got: $full_guidance"
fi

# Partial setup (a subset): steer to an explicit --targets run for exactly that
# subset plus the offline hint, and do NOT print the bare-run line.
partial_guidance="$(run_tests_guidance "rest-api")"
if [[ "$partial_guidance" == *"--targets rest-api"* ]] \
   && [[ "$partial_guidance" == *"--group offline"* ]] \
   && [[ "$partial_guidance" != *"Run tests with: ./test/run-live-tests.sh"* ]]; then
    pass "guidance (partial setup): steers to --targets rest-api + offline hint, no bare run"
else
    fail "guidance (partial setup): expected --targets steering, got: $partial_guidance"
fi

echo ""
echo "=== load_config key allowlist (security hardening) ==="

# load_config must apply only allowlisted keys and skip anything else, so a
# crafted/edited config cannot rebind security-relevant globals (VESPASIAN, PATH,
# RESULTS_DIR, TEST_HOST). Drive the REAL load_config from the runner (with
# common.sh sourced for its log_* helpers) inside a subshell — its `declare -g`
# assignments stay in that subshell — and echo the resulting values to assert on.
allowlist_cfg=$(new_tmp)
printf '%s\n' "REST_API_PORT=8990" "VESPASIAN=/tmp/evil" "TARGETS_SETUP=" > "$allowlist_cfg"
allowlist_out=$(
    source "$SCRIPT_DIR/common.sh"
    source <(sed -n '/^load_config()/,/^}/p' "$RUNNER")
    # Same fidelity sentinel as the two extractions above: a broken sed range
    # would leave load_config undefined, and the assertions below — which look
    # for a *warning* in the output — would then read an empty result as "no
    # disallowed key applied" and pass without exercising the allowlist at all.
    declare -F load_config >/dev/null || echo "SENTINEL_LOAD_CONFIG_MISSING"
    VESPASIAN="__sentinel__"
    REST_API_PORT="__unset__"
    CONFIG_FILE="$allowlist_cfg"
    load_config 2>&1 || true
    echo "RESULT_VESPASIAN=$VESPASIAN"
    echo "RESULT_REST_API_PORT=$REST_API_PORT"
) || true

if printf '%s\n' "$allowlist_out" | grep -q "SENTINEL_LOAD_CONFIG_MISSING"; then
    fail "load_config was not sourced (extraction broken/empty) — assertions below are vacuous"
else
    pass "load_config sourced from run-live-tests.sh"
fi

if printf '%s\n' "$allowlist_out" | grep -q "Skipping unexpected config key: VESPASIAN"; then
    pass "load_config: disallowed key VESPASIAN skipped with warning"
else
    fail "load_config: expected 'Skipping unexpected config key: VESPASIAN', got: $allowlist_out"
fi
if printf '%s\n' "$allowlist_out" | grep -qx "RESULT_VESPASIAN=__sentinel__"; then
    pass "load_config: disallowed key VESPASIAN not applied (sentinel preserved)"
else
    fail "load_config: VESPASIAN was rebound by config (expected __sentinel__): $allowlist_out"
fi
if printf '%s\n' "$allowlist_out" | grep -qx "RESULT_REST_API_PORT=8990"; then
    pass "load_config: allowed key REST_API_PORT applied"
else
    fail "load_config: allowed key REST_API_PORT not applied (expected 8990): $allowlist_out"
fi

# Fixture parity (cross-file lockstep + per-fixture invariants for the rest-api
# fixtures) moved to test/validate_test.sh so the un-gated validator-regression
# job enforces it — `skip-live-tests` no longer disables it. This drift guard
# runs only in the label-gated `test` job, so the parity check lived behind a
# gate; the richer checks now live in the "rest-api fixture parity" section of
# validate_test.sh (LAB-5611 / PR #208 review).

echo ""
echo "=== load_config value validation ==="
# The block above only exercises the KEY half of load_config's allowlist. The
# format regex still admits '@'/':' in the VALUE, so REST_API_PORT=@evil.com
# passes both the format check and the key allowlist and, unvalidated, would
# make _probe_target_host build a URL curl parses as userinfo + an
# attacker-chosen host. Drive the real load_config against a config that
# exercises every value-validation arm: an out-of-charset port, an
# out-of-range port on both ends, an empty port (must be skipped SILENTLY —
# Since setup-live-targets.sh's write_config always emits every
# allowlisted key, so a partial setup writes empty values for targets it
# never configured), and a TARGETS_SETUP value outside its own charset.
invalid_values_cfg=$(new_tmp)
printf '%s\n' \
    "REST_API_PORT=@evil.com" \
    "SOAP_SERVICE_PORT=99999" \
    "GRAPHQL_SERVER_PORT=0" \
    "GRPC_SERVER_PORT=" \
    "TARGETS_SETUP=rest-api:evil" \
    > "$invalid_values_cfg"
invalid_values_out=$(
    source "$SCRIPT_DIR/common.sh"
    source <(sed -n '/^load_config()/,/^}/p' "$RUNNER")
    declare -F load_config >/dev/null || echo "SENTINEL_LOAD_CONFIG_MISSING"
    REST_API_PORT="__sentinel_rest__"
    SOAP_SERVICE_PORT="__sentinel_soap__"
    GRAPHQL_SERVER_PORT="__sentinel_graphql__"
    GRPC_SERVER_PORT="__sentinel_grpc__"
    TARGETS_SETUP="__sentinel_targets__"
    CONFIG_FILE="$invalid_values_cfg"
    load_config 2>&1 || true
    echo "RESULT_REST_API_PORT=$REST_API_PORT"
    echo "RESULT_SOAP_SERVICE_PORT=$SOAP_SERVICE_PORT"
    echo "RESULT_GRAPHQL_SERVER_PORT=$GRAPHQL_SERVER_PORT"
    echo "RESULT_GRPC_SERVER_PORT=$GRPC_SERVER_PORT"
    echo "RESULT_TARGETS_SETUP=$TARGETS_SETUP"
) || true

if printf '%s\n' "$invalid_values_out" | grep -q "SENTINEL_LOAD_CONFIG_MISSING"; then
    fail "load_config was not sourced (extraction broken/empty) — value-validation assertions below are vacuous"
else
    pass "load_config sourced from run-live-tests.sh (value-validation block)"
fi

if printf '%s\n' "$invalid_values_out" | grep -qF "Skipping REST_API_PORT: not a valid port (1-65535): @evil.com"; then
    pass "load_config: REST_API_PORT=@evil.com (userinfo-style value) rejected with warning"
else
    fail "load_config: expected REST_API_PORT=@evil.com to be rejected, got: $invalid_values_out"
fi
if printf '%s\n' "$invalid_values_out" | grep -qx "RESULT_REST_API_PORT=__sentinel_rest__"; then
    pass "load_config: rejected REST_API_PORT value not applied (sentinel preserved)"
else
    fail "load_config: REST_API_PORT was rebound despite an invalid value: $invalid_values_out"
fi

if printf '%s\n' "$invalid_values_out" | grep -qF "Skipping SOAP_SERVICE_PORT: not a valid port (1-65535): 99999"; then
    pass "load_config: SOAP_SERVICE_PORT=99999 (out of range, high) rejected with warning"
else
    fail "load_config: expected SOAP_SERVICE_PORT=99999 to be rejected, got: $invalid_values_out"
fi
if printf '%s\n' "$invalid_values_out" | grep -qx "RESULT_SOAP_SERVICE_PORT=__sentinel_soap__"; then
    pass "load_config: rejected SOAP_SERVICE_PORT value not applied (sentinel preserved)"
else
    fail "load_config: SOAP_SERVICE_PORT was rebound despite an out-of-range value: $invalid_values_out"
fi

if printf '%s\n' "$invalid_values_out" | grep -qF "Skipping GRAPHQL_SERVER_PORT: not a valid port (1-65535): 0"; then
    pass "load_config: GRAPHQL_SERVER_PORT=0 (out of range, low) rejected with warning"
else
    fail "load_config: expected GRAPHQL_SERVER_PORT=0 to be rejected, got: $invalid_values_out"
fi
if printf '%s\n' "$invalid_values_out" | grep -qx "RESULT_GRAPHQL_SERVER_PORT=__sentinel_graphql__"; then
    pass "load_config: rejected GRAPHQL_SERVER_PORT value not applied (sentinel preserved)"
else
    fail "load_config: GRAPHQL_SERVER_PORT was rebound despite an out-of-range value: $invalid_values_out"
fi

# An EMPTY port value is "target not set up", not tampering, so it
# must be skipped WITHOUT a warning — unlike every other reject case above.
if printf '%s\n' "$invalid_values_out" | grep -q "GRPC_SERVER_PORT"'.*not a valid port'; then
    fail "load_config: empty GRPC_SERVER_PORT logged a 'not a valid port' warning — the empty-value desensitization regressed"
else
    pass "load_config: empty GRPC_SERVER_PORT is skipped without a warning"
fi
if printf '%s\n' "$invalid_values_out" | grep -qx "RESULT_GRPC_SERVER_PORT=__sentinel_grpc__"; then
    pass "load_config: empty GRPC_SERVER_PORT value not applied (sentinel preserved)"
else
    fail "load_config: GRPC_SERVER_PORT was rebound by an empty value: $invalid_values_out"
fi

if printf '%s\n' "$invalid_values_out" | grep -qF "Skipping TARGETS_SETUP: unexpected characters in value: rest-api:evil"; then
    pass "load_config: TARGETS_SETUP=rest-api:evil (outside its charset) rejected with warning"
else
    fail "load_config: expected TARGETS_SETUP=rest-api:evil to be rejected, got: $invalid_values_out"
fi
if printf '%s\n' "$invalid_values_out" | grep -qx "RESULT_TARGETS_SETUP=__sentinel_targets__"; then
    pass "load_config: rejected TARGETS_SETUP value not applied (sentinel preserved)"
else
    fail "load_config: TARGETS_SETUP was rebound despite an invalid value: $invalid_values_out"
fi

# The accept direction for TARGETS_SETUP: a value inside its charset (letters,
# digits, comma, hyphen) must still be applied — the reject-only block above
# would also pass if the case arm rejected every value unconditionally.
valid_targets_cfg=$(new_tmp)
printf '%s\n' "TARGETS_SETUP=rest-api,soap-service" > "$valid_targets_cfg"
valid_targets_out=$(
    source "$SCRIPT_DIR/common.sh"
    source <(sed -n '/^load_config()/,/^}/p' "$RUNNER")
    # This extraction's two siblings (969-991, 1029-1051) both echo
    # SENTINEL_LOAD_CONFIG_MISSING out of their subshell and grep for it, so a
    # broken sed range is caught. This copy had neither, so a broken range
    # here would leave the accept-direction assertion below reading an empty
    # result and silently agreeing that nothing was applied.
    declare -F load_config >/dev/null || echo "SENTINEL_LOAD_CONFIG_MISSING"
    TARGETS_SETUP="__sentinel_targets__"
    CONFIG_FILE="$valid_targets_cfg"
    load_config 2>&1 || true
    echo "RESULT_TARGETS_SETUP=$TARGETS_SETUP"
) || true
if printf '%s\n' "$valid_targets_out" | grep -q "SENTINEL_LOAD_CONFIG_MISSING"; then
    fail "load_config was not sourced (extraction broken/empty) — the accept-direction assertion below is vacuous"
else
    pass "load_config sourced from run-live-tests.sh (accept-direction block)"
fi
if printf '%s\n' "$valid_targets_out" | grep -qx "RESULT_TARGETS_SETUP=rest-api,soap-service"; then
    pass "load_config: TARGETS_SETUP=rest-api,soap-service (valid charset) applied"
else
    fail "load_config: valid TARGETS_SETUP value not applied (expected rest-api,soap-service): $valid_targets_out"
fi

echo ""
echo "=== Un-gated CI job wiring (the guards must actually be invoked) ==="


# Every suite in this repo is only as good as the CI step that runs it, and
# those steps are hand-maintained in a YAML block that nothing checks. Dropping
# one is invisible: the suite still passes locally, CI still goes green, and
# coverage silently falls. The job block is extracted by name so an unrelated
# `test` job invoking the same script cannot satisfy this.
WORKFLOW="$SCRIPT_DIR/../.github/workflows/live-tests.yml"

# extract_job_block(name) prints the body of a top-level job block — the
# lines strictly between "  <name>:" and the next top-level job key. Defined
# once, here, so every job-block extraction in this file (preflight_block,
# e2e_block, test_block, and the hosting-job loop below) shares one
# implementation instead of four hand-copied ones.
#
# The end-of-block regex adds 0-9 to the character class a narrower copy
# would use ([a-zA-Z_-]+): that narrower class alone stops mid-name on
# install-chrome-e2e (the digit in "e2e" breaks the match), which would
# silently swallow the next job's content whenever the search starts at the
# job immediately before it. It also compares $0 to the job line
# EXACTLY, unlike an unanchored `/^  test:/`-style regex, which would also
# match a future two-space-indented `  test:` key that is not the job.
extract_job_block() {
    awk -v job_line="  $1:" '
        $0 == job_line { inblock=1; next }
        inblock && /^  [A-Za-z0-9_-]+:/ { inblock=0 }
        inblock { print }
    ' "$WORKFLOW"
}

# yq_query "$expr": answers a SEMANTIC question about live-tests.yml with a
# real YAML parse. A regex over source text cannot: every mutation this
# closes preserves the text while changing the meaning, or the reverse (a
# reordered step key, a paths: filter, a needs: on a sibling job).
#
# yq, not python3+PyYAML: PyYAML is NOT on the
# ubuntu-24.04 runner image, whereas yq 4.53.3 is — a single static Go
# binary, no interpreter or site-packages provenance problem. yq is also
# YAML 1.2, where `on` is a plain string key; PyYAML is YAML 1.1, where a
# bare `on:` parses as the BOOLEAN True, a live footgun for the next
# maintainer.
#
# Absence is a FAIL, never a skip: a guard that cannot run is the exact
# defect this suite exists to catch. The presence check is memoised once,
# and on absence this prints the sentinel __NO_YQ__ on stdout rather than
# calling fail() itself: every call site below reads this via command
# substitution ($(yq_query ...)), which runs in a SUBSHELL — a fail() call
# from inside it would increment a subshell-local copy of $FAIL, discarded
# when the subshell exits, silently UNDER-counting the very hard failure this
# fail-closed rule requires to be counted (the identical trap the sibling review records for
# chrome_probe_budget in the sibling suite). So each call site's own `case`
# calls fail_no_yq in the parent shell instead, keeping the counted-outcome
# total identical whether yq is present or absent.
_YQ_OK=""   # "" = not probed, 1 = usable, 0 = absent
yq_query() {
    if [[ -z "$_YQ_OK" ]]; then
        if command -v yq >/dev/null 2>&1; then _YQ_OK=1; else _YQ_OK=0; fi
    fi
    if [[ "$_YQ_OK" != 1 ]]; then printf '%s\n' '__NO_YQ__'; return 0; fi
    local expr=$1; shift
    # Distinguish a yq FAILURE from a legitimate empty/false answer. yq
    # exits non-zero with empty stdout on unparseable YAML; without this, a
    # corrupted live-tests.yml aborted the suite mid-run under `set -e` and was
    # caught only by the whole-suite completion sentinel — fail-closed, but the
    # diagnostic named the wrong defect and the run never reached its assertion
    # count, so the accounting pin could not tell a broken workflow from deleted
    # assertions. A third sentinel makes it a counted, correctly-named failure.
    local out
    if ! out=$(yq "$@" "$expr" "$WORKFLOW" 2>/dev/null); then
        printf '%s\n' '__YQ_ERROR__'
        return 0
    fi
    printf '%s\n' "$out"
}

# One wording, one place, for the parse-error arm — same reasoning as fail_no_yq.
fail_yq_error() {
    fail "$1 could not be verified: yq could not parse ${WORKFLOW} (it exits non-zero with empty output on malformed YAML). The workflow is broken, or the query no longer matches its structure — fix the workflow rather than deleting this assertion."
}

# One wording, one place, so it cannot drift across call sites.
fail_no_yq() {
    fail "$1 could not be verified: yq is required to answer this question about live-tests.yml, and a guard that cannot run is the exact defect this suite exists to catch — install it (https://github.com/mikefarah/yq). CI's ubuntu-24.04 runner already ships yq 4.53.3, so this cannot fail in CI."
}

if [[ ! -f "$WORKFLOW" ]]; then
    fail "live-tests.yml not found at $WORKFLOW"
else
    # Every script the workflow DIRECT-EXECS must be committed executable.
    #
    # install-chrome-selftest.sh was 100755 for twenty-one commits and silently
    # became 100644 at 5f45b53 ("assertions now prove, not grep"). live-tests.yml
    # runs it as `./test/install-chrome-selftest.sh`, so from that commit on every
    # CI run died with `Permission denied`, exit 126, BEFORE the suite executed a
    # single assertion — measured in run 31619662298 on head 328d21f. The `test`
    # job declares `needs: preflight-selftest`, so the live suite was skipped too.
    # The guard suite was dead in CI for three review rounds while assertions were
    # being ADDED to it, and nothing noticed: the job failed, but for a reason no
    # assertion was watching. 4a2f939 had to restore the same bit on
    # install-chrome.sh, so this has happened twice.
    #
    # The list is derived from the workflow, not hardcoded, so a newly
    # direct-exec'd script is covered the day it is added. And the derivation is
    # itself asserted non-empty: the first version of this check sat ABOVE the
    # `WORKFLOW=` assignment, so its grep read an empty path, its loop never
    # iterated, and it printed PASS with the exec bit reverted. A guard that
    # cannot fail is the exact defect this suite exists to catch.
    # The EIGHTH unguarded extraction, missed when seven others were fixed (the
    # commit message's count of seven was wrong). On an unparseable workflow the
    # grep matches nothing, the assignment goes non-zero under pipefail, and the
    # suite dies before ANY __YQ_ERROR__ sentinel can name the broken file.
    # MEASURED with `bash -x`: execution stopped at `+ direct_exec_scripts=`.
    direct_exec_scripts=$( { grep -oE 'run: \./(test/[a-zA-Z0-9_.-]+\.sh)' "$WORKFLOW" || true; } | sed 's|run: \./||' | sort -u)
    if [[ -z "$direct_exec_scripts" ]]; then
        fail "could not derive the direct-exec script list from live-tests.yml — the exec-bit assertion below would be vacuous"
    else
        exec_missing=""
        while IFS= read -r rel; do
            [[ -n "$rel" ]] || continue
            mode=$(git -C "$SCRIPT_DIR/.." ls-files -s -- "$rel" 2>/dev/null | awk '{print $1}')
            [[ -n "$mode" ]] || continue
            [[ "$mode" == "100755" ]] || exec_missing="${exec_missing} ${rel}(${mode})"
        done <<< "$direct_exec_scripts"
        if [[ -n "$exec_missing" ]]; then
            fail "live-tests.yml direct-execs script(s) NOT committed executable:${exec_missing} — CI dies with exit 126 before the suite runs one assertion"
        else
            pass "every script live-tests.yml direct-execs is committed 100755 ($(wc -l <<< "$direct_exec_scripts") scripts checked)"
        fi
    fi

    # The per-suite/continue-on-error/if: checks below all operate on
    # the preflight-selftest JOB BLOCK, which by construction starts after the
    # `preflight-selftest:` line — so none of them can see the top-level `on:`
    # triggers (line 3 of this file, structurally outside every job block).
    # Deleting `pull_request:` there switches the un-gated guards off for every
    # PR while every check below stays green, since the job itself, and every
    # step inside it, is untouched. Verified by mutation: removing the
    # `pull_request:` trigger left this suite at 117/0, exit 0.
    case "$(yq_query '.on | has("pull_request")')" in
        __NO_YQ__) fail_no_yq "live-tests.yml's pull_request trigger" ;;
        __YQ_ERROR__) fail_yq_error "live-tests.yml's pull_request trigger" ;;
        true)      pass "live-tests.yml still triggers on pull_request (the un-gated guard suites only run on PRs because of this)" ;;
        *)         fail "live-tests.yml no longer triggers on pull_request — the un-gated guard suites (preflight-selftest, validator-regression) would never run on a PR" ;;
    esac
    # The vacuity check above only proves pull_request: exists — not
    # that it still fires on every PR. A paths/paths-ignore filter under it
    # silently switches every un-gated guard suite off for a PR that touches
    # only test/*.sh or the workflow itself, which is every PR they exist to
    # police (ci.yml already carries exactly such a filter, so this is not
    # hypothetical). Two properties with different remedies get two messages.
    # Pin the trigger's WHOLE SHAPE, not an enumeration of known-bad keys.
    #
    # The predecessor of this check asked `has("paths") or has("paths-ignore")`.
    # That was the same mistake one level down: `types:` and `branches:` narrow a
    # trigger just as completely, and neither was enumerated. MUTATION-PROVEN:
    # `types: [opened, synchronize, ...]` -> `types: [labeled]` left this suite at
    # 129/0 exit 0 while no ordinary PR push would run a single guard suite.
    #
    # Enumerating keys can only ever be as complete as the enumeration. Comparing
    # the whole block to an expected value is complete by construction: any added,
    # removed or altered key is a mismatch. sort_keys makes it order-independent so
    # a benign reformat cannot trip it.
    #
    # If you INTENTIONALLY change the trigger, update EXPECTED_PR_TRIGGER below and
    # say why in the commit — that edit is exactly the review moment this pin exists
    # to force.
    EXPECTED_PR_TRIGGER='{"branches":["main"],"types":["opened","synchronize","reopened","labeled","unlabeled"]}'
    actual_pr_trigger="$(yq_query '.on.pull_request | sort_keys(..)' -o=json -I=0)"
    case "$actual_pr_trigger" in
        __NO_YQ__) fail_no_yq "live-tests.yml's pull_request trigger shape" ;;
        __YQ_ERROR__) fail_yq_error "live-tests.yml's pull_request trigger shape" ;;
        "$EXPECTED_PR_TRIGGER")
            pass "live-tests.yml's pull_request trigger carries no paths/paths-ignore narrowing, so a shell-only PR still runs the un-gated guard suites (branches and types are expected and are part of EXPECTED_PR_TRIGGER)" ;;
        *)  fail "live-tests.yml's pull_request trigger shape changed: expected ${EXPECTED_PR_TRIGGER}, got ${actual_pr_trigger} — a paths/paths-ignore narrowing switches off every un-gated guard suite for the PRs they exist to police, and dropping a types entry (labeled/unlabeled) stops a label change re-evaluating the gate; if the change is deliberate, update EXPECTED_PR_TRIGGER" ;;
    esac

    # The test job's OWN gate. The per-step if: check further below asks
    # whether the two suite-running STEPS are gated; it cannot see a gate on the
    # JOB that contains them, which is strictly more powerful. MUTATION-PROVEN:
    # replacing this job's condition with `if: false` left this suite at 129/0
    # exit 0 while the entire live suite — offline group, live group, every
    # rod-backed target — stopped running.
    #
    # Asserting the VALUE, not absence: this job legitimately HAS an if:, so
    # `has("if")` would fail immediately and is the wrong question.
    EXPECTED_TEST_JOB_IF="needs.check-label.outputs.should-run == 'true'"
    case "$(yq_query '.jobs.test.if // "__ABSENT__"')" in
        __NO_YQ__) fail_no_yq "the test job's gate condition" ;;
        __YQ_ERROR__) fail_yq_error "the test job's gate condition" ;;
        "$EXPECTED_TEST_JOB_IF")
            pass "the test job's gate is still the check-label condition (the whole live suite cannot be switched off by retargeting it)" ;;
        *)  fail "the test job's gate condition is no longer ${EXPECTED_TEST_JOB_IF} — retargeting or falsifying it stops the ENTIRE live suite while CI stays green; if the change is deliberate, update EXPECTED_TEST_JOB_IF" ;;
    esac

    # The checks in the loop below apply to preflight-selftest AND
    # validator-regression — live-tests.yml's SECOND un-gated guard job (its
    # own header comment says "Deliberately outside the check-label gate —
    # same rationale as preflight-selftest above"), which this suite's own
    # failure messages already name. Applying the neutering checks to only
    # the first of the two left validator-regression's continue-on-error,
    # if:, and needs: unguarded — verified by mutation: `needs: check-label`
    # and `needs: test` on validator-regression both left this suite at
    # 122/0, exit 0 (the latter is the worse case: `test` carries
    # `if: needs.check-label.outputs.should-run == 'true'`, so that needs:
    # would genuinely skip validator-regression whenever skip-live-tests is
    # applied — exactly the outcome being un-gated is supposed to prevent).
    #
    # Both jobs are deliberately outside the check-label gate (see each job's
    # header comment in live-tests.yml).
    UNGATED_GUARD_JOBS=(preflight-selftest validator-regression)
    for job in "${UNGATED_GUARD_JOBS[@]}"; do
        job_block=$(extract_job_block "$job")
        if [[ -z "$job_block" ]]; then
            fail "could not extract the ${job} job block (extraction broken — assertions below are vacuous)"
        else
            pass "${job} job block extracted from live-tests.yml"
            ungated_runlines=$(printf '%s\n' "$job_block" | grep -vE '^[[:space:]]*#')

            # A step that is PRESENT but neutered is the same coverage loss as a
            # deleted one, and it is harder to spot in review: `continue-on-error`
            # turns a red suite green, and a step-level `if:` can switch it off for
            # exactly the events that matter. Checking only that the invocation
            # exists would call both of those wired.
            if printf '%s\n' "$ungated_runlines" | grep -qE '^[[:space:]]*continue-on-error:[[:space:]]*true'; then
                fail "${job} sets continue-on-error: true — a failing guard would not fail CI"
            else
                pass "${job} has no continue-on-error: true"
            fi
            # The cheapest neutering shape of all — a trailing
            # '|| true' / '|| exit 0' / '|| :' on a run line — trips neither the
            # continue-on-error check above nor the per-suite invocation regexes,
            # which only assert the invocation is PRESENT, not un-neutered.
            if printf '%s\n' "$ungated_runlines" | grep -qE '\|\|[[:space:]]*(true|exit 0|:)([[:space:]]|$)'; then
                fail "${job} neuters a step with a trailing '|| true'/'|| exit 0'/'|| :' — a failing guard would not fail CI"
            else
                pass "${job} has no trailing '|| true'/'|| exit 0'/'|| :' step neutering"
            fi
            # ANY `if:` inside this job block is a finding, at any indentation.
            #
            # The first version anchored on `^[[:space:]]{8,}if:` to distinguish a
            # step-level `if:` from a job-level one. That encoded the file's CURRENT
            # indentation (steps items at 6, keys at 8) into a security guard, and
            # YAML permits the sequence at the parent key's indent instead (items at
            # 4, keys at 6) — a reformat nobody would think twice about silently
            # disarmed it. Mutation-proven.
            #
            # Dropping the depth distinction is safe BECAUSE of what this block is:
            # extraction starts after the job's own name line, so the job's own
            # key/value lines are inside it, and this job is deliberately un-gated.
            # It has no `if:` of any kind today, and if someone adds one — at
            # either level — that is exactly the change this guard should refuse
            # to let through unnoticed.
            if printf '%s\n' "$ungated_runlines" | grep -qE '^[[:space:]]*if:'; then
                fail "${job} contains an if: condition — a guard can be silently skipped"
            else
                pass "${job} has no if: conditions at any level"
            fi

            # An `if:` isn't the only way to gate this job — a `needs:`
            # on a job the check-label gate blocks (or that never runs on a plain
            # PR push) has the same effect, and this job's own header comment says
            # it is deliberately un-gated so that 'skip-live-tests' cannot switch
            # off the regression net. A `needs:` value may be a string or a list,
            # which a text grep over the extracted block cannot see reliably —
            # ask the parser instead (D1's second bound assertion).
            case "$(yq_query ".jobs[\"${job}\"] | has(\"needs\")")" in
                __NO_YQ__) fail_no_yq "${job}'s needs: dependencies" ;;
                __YQ_ERROR__) fail_yq_error "${job}'s needs: dependencies" ;;
                false)     pass "${job} has no needs: dependency (stays un-gated)" ;;
                *)         fail "${job} now has a needs: dependency — this job is deliberately un-gated (see its header comment); a needs: on check-label, or on anything check-label gates, would put every un-gated guard suite behind the skip-live-tests label" ;;
            esac
        fi
    done

    # Which suites does preflight-selftest actually invoke. Scoped to
    # preflight-selftest only: validator-regression hosts validate_test.sh,
    # which is already covered by the generic suite-coverage loop below.
    # Driven by a fresh extraction (not the loop's job_block above) — the
    # loop already asserts preflight-selftest's block extracted successfully,
    # so re-asserting it here would double-count; if extraction were ever
    # broken, every check below would legitimately FAIL (an empty $runlines
    # matches no run: line), not pass vacuously.
    preflight_block=$(extract_job_block preflight-selftest)
    # Comments are stripped and the match is anchored on the `run:` line.
    # Matching the bare filename anywhere in the block was a FALSE NEGATIVE:
    # the surrounding comments name every suite, so deleting a step left the
    # guard green. Verified by mutation — with the plain -qF match, removing
    # the install-chrome self-test step still passed.
    runlines=$(printf '%s\n' "$preflight_block" | grep -vE '^[[:space:]]*#')
    for suite in preflight-selftest.sh install-chrome-selftest.sh setup-live-targets_test.sh test-runner-args.sh; do
        # Dots are escaped: unescaped, `.` matches any character, so the
        # pattern for install-chrome-selftest.sh would also accept
        # `install-chrome-selftestXsh`. Harmless today, but this guard exists
        # precisely to notice small edits nobody meant to make.
        suite_re=${suite//./\\.}
        # Anchored strictly to end-of-line (only trailing
        # whitespace allowed after the script name) — previously the
        # `([[:space:]]|$)` alternation matched the space before a
        # trailing '|| true' too, so appending that to a run line still
        # satisfied "invokes $suite" even though the failure it produces
        # would be swallowed.
        if printf '%s\n' "$runlines" | grep -qE "run:[[:space:]]*(\./|bash )?test/${suite_re}[[:space:]]*\$"; then
            pass "un-gated job invokes $suite"
        else
            fail "un-gated preflight-selftest job no longer invokes $suite — coverage dropped silently"
        fi
    done
fi

echo ""
echo "=== Suite coverage: every suite in test/ is wired into some CI job ==="
# The hardcoded loop above only proves the DELETE direction for four names
# inside ONE job. It misses (1) a suite wired into a DIFFERENT job — e.g.
# test/validate_test.sh runs under validator-regression, not
# preflight-selftest, and a grep for validate_test anywhere above this point
# in this file returns nothing — and (2) a suite added to test/ and never
# wired into ANY job, since a hand-maintained loop can only check names
# someone remembered to add to it — the same failure mode as remembering to
# add the CI step in the first place. Mirrors the ALL_TARGETS/BROWSER_TARGETS
# exhaustiveness pattern below: derive the candidate set from the tree instead
# of trusting a hardcoded list to stay current.
# Derive from TRACKED files, not a working-tree listing. An `ls` picks up
# untracked scratch copies — a `test/foo_test.sh` left over from debugging — and then
# demands CI wiring for a file that is not in the repo, failing the suite on the
# developer's machine and nowhere else. Falls back to `ls` only outside a git
# checkout (a release tarball), where the two are equivalent anyway.
mapfile -t candidate_suites < <(
    {
        if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            git -C "$SCRIPT_DIR" ls-files -- '*selftest.sh' '*_test.sh' | xargs -r -n1 basename
        else
            (cd "$SCRIPT_DIR" && ls -1 -- *selftest.sh *_test.sh 2>/dev/null)
        fi
        printf '%s\n' test-runner-args.sh
    } | sort -u
)
if printf '%s\n' "${candidate_suites[@]}" | grep -qx 'install-chrome-selftest.sh' \
   && printf '%s\n' "${candidate_suites[@]}" | grep -qx 'test-runner-args.sh'; then
    pass "candidate suite list derived from test/*selftest.sh + test/*_test.sh (sentinels present)"
else
    fail "candidate suite list derivation is broken/empty (expected sentinels missing)"
fi

if [[ -f "$WORKFLOW" ]]; then
    # Presence of a matching `run:` line anywhere in the file proves
    # only that the text exists, not that anything can execute it — a job
    # gated off with `if: false` (or any other neutering) still contains the
    # line. Resolve which job actually HOSTS the match, the same way
    # preflight_block/e2e_block/test_block above pin a single named job, but
    # parameterized: the hosting job for a given suite isn't known ahead of
    # time, so the extraction idiom (extract_job_block, defined once above
    # near WORKFLOW=) is driven by the job-name list derived from the
    # workflow itself.

    mapfile -t all_job_names < <(
        awk '
            /^jobs:/ { in_jobs=1; next }
            in_jobs && /^[A-Za-z]/ { in_jobs=0 }
            in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
                line=$0
                sub(/^  /, "", line)
                sub(/:[[:space:]]*$/, "", line)
                print line
            }
        ' "$WORKFLOW"
    )
    if printf '%s\n' "${all_job_names[@]}" | grep -qx 'preflight-selftest' \
       && printf '%s\n' "${all_job_names[@]}" | grep -qx 'validator-regression'; then
        pass "job name list derived from live-tests.yml (sentinels present)"
    else
        fail "job name list derivation from live-tests.yml is broken/empty (expected sentinels missing)"
    fi

    # Jobs whose if: gate is deliberate and already pinned elsewhere in this
    # file: install-chrome-e2e's exact trigger arms, above. `test`
    # is deliberately NOT on this list: it is the label-gated job
    # (`skip-live-tests` switches it off via check-label), so a guard suite
    # hosted ONLY by `test` would satisfy "wired into some CI job" while
    # staying silently skippable on any PR carrying that label — precisely
    # the defect this PR fixes by moving test-runner-args.sh out of `test`
    # and into the un-gated preflight-selftest job. A job reaching this
    # allowlist is not itself a finding — only an if: on a job NOT on it.
    ALLOWED_GATED_JOBS=(install-chrome-e2e)

    declare -a hosting_jobs=()
    for suite in "${candidate_suites[@]}"; do
        suite_re=${suite//./\\.}
        hosting_job=""
        for job_name in "${all_job_names[@]}"; do
            job_runlines=$(extract_job_block "$job_name" | grep -vE '^[[:space:]]*#')
            # End-anchored, matching the tightening applied
            # to the preflight-selftest block's own per-suite regex (below,
            # and at the hardcoded block above) — the loose `([[:space:]]|$)`
            # alternation also matches the space before a trailing
            # '|| true'/'|| exit 0'/'|| :', so a neutered invocation would
            # still count as "hosted" here.
            if printf '%s\n' "$job_runlines" | grep -qE "run:[[:space:]]*(\./|bash )?test/${suite_re}[[:space:]]*\$"; then
                hosting_job="$job_name"
                break
            fi
        done
        if [[ -n "$hosting_job" ]]; then
            pass "suite '$suite' is invoked by job '$hosting_job' in live-tests.yml"
            hosting_jobs+=("$hosting_job")
        else
            fail "suite '$suite' exists in test/ but is not invoked by any CI job — add it to a job, or to the exemption list here"
        fi
    done

    # A suite's coverage is only as real as the job hosting it being able to
    # run at all. Apply the same THREE neutering checks the preflight-selftest
    # and install-chrome-e2e blocks above already apply to themselves — but to
    # whichever job the loop above actually found — once per distinct hosting
    # job rather than once per suite, since several suites share a host.
    mapfile -t unique_hosting_jobs < <(printf '%s\n' "${hosting_jobs[@]}" | sort -u)
    for job_name in "${unique_hosting_jobs[@]}"; do
        [[ -z "$job_name" ]] && continue
        job_runlines=$(extract_job_block "$job_name" | grep -vE '^[[:space:]]*#')

        if printf '%s\n' "$job_runlines" | grep -qE '^[[:space:]]*continue-on-error:[[:space:]]*true'; then
            fail "job '$job_name' (hosts suite coverage asserted above) sets continue-on-error: true — a failing suite would not fail CI"
        else
            pass "job '$job_name' (hosts suite coverage asserted above) has no continue-on-error: true"
        fi

        # The two checks above only re-implemented two of the three
        # neutering shapes the hardcoded preflight-selftest/install-chrome-e2e
        # blocks apply to themselves — this generic loop was missing the
        # cheapest one of all, a trailing '|| true'/'|| exit 0'/'|| :' on a
        # run line, which trips neither continue-on-error nor an if: gate.
        if printf '%s\n' "$job_runlines" | grep -qE '\|\|[[:space:]]*(true|exit 0|:)([[:space:]]|$)'; then
            fail "job '$job_name' (hosts suite coverage asserted above) neuters a step with a trailing '|| true'/'|| exit 0'/'|| :' — a failing suite would not fail CI"
        else
            pass "job '$job_name' (hosts suite coverage asserted above) has no trailing '|| true'/'|| exit 0'/'|| :' step neutering"
        fi

        if printf '%s\n' "$job_runlines" | grep -qE '^[[:space:]]*if:'; then
            allowed=0
            for allowed_job in "${ALLOWED_GATED_JOBS[@]}"; do
                [[ "$job_name" == "$allowed_job" ]] && allowed=1
            done
            if [[ "$allowed" -eq 1 ]]; then
                pass "job '$job_name' carries an if: gate, but is on the allowlist of legitimately-gated jobs"
            else
                fail "job '$job_name' (hosts suite coverage asserted above) carries an if: gate not on the allowlist — the job, and every suite it hosts, may never run"
            fi
        else
            pass "job '$job_name' (hosts suite coverage asserted above) has no if: gate"
        fi
    done
else
    fail "live-tests.yml not found at $WORKFLOW (suite-coverage assertions vacuous)"
fi

# install-chrome-e2e is the sole automated coverage of the installer's
# privileged region (download, signature-verified apt install, trap teardown,
# AC4 cleanup). Deleting the job would remove that coverage with every other
# check in the repo still green — the same silent-loss shape this file exists
# to prevent, one level up.
if [[ -f "$WORKFLOW" ]]; then
    if grep -qE '^  install-chrome-e2e:' "$WORKFLOW"; then
        pass "install-chrome-e2e job still defined (privileged-path coverage present)"
        e2e_block=$(extract_job_block install-chrome-e2e)
        # e2e_block's two siblings (preflight_block, test_block) each
        # guard their extraction with a fidelity sentinel; this one had
        # neither, so every assertion below would pass vacuously if the
        # extraction ever returned empty — the same vacuous-guard shape this file polices.
        if [[ -z "$e2e_block" ]]; then
        fail "could not extract the install-chrome-e2e job block (extraction broken — the assertions below would be vacuous)"
        else
        # Strip comments BEFORE any content grep below. extract_job_block stops at
        # the next `^  <name>:` line, and a comment line begins `  #`, which does
        # not match that terminator — so a job's extracted block runs on to the
        # last comment line preceding the NEXT job key. The devcontainer jobs
        # added a long preamble immediately after this one, which widened this
        # block by those comment lines. Grepping the raw block would then let a
        # sentence in a FOREIGN job's preamble satisfy an assertion about THIS
        # job's steps: quote `run: ./test/install-chrome.sh` in a comment down
        # there, delete the real step, and the guard passes vacuously. Only the
        # step-list greps further down used to strip; these two did not.
        e2e_runlines=$(printf '%s\n' "$e2e_block" | grep -vE '^[[:space:]]*#')
        if printf '%s\n' "$e2e_runlines" | grep -qE 'run:[[:space:]]*(\./|bash )?test/install-chrome\.sh'; then
            pass "install-chrome-e2e still invokes test/install-chrome.sh end-to-end"
        else
            fail "install-chrome-e2e no longer runs test/install-chrome.sh — the privileged path is uncovered"
        fi

        # The checks above prove the job exists and still runs the
        # script, but say nothing about the one thing that decides whether it
        # ever runs at all — its `if:`. This job is deliberately opt-in
        # (workflow_dispatch, plus push to main so a break there cannot stay
        # hidden); narrowing that gate to one arm, or to `if: false`, leaves
        # every other check in this file green while the installer's
        # privileged path silently loses all coverage. Pin the gate's
        # content, not just its absence — require both trigger arms by name.
        if printf '%s\n' "$e2e_runlines" | grep -qE '^[[:space:]]*if:.*workflow_dispatch' \
           && printf '%s\n' "$e2e_runlines" | grep -qE '^[[:space:]]*if:.*refs/heads/main'; then
            pass "install-chrome-e2e's if: gate still names both the workflow_dispatch and push-to-main arms"
        else
            fail "install-chrome-e2e's if: gate no longer names both trigger arms — the opt-in gate may have been narrowed or disabled, silently dropping the installer's only privileged-path coverage"
        fi

        # The job-exists / script-runs checks above say nothing about the
        # STEPS that turn that run into a test: deleting the "Assert
        # no phone-home artifacts survive" step — the only place AC4 and the
        # version record are verified against a real install — left the two
        # checks above green with no other signal. Require the verification
        # steps explicitly, and reject the same continue-on-error escape hatch
        # the preflight-selftest block above rejects.
        # (e2e_runlines is computed above, before the first content grep.)
        # Every CONTAINER job that uses bash in an inline `run:` must declare
        # `shell: bash`. The runner does NOT default a container job's `run:` to
        # bash — it uses `sh -e {0}` — so `set -euo pipefail` in an inline block
        # is a line-1 fatal ("Illegal option -o pipefail", exit 2) and every
        # assertion beneath it is skipped. MEASURED in run 32388761616, the first
        # execution of this job in its life: two steps lost that way, and neither
        # `bash -n` nor any suite could see it, because an inline block is not a
        # file and the job is opt-in so no PR ever ran it.
        #
        # Asked of the CONTAINER-ness, not of install-chrome-e2e by name, so a
        # future container job inherits the check. Non-container jobs are exempt:
        # the runner does default those to bash.
        e2e_is_container=$(yq_query '.jobs["install-chrome-e2e"] | has("container")' -o=json -I=0)
        e2e_shell=$(yq_query '.jobs["install-chrome-e2e"].defaults.run.shell // ""' -o=json -I=0)
        case "$e2e_is_container:$e2e_shell" in
            __NO_YQ__*|*__NO_YQ__) fail_no_yq "install-chrome-e2e's container/shell shape" ;;
            __YQ_ERROR__*|*__YQ_ERROR__) fail_yq_error "install-chrome-e2e's container/shell shape" ;;
            'false:'*) pass "install-chrome-e2e is not a container job, so the runner defaults its run: steps to bash" ;;
            'true:"bash"') pass "install-chrome-e2e is a container job and declares shell: bash, so its inline run: blocks get bash rather than sh -e" ;;
            'true:'*) fail "install-chrome-e2e is a container job but does not declare 'defaults.run.shell: bash' (got ${e2e_shell:-none}) — the runner gives container jobs 'sh -e', so any inline run: block using 'set -o pipefail', arrays, or [[ ]] dies on its first line with exit 2 and every assertion under it is skipped" ;;
            *) fail "could not determine install-chrome-e2e's container/shell shape (container=${e2e_is_container} shell=${e2e_shell})" ;;
        esac

        # Also require the headless-render assertion — the only
        # place anything actually drives the installed binary — not just the
        # three needles below (chrome-version, cron.daily absence, idempotent
        # re-run). --dump-dom is the most specific token: it appears nowhere
        # else in the assertion.
        #
        # That assertion moved out of an inline `run:` block into
        # test/assert-chrome-install.sh so the un-gated `bash -n` step covers
        # it, which splits the property across two files. Both links are
        # required: the job must still invoke the script, AND the script must
        # still drive the binary. Checking only one leaves the other free to
        # be deleted with this guard green — a job that runs a script whose
        # render check was removed, or a script nothing runs.
        RENDER_ASSERT="$SCRIPT_DIR/assert-chrome-install.sh"
        if ! printf '%s\n' "$e2e_runlines" | grep -qE 'run:[[:space:]]*(\./|bash )?test/assert-chrome-install\.sh'; then
            fail "install-chrome-e2e no longer invokes test/assert-chrome-install.sh — the headless-render assertion is not run"
        elif [[ ! -f "$RENDER_ASSERT" ]]; then
            fail "test/assert-chrome-install.sh is missing, but install-chrome-e2e still invokes it — the job dies before asserting anything"
        # Comments stripped, and the token required on a line that actually
        # INVOKES the binary. Grepping the raw file was satisfiable from a
        # comment: MUTATION-PROVEN — commenting out the exec while leaving
        # `# was: "${bin}" --headless --no-sandbox --dump-dom about:blank` in
        # place kept this printing "still asserts a runnable headless render"
        # at exit 0 with nothing driving the browser. install-chrome-selftest.sh
        # built fn_code() for exactly this class and records it as hit in three
        # consecutive review rounds; this check is the same idea, inline.
        elif ! { grep -vE '^[[:space:]]*#' "$RENDER_ASSERT" | grep -e '--dump-dom' | grep -q '\${bin}'; }; then
            fail "test/assert-chrome-install.sh no longer drives the browser on a line carrying --dump-dom — the only assertion that actually renders a page is gone, on the privileged install path that had no automated coverage at all before this PR"
        # EXECUTED, not grepped. Every text form of this check has now been
        # defeated: grepping the raw file was satisfied by a comment; stripping
        # comments and requiring ${bin} on the token's line was satisfied by the
        # unbounded fallback; requiring the bound's literal text was satisfied by
        # a `cat >/dev/null <<EOF` here-doc holding the same line. All three
        # MUTATION-PROVEN. A source scan cannot distinguish a command from a
        # string that looks like one, so this runs the script and observes what
        # it actually invokes.
        #
        # The stubs are the observation: a `timeout` that logs its argv then
        # execs, and a browser answering --version. If the script drives the
        # browser under a bound, the log holds a timeout invocation naming both a
        # positive duration and --dump-dom. Nothing textual is asserted.
        elif ! command -v mktemp >/dev/null 2>&1; then
            fail "mktemp unavailable — cannot execute test/assert-chrome-install.sh to observe its render call"
        else
            # Under THIS file's pinned temp root (see TMPDIR_T's rationale at the
            # top), not a bare `mktemp -d`. This is the one fixture in the suite
            # that holds EXECUTABLES which are then PATH-prepended and run, which
            # is precisely the hazard that pin exists for: an inherited TMPDIR on
            # a non-sticky directory lets a second local user swap the tree
            # between creation and use and choose the binaries this suite
            # executes. Living under TMPDIR_T also means the file-scope EXIT trap
            # removes it if the suite dies before the `rm -rf` below.
            rdir=$(TMPDIR="$TMPDIR_T" mktemp -d)
            # The stub logs its argv, then drops timeout's own options and the
            # DURATION before exec-ing the rest — same shape as
            # install-chrome-selftest.sh's plant_timeout_stub. A stub that
            # exec'd "$@" verbatim would try to run the duration as a command,
            # which is how the first draft of this check reported the script
            # broken when the script was fine.
            # QUOTED delimiter, so the stub BODY is literal: an unquoted here-doc
            # was needed only to splice $rdir into the logging line, and that let
            # a quote in the path break out of the stub itself.
            #
            # Stated precisely, because a previous version of this comment
            # overclaimed: $rdir is STILL interpolated, into the one-line wrapper
            # written just below. That is a smaller surface than the whole stub,
            # not zero — a quote in $rdir would break the wrapper too. It is
            # unexploitable here (mktemp under the pinned sticky /tmp root cannot
            # produce one) and is left rather than validated, because validating a
            # path this suite generates itself would be theatre. install-chrome-
            # selftest.sh's plant_timeout_stub needs no interpolation at all,
            # since its stub does not log; it is not the same situation.
            cat > "$rdir/timeout-impl" <<'TIMEOUT_STUB'
#!/bin/bash
# Resolve timeout's own options the way timeout(1) does, then log the RESOLVED
# kill-after and duration alongside the argv. The assertion reads those two
# numbers instead of re-parsing argv with a regex — four successive regexes over
# this log were each defeated or made to false-alarm (satisfiable from a comment,
# satisfiable across two invocations, blind to the bound's position, then blind to
# the DURATION while rejecting `--preserve-status -k 5 30`). A parser cannot be
# out-spelled by the shapes this call can take: `-k 5`, `-k5`, `--kill-after=5`,
# `--kill-after 5` and a leading `-s KILL` all resolve to the same two numbers,
# verified against timeout(1) itself. Not an absolute — a token this loop does not
# recognise lands in the duration slot, where it fails the numeric check or breaks
# the exec. That is fail-closed, which is the property being claimed, rather than
# completeness, which is not.
log=$1; shift
argv="$*"
ka=""
while [ $# -gt 0 ]; do
    case "$1" in
        -k|--kill-after)  ka=$2; shift 2 ;;
        --kill-after=*)   ka=${1#--kill-after=}; shift ;;
        -k?*)             ka=${1#-k}; shift ;;
        -s|--signal)      shift 2 ;;
        -s*|--signal=*|--preserve-status|--foreground) shift ;;
        *) break ;;
    esac
done
dur=$1; shift
printf 'kill_after=%s duration=%s argv=%s\n' "${ka:-none}" "${dur:-none}" "$argv" >> "$log"
exec "$@"
TIMEOUT_STUB
            printf '#!/bin/bash\nexec "%s/timeout-impl" "%s/timeout.log" "$@"\n' "$rdir" "$rdir" > "$rdir/timeout"
            chmod +x "$rdir/timeout-impl"
            printf '#!/bin/bash\n[ "$1" = "--version" ] && { echo "Google Chrome 999.0.0.0"; exit 0; }\necho "<html></html>"\n' > "$rdir/google-chrome"
            chmod +x "$rdir/timeout" "$rdir/google-chrome"
            # `|| render_rc=$?` rather than a bare call: this suite runs under
            # `set -e`, so a non-zero exit here would abort the whole run before
            # the arms below could report it — the completion sentinel would then
            # blame the suite rather than naming the defect.
            render_rc=0
            PATH="$rdir:$PATH" bash "$RENDER_ASSERT" >/dev/null 2>&1 || render_rc=$?
            render_log=$(cat "$rdir/timeout.log" 2>/dev/null || true)
            rm -rf "$rdir"
            if [[ $render_rc -ne 0 ]]; then
                fail "executing test/assert-chrome-install.sh against a healthy stub browser failed (rc $render_rc) — the assertion install-chrome-e2e depends on does not run"
            # ONE LINE must satisfy BOTH predicates. Matching them against the
            # whole concatenated log let two SEPARATE timeout invocations satisfy
            # it jointly — one carrying the bound, another carrying --dump-dom.
            # Not defeatable today, because chrome_runnable's probe passes a bare
            # duration and is the only other timeout in the log; but adding `-k`
            # to that probe would activate it, and the comment this commit adds
            # to assert-chrome-install.sh discusses exactly that choice.
            # Every spelling timeout(1) accepts for the kill-after, not just the
            # one this script happens to use: `-k 5`, `-k5`, `--kill-after=5`,
            # and a unit suffix (`5s`). The stub's own option loop handles all of
            # them, so a render bounded any of those ways is correctly bounded —
            # and a regex pinning one spelling would fail it with text naming a
            # regression that had not happened. A false alarm here is as much a
            # defect as a false pass: it trains a reader to edit the guard.
            # Read the RESOLVED numbers the stub logged, and require BOTH to be
            # positive. `timeout --help`: "A duration of 0 disables the associated
            # timeout" — verified locally, `timeout -k 5 0 sleep 2` returns 0 after
            # 2s — so a zero duration is an unbounded render, and the regex this
            # replaces constrained only the kill-after and passed it. Position is
            # implicit: a bound written after the binary is parsed by timeout as
            # arguments to the BROWSER, so it never becomes kill_after/duration at
            # all and the numbers come back `none`.
            # ANCHORED to the start of the line, so only the stub's OWN resolved
            # fields can satisfy this. Unanchored, the browser's argv — appended
            # to the same line as `argv=` — could carry the text `kill_after=5
            # duration=30` and satisfy the read while the bound was `0`.
            # MUTATION-PROVEN defeated at head 68b9484.
            #
            # A fractional duration is allowed (`-k 5 1.5`), which timeout(1)
            # accepts. Options this stub's loop does not model (`-v`, an
            # abbreviation) land in the duration slot and fail this read with a
            # named message — a false alarm in principle, accepted because this
            # guard covers exactly one call site whose invocation shape is fixed
            # and reviewed, and modelling all of timeout(1)'s options to remove a
            # false alarm nobody can trigger is not worth the code.
            elif printf '%s\n' "$render_log" \
                 | grep -- '--dump-dom' \
                 | grep -qE '^kill_after=[1-9][0-9]*(\.[0-9]+)?[a-z]?[[:space:]]+duration=[1-9][0-9]*(\.[0-9]+)?[a-z]?[[:space:]]'; then
                pass "executing test/assert-chrome-install.sh drives the browser with --dump-dom under a timeout carrying a positive -k bound (observed, not grepped)"
            else
                fail "executing test/assert-chrome-install.sh did not invoke timeout with a positive -k bound around a --dump-dom render (observed argv: ${render_log:-<none>}) — the render either does not run or runs unbounded"
            fi
        fi
        # Match the assertion's own shape, not the bare path — the
        # bare 'chrome-version' token also matches the purely informational
        # `echo "recorded build: ..."` line beneath it, so deleting the real
        # assertion while keeping the echo left this guard green.
        if printf '%s\n' "$e2e_runlines" | grep -qE '\[ -s /usr/share/vespasian/chrome-version \]'; then
            pass "install-chrome-e2e still asserts the chrome-version record (AC4)"
        else
            fail "install-chrome-e2e no longer asserts the chrome-version record — AC4 version-record coverage dropped silently"
        fi
        # `[ -s ]` alone passes on a bare newline or a record left by
        # an earlier image layer, so the real install was verified LESS
        # specifically than the fixture-level case v, which already asserts both
        # the version string and 0644. Require the two content checks that close
        # that gap, so deleting either one fails here rather than silently
        # reverting the e2e assertion to a non-emptiness test.
        # Needle tracks the CURRENT shape: an equality test between the record's
        # own first version number and the installed major. The previous needle
        # matched the literal `grep -qF "$major" "$record"`, which was itself the
        # defect — an unanchored substring search that "150" satisfied inside
        # "1150" or a date. Assert the comparison exists, not the old spelling.
        if printf '%s\n' "$e2e_runlines" | grep -qE '\[ "\$rec_major" = "\$major" \]'; then
            pass "install-chrome-e2e asserts the record's version number EQUALS the installed major"
        else
            fail "install-chrome-e2e no longer compares the record's version to the installed major — a bare newline, or a record naming another build, would satisfy the -s test alone"
        fi
        if printf '%s\n' "$e2e_runlines" | grep -qE 'stat -c .%a. "\$record"'; then
            pass "install-chrome-e2e asserts the record's achieved mode"
        else
            fail "install-chrome-e2e no longer asserts the version record's mode — a literal 0644 in the installer is not evidence of the mode on disk"
        fi
        # Same tightening for the cron.daily check — the bare path
        # also matches the `for p in ...` list on its own, without proving the
        # loop body that actually inspects each $p and sets fail=1 is intact.
        if printf '%s\n' "$e2e_runlines" | grep -qE '/etc/cron\.daily/google-chrome' \
           && printf '%s\n' "$e2e_runlines" | grep -qE 'if \[ -e "[$]p" \]; then echo "LEFTOVER: [$]p"; fail=1; fi'; then
            pass "install-chrome-e2e still asserts /etc/cron.daily/google-chrome is absent (AC4)"
        else
            fail "install-chrome-e2e no longer asserts /etc/cron.daily/google-chrome is absent — AC4 phone-home coverage dropped silently"
        fi
        if printf '%s\n' "$e2e_runlines" | grep -q 'already present'; then
            pass "install-chrome-e2e still asserts the idempotent re-run marker"
        else
            fail "install-chrome-e2e no longer asserts the 'already present' idempotent re-run marker"
        fi
        # The workflow hardcodes the phone-home path list that
        # install-chrome.sh already defines once (PHONE_HOME_PATHS, plus
        # TMP_LIST/TMP_KEYRING/TMP_PREF). The duplication is deliberate — an
        # assertion that sourced the script under test would inherit the
        # script's own blind spot — but a deliberate duplicate still drifts, and
        # this one HAS already drifted once in this branch's history (it lost the
        # deb822 source and the package's own keyring). Nothing enforced that
        # they stay in step, so a future rename in the installer would leave the
        # AC4 assertion quietly checking a path the installer no longer writes.
        # Compare the two sets here: keep the duplication, remove the silence.
        installer_paths=$(
            sed -n 's/^[[:space:]]*"\${TEST_ROOT}\(\/[^"]*\)".*/\1/p' "$SCRIPT_DIR/install-chrome.sh" \
            | sort -u
        )
        # The installer also defines the three temp artifacts as scalars.
        installer_paths=$(
            printf '%s\n' "$installer_paths"
            sed -n 's/^TMP_\(LIST\|KEYRING\|PREF\)="\${TEST_ROOT}\(\/[^"]*\)".*/\2/p' "$SCRIPT_DIR/install-chrome.sh"
        )
        installer_paths=$(printf '%s\n' "$installer_paths" | grep -E '^/(etc|usr)/' | sort -u)
        workflow_paths=$(
            printf '%s\n' "$e2e_runlines" \
            | grep -oE '/(etc/apt/[a-z0-9./-]+|etc/cron\.daily/[a-z0-9.-]+|usr/share/keyrings/[a-z0-9.-]+)' \
            | sort -u
        )
        missing_from_workflow=$(comm -23 <(printf '%s\n' "$installer_paths") <(printf '%s\n' "$workflow_paths"))
        if [[ -z "$missing_from_workflow" ]]; then
            pass "install-chrome-e2e's phone-home list covers every path install-chrome.sh writes ($(printf '%s\n' "$installer_paths" | grep -c .) paths)"
        else
            fail "install-chrome-e2e's phone-home list has DRIFTED from install-chrome.sh — the installer writes paths the AC4 assertion never checks: $(printf '%s' "$missing_from_workflow" | tr '\n' ' ')"
        fi
        if printf '%s\n' "$e2e_runlines" | grep -qE '^[[:space:]]*continue-on-error:[[:space:]]*true'; then
            fail "install-chrome-e2e sets continue-on-error: true — a failing verification step would not fail CI"
        else
            pass "install-chrome-e2e has no continue-on-error: true"
        fi
        # Continue-on-error isn't the only neutering shape — a
        # trailing '|| true' / '|| exit 0' / '|| :' on a run line swallows the
        # failure just as effectively and trips neither the check above nor
        # the invocation regexes elsewhere in this file.
        if printf '%s\n' "$e2e_runlines" | grep -qE '\|\|[[:space:]]*(true|exit 0|:)([[:space:]]|$)'; then
            fail "install-chrome-e2e neuters a step with a trailing '|| true'/'|| exit 0'/'|| :' — a failing verification step would not fail CI"
        else
            pass "install-chrome-e2e has no trailing '|| true'/'|| exit 0'/'|| :' step neutering"
        fi

        echo ""
        echo "=== Phone-home path list: workflow vs install-chrome.sh ==="
        # AC4's control surface is hand-copied under a "KEEP IN LOCKSTEP" comment
        # with no guard: PHONE_HOME_PATHS + TMP_LIST/TMP_KEYRING/TMP_PREF in
        # install-chrome.sh, and the `for p in ...` list in this job's own
        # "Assert no phone-home artifacts survive" step (already extracted above
        # as e2e_block). Nothing detected the drift the comment itself admits
        # already happened once. Parse PHONE_HOME_PATHS structurally (sed range
        # + array source, like OFFLINE_TARGETS/LIVE_TARGETS above) rather than
        # grepping for literal paths, so this guard is robust to unrelated edits
        # to install-chrome.sh's surrounding code.
        INSTALL_CHROME="$SCRIPT_DIR/install-chrome.sh"
        if [[ ! -f "$INSTALL_CHROME" ]]; then
            fail "install-chrome.sh not found at $INSTALL_CHROME (phone-home drift guard vacuous)"
        else
            # TEST_ROOT must be set (empty) before sourcing: PHONE_HOME_PATHS,
            # TMP_LIST, TMP_KEYRING and TMP_PREF all reference "${TEST_ROOT}/...",
            # and this file runs under `set -u`. Empty TEST_ROOT resolves to the
            # bare system paths the workflow's e2e job — which runs unrooted, as
            # root — actually asserts against.
            TEST_ROOT=""
            source <(sed -n '/^PHONE_HOME_PATHS=(/,/^)/p' "$INSTALL_CHROME")
            source <(grep '^TMP_LIST=' "$INSTALL_CHROME")
            source <(grep '^TMP_KEYRING=' "$INSTALL_CHROME")
            source <(grep '^TMP_PREF=' "$INSTALL_CHROME")

            # Fidelity sentinel: an empty/broken extraction would make the
            # comparison below vacuously agree with whatever (nothing) it found.
            if [[ "${#PHONE_HOME_PATHS[@]}" -gt 0 && -n "${TMP_LIST:-}" && -n "${TMP_KEYRING:-}" && -n "${TMP_PREF:-}" ]] \
               && printf '%s\n' "${PHONE_HOME_PATHS[@]}" | grep -qx '/etc/cron.daily/google-chrome'; then
                pass "PHONE_HOME_PATHS/TMP_LIST/TMP_KEYRING/TMP_PREF extracted from install-chrome.sh"
            else
                fail "PHONE_HOME_PATHS/TMP_LIST/TMP_KEYRING/TMP_PREF extraction from install-chrome.sh is broken/empty"
            fi

            install_chrome_paths=$(printf '%s\n' "${PHONE_HOME_PATHS[@]}" "$TMP_LIST" "$TMP_KEYRING" "$TMP_PREF" | sort -u)

            # The workflow's `for p in ...; do` list, from e2e_block above.
            # Backslash line-continuations are stripped before word-splitting.
            workflow_phone_home_paths=$(printf '%s\n' "$e2e_block" \
                | sed -n '/for p in /,/; do/p' \
                | sed -e 's/^[[:space:]]*for p in //' -e 's/\\$//' -e 's/;[[:space:]]*do$//' \
                | tr -s '[:space:]' '\n' | grep -v '^$' | sort -u)

            if [[ -z "$workflow_phone_home_paths" ]]; then
                fail "could not extract the workflow's 'for p in ...' phone-home path list (extraction broken)"
            elif [[ "$install_chrome_paths" == "$workflow_phone_home_paths" ]]; then
                pass "workflow phone-home path list matches install-chrome.sh's PHONE_HOME_PATHS + TMP_LIST/TMP_KEYRING/TMP_PREF"
            else
                fail "workflow phone-home path list has drifted from install-chrome.sh: $(diff <(printf '%s\n' "$install_chrome_paths") <(printf '%s\n' "$workflow_phone_home_paths") | tr '\n' ' ')"
            fi
        fi
        fi
    else
        fail "install-chrome-e2e job is gone — the installer's privileged path has no coverage at all"
    fi
fi

echo ""
echo "=== test job wiring ==="
# preflight-selftest and install-chrome-e2e got step-list wiring guards above
# because a hand-maintained YAML block can silently lose a step with every
# other check in the repo still green. The `test` job — where the entire
# offline/live suite actually executes — had no equivalent.
if [[ -f "$WORKFLOW" ]]; then
    test_block=$(extract_job_block test)
    if [[ -z "$test_block" ]]; then
        fail "could not extract the test job block (extraction broken — assertions below are vacuous)"
    else
        pass "test job block extracted from live-tests.yml"
        test_runlines=$(printf '%s\n' "$test_block" | grep -vE '^[[:space:]]*#')

        if printf '%s\n' "$test_runlines" | grep -qE 'run:[[:space:]]*(\./|bash )?test/run-live-tests\.sh.*--group[[:space:]]+offline([[:space:]]|$)'; then
            pass "test job still runs the offline group via run-live-tests.sh --group offline"
        else
            fail "test job no longer runs run-live-tests.sh --group offline — offline coverage dropped silently"
        fi

        if printf '%s\n' "$test_runlines" | grep -qE 'run:[[:space:]]*(\./|bash )?test/run-live-tests\.sh.*--group[[:space:]]+live([[:space:]]|$)'; then
            pass "test job still runs the live group via run-live-tests.sh --group live"
        else
            fail "test job no longer runs run-live-tests.sh --group live — live coverage dropped silently"
        fi

        if printf '%s\n' "$test_block" | grep -qE '^[[:space:]]*needs:.*preflight-selftest'; then
            pass "test job still depends on preflight-selftest (fail-fast preserved)"
        else
            fail "test job no longer depends on preflight-selftest — the fail-fast dependency was dropped"
        fi

        # LAB-5064's AC3 promise: the offline group exercises the same
        # no-config path a developer gets on a fresh checkout. Re-adding a
        # stub-config step ahead of "Run offline tests" would silently revert
        # that without tripping either check above, since the offline run
        # step itself is untouched.
        # Match the SCRIPT that writes the config, not just the config
        # FILENAME. Grepping only for `.live-test-config` was a false negative:
        # `setup-live-targets.sh` is what writes that file, and a `run:
        # ./test/setup-live-targets.sh` step contains the filename nowhere, so
        # inserting one ahead of the offline run reverted AC3 while this
        # assertion still printed "no-config path preserved". Mutation-proven —
        # with the filename-only grep, adding a setup step before the offline run
        # left the suite at 112/0, exit 0.
        #
        # Do not anchor on `run:` being on the SAME line as the script
        # path. A YAML block scalar step —
        #   run: |
        #     ./test/setup-live-targets.sh
        # — puts the invocation on the line AFTER `run:`, so requiring
        # `run:[[:space:]]*(\./|bash )?test/setup-live-targets\.sh` on one line
        # never matches it: the second alternative only ever fired for the
        # single-line `run: ./test/setup-live-targets.sh` form. Matching the
        # invocation itself, independent of what precedes it on the same line,
        # catches both forms. Mutation-proven — with the `run:`-anchored regex,
        # inserting a `run: |` step ahead of the offline run left the suite at
        # 117/0, exit 0.
        before_offline=$(printf '%s\n' "$test_runlines" | sed -n '1,/Run offline tests/p' | sed '$d')
        if printf '%s\n' "$before_offline" | grep -qE '\.live-test-config|(\./|bash )?test/setup-live-targets\.sh'; then
            fail "test job writes a config file (or runs setup-live-targets.sh) before the offline run — the no-config offline path (AC3) is no longer exercised"
        else
            pass "test job writes no config before the offline run (AC3 no-config path preserved)"
        fi

        # The same three neutering shapes the un-gated job is held to.
        # This job is where the entire offline+live suite actually executes, and
        # it had NONE of these checks: the four assertions above prove the run
        # steps are PRESENT, not that a failure from them can still fail CI.
        # Mutation-proven — `continue-on-error: true` on the offline run step, and
        # separately a trailing `|| true` on its command, each left this suite at
        # 112/0, exit 0.
        if printf '%s\n' "$test_runlines" | grep -qE '^[[:space:]]*continue-on-error:[[:space:]]*true'; then
            fail "test job sets continue-on-error: true — a failing suite would not fail CI"
        else
            pass "test job has no continue-on-error: true"
        fi
        if printf '%s\n' "$test_runlines" | grep -qE '\|\|[[:space:]]*(true|exit 0|:)([[:space:]]|$)'; then
            fail "test job neuters a step with a trailing '|| true'/'|| exit 0'/'|| :' — a failing suite would not fail CI"
        else
            pass "test job has no trailing '|| true'/'|| exit 0'/'|| :' step neutering"
        fi
        # Unlike the un-gated job, this one legitimately carries `if:` — a
        # job-level label gate and `if: always()` on the upload/teardown steps —
        # so a blanket ban would be wrong. Pin the property that actually
        # matters instead: the two steps that RUN the suites are unconditional.
        # An `if: false` (or any condition) on either is the neutering this
        # catches, and it is invisible to the three checks above.
        #
        # Locate each step by the invocation it CONTAINS, not by its
        # human-readable name. A name-anchored sed range fails OPEN: reorder the
        # step's keys so `if:` leads the mapping (YAML mappings are unordered,
        # so this is valid) and the `- name: ...` line loses its `- ` prefix —
        # the anchor never matches, sed emits nothing, and the guard reports
        # "unconditional" for a step that is disabled. A rename reaches the same
        # place permanently. Asking the parser for the step whose `run:` contains
        # the invocation makes both mutations impossible at once, and a
        # not-found result is a distinct FAIL value rather than a silent pass —
        # the missing fidelity sentinel becomes free.
        for group in offline live; do
            case "$(yq_query "[.jobs.test.steps[] | select((.run // \"\") | test(\"--group ${group}\")) | has(\"if\")] | .[0]")" in
                __NO_YQ__)      fail_no_yq "the test job's '--group ${group}' step gate" ;;
                false)          pass "test job's '--group ${group}' step is unconditional (no if:, at any key position)" ;;
                null)           fail "no step in the test job runs 'run-live-tests.sh --group ${group}' — the ${group} suite is not executed at all, or the step was renamed/restructured out of range" ;;
                *)              fail "test job's '--group ${group}' step carries an if: — the suite can be silently skipped while CI stays green" ;;
            esac
        done
    fi
else
    fail "live-tests.yml not found at $WORKFLOW (test-job wiring assertions vacuous)"
fi

echo ""
echo "=== ci.yml proto-validate-tests job wiring ==="

# test/proto-validate is a separate module, so a root `go test ./...` does not
# reach it -- verified, not assumed. ci.yml's proto-validate-tests job is the
# ONLY thing running its tests in CI, which makes that job the single point of
# failure for the AC4 helper's entire test suite. Switch it off and every one of
# those tests silently stops running while this suite stays green: the exact
# never-executed-assertion shape LAB-5549 exists to remove.
#
# Reuses the live-tests.yml helpers by repointing $WORKFLOW rather than growing a
# parallel copy of yq_query's no-yq and parse-error handling. Both arms of that
# handling are counted failures, not skips, so this adds no skip credit.
_WORKFLOW_SAVED="$WORKFLOW"
WORKFLOW="$SCRIPT_DIR/../.github/workflows/ci.yml"

# File-existence guard, matching the live-tests.yml block above. Without it a
# renamed or deleted ci.yml makes every assertion below fail with a yq parse
# error that names the wrong cause.
# GATES the block, rather than merely reporting. As a bare fail() this emitted its
# correct diagnostic and then let the assertions run on: two yq errors naming the
# wrong cause, then extract_job_block's unguarded awk aborted the whole suite
# BEFORE the accounting pin. The live-tests.yml sibling gates its block for the
# same reason. Skip credit 3 keeps the pin exact for the three assertions the
# gate skips.
if [ -f "$WORKFLOW" ]; then
    pass "ci.yml is present and readable"

# The job being unconditional is worthless if the WORKFLOW never fires. ci.yml is
# paths-filtered, and the nested module's manifests are not matched by the
# root-scoped go.mod/go.sum patterns -- so a change confined to
# test/proto-validate/go.mod must still trigger the job that tests it.
ci_paths=$(yq_query '.on.pull_request.paths | join(" ")')
case "$ci_paths" in
    __NO_YQ__)    fail_no_yq "ci.yml fires on the nested module's manifests" ;;
    __YQ_ERROR__) fail_yq_error "ci.yml fires on the nested module's manifests" ;;
    *test/proto-validate/go.mod*) pass "ci.yml's paths filter covers test/proto-validate/go.mod" ;;
    *)            fail "ci.yml's paths filter does not name test/proto-validate/go.mod — a change to the nested module's manifest would not trigger the job that tests it" ;;
esac

# has("if"), NOT `.if // "__ABSENT__"`. yq's `//` is jq's alternative operator,
# which falls through on `false` as well as null -- so `if: false`, the single
# most likely way to switch a job off, reads EXACTLY like having no `if:` at all.
# Measured: with `if: false` present, `.if // "__ABSENT__"` returns __ABSENT__
# while `has("if")` returns true. A guard that cannot see the disabling edit is
# the "unable to fail" defect this suite exists to catch.
case "$(yq_query '.jobs["proto-validate-tests"] | has("if")')" in
    __NO_YQ__)    fail_no_yq "ci.yml proto-validate-tests is unconditional" ;;
    __YQ_ERROR__) fail_yq_error "ci.yml proto-validate-tests is unconditional" ;;
    false)        pass "ci.yml proto-validate-tests runs unconditionally (no job-level if:)" ;;
    *)            fail "ci.yml proto-validate-tests has a job-level if: — the nested module's tests can be switched off while this suite stays green" ;;
esac

# Existence of the job is not the property; RUNNING THE NESTED MODULE is. A job
# that still exists but no longer names ./test/proto-validate/... tests nothing.
# The job enters the module with working-directory (there is no go.work, so a
# root-relative module pattern does not resolve). BOTH halves are required: the
# working-directory that selects the module, and a `go test` that actually runs
# its packages. Either alone tests nothing.
# Scoped to the TEST STEP, not the whole job. Grepping the job block for the two
# strings independently passed even with working-directory deleted from the test
# step, because the sibling VET step still supplied one -- the same
# any-two-lines-anywhere hole the timeout-bound assertions had.
pv_block=$(extract_job_block proto-validate-tests)
# Parsed, not truncated with awk. The awk form stopped at the first `run:` key,
# so it pinned YAML KEY ORDER: moving `run:` above `working-directory:` -- identical
# semantics to Actions -- failed the assertion. That traded a false negative for a
# false positive. yq answers the structural question directly.
# BOTH properties, on the SAME step. The awk form this replaced checked
# working-directory AND `-race`; the first yq rewrite kept only the
# working-directory, so `run: go test ./...` -- dropping -race from the only job
# that runs the nested module's tests in CI -- survived at 179/0 while the file
# still visibly contained a -race pin (which by then covered the Makefile alone).
# Fixing the key-order false positive must not cost the property being pinned.
pv_step_wd=$(yq_query '.jobs["proto-validate-tests"].steps[] | select(.run | test("go test")) | .["working-directory"] // "__ABSENT__"')
pv_step_run=$(yq_query '.jobs["proto-validate-tests"].steps[] | select(.run | test("go test")) | .run')
case "$pv_step_wd" in
    __NO_YQ__)    fail_no_yq "ci.yml's go-test step runs inside test/proto-validate with -race" ;;
    __YQ_ERROR__) fail_yq_error "ci.yml's go-test step runs inside test/proto-validate with -race" ;;
    test/proto-validate)
        if printf '%s' "$pv_step_run" | grep -q -- '-race'; then
            pass "ci.yml proto-validate-tests' go-test step runs with working-directory: test/proto-validate AND -race (key-order independent)"
        else
            fail "ci.yml's go-test step lost -race — this job is the only thing running the nested module's tests in CI, so the race detector would stop running there entirely. Got run: $pv_step_run"
        fi ;;
    *)            fail "ci.yml's go-test step must set working-directory: test/proto-validate — without a workspace a root-relative module pattern does not resolve, so the nested module's tests would not run. Got: $pv_step_wd" ;;
esac

# A job-level `if:` is not the only way to switch this off. A step-level `if:`,
# `continue-on-error: true`, or a trailing `|| true` on the test command each
# leave the job green while running nothing that can fail -- the same neutering
# the live-tests.yml block above already checks for.
if printf '%s' "$pv_block" | grep -qE 'continue-on-error:[[:space:]]*true|\|\|[[:space:]]*(true|exit 0|:)[[:space:]]*$|^[[:space:]]+if:'; then
    fail "ci.yml proto-validate-tests contains step-level neutering (continue-on-error, a trailing '|| true', or a step if:) — the job would stay green while testing nothing"
else
    pass "ci.yml proto-validate-tests has no step-level neutering"
fi

else
    # Credit 5, MEASURED: the block emits five counted outcomes (presence, paths
    # filter, job-level if, test-step scoping, step neutering). It credited 3, so
    # renaming ci.yml gave `saw 172` against a pin of 174 -- blaming test
    # maintenance for a missing workflow, the exact wrong-credit failure this
    # repo has been bitten by before.
    skip "ci.yml not found at $WORKFLOW — its five wiring assertions cannot be evaluated" 5
fi

WORKFLOW="$SCRIPT_DIR/../.github/workflows/security.yml"

# security.yml's proto-validate-security job is the ONLY place the nested
# module's dependency graph is scanned, and with go.work deleted its correctness
# rests entirely on two `working-directory` lines. Its ci.yml twin has a whole
# guard block; this job had none, so deleting working-directory (govulncheck then
# re-scans the repo root the reusable job already covers, and exits 0) or adding
# `if: false` left every suite green and the nested module unscanned.
if [ -f "$WORKFLOW" ]; then
    pass "security.yml is present and readable"

    case "$(yq_query '.jobs["proto-validate-security"] | has("if")')" in
        __NO_YQ__)    fail_no_yq "security.yml proto-validate-security is unconditional" ;;
        __YQ_ERROR__) fail_yq_error "security.yml proto-validate-security is unconditional" ;;
        false)        pass "security.yml proto-validate-security runs unconditionally (no job-level if:)" ;;
        *)            fail "security.yml proto-validate-security has a job-level if: — the nested module's dependency scan can be switched off while every suite stays green" ;;
    esac

    # Both scanners pinned BY THEIR run: COMMAND via yq, not by grepping an awk
    # slice. The earlier form extracted from `- name: govulncheck ...` and then
    # grepped the slice for "govulncheck" — which the NAME LINE satisfies. Measured:
    # replacing `run: govulncheck ./...` with `run: true` kept the suite at 179/179
    # while leaving the nested module entirely unscanned. That is the very failure
    # this block exists to prevent, inside the block itself. yq also makes the check
    # independent of YAML key order, the false positive the ci.yml twin already hit.
    pvs_block=$(extract_job_block proto-validate-security)
    if [ -n "$pvs_block" ] && printf '%s' "$pvs_block" | grep -q 'proto-validate'; then
        pass "security.yml proto-validate-security job block extracted (assertions below are non-vacuous)"
    else
        fail "security.yml proto-validate-security job block is empty — the scan-wiring assertions below would pass vacuously; fix extract_job_block rather than deleting them"
    fi

    for pvs_tool in govulncheck gosec; do
        pvs_wd=$(yq_query ".jobs[\"proto-validate-security\"].steps[] | select(.run | test(\"^${pvs_tool} \")) | .[\"working-directory\"] // \"__ABSENT__\"")
        case "$pvs_wd" in
            __NO_YQ__)    fail_no_yq "security.yml's ${pvs_tool} step runs inside test/proto-validate" ;;
            __YQ_ERROR__) fail_yq_error "security.yml's ${pvs_tool} step runs inside test/proto-validate" ;;
            test/proto-validate) pass "security.yml's ${pvs_tool} step RUNS ${pvs_tool} with working-directory: test/proto-validate" ;;
            __ABSENT__)   fail "security.yml has no step whose run: command starts with '${pvs_tool} ', or it lacks working-directory: test/proto-validate — the nested module would go unscanned while every suite stays green" ;;
            *)            fail "security.yml's ${pvs_tool} step runs with working-directory '$pvs_wd', not test/proto-validate — it would scan the repo root the reusable job already covers and leave the nested module unscanned" ;;
        esac
    done

    if printf '%s' "$pvs_block" | grep -qE 'continue-on-error:[[:space:]]*true|\|\|[[:space:]]*(true|exit 0|:)[[:space:]]*$|^[[:space:]]+if:'; then
        fail "security.yml proto-validate-security contains step-level neutering (continue-on-error, a trailing '|| true', or a step if:) — the scan would stay green while detecting nothing"
    else
        pass "security.yml proto-validate-security has no step-level neutering"
    fi
else
    # Credit 4, MEASURED: presence, job-level if, govulncheck-step scoping, step
    # neutering. Credited 3, so renaming security.yml gave `saw 173` against 174.
    # Credit 6, MEASURED: presence, block-extraction sentinel, job-level if,
    # govulncheck step, gosec step, step neutering.
    skip "security.yml not found at $WORKFLOW — its six scan-wiring assertions cannot be evaluated" 6
fi

WORKFLOW="$_WORKFLOW_SAVED"

# ci.yml's job is pinned five ways; the Makefile path that runs the same tests
# locally was pinned nowhere. Without a workspace a root-relative pattern does not
# resolve, so reverting `make test`'s second line to `./test/proto-validate/...`
# makes it fail rather than silently skip -- but nothing asserted the working form,
# and `make test` is what a developer runs before pushing.
# [[:space:]] rather than \t -- POSIX ERE has no \t escape, so the literal form
# matched a backslash followed by 't' and the assertion failed on a correct tree.
if grep -qE '^[[:space:]]+cd test/proto-validate && go test .*-race.*\./\.\.\.' "$SCRIPT_DIR/../Makefile"; then
    pass "Makefile's test target enters test/proto-validate and runs go test -race ./... there"
else
    fail "Makefile's test target must run 'cd test/proto-validate && go test -race ./...' — without a workspace a root-relative module pattern does not resolve, so the nested module's tests would not run locally"
fi

echo ""
echo "=== No Go workspace file (product/scan graph coupling) ==="

# go.work is deliberately absent: a workspace puts test/proto-validate into the
# product's MVS build list, so a bump to that helper's manifest could move the
# shipped binary's dependency set, and the repo-root security scan could then
# report on a graph ABOVE the one that ships. The GOWORK=off belt that used to
# mask this was removed once the workspace went, so recreating the file
# re-couples them silently. Nothing else asserts the absence.
if [ ! -e "$SCRIPT_DIR/../go.work" ]; then
    pass "no go.work at the repo root (product and scan resolve the same graph)"
else
    fail "go.work exists at the repo root — it puts test/proto-validate into the product's MVS build list, so a bump to that helper's manifest can move the shipped binary's dependencies and the security scan can report on a graph above what ships. Delete it; consumers enter the module with cd/working-directory."
fi

echo ""
echo "=== Browser-target classification is exhaustive (no fail-open) ==="
# BROWSER_TARGETS is hand-maintained and decides whether the Chrome preflight is
# fatal. A target missing from it fails OPEN: setup proceeds browserless and the
# target fails later with a confusing error instead of a clear prerequisite one.
# Requiring every ALL_TARGETS member to be classified one way or the other turns
# that into a loud CI failure at the moment a target is added.
NON_BROWSER_TARGETS="grpc-server"
setup_all=$(grep -E '^ALL_TARGETS=' "$SETUP" | sed 's/^ALL_TARGETS=//; s/"//g' | tr ',' ' ')
setup_browser=$(grep -E '^BROWSER_TARGETS=' "$SETUP" | sed 's/^BROWSER_TARGETS=//; s/"//g')
if [[ -z "$setup_all" || -z "$setup_browser" ]]; then
    fail "could not extract ALL_TARGETS/BROWSER_TARGETS from setup-live-targets.sh (assertions vacuous)"
else
    pass "ALL_TARGETS and BROWSER_TARGETS extracted from setup-live-targets.sh"
    unclassified=""
    for t in $setup_all; do
        case " $setup_browser $NON_BROWSER_TARGETS " in
            *" $t "*) ;;
            *) unclassified="$unclassified $t" ;;
        esac
    done
    if [[ -n "$unclassified" ]]; then
        fail "target(s) in ALL_TARGETS classified neither browser nor non-browser:$unclassified"
        fail "  add to BROWSER_TARGETS in setup-live-targets.sh, or to NON_BROWSER_TARGETS in this guard"
    else
        pass "every ALL_TARGETS member is classified browser or non-browser"
    fi
    # And the converse: a BROWSER_TARGETS entry that is not a real target is a
    # typo that silently classifies nothing.
    stale=""
    for t in $setup_browser; do
        case " $setup_all " in *" $t "*) ;; *) stale="$stale $t" ;; esac
    done
    if [[ -n "$stale" ]]; then
        fail "BROWSER_TARGETS names target(s) absent from ALL_TARGETS (typo?):$stale"
    else
        pass "every BROWSER_TARGETS entry is a real target"
    fi
fi

echo ""

# The un-gated `bash -n` chain is the ONLY thing that parses the committed
# assertion scripts, and it is a hardcoded list. A new committed assertion
# script that is not added to it gets no syntax coverage at all — which is the
# whole reason these are files rather than inline blocks. Derive the set that
# should be covered from what the workflow actually execs, and require each.
if [[ -f "$WORKFLOW" ]]; then
    # `|| true` is load-bearing, not defensive noise. The suite runs under
    # `set -euo pipefail`, and while SUITE_COMPLETED used to be set 1119 lines
    # before the summary (it is now set immediately above it), an
    # unmatched grep makes the ASSIGNMENT non-zero, kills the script, and
    # produces exit 1 with no summary, no message, and the EXIT trap's
    # truncation warning suppressed. The vacuity sentinel below — the thing
    # written to report exactly this — becomes unreachable dead code. Measured
    # in a clean child shell: rewriting the Syntax check step without its
    # `bash -n test/...` chain gave rc=1 with an empty last line.
    bn_line=$( { grep -oE 'bash -n test/[a-zA-Z0-9_.-]+\.sh' "$WORKFLOW" || true; } | sed 's/^bash -n //' | sort -u)
    bn_needed=$(grep -oE 'test/assert-[a-zA-Z0-9_.-]+\.sh' "$WORKFLOW" | sort -u || true)
    if [[ -z "$bn_line" || -z "$bn_needed" ]]; then
        fail "could not derive the bash -n list or the assertion-script set from live-tests.yml — the check below would be vacuous"
    else
        bn_missing=""
        while IFS= read -r bn_s; do
            [[ -z "$bn_s" ]] && continue
            printf '%s\n' "$bn_line" | grep -qx "$bn_s" || bn_missing="${bn_missing} ${bn_s}"
        done <<< "$bn_needed"
        if [[ -z "$bn_missing" ]]; then
            pass "every committed test/assert-*.sh the workflow execs is in the un-gated bash -n chain ($(printf '%s' "$bn_needed" | grep -c .) scripts)"
        else
            fail "committed assertion script(s) absent from the un-gated bash -n chain:${bn_missing} — a syntax error in one would first surface on main, which is why they are files"
        fi
    fi
fi

# ── devcontainer-image: the wiring that closes LAB-5064 AC1 ────────────────────
#
# The devcontainer job is the sole automated check that .devcontainer/ still
# builds and still ships a browser the Go side can resolve and drive. It sits in
# exactly the position install-chrome-e2e sits in and had none of the pins that
# job has: measured on PR #228, deleting its whole LookPath assertion step left
# this suite at 135/135 exit 0 and every other check in the repo green.
if [[ -f "$WORKFLOW" ]]; then
    if grep -qE '^  devcontainer-image:' "$WORKFLOW"; then
        pass "devcontainer-image job still defined (the devcontainer wiring has automated coverage)"
        dc_block=$(extract_job_block devcontainer-image)
        if [[ -z "$dc_block" ]]; then
            fail "could not extract the devcontainer-image job block (extraction broken — the assertions below would be vacuous)"
        else
            dc_runlines=$(printf '%s\n' "$dc_block" | grep -vE '^[[:space:]]*#')

            # Built THROUGH devcontainer.json, not around it. A raw
            # `docker build -f .devcontainer/Dockerfile` re-specifies the build by
            # hand, so devcontainer.json's context, containerEnv, runArgs and
            # remoteUser go unparsed and unasserted — breaking any of them changed
            # no signal anywhere in this repo.
            # Backslash-continuations are joined first: the invocation spans
            # several lines, so a per-line grep for "build ... --workspace-folder"
            # can never match it. Safe here because these are `grep -q`
            # existence tests — joining before a `grep -c` is what silently
            # broke a count elsewhere in this repo's history, and that is a
            # different operation.
            dc_joined=$(printf '%s\n' "$dc_runlines" | sed -e ':a' -e '/\\$/{N; s/\\\n[[:space:]]*//; ta}')
            if printf '%s\n' "$dc_joined" | grep -qE '@devcontainers/cli@[0-9]' \
               && printf '%s\n' "$dc_joined" | grep -qE 'build[[:space:]].*--workspace-folder'; then
                pass "devcontainer-image builds through devcontainer.json (@devcontainers/cli, pinned, --workspace-folder)"
            else
                fail "devcontainer-image no longer builds through devcontainer.json — a hand-written docker build leaves the file developers actually use unparsed and unasserted"
            fi

            # A successful build is AC4's only proof, and only the in_container()
            # arm emits this marker; the other arm prints "No temporary apt
            # artifacts left behind". Without the grep the build can suppress the
            # phone-home artifacts without ever confirming their absence.
            if printf '%s\n' "$dc_runlines" | grep -qF 'No Google apt source, keyring, or update pinger left behind'; then
                pass "devcontainer-image asserts install-chrome.sh took its in_container() branch (AC4's verify-absent pass ran)"
            else
                fail "devcontainer-image no longer greps the in_container() marker — the build could suppress phone-home artifacts without verifying their absence, and AC4 becomes an assumption"
            fi

            # Both committed assertion scripts must still be invoked. They are
            # committed rather than inline precisely so the un-gated `bash -n`
            # step can see them; dropping the invocation leaves the file present
            # and syntactically fine while nothing runs it.
            # The invocation SHAPE, not the path. The whole value of these steps
            # is that they run INSIDE the built image via `devcontainer exec`; a
            # bare path grep cannot see `exec` and is satisfied by
            # `run: bash test/assert-devcontainer-lookpath.sh`, which executes on
            # the ubuntu-24.04 runner instead. That is worse than a silent-green
            # guard: the runner ships its own Chrome, so the host-side run can
            # PASS, leaving a green "resolves and launches" step that never
            # touched the image. Matched on the continuation-joined stream so a
            # multi-line invocation still reads as one line.
            for dc_script in assert-chrome-install.sh assert-devcontainer-lookpath.sh; do
                if printf '%s\n' "$dc_joined" | grep -qE "exec[[:space:]].*--workspace-folder.*test/${dc_script//./\\.}"; then
                    pass "devcontainer-image invokes test/${dc_script} INSIDE the image (exec + --workspace-folder)"
                else
                    fail "devcontainer-image does not invoke test/${dc_script} via 'devcontainer exec --workspace-folder' — either the step is gone, or it was changed to run on the host, where the runner's own Chrome can make it pass without ever touching the built image"
                fi
            done

            # The image is only useful if the suites the repo tells contributors
            # to run actually run in it. This is what caught the missing yq.
            if printf '%s\n' "$dc_runlines" | grep -qE 'test/test-runner-args\.sh'; then
                pass "devcontainer-image runs a guard suite inside the image (prerequisites are asserted by execution, not by prose)"
            else
                fail "devcontainer-image no longer runs a guard suite inside the image — a missing prerequisite (python3, yq, spec-validator deps) would surface in a developer's terminal instead of in CI"
            fi

            # The two steps added to close AC3 and to assert the applied
            # devcontainer.json config are pinned like the others: without this,
            # deleting either left the suite green and the criterion unevidenced.
            for dc_step in 'run-live-tests.sh --no-build --group live' 'id -un'; do
                if printf '%s\n' "$dc_joined" | grep -qF -- "$dc_step"; then
                    pass "devcontainer-image still carries the step containing '${dc_step}'"
                else
                    fail "devcontainer-image no longer carries the step containing '${dc_step}' — either AC3's only in-image evidence or the devcontainer.json conformance assertion was dropped"
                fi
            done

            # TEST-014: the arm64 leg was pinned only by its if:. Its build step
            # and its in_container marker grep are the whole point of the job.
            arm_block=$( { extract_job_block devcontainer-image-arm64 || true; } | grep -vE '^[[:space:]]*#' || true)
            if [[ -z "$arm_block" ]]; then
                fail "could not extract the devcontainer-image-arm64 job block — the assertions below would be vacuous"
                # Credit the outcome the else-arm does not emit, so this reports
                # the REAL cause instead of also tripping the accounting pin with
                # a misleading "assertion accounting drift".
                skip "devcontainer-image-arm64 in_container marker (job block unreadable)" 1
            else
                if printf '%s\n' "$arm_block" | grep -qE 'buildx build.*--platform linux/arm64|--platform linux/arm64'; then
                    pass "devcontainer-image-arm64 still cross-builds for linux/arm64"
                else
                    fail "devcontainer-image-arm64 no longer builds --platform linux/arm64 — the multi-arch claim rests on registry inspection again"
                fi
                if printf '%s\n' "$arm_block" | grep -qF 'No Google apt source, keyring, or update pinger left behind'; then
                    pass "devcontainer-image-arm64 still asserts the in_container() marker on the arm64 build"
                else
                    fail "devcontainer-image-arm64 no longer greps the in_container() marker — AC4 is unasserted on that architecture"
                fi
            fi

            # Same three neutering shapes the preflight-selftest and
            # install-chrome-e2e blocks reject for themselves.
            if printf '%s\n' "$dc_runlines" | grep -qE '^[[:space:]]*continue-on-error:[[:space:]]*true'; then
                fail "devcontainer-image sets continue-on-error: true — a failing image build would not fail CI"
            else
                pass "devcontainer-image has no continue-on-error: true"
            fi
            if printf '%s\n' "$dc_runlines" | grep -qE '\|\|[[:space:]]*(true|exit 0|:)([[:space:]]|$)'; then
                fail "devcontainer-image neuters a step with a trailing '|| true'/'|| exit 0'/'|| :'"
            else
                pass "devcontainer-image has no trailing '|| true'/'|| exit 0'/'|| :' step neutering"
            fi

            # The gate. Three arms now: the original opt-in pair, plus the
            # pull_request arm that builds the image before merge when the PR
            # actually touches it. Losing the third arm silently restores the
            # state where .devcontainer/ merges unverified and breaks on main.
            # Both image jobs consume one computed gate, so assert the GATE'S
            # BEHAVIOUR rather than tokens in an expression. The previous form was
            # three unanchored substring searches for `workflow_dispatch`,
            # `refs/heads/main` and `pull_request`; swapping the two `||`
            # operators for `&&` keeps all three tokens, satisfies all three
            # greps, and yields a condition no event can satisfy — the job would
            # silently never run again. Tokens cannot express disjunction, so this
            # extracts the gate step's shell and RUNS it against synthetic events,
            # the same execute-and-observe approach the assert-chrome-install.sh
            # block below uses instead of grepping.
            gate_body=$(yq_query '.jobs["devcontainer-changes"].steps[] | select(.id == "gate") | .run' -r)
            case "$gate_body" in
                __NO_YQ__) fail_no_yq "the devcontainer gate's behaviour" ;;
                __YQ_ERROR__) fail_yq_error "the devcontainer gate's behaviour" ;;
                "" ) fail "could not extract the devcontainer-changes gate step's run: body — the behaviour assertions below would be vacuous" ;;
                *)
                    gate_bad=""
                    # event | ref | filter-output | expected run=
                    while IFS='|' read -r ev ref filt want; do
                        [ -z "$ev" ] && continue
                        # The gate reads its context from env: rather than having
                        # ${{ }} interpolated into its body, so the harness sets
                        # those variables instead of substituting tokens. That is
                        # both simpler and the reason the injection class is gone:
                        # nothing attacker-shaped reaches the shell source.
                        got=$(
                            GITHUB_OUTPUT=$(mktemp)
                            export GITHUB_OUTPUT EVENT_NAME="$ev" REF="$ref" FILTER="$filt"
                            bash -c "$gate_body" >/dev/null 2>&1
                            sed -n 's/^run=//p' "$GITHUB_OUTPUT" | tail -1
                            rm -f "$GITHUB_OUTPUT"
                        )
                        [ "$got" = "$want" ] || gate_bad="${gate_bad} ${ev}/${ref}/${filt}:got=${got:-<none>},want=${want}"
                    done <<'GATECASES'
workflow_dispatch|refs/heads/anything|false|true
push|refs/heads/main|false|true
push|refs/heads/other|true|false
pull_request|refs/pull/1/merge|true|true
pull_request|refs/pull/1/merge|false|false
GATECASES
                    if [ -z "$gate_bad" ]; then
                        pass "the devcontainer gate fires on exactly the three intended arms (5 synthetic events, executed not grepped)"
                    else
                        fail "the devcontainer gate does not behave as intended —${gate_bad}. An &&-joined or narrowed gate can keep every token and still never fire."
                    fi
                    ;;
            esac

            # The harness above proves the STEP computes the right value. The
            # job-level output is the only wire from that step to the two
            # consumers, and nothing read it: hardcoding it to 'false' switched
            # both image jobs off permanently while every harness case still
            # reported correct.
            dc_wire=$(yq_query '.jobs["devcontainer-changes"].outputs["should-run"]' -r)
            case "$dc_wire" in
                __NO_YQ__) fail_no_yq "the devcontainer-changes should-run wire" ;;
                __YQ_ERROR__) fail_yq_error "the devcontainer-changes should-run wire" ;;
                *steps.gate.outputs.run*)
                    pass "devcontainer-changes' should-run output is wired to the gate step's own result" ;;
                *)
                    fail "devcontainer-changes' should-run output is not wired to steps.gate.outputs.run (got: ${dc_wire}) — the executed gate harness would still pass while both image jobs are switched off" ;;
            esac

            # The harness substitutes steps.filter.outputs.devcontainer with a
            # literal, so it is blind to whether the producing step exists at
            # all. Renaming `id: filter` leaves the third arm comparing "" to
            # "true" — it can never fire — with every harness case still green.
            dc_filter_id=$(yq_query '[.jobs["devcontainer-changes"].steps[] | select(.id == "filter")] | length' -o=json -I=0)
            # The watch list moved out of a marketplace action's `with.filters`
            # into the step's own shell (WATCHED=), because dorny/paths-filter is
            # not on this org's Actions allowlist and referencing it made the
            # whole workflow fail at STARTUP — no jobs, no annotations, no logs.
            dc_filter_paths=$(yq_query '.jobs["devcontainer-changes"].steps[] | select(.id == "filter") | .run' -r)
            case "$dc_filter_id" in
                __NO_YQ__) fail_no_yq "the devcontainer paths-filter step" ;;
                __YQ_ERROR__) fail_yq_error "the devcontainer paths-filter step" ;;
                1) pass "the devcontainer-changes step the gate reads is still id: filter" ;;
                *) fail "devcontainer-changes has no step with id: filter (found ${dc_filter_id}) — steps.filter.outputs.devcontainer resolves empty, so the pull_request arm compares \"\" to \"true\" and can never fire" ;;
            esac
            dc_filter_missing=""
            # dc_filter_paths carries yq's sentinel when yq is absent or the
            # workflow is unparseable. The case above switches on dc_filter_id,
            # not on this, so without an explicit check the loop below would grep
            # the literal string __NO_YQ__ for nine paths, find none, and report
            # every watched path as missing — naming the wrong defect.
            case "$dc_filter_paths" in
                __NO_YQ__|__YQ_ERROR__|"")
                    dc_filter_paths="" ;;
            esac
            # go.mod is in this list because the conformance step READS it: the
            # in-image check compares the container's toolchain against go.mod's
            # `go` directive. Bumping that directive is exactly the change that
            # broke the image (1.25.12 shipped against a go.mod asking 1.27.0),
            # and without go.mod watched, that PR does not run this job at all.
            for dc_need in '.devcontainer/\*' '.dockerignore' '.github/workflows/live-tests.yml' \
                           'go.mod' 'test/install-chrome.sh' 'test/common.sh' \
                           'test/assert-chrome-install.sh' 'test/assert-devcontainer-lookpath.sh' \
                           'test/setup-live-targets.sh' 'test/run-live-tests.sh'; do
                printf '%s\n' "$dc_filter_paths" | grep -qF -- "${dc_need//\\/}" || dc_filter_missing="${dc_filter_missing} ${dc_need//\\/}"
            done
            if [[ -z "$dc_filter_paths" ]]; then
                fail "could not read the devcontainer filter step's watch list (yq unavailable or the workflow is unparseable) — the coverage check below would be vacuous"
            elif [[ -z "$dc_filter_missing" ]]; then
                pass "the devcontainer paths filter still covers every path the image build and its in-image steps read"
            else
                fail "the devcontainer paths filter no longer covers:${dc_filter_missing} — a PR touching one of those would not build or verify the image before merge"
            fi

            # The gate must take its context through env:, not ${{ }} in the body.
            # GitHub substitutes ${{ }} into the source before bash parses it, so
            # a ref carrying $(...) would execute. Cheap to assert, and it also
            # keeps the harness above honest — it drives the gate through the same
            # env vars the runner would set.
            gate_env=$(yq_query '.jobs["devcontainer-changes"].steps[] | select(.id == "gate") | .env | keys | join(" ")' -r)
            case "$gate_env" in
                __NO_YQ__) fail_no_yq "the gate step's env: block" ;;
                __YQ_ERROR__) fail_yq_error "the gate step's env: block" ;;
                *EVENT_NAME*REF*|*EVENT_NAME*FILTER*|*FILTER*REF*)
                    if printf '%s\n' "$gate_body" | grep -q '\${{'; then
                        fail "the gate step still interpolates \${{ }} into its shell body — a ref containing \$(...) is executed before bash parses the line"
                    else
                        pass "the gate step takes its context through env: and interpolates nothing into its shell body"
                    fi ;;
                *)
                    fail "the gate step's env: does not carry EVENT_NAME/REF/FILTER (got: ${gate_env}) — the harness drives it through those, and without them the gate must be interpolating \${{ }} instead" ;;
            esac

            # Both image jobs must consume that one gate rather than restating it.
            for dc_job in devcontainer-image devcontainer-image-arm64; do
                dc_if=$(yq_query ".jobs[\"${dc_job}\"].if" -r)
                case "$dc_if" in
                    __NO_YQ__) fail_no_yq "${dc_job}'s if: gate" ;;
                    __YQ_ERROR__) fail_yq_error "${dc_job}'s if: gate" ;;
                    "needs.devcontainer-changes.outputs.should-run == 'true'")
                        pass "${dc_job}'s if: is EXACTLY the shared gate (no prefix, no extra conjunct)" ;;
                    *)
                        # Exact, not a substring match. A glob accepts
                        # `${{ false && needs.devcontainer-changes.outputs.should-run == 'true' }}`,
                        # which carries the required text and can never be true —
                        # the same defeat the producer side was rebuilt as an
                        # executed harness to prevent, left open on the consumer.
                        fail "${dc_job}'s if: is not exactly \"needs.devcontainer-changes.outputs.should-run == 'true'\" (got: ${dc_if}) — a restated or prefixed gate desynchronises the legs, and a 'false &&' prefix keeps the text while never firing" ;;
                esac
            done
        fi
    else
        fail "devcontainer-image job is gone from live-tests.yml — nothing builds .devcontainer/Dockerfile, and LAB-5064's AC1 wiring can rot invisibly"
    fi

    # The paths filter the pull_request arm depends on. Without this job the
    # third arm above evaluates against an undefined output and never fires.
    if grep -qE '^  devcontainer-changes:' "$WORKFLOW"; then
        pass "devcontainer-changes job still defined (the pull_request arm has a filter to gate on)"
    else
        fail "devcontainer-changes job is gone — devcontainer-image's pull_request arm gates on an undefined output and can never fire"
    fi
fi

# ── test/assert-devcontainer-lookpath.sh: EXECUTED, not grepped ────────────────
#
# The script's load-bearing logic is its per-test `--- PASS: NAME (` loop, and
# nothing tested it. `go test` exits 0 on a skip — the script's own comment says
# so — so that loop is the ONLY thing separating "the browser resolved and
# launched" from "every test skipped" or "the -run regex matched nothing".
# Deleting the loop left `bash -n` happy and this suite green.
#
# Its sibling test/assert-chrome-install.sh is covered far more strongly in this
# same file: executed against a stub browser on a prepared PATH, with the result
# observed rather than grepped. Same treatment here — a stub `go` printing a
# synthetic `go test -v` transcript, three transcripts, three observed outcomes.
if [[ -x "$SCRIPT_DIR/assert-devcontainer-lookpath.sh" ]]; then
    adl_tmp=$(mktemp -d)
    adl_stub="$adl_tmp/bin"
    mkdir -p "$adl_stub"
    # run_adl <transcript-file> -> exit code of the script under a stub `go`
    run_adl() {
        cat > "$adl_stub/go" <<STUB
#!/usr/bin/env bash
cat "\$ADL_TRANSCRIPT"
exit 0
STUB
        chmod 0755 "$adl_stub/go"
        ADL_TRANSCRIPT="$1" PATH="$adl_stub:$PATH" \
            bash "$SCRIPT_DIR/assert-devcontainer-lookpath.sh" >/dev/null 2>&1
        echo $?
    }
    adl_all_pass="$adl_tmp/all-pass.txt"
    {
        for t in TestBrowserManager_LaunchAndKill TestBrowserManager_KillIdempotent \
                 TestBrowserManager_Close TestBrowserManager_CloseIdempotent \
                 TestConfigureLauncher_PinsSystemBrowser; do
            printf -- '=== RUN   %s\n--- PASS: %s (0.01s)\n' "$t" "$t"
        done
        printf 'PASS\nok  \tgithub.com/praetorian-inc/vespasian/pkg/crawl\t0.05s\n'
    } > "$adl_all_pass"

    # (1) The honest green path must be green, or the other two prove nothing.
    if [[ "$(run_adl "$adl_all_pass")" -eq 0 ]]; then
        pass "assert-devcontainer-lookpath.sh accepts a transcript where all five tests PASS (executed against a stub go, not grepped)"
    else
        fail "assert-devcontainer-lookpath.sh rejects an all-PASS transcript — the script is broken, or this harness no longer drives it"
    fi

    # (2)+(3) EVERY required name, not just one. The earlier version derived
    # both negative cases by sed-ing only TestConfigureLauncher_PinsSystemBrowser,
    # so it proved that ONE of the five entries was required and anchored.
    # The four TestBrowserManager_* names are the ones LAB-5064 AC1 is worded
    # around — and the script's own header says PinsSystemBrowser is the one
    # that runs even where Chrome cannot launch, so the four launch tests are
    # precisely the ones whose PASS evidences a runnable browser. Deleting any
    # of them from REQUIRED_TESTS left all three cases passing.
    #
    # Names are read from the script itself, so adding a sixth required test
    # extends this coverage automatically rather than silently escaping it.
    adl_required=$(sed -n '/^REQUIRED_TESTS=(/,/^)/p' "$SCRIPT_DIR/assert-devcontainer-lookpath.sh" \
                   | { grep -oE 'Test[A-Za-z0-9_]+' || true; })
    # `grep -c .` EXITS 1 when the count is 0, so a bare assignment here dies
    # under `set -euo pipefail` — which made the `adl_n -lt 2` sentinel below,
    # and the skip credit added beside it, unreachable dead code. Guarding the
    # extraction was not enough; the COUNT needed it too.
    adl_n=$(printf '%s\n' "$adl_required" | grep -c . || true)

    # The list must match an INDEPENDENT source of truth, or the per-name cases
    # below are self-referential: they derive their names from REQUIRED_TESTS, so
    # DELETING an entry simply shrinks what they check and every case still
    # passes. Measured — dropping TestBrowserManager_LaunchAndKill left the suite
    # at 170/0. The real authority is pkg/crawl/browser_integration_test.go: the
    # launch/kill/close tests LAB-5064 AC1 names are whatever
    # TestBrowserManager_* functions exist there.
    adl_srcfile="$SCRIPT_DIR/../pkg/crawl/browser_integration_test.go"
    if [[ ! -f "$adl_srcfile" ]]; then
        fail "pkg/crawl/browser_integration_test.go not found — the REQUIRED_TESTS completeness check would be vacuous"
    else
        adl_expected=$( { grep -oE '^func (TestBrowserManager_[A-Za-z0-9_]+|TestConfigureLauncher_PinsSystemBrowser)' "$adl_srcfile" || true; } \
                       | sed 's/^func //' | sort -u)
        adl_exp_n=$(printf '%s\n' "$adl_expected" | grep -c . || true)
        if [[ "$adl_exp_n" -lt 2 ]]; then
            fail "derived only ${adl_exp_n} integration test name(s) from browser_integration_test.go — the completeness check would be vacuous"
        else
            adl_absent=""
            while IFS= read -r adl_e; do
                [[ -z "$adl_e" ]] && continue
                printf '%s\n' "$adl_required" | grep -qx "$adl_e" || adl_absent="${adl_absent} ${adl_e}"
            done <<< "$adl_expected"
            if [[ -z "$adl_absent" ]]; then
                pass "assert-devcontainer-lookpath.sh requires every launch/kill/close test that exists in browser_integration_test.go (${adl_exp_n} names)"
            else
                fail "assert-devcontainer-lookpath.sh's REQUIRED_TESTS is missing:${adl_absent} — those are the tests LAB-5064 AC1 is worded around, and dropping one silently stops the image being asked to launch a browser"
            fi
        fi
    fi
    if [[ "$adl_n" -lt 2 ]]; then
        fail "could not derive REQUIRED_TESTS from assert-devcontainer-lookpath.sh (got ${adl_n} names) — the per-name cases below would be vacuous"
        skip "assert-devcontainer-lookpath.sh PASS anchoring (REQUIRED_TESTS unreadable)" 1
    else
        adl_skip_bad=""; adl_anchor_bad=""
        while IFS= read -r adl_t; do
            [[ -z "$adl_t" ]] && continue
            sed "s/--- PASS: ${adl_t} (/--- SKIP: ${adl_t} (/" "$adl_all_pass" > "$adl_tmp/skip.txt"
            [[ "$(run_adl "$adl_tmp/skip.txt")" -ne 0 ]] || adl_skip_bad="${adl_skip_bad} ${adl_t}"
            sed "s/--- PASS: ${adl_t} (/--- PASS: ${adl_t}Extra (/" "$adl_all_pass" > "$adl_tmp/sib.txt"
            [[ "$(run_adl "$adl_tmp/sib.txt")" -ne 0 ]] || adl_anchor_bad="${adl_anchor_bad} ${adl_t}"
        done <<< "$adl_required"
        if [[ -z "$adl_skip_bad" ]]; then
            pass "assert-devcontainer-lookpath.sh rejects a SKIP for EVERY one of its ${adl_n} required tests (go test exits 0 on a skip)"
        else
            fail "assert-devcontainer-lookpath.sh accepts a SKIPPED run for:${adl_skip_bad} — the job would go green having asserted nothing about the browser for those tests"
        fi
        if [[ -z "$adl_anchor_bad" ]]; then
            pass "assert-devcontainer-lookpath.sh's PASS match is anchored for EVERY one of its ${adl_n} required tests"
        else
            fail "assert-devcontainer-lookpath.sh accepts a longer sibling name in place of:${adl_anchor_bad} — the PASS match lost its trailing ' (' anchor"
        fi
    fi
    # (4) The rc != 0 arm. A failing `go test` must be reported
    #     environment-neutrally, not blamed on browser resolution.
    cat > "$adl_stub/go" <<'STUBFAIL'
#!/usr/bin/env bash
echo "build failed: some unrelated compile error" >&2
exit 2
STUBFAIL
    chmod 0755 "$adl_stub/go"
    if PATH="$adl_stub:$PATH" bash "$SCRIPT_DIR/assert-devcontainer-lookpath.sh" >/dev/null 2>&1; then
        fail "assert-devcontainer-lookpath.sh exits 0 when go test fails (rc=2) — a compile or module error would pass as a browser assertion"
    else
        pass "assert-devcontainer-lookpath.sh propagates a failing go test (rc != 0 arm exercised)"
    fi

    rm -rf "$adl_tmp"
    unset -f run_adl
else
    fail "test/assert-devcontainer-lookpath.sh is missing or not executable — the devcontainer job's Go-side assertion cannot run"
    # The then-arm emits FIVE counted outcomes; this arm emits one. Without the
    # credit the suite reported `177 passed, 1 failed` against the pin and then
    # `assertion accounting drift`, which names a stale ledger instead of the
    # missing script. MEASURED by moving the script aside.
    skip "assert-devcontainer-lookpath.sh cases (script absent)" 4
fi

# ── harden-runner: count and pin, not just prose ───────────────────────────────
#
# The lockstep comment states its own failure mode ("bump ALL SEVEN copies in
# lockstep — a missed copy silently leaves a job on a stale pin") and nothing
# computed either half. Measured on PR #228: deleting one harden-runner step left
# six comments claiming seven beside six actual steps, with every check green.
if [[ -f "$WORKFLOW" ]]; then
    hr_steps=$( { grep -cE '^[[:space:]]*uses:[[:space:]]*step-security/harden-runner@' "$WORKFLOW" || true; } )
    hr_word=$(grep -oE 'bump ALL [A-Z]+ copies' "$WORKFLOW" | head -1 | awk '{print $3}')
    declare -A hr_numbers=( [ONE]=1 [TWO]=2 [THREE]=3 [FOUR]=4 [FIVE]=5 [SIX]=6 [SEVEN]=7 [EIGHT]=8 [NINE]=9 [TEN]=10 )
    hr_claimed=${hr_numbers[${hr_word:-NONE}]:-}
    if [[ -z "$hr_claimed" ]]; then
        fail "could not read the harden-runner lockstep comment's number-word from ${WORKFLOW} (the count check below would be vacuous) — got '${hr_word:-<none>}'"
    elif [[ "$hr_steps" -eq "$hr_claimed" ]]; then
        pass "harden-runner step count ($hr_steps) matches the lockstep comment's claim ($hr_word)"
    else
        fail "harden-runner drift: ${hr_steps} step(s) present but the lockstep comment claims ${hr_word} (${hr_claimed}) — a job gained or lost the control without the comment moving"
    fi

    # Every copy of the comment must claim the same number, or bumping "one" of
    # them is meaningless.
    hr_word_variants=$(grep -oE 'bump ALL [A-Z]+ copies' "$WORKFLOW" | sort -u | wc -l | tr -d ' ')
    if [[ "$hr_word_variants" -eq 1 ]]; then
        pass "all harden-runner lockstep comments claim the same count"
    else
        fail "the harden-runner lockstep comment disagrees with itself across copies (${hr_word_variants} distinct claims) — at least one was updated and the rest were not"
    fi

    # AGENTS.md states the non-container job count in prose, and prose is what
    # went stale twice: it said "the six non-container jobs" when seven were
    # non-container, was corrected to "eight", and was wrong again the moment a
    # tenth job landed. Derive both numbers and compare, so the third recurrence
    # is a failing assertion rather than a review finding.
    agents_md="$SCRIPT_DIR/../AGENTS.md"
    if [[ -f "$agents_md" ]]; then
        # A job declares `container:` at job level; everything else is non-container.
        nc_actual=$(yq_query '[.jobs[] | select(has("container") | not)] | length' -o=json -I=0)
        nc_word=$(grep -oE '(One|Two|Three|Four|Five|Six|Seven|Eight|Nine|Ten) of the (one|two|three|four|five|six|seven|eight|nine|ten) non-container jobs' "$agents_md" | head -1 | awk '{print $4}')
        declare -A nc_numbers=( [one]=1 [two]=2 [three]=3 [four]=4 [five]=5 [six]=6 [seven]=7 [eight]=8 [nine]=9 [ten]=10 )
        nc_claimed=${nc_numbers[${nc_word:-none}]:-}
        case "$nc_actual" in
            # Both sentinels credit 1: the `*` arm below emits TWO counted
            # outcomes (the non-container count AND the harden-runner word from
            # the same AGENTS.md sentence, nested in this same arm). Without the
            # credit a yq-less host reported `157 passed, 19 failed` and then a
            # spurious `accounting drift` on top of 18 correct yq diagnostics.
            # MEASURED with a PATH holding every executable except yq.
            __NO_YQ__) fail_no_yq "the non-container job count"
                       skip "AGENTS.md harden-runner word (yq unavailable)" 1 ;;
            __YQ_ERROR__) fail_yq_error "the non-container job count"
                          skip "AGENTS.md harden-runner word (workflow unparseable)" 1 ;;
            *)
                if [[ -z "$nc_claimed" ]]; then
                    fail "could not read AGENTS.md's non-container job count claim (the comparison below would be vacuous) — got '${nc_word:-<none>}'"
                elif [[ "$nc_actual" -eq "$nc_claimed" ]]; then
                    pass "AGENTS.md's non-container job count ($nc_word) matches live-tests.yml ($nc_actual)"
                else
                    fail "AGENTS.md claims ${nc_word} (${nc_claimed}) non-container jobs but live-tests.yml has ${nc_actual} — the prose went stale when a job was added or gained a container:"
                fi

                # The sentence carries TWO numbers — "<N> of the <M> non-container
                # jobs open with harden-runner" — and pinning only M let the N half
                # go stale the moment a job gained the step. Pin both.
                hr_word_agents=$(grep -oE '(One|Two|Three|Four|Five|Six|Seven|Eight|Nine|Ten) of the (one|two|three|four|five|six|seven|eight|nine|ten) non-container jobs' "$agents_md" | head -1 | awk '{print $1}')
                declare -A hr_agents_numbers=( [One]=1 [Two]=2 [Three]=3 [Four]=4 [Five]=5 [Six]=6 [Seven]=7 [Eight]=8 [Nine]=9 [Ten]=10 )
                hr_agents_claimed=${hr_agents_numbers[${hr_word_agents:-None}]:-}
                hr_actual_steps=$( { grep -cE '^[[:space:]]*uses:[[:space:]]*step-security/harden-runner@' "$WORKFLOW" || true; } )
                if [[ -z "$hr_agents_claimed" ]]; then
                    fail "could not read AGENTS.md's harden-runner job-count claim (the comparison would be vacuous) — got '${hr_word_agents:-<none>}'"
                elif [[ "$hr_actual_steps" -eq "$hr_agents_claimed" ]]; then
                    pass "AGENTS.md's harden-runner job count ($hr_word_agents) matches live-tests.yml ($hr_actual_steps steps)"
                else
                    fail "AGENTS.md says ${hr_word_agents} (${hr_agents_claimed}) non-container jobs open with harden-runner but live-tests.yml has ${hr_actual_steps} — the prose went stale when a job gained or lost the step"
                fi
                ;;
        esac
    else
        fail "AGENTS.md not found — its job-count claim cannot be checked"
    # The normal arm emits TWO counted outcomes from this one AGENTS.md sentence —
    # the non-container job count and the harden-runner word. MEASURED with the file
    # removed: 234 + 1 = 235 against a pin of 236.
    skip "AGENTS.md harden-runner word (AGENTS.md absent)" 1
    fi

    # The pin itself. Counting copies says nothing about whether they agree on a
    # SHA, which is the property the comment actually cares about. ci.yml carries
    # its own copy and is included deliberately: a partial bump across files is
    # the same defect across a file boundary.
    # ci.yml is named in the failure message, so its absence must be a failure
    # rather than a silently dropped file — `2>/dev/null` on the grep would have
    # hidden it and still reported success over live-tests.yml alone.
    hr_ci="$(dirname "$WORKFLOW")/ci.yml"
        hr_ci_present=1
    if [[ ! -f "$hr_ci" ]]; then
            hr_ci_present=0
        fail "ci.yml not found at ${hr_ci} — it carries a harden-runner copy this check claims to cover, so the pin-uniformity assertion would be silently narrower than its own message"
        hr_ci="$WORKFLOW"
    fi
    # Every use must be SHA-pinned. Matching only @<40-hex> means a copy reverted
    # to a mutable tag (@v2.20.0) is not counted at all, so one remaining pinned
    # copy still reports "1 distinct sha" and the check passes over a job that
    # lost its pin entirely.
    hr_all_uses=$(grep -rhoE 'step-security/harden-runner@[^[:space:]]+' "$WORKFLOW" "$hr_ci" | sed 's/#.*//' | sort -u)
    hr_unpinned=$(printf '%s\n' "$hr_all_uses" | grep -vE '@[0-9a-f]{40}$' || true)
    if [[ -n "$hr_unpinned" ]]; then
        fail "harden-runner use(s) are not SHA-pinned: $(printf '%s ' $hr_unpinned) — a mutable tag defeats the pin the lockstep comment exists to protect"
    else
        pass "every harden-runner use across live-tests.yml and ci.yml is SHA-pinned (no mutable tags)"
    fi
    # Which jobs, not just how many. A count is satisfied by moving the control
    # from a job that needs it to one that does not.
    hr_expected="preflight-selftest validator-regression docs-check devcontainer-changes devcontainer-image devcontainer-image-arm64 integration-tests test"
    hr_actual=$(yq_query '[.jobs | to_entries[] | select(.value.steps[]?.uses? // "" | test("step-security/harden-runner")) | .key] | sort | join(" ")' -r)
    case "$hr_actual" in
        __NO_YQ__) fail_no_yq "which jobs carry harden-runner" ;;
        __YQ_ERROR__) fail_yq_error "which jobs carry harden-runner" ;;
        *)
            hr_want=$(printf '%s\n' $hr_expected | sort | tr '\n' ' ' | sed 's/ $//')
            hr_got=$(printf '%s\n' $hr_actual | sort | tr '\n' ' ' | sed 's/ $//')
            if [[ "$hr_want" == "$hr_got" ]]; then
                pass "harden-runner is carried by exactly the expected 8 jobs, by name"
            else
                fail "harden-runner job set changed — expected [${hr_want}] got [${hr_got}]; a count alone would not notice the control moving between jobs"
            fi ;;
    esac

    hr_shas=$(grep -rhoE 'step-security/harden-runner@[0-9a-f]{40}' "$WORKFLOW" "$hr_ci" | sort -u)
    hr_sha_count=$(printf '%s\n' "$hr_shas" | grep -c . || true)
    if [[ "$hr_sha_count" -eq 0 ]]; then
        fail "found no SHA-pinned harden-runner uses at all (the pin-uniformity check would be vacuous) — is the action still SHA-pinned?"
    elif [[ "${hr_ci_present:-1}" -eq 0 ]]; then
        : # ci.yml is absent, and its not-found fail above already stands as this
          # block's outcome. Emitting a cross-FILE uniformity pass over ONE file
          # would be a false claim, and emitting it in ADDITION to that fail put
          # the block one counted outcome above the pin — MEASURED: saw 237 vs 236.
          #
          # This arm sits ABOVE the -eq 1 case, so in the ci.yml-absent state it
          # swallows EVERY non-zero count, not only the count-of-1 it was written
          # for: with ci.yml gone AND a divergent SHA in live-tests.yml, no
          # 'DIFFERENT SHAs' message is emitted. That is a deliberate trade, not
          # an oversight — tightening it to `&& "$hr_sha_count" -eq 1` re-
          # introduces the 237-vs-236 overcount in exactly that sub-case. It is
          # tolerable because the arm is unreachable while ci.yml exists, and in
          # the ci.yml-absent state the suite is already red on two other counted
          # outcomes, so no GREEN run can hide a divergence behind it.
          # block's outcome. Emitting a cross-FILE uniformity pass over ONE file
          # would be a false claim, and emitting it in ADDITION to that fail put
          # the block one counted outcome above the pin — MEASURED: saw 237 vs 236.
    elif [[ "$hr_sha_count" -eq 1 ]]; then
        pass "every harden-runner copy across live-tests.yml and ci.yml pins the same SHA"
    else
        fail "harden-runner copies pin ${hr_sha_count} DIFFERENT SHAs — a bump missed at least one copy, leaving a job on a stale pin: $(printf '%s ' $hr_shas)"
    fi
fi

# ── .devcontainer/Dockerfile: the COPY sources must exist ──────────────────────
#
# The Dockerfile hardcodes repo-relative paths that only `docker build` resolves,
# and that build is gated. Renaming test/common.sh would leave every un-gated
# check green and break the image — the exact failure the Dockerfile's own
# comment warns about ("copying the installer alone fails at `source`").
DEVCONTAINER_DOCKERFILE="$SCRIPT_DIR/../.devcontainer/Dockerfile"
if [[ -f "$DEVCONTAINER_DOCKERFILE" ]]; then
    copy_sources=$(grep -oE '^COPY[[:space:]]+.*[[:space:]]/' "$DEVCONTAINER_DOCKERFILE" \
        | sed -E 's/^COPY[[:space:]]+//; s/[[:space:]]+\/[^[:space:]]*$//' | tr ' ' '\n' | grep -E '^test/' || true)
    if [[ -z "$copy_sources" ]]; then
        fail "could not derive any COPY source from .devcontainer/Dockerfile — the existence assertion below would be vacuous"
    else
        copy_missing=""
        while IFS= read -r src; do
            [[ -z "$src" ]] && continue
            [[ -f "$SCRIPT_DIR/../$src" ]] || copy_missing="${copy_missing} ${src}"
        done <<< "$copy_sources"
        if [[ -z "$copy_missing" ]]; then
            pass "every path .devcontainer/Dockerfile COPYs exists ($(printf '%s' "$copy_sources" | grep -c .) checked)"
        else
            fail ".devcontainer/Dockerfile COPYs path(s) that do not exist:${copy_missing} — the image build fails and no un-gated check can see it"
        fi

        # Existence is not the invariant. install-chrome.sh derives SCRIPT_DIR
        # from its own dirname and sources common.sh from there, so the two must
        # land in the SAME directory — copying the installer alone leaves every
        # path valid and dies at `source` with "No such file or directory", which
        # is what the Dockerfile's own comment at that COPY warns about. Caught
        # by mutation: dropping common.sh from the COPY left the existence check
        # above green at 150/150, because the one remaining path did exist.
        # Per-COPY-line, not aggregated. The installer sources common.sh from its
        # OWN dirname, so the two must share ONE COPY instruction's destination;
        # aggregating across every COPY line meant splitting the pair into two
        # instructions with different destinations still passed.
        copy_pair_ok=0
        while IFS= read -r cl; do
            printf '%s' "$cl" | grep -q 'test/install-chrome\.sh' || continue
            printf '%s' "$cl" | grep -q 'test/common\.sh' && copy_pair_ok=1
        done < <(grep -E '^COPY[[:space:]]' "$DEVCONTAINER_DOCKERFILE")
        if printf '%s\n' "$copy_sources" | grep -qx 'test/install-chrome.sh'; then
            if [[ "$copy_pair_ok" -eq 1 ]]; then
                pass ".devcontainer/Dockerfile COPYs common.sh in the SAME instruction as install-chrome.sh (the installer sources it from its own dirname)"
            else
                fail ".devcontainer/Dockerfile COPYs install-chrome.sh WITHOUT common.sh — the installer sources common.sh from its own dirname, so the layer dies at 'source'; every path it names still exists, so an existence check cannot see this"
            fi
        else
            fail ".devcontainer/Dockerfile no longer COPYs test/install-chrome.sh — the image ships no browser and LAB-5064's AC1 wiring is gone"
        fi
    fi
else
    fail ".devcontainer/Dockerfile not found — the devcontainer wiring assertions above are vacuous"
fi

# .dockerignore governs the repo-root build CONTEXT, so an entry added for the
# devcontainer build can silently strip a path the Dockerfile COPYs — the build
# then fails only inside the gated image job. Checked here beside the COPY
# assertions rather than left to `docker build` to discover.
DOCKERIGNORE="$SCRIPT_DIR/../.dockerignore"
if [[ -f "$DOCKERIGNORE" ]]; then
    di_bad=""
    while IFS= read -r di_src; do
        [[ -z "$di_src" ]] && continue
        while IFS= read -r di_pat; do
            case "$di_pat" in ''|'#'*) continue ;; esac
            # shellcheck disable=SC2053
            if [[ "$di_src" == $di_pat || "$di_src" == ${di_pat%/}/* ]]; then
                di_bad="${di_bad} ${di_src}(by '${di_pat}')"
            fi
        done < "$DOCKERIGNORE"
    done <<< "$copy_sources"
    if [[ -z "$di_bad" ]]; then
        pass ".dockerignore excludes none of the paths .devcontainer/Dockerfile COPYs"
    else
        fail ".dockerignore excludes path(s) the Dockerfile COPYs:${di_bad} — the image build fails and only the gated job would see it"
    fi
else
    fail ".dockerignore not found — it governs the repo-root build context this image uses"
fi

# ── VESPASIAN_TEST_ROOT stays a test-only seam ─────────────────────────────────
#
# test/README.md states, absolutely, that no production caller sets it, and the
# variable feeds root-privileged writes. AGENTS.md's own convention is that a
# comment claiming a state cannot occur must cite a test; this is that test.
# Callers are DERIVED, not hardcoded. The earlier version listed five paths and
# omitted .devcontainer/devcontainer.json, whose containerEnv reaches every
# developer's container and every `devcontainer exec` step in the image job —
# a strictly more privileged setter than the Dockerfile RUN that WAS listed.
# It also had no vacuity sentinel, so if the paths stopped resolving it printed
# its single pass having read nothing.
tr_expect=()
tr_callers=()
for tr_c in "$SCRIPT_DIR/install-chrome.sh" "$SCRIPT_DIR/setup-live-targets.sh" \
            "$SCRIPT_DIR/run-live-tests.sh" "$SCRIPT_DIR/common.sh" \
            "$SCRIPT_DIR/../.devcontainer/Dockerfile" "$SCRIPT_DIR/../.devcontainer/devcontainer.json" \
            "$WORKFLOW" "$(dirname "$WORKFLOW")/ci.yml"; do
    tr_expect+=("$tr_c")
    [[ -f "$tr_c" ]] && tr_callers+=("$tr_c")
done
# ALL of them, not "at least 6". Every entry is a committed path, so a shortfall
# is a real repo change worth naming — and tolerating two missing let two callers
# be renamed or moved while the check passed silently over the rest, which is a
# narrower version of the omission this sentinel was added for.
if [[ "${#tr_callers[@]}" -ne "${#tr_expect[@]}" ]]; then
    tr_absent=""
    for tr_c in "${tr_expect[@]}"; do [[ -f "$tr_c" ]] || tr_absent="${tr_absent} ${tr_c#"$SCRIPT_DIR"/}"; done
    fail "only ${#tr_callers[@]} of the ${#tr_expect[@]} VESPASIAN_TEST_ROOT production callers resolved (missing:${tr_absent}) — the assertion below would read less than it claims; fix the paths rather than letting it pass vacuously"
else
    tr_setters=""
    for tr_caller in "${tr_callers[@]}"; do
        # Four forms, because the callers are four languages. install-chrome.sh
        # READS the variable by design and its selftest SETS it — that is the
        # seam — so only these callers are checked, and only for an assignment.
        if grep -qE '(^|[[:space:];&|])(export[[:space:]]+)?VESPASIAN_TEST_ROOT=' "$tr_caller" \
           || grep -qE '^[[:space:]]*VESPASIAN_TEST_ROOT:[[:space:]]*\S' "$tr_caller" \
           || grep -qE '^[[:space:]]*(ENV|ARG)[[:space:]]+VESPASIAN_TEST_ROOT([[:space:]]|=)' "$tr_caller" \
           || grep -qE '"VESPASIAN_TEST_ROOT"[[:space:]]*:' "$tr_caller"; then
            tr_setters="${tr_setters} $(basename "$tr_caller")"
        fi
    done
    if [[ -z "$tr_setters" ]]; then
        pass "no production caller sets VESPASIAN_TEST_ROOT (all ${#tr_expect[@]} callers checked — $(for tr_c in "${tr_expect[@]}"; do printf '%s ' "$(basename "$tr_c")"; done)— 4 assignment forms: shell, YAML env:, Dockerfile ENV/ARG, JSON containerEnv)"
    else
        fail "VESPASIAN_TEST_ROOT is set by production caller(s):${tr_setters} — it reroots root-privileged writes and test/README.md states no production caller sets it"
    fi
fi

# Both sibling suites pin their assertion total; this one did not, so
# deleting a case reduced coverage in silence — every remaining assertion still
# passed and the suite still exited 0.
#
# The pin now counts skip credit. One arm here is environmental (the
# RESULTS_DIR isolation check cannot measure anything when test/.results already
# existed before the run), and it takes a credit of 1 rather than emitting
# nothing, so a genuinely deleted assertion is still caught on a host where that
# arm fires. The pin itself stays UNCONDITIONAL — gating it on "no skips", the
# way the sibling suite used to, is what let a deletion hide behind an unrelated
# ambient condition.
#
# Bumped 117 -> 121: +2 for the un-gated job's on:/pull_request and needs:
# checks, +2 for targets_need_config's substring/glob-anchoring
# checks.
# 121 -> 122. One assertion added, checking that every script
# live-tests.yml direct-execs is committed 100755 — the gap that let
# install-chrome-selftest.sh run as 100644 and kill CI with exit 126 for three
# review rounds without any assertion noticing.
#
# Round-15 review: 122 -> 129. MEASURED by running the suite, not derived — the
# per-task deltas in the round-15 plan were written without shell access and are
# explicitly untrusted. Breakdown of the +7:
#   +1  on: trigger vacuity guard (pull_request must EXIST before asking whether
#       it is filtered, so a `false` from the filter query can never be vacuous)
#   +1  on:/pull_request must carry no paths:/paths-ignore: filter — the old
#       check asserted the trigger EXISTED, which a paths: filter satisfies
#       while switching every guard suite off for shell-only PRs
#   +3  the un-gated job checks (continue-on-error / trailing || true / needs:)
#       now iterate BOTH un-gated guard jobs instead of preflight-selftest
#       alone; validator-regression was unprotected, and `needs: test` on it
#       genuinely skips it whenever skip-live-tests is applied
#   +1  fidelity sentinel for e2e_block, whose five consumers could all pass
#       vacuously on an empty extraction (its two sibling blocks already had one)
#   +1  third load_config extraction's SENTINEL_LOAD_CONFIG_MISSING guard, which
#       its two siblings already carried
# Net zero, so not in the +7: routing the three inline awk job-block extractors
# through the existing extract_job_block helper (their terminator class
# [a-zA-Z_-]+ could not stop at a digit-bearing job name such as
# install-chrome-e2e), locating the two suite-running steps by what they RUN
# rather than by their name, widening the exec-bit derivation, matching suites
# by repo-relative path, and collapsing the double-fail at the browser-target
# classification arm to one counted outcome.
# Adversarial self-review: 129 -> 130. MEASURED. +1 for the test job's own gate
# check: the per-step if: check could not see a JOB-level gate, and
# replacing the test job's condition with `if: false` stopped the entire live
# suite while this file stayed at 129/0 exit 0. The trigger-shape check
# is net zero — it replaced the narrower paths/paths-ignore check rather than
# adding to it.
#
# Round-16 review: 130 -> 134. MEASURED. +1 for chrome_available's ORDERING pin
# (the three per-line pins above it are all evaded by the same multi-line
# presence-only fast path, and order is the one property none of them can see),
# and +3 for the ambient-VESPASIAN override notice, which had no assertion in
# any suite — deleting the capture, the guard and the message together left
# every suite green while a run under an override reported results for an
# arbitrary binary. The --dump-dom pin is net zero: the assertion moved into
# test/assert-chrome-install.sh and the pin now requires both links (the job
# invokes the script, the script drives the binary) in one counted outcome.
#
# 134 -> 135. MEASURED. +1 for the container-shell check: a container job's
# inline `run:` gets `sh -e {0}`, not bash, and run 32388761616 — the first time
# install-chrome-e2e ever executed — lost two steps to `set -euo pipefail` dying
# on line 1. Nothing could have caught it: an inline block is not a file, so
# `bash -n` never sees it, and the job is opt-in, so no PR run exercised it.


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# .devcontainer/on-create.sh, executed. It was in the `bash -n` chain and
# nothing else — and syntax is not the failure this script has. It already
# failed once in CI for real (`/bin/sh: 1: npm: not found`, onCreateCommand exit
# 127), and the devcontainers CLI does NOT surface a failing onCreateCommand as
# a non-zero exit from `devcontainer up`
# (microsoft/vscode-remote-release#8906), so a regression here is silent at the
# only moment it runs. Both arms are driven with npm stubbed.
oc_script="$SCRIPT_DIR/../.devcontainer/on-create.sh"
if [[ -f "$oc_script" ]]; then
    oc_tmp=$(mktemp -d); mkdir -p "$oc_tmp/bin" "$oc_tmp/nonpm"
    # (1) npm absent: must fail, and must say WHY rather than dying on `npm ci`.
    #     The PATH must genuinely lack npm — pointing at /usr/bin finds the
    #     system one and the case passes vacuously, which is what happened on the
    #     first run of this block. So: a directory holding symlinks to only the
    #     externals the script actually needs. Everything else it uses
    #     (command -v, echo, cd) is a bash builtin.
    # bash as well as dirname: the script's `$(dirname ...)` substitution spawns a
    # subshell, and an npm-free PATH that cannot find bash makes the script die at
    # 127 BEFORE its diagnostic — which the assertion would then read as the
    # diagnostic being absent. /usr/bin:/bin is not an alternative here: this image
    # carries /usr/bin/npm, so that PATH is not npm-free at all and the case passed
    # vacuously against a real `npm ci`.
    for oc_bin in bash dirname; do
        oc_p=$(command -v "$oc_bin" 2>/dev/null) && ln -sf "$oc_p" "$oc_tmp/nonpm/$oc_bin"
    done
    # `|| oc_rc=$?` and not a bare assignment: this case EXPECTS a non-zero exit,
    # and under `set -e` a failing command substitution kills the whole suite
    # before the assertion can read it — the same shape that made seven other
    # extractions in this file unable to report their own vacuity.
    oc_rc=0
    oc_out=$(PATH="$oc_tmp/nonpm" bash "$oc_script" 2>&1) || oc_rc=$?
    if [[ "$oc_rc" -ne 0 ]] && printf '%s\n' "$oc_out" | grep -q 'npm not on PATH' \
       && printf '%s\n' "$oc_out" | grep -q 'NVM_DIR='; then
        pass "on-create.sh fails with a diagnostic naming NVM_DIR/PATH when npm is absent (executed, not grepped)"
    else
        fail "on-create.sh did not fail with its npm-absent diagnostic (rc=${oc_rc}) — the one failure this script actually has in CI would surface as a bare exit 127 that devcontainer up does not even report"
    fi
    # (2) npm present: must invoke `npm ci --ignore-scripts`. --ignore-scripts is
    #     the control — it blocks package lifecycle scripts under the audit-only
    #     egress policy — so losing the flag is the regression worth catching.
    cat > "$oc_tmp/bin/npm" <<'NPMSTUB'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then echo "0.0.0-stub"; exit 0; fi
printf '%s\n' "$*" >> "$NPM_ARGS_LOG"
exit 0
NPMSTUB
    chmod 0755 "$oc_tmp/bin/npm"
    : > "$oc_tmp/npm-args"
    NPM_ARGS_LOG="$oc_tmp/npm-args" PATH="$oc_tmp/bin:/usr/bin:/bin" bash "$oc_script" >/dev/null 2>&1 || true
    if grep -q -- 'ci --ignore-scripts' "$oc_tmp/npm-args" 2>/dev/null; then
        pass "on-create.sh runs 'npm ci --ignore-scripts' for the spec validators (observed via a stub npm, not grepped)"
    else
        fail "on-create.sh no longer invokes 'npm ci --ignore-scripts' (recorded: $(tr '\n' ';' < "$oc_tmp/npm-args" 2>/dev/null)) — either the install was dropped, or --ignore-scripts was, which is the flag that stops package lifecycle scripts running under the audit-only egress policy"
    fi
    rm -rf "$oc_tmp"
else
    fail ".devcontainer/on-create.sh is missing — devcontainer.json's onCreateCommand points at it, so container creation would fail"
    skip "on-create.sh npm ci --ignore-scripts invocation (script absent)" 1
fi


# ---------------------------------------------------------------------------
# The yq-less guard step must exist. It is the only mechanical check on
# skip-credit accounting, and the four guard suites in this job are each pinned
# by name for exactly this reason — a step nothing asserts can be deleted to save
# CI minutes and nothing notices. Pinned on the command it runs, not its name, so
# a rename does not silently drop the coverage.
if [[ -f "$WORKFLOW" ]]; then
    yqless=$(yq_query '.jobs["preflight-selftest"].steps[] | select(.run != null) | .run' -r 2>/dev/null || true)
    case "$yqless" in
        __NO_YQ__)    fail_no_yq "the yq-less guard step" ;;
        __YQ_ERROR__) fail_yq_error "the yq-less guard step" ;;
        *)
            if printf '%s\n' "$yqless" | grep -q 'PATH="\$noyq" bash test/test-runner-args.sh' \
               && printf '%s\n' "$yqless" | grep -q 'accounting drift'; then
                pass "preflight-selftest still runs test-runner-args.sh on a yq-less PATH and fails on accounting drift"
            else
                fail "preflight-selftest no longer runs the guard suite on a yq-less PATH — the skip-credit accounting class it catches has recurred repeatedly here and CI ships yq, so nothing else exercises those arms"
            fi ;;
    esac
fi

# ---------------------------------------------------------------------------
# The AC3 rod-backed-target matcher, EXECUTED. This delta rewrote it twice —
# `printf | grep -q` became a herestring (SIGPIPE under pipefail turned a green
# suite red), and the pattern lost one of its two alternatives — and the suite
# pinned only that the AC3 step EXISTS, by its `run-live-tests.sh --no-build
# --group live` substring. Nothing exercised the matcher, so a weakened
# `[^a-z-]` boundary or a dropped target name would ship silently. The boundary
# is what stops `concat-spa` being satisfied by a `concat-spa-two-stage` row,
# which is the whole reason the pattern is not a plain substring search.
ac3_step=$(yq_query '.jobs["devcontainer-image"].steps[] | select(.name == "Assert the live suite runs in the image (AC3)") | .run' -r)
case "$ac3_step" in
    __NO_YQ__)    fail_no_yq "the AC3 rod-backed-target matcher"
                  skip "AC3 matcher executed cases (yq unavailable)" 3 ;;
    __YQ_ERROR__) fail_yq_error "the AC3 rod-backed-target matcher"
                  skip "AC3 matcher executed cases (workflow unparseable)" 3 ;;
    "")           fail "devcontainer-image has no step named 'Assert the live suite runs in the image (AC3)' — AC3's only in-image evidence is gone"
                  skip "AC3 matcher executed cases (step absent)" 3 ;;
    *)
        # The loop header names the targets; the grep line is the matcher.
        ac3_loop=$(printf '%s\n' "$ac3_step" | grep -E '^[[:space:]]*for t in ' | head -1 || true)
        # The trailing ` \` is a shell line-continuation in the workflow; it must be
        # stripped or the lifted line swallows whatever the harness puts after it.
        ac3_grep=$(printf '%s\n' "$ac3_step" | grep -E '^[[:space:]]*grep -qE .*<<<"\$out"' | head -1 \
                   | sed -e 's/[[:space:]]*\\$//' -e 's/^[[:space:]]*//' || true)
        ac3_names=$(printf '%s\n' "$ac3_loop" | sed -n 's/.*for t in \(.*\); do.*/\1/p')
        # ac3_names is read FROM the loop under test, which makes the cases below
        # self-referential on their own: deleting a target simply shrinks what they
        # check, and MEASURED, that left the suite green. This is the same defect
        # shape as round-3 TEST-015. So the required names are also stated HERE,
        # independently: no-download is the target LAB-4999 names as rod-backed,
        # and concat-spa and forms-target are the two BROWSER_TARGETS entries the
        # AC3 step exists to prove actually launched a browser.
        # The matcher cases below prove the PATTERN discriminates. They say nothing
        # about whether the step ACTS on the result: deleting the whole
        # `if [ -n "$missing" ]; then ... exit 1; fi` block left the suite at
        # 187/0 while AC3 became incapable of failing. MEASURED. Pin the
        # enforcement separately from the matching.
        # The `exit 1` must be INSIDE the missing-block. Grepping the two patterns
        # independently was defeated by deleting only the `exit 1` from the block:
        # the step has three other `exit 1` lines (the live-suite failure handler
        # among them), so both greps still matched and the suite stayed at 188/0
        # with AC3 unable to fail. MEASURED. Extract the block, then look inside it.
        ac3_enforce=$(printf '%s\n' "$ac3_step" \
            | sed -n '/^[[:space:]]*if \[ -n "\$missing" \]/,/^[[:space:]]*fi[[:space:]]*$/p')
        if [ -n "$ac3_enforce" ] && printf '%s\n' "$ac3_enforce" | grep -qE '^[[:space:]]*exit 1[[:space:]]*$'; then
            pass "the AC3 step ENFORCES its result (the missing-block itself exits 1), not merely computes it"
        else
            fail "the AC3 step computes \$missing but no longer acts on it — the rod-backed-target check cannot fail, so a browserless image reports AC3 green"
        fi
        ac3_absent=""
        for ac3_req in no-download concat-spa forms-target; do
            case " $ac3_names " in *" $ac3_req "*) ;; *) ac3_absent="${ac3_absent} ${ac3_req}" ;; esac
        done
        if [[ -n "$ac3_absent" ]]; then
            fail "the AC3 step no longer requires rod-backed target(s):${ac3_absent} — a browserless image would report AC3 green for whatever remains, which is the exact condition LAB-5766 exists to remove"
        else
            pass "the AC3 step still requires all three rod-backed targets by name (checked against an independent list, not against its own loop)"
        fi
        if [[ -z "$ac3_grep" || -z "$ac3_names" ]]; then
            fail "could not lift the AC3 matcher (loop='${ac3_loop}' grep='${ac3_grep}') — either it was restructured or it no longer feeds grep from a herestring, which is what keeps SIGPIPE from reporting a green suite as red"
            # 1, not 2. This arm sits inside the `*)` arm, so BOTH the enforcement
            # pin and the independent-names check have already emitted; only the two
            # matcher cases are lost, and this arm's own `fail` covers one of them.
            # The previous comment reasoned in the wrong direction and left the
            # credit at 2: a whitespace-only edit to the lifted grep then reported
            # `saw 189` against a pin of 188. MEASURED — sixth recurrence of this
            # class, which is why the yq-less CI step now exists.
            skip "AC3 matcher executed cases (matcher not liftable)" 1
        else
            # run_ac3 <out> -> the targets the matcher reports MISSING
            run_ac3() {
                out="$1" bash -c "
                    set -u
                    missing=\"\"
                    for t in $ac3_names; do
                        $ac3_grep || missing=\"\${missing} \${t}\"
                    done
                    printf '%s' \"\$missing\"
                " 2>/dev/null
            }
            ac3_real=$(printf '  no-download                 PASS      -   -   9s\n  concat-spa                  PASS      2   2   9s\n  forms-target                PASS      4   4  10s\n')
            ac3_skipped=$(printf '  no-download                 PASS      -   -   9s\n  concat-spa                  SKIP      -   -   0s\n  forms-target                PASS      4   4  10s\n')
            ac3_nearmiss=$(printf '  no-download                 PASS      -   -   9s\n  concat-spa-two-stage        PASS      2   2   9s\n  forms-target                PASS      4   4  10s\n')
            # (1) genuine rows -> nothing missing, or the other cases prove nothing
            if [[ -z "$(run_ac3 "$ac3_real")" ]]; then
                pass "the AC3 matcher accepts the real PASS rows for all $(printf '%s' "$ac3_names" | wc -w) rod-backed targets (executed against captured-format output)"
            else
                fail "the AC3 matcher reports '$(run_ac3 "$ac3_real")' missing from output in the format the suite actually prints — the gate would red a passing run"
            fi
            # (2) a SKIP must be caught, and a near-miss must NOT satisfy the name
            ac3_bad=""
            [[ "$(run_ac3 "$ac3_skipped")" == *concat-spa* ]] || ac3_bad="${ac3_bad} a SKIPped target was not reported missing"
            [[ "$(run_ac3 "$ac3_nearmiss")" == *concat-spa* ]] || ac3_bad="${ac3_bad} a concat-spa-two-stage row satisfied concat-spa (the [^a-z-] boundary is gone)"
            if [[ -z "$ac3_bad" ]]; then
                pass "the AC3 matcher catches a SKIPped target and refuses a longer sibling name in its place"
            else
                fail "the AC3 matcher is too loose:${ac3_bad} — a browserless image would report AC3 green"
            fi
            unset -f run_ac3
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# No `#` inside a Dockerfile RUN continuation. Dockerfile line-continuations
# join every `\`-terminated line into ONE logical shell line, so a `#` anywhere
# in the block comments out the REST of it. Added after exactly that was written
# into the Node layer during this PR: the comment swallowed the node/npm probe,
# the FATAL branch and the loop's `done`, leaving an unterminated `for`. Nothing
# local catches it — a Dockerfile is not a shell script so `bash -n` cannot see
# it, and no guard suite builds the image — so it surfaces only in CI.
dfc="$SCRIPT_DIR/../.devcontainer/Dockerfile"
if [[ -f "$dfc" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        fail "python3 is not available, so the Dockerfile RUN-continuation check cannot run — that guard covers a defect no other check sees; install python3 rather than leaving it silently unchecked"
    else
    df_bad=$(python3 - "$dfc" <<'DFPY'
import re, sys
# The hazard is a `#` that follows CODE on a continued line. A `#` on its OWN
# line is NOT a hazard: BuildKit strips comment lines while assembling the
# continuation (parser.go isComment() trims leading whitespace then tests
# line[0] == '#', and the assembly loop skips such lines), so an indented
# comment inside a RUN block is removed before the join. The first version of
# this check had that backwards and flagged the safe form.
#
# A `#` inside a quoted string is also harmless — the shell sees a literal —
# so quote state is tracked across the line.
src = open(sys.argv[1]).read()
bad = []
for m in re.finditer(r'^RUN .*?(?<!\\)\n', src, re.S | re.M):
    block = m.group(0)
    if '\\\n' not in block:
        continue                      # not a continuation; nothing joins
    for raw in block.split('\n'):
        line = raw.rstrip()
        if line.endswith('\\'):
            line = line[:-1]
        if re.match(r'^\s*#', raw):
            continue                  # whole-line comment: stripped by the parser
        sq = dq = False
        for k, ch in enumerate(line):
            if ch == "'" and not dq:
                sq = not sq
            elif ch == '"' and not sq:
                dq = not dq
            elif ch == '#' and not sq and not dq and k > 0 and line[:k].strip():
                bad.append(raw.strip()[:70])
                break
print('\n'.join(bad))
DFPY
    )
    if [[ -z "$df_bad" ]]; then
        pass "no '#' follows code on a continued Dockerfile RUN line (that form survives the join and comments out the rest of the instruction)"
    else
        fail "a '#' follows code on a continued Dockerfile RUN line, so after the continuation join it comments out the remainder — the probe, the FATAL branch and the loop's done: ${df_bad}"
    fi
    fi
else
    fail ".devcontainer/Dockerfile not found at ${dfc} — cannot check for comment-swallowing in RUN continuations"
fi


# ---------------------------------------------------------------------------
# The devcontainer paths FILTER, executed rather than described.
#
# d7f5129 replaced dorny/paths-filter (rejected by the org Actions allowlist)
# with hand-written shell: a per-line read over `git diff --name-only`, a
# `for pat in $WATCHED` inner loop, and `case "$f" in $pat)`. That matcher is
# the sole producer of the output the gate's pull_request arm consumes, and
# nothing executed it — the suite asserted only that a step with `id: filter`
# exists and that its run: TEXT contains the nine watched paths, while the gate
# harness two blocks up stubs steps.filter.outputs.devcontainer with a literal
# and is blind to the producer entirely.
#
# That gap is not theoretical, and it was demonstrated while writing this block:
# an `IFS=$'\n'` added to make the outer loop newline-safe ALSO stopped the
# space-separated $WATCHED from splitting, so every pattern became one long
# string, every path stopped matching, and the filter reported
# devcontainer=false for every PR. The suite stayed at 177 passed / 0 failed.
# A one-token `case "$f" in "$pat")` quoting cleanup does the same thing.
#
# So: pull the step's run: with yq, stub `git` so the changed list is an input,
# and drive a table of (event, path, expected) through the real code.
filter_body=$(yq_query '.jobs["devcontainer-changes"].steps[] | select(.id == "filter") | .run' -r)
case "$filter_body" in
    # Each sentinel credits 1: the `*)` arm emits TWO counted outcomes — the
    # --no-renames producer pin and the FLTCASES result. The pin was added in a
    # later commit without updating these arms, and a yq-less host then reported
    # `accounting drift: expected 187, saw 186` on top of 20 correct diagnostics.
    # MEASURED with a PATH holding every executable except yq.
    __NO_YQ__)    fail_no_yq "the devcontainer paths-filter behaviour"
                  skip "devcontainer filter --no-renames pin (yq unavailable)" 1 ;;
    __YQ_ERROR__) fail_yq_error "the devcontainer paths-filter behaviour"
                  skip "devcontainer filter --no-renames pin (workflow unparseable)" 1 ;;
    "")           fail "could not extract the devcontainer-changes filter step's run: body — the matcher assertions below would be vacuous"
                  skip "devcontainer filter --no-renames pin (step body unreadable)" 1 ;;
    *)
        flt_tmp=$(mktemp -d)
        mkdir -p "$flt_tmp/bin"
        cat > "$flt_tmp/bin/git" <<'GITSTUB'
#!/usr/bin/env bash
# Only the two subcommands the filter step uses. `diff` replays the synthetic
# changed-file list so the matcher, not git, is what is under test.
case "${1:-}" in
    fetch) exit 0 ;;
    diff)  printf '%s\n' "$FILTER_CHANGED" ;;
    *)     exit 0 ;;
esac
GITSTUB
        chmod 0755 "$flt_tmp/bin/git"
        # run_filter <event> <newline-separated changed paths> -> "true"/"false"
        run_filter() {
            : > "$flt_tmp/out"
            EVENT_NAME="$1" BASE_REF="main" FILTER_CHANGED="$2" \
                GITHUB_OUTPUT="$flt_tmp/out" PATH="$flt_tmp/bin:$PATH" \
                bash -c "$filter_body" >/dev/null 2>&1 || true
            sed -n 's/^devcontainer=//p' "$flt_tmp/out" | head -1
        }
        flt_bad=""; flt_n=0
        # event|changed paths (\n-separated)|expected
        #
        # The whitespace row pairs a spacey path WITH a watched path so it can
        # actually discriminate: the earlier `docs/a file with spaces.md|false`
        # row passed under both the old `for f in $changed` loop and the new
        # `while read` one, because neither fragment matched anything either way.
        # Pairing them means the pre-fix loop splits the spacey path into
        # fragments and still finds test/common.sh, while a loop that mishandles
        # the newline separation misses it. The rename row covers the
        # --no-renames flag on the producer: git reports a rename as delete+add,
        # so the SOURCE path under .devcontainer/ must reach the matcher.
        flt_table=$(cat <<'FLTCASES'
pull_request|.devcontainer/Dockerfile|true
pull_request|.devcontainer/nested/thing.sh|true
pull_request|test/common.sh|true
pull_request|.github/workflows/live-tests.yml|true
pull_request|README.md|false
pull_request|test/some-other-file.sh|false
pull_request|README.md\ntest/install-chrome.sh|true
pull_request|go.mod|true
pull_request|docs/notes .devcontainer/x.sh|false
pull_request|.devcontainer/moved-away.sh\ndocs/moved-away.sh|true
push|.devcontainer/Dockerfile|false
FLTCASES
        )
        while IFS='|' read -r flt_ev flt_changed flt_want; do
            [ -z "$flt_ev" ] && continue
            flt_n=$((flt_n + 1))
            flt_got=$(run_filter "$flt_ev" "$(printf '%b' "$flt_changed")")
            [ "$flt_got" = "$flt_want" ] \
                || flt_bad="${flt_bad} [${flt_ev} ${flt_changed} -> got '${flt_got}' want '${flt_want}']"
        done <<< "$flt_table"
        # The rename ROW above exercises the matcher, not the producer: the stub
        # git replays FILTER_CHANGED verbatim and ignores flags, so the row passes
        # whether or not the real step asks git for both paths. MEASURED — dropping
        # --no-renames left the whole harness green. The flag therefore needs its
        # own pin, because git reports a rename as the DESTINATION only by default
        # and a file moved OUT of a watched path would stop firing the filter.
        if printf '%s\n' "$filter_body" | grep -qF -- 'git diff --no-renames --name-only'; then
            pass "the devcontainer filter asks git for both sides of a rename (--no-renames), so a file moved OUT of a watched path still builds"
        else
            fail "the devcontainer filter's git diff lost --no-renames — rename detection is on by default and reports only the DESTINATION, so moving a file out of .devcontainer/ would report devcontainer=false and skip the image build"
        fi
        # An empty table drives zero cases, finds nothing bad, and passes while
        # printing "0 cases executed". MEASURED: emptying the heredoc left the
        # suite at 187/0. Floor the count the same way DCPROPS is floored.
        # Content, not count. A floor of 8 against 11 rows let the THREE
        # discriminating rows be deleted while the count stayed legal, leaving the
        # suite at 188/0. MEASURED. Require the rows that actually discriminate:
        # the whitespace row (separates the read-loop from a for-loop), the rename
        # source (covers --no-renames), and the nested path (covers set -f).
        flt_want=""
        for flt_req in 'docs/notes .devcontainer/x.sh' '.devcontainer/moved-away.sh' '.devcontainer/nested/thing.sh' 'go.mod'; do
            printf '%s\n' "$flt_table" | grep -qF -- "$flt_req" || flt_want="${flt_want} [${flt_req}]"
        done
        if [ -n "$flt_want" ]; then
            fail "the FLTCASES table lost the discriminating row(s):${flt_want} — the remaining rows pass under a broken matcher too; restore them rather than letting it pass vacuously"
        elif [ -z "$flt_bad" ]; then
            pass "the devcontainer paths filter MATCHES the paths it watches and rejects the ones it does not (${flt_n} cases executed against the real step, stubbed git)"
        else
            fail "the devcontainer paths filter misclassified:${flt_bad} — the image job's pull_request arm is driven by this output, so a wrong answer means a PR touching the image is never built before merge"
        fi
        rm -rf "$flt_tmp"
        unset -f run_filter
        ;;
esac


# ---------------------------------------------------------------------------
# The devcontainer's Go toolchain must satisfy go.mod — checked TWICE, because
# the two checks fail on different days and only one of them is un-gated.
#
# The break: the image shipped Go 1.25.12 while go.mod on main asked 1.27.0.
# Under GOTOOLCHAIN=local (kept on purpose, so no build silently downloads a
# compiler) Go refuses rather than upgrading, so every Go step in the container
# died and AC2 went with it.
#
# (A) is un-gated and runs on every PR: the Dockerfile's pin against go.mod,
#     here in this suite. It exists because the in-image check lives in
#     devcontainer-image, which only runs when the paths filter fires — and a PR
#     whose ONLY change is bumping go.mod's `go` directive is precisely the one
#     that caused this break. go.mod is now in WATCHED, but a filter is a
#     heuristic and this assertion is not.
# (B) is the in-image gate, executed here against a stub `go` and a synthetic
#     go.mod. Greping that live-tests.yml MENTIONS a version check would assert
#     the control exists, not that it discriminates.

# ── (A) un-gated: the Dockerfile's Go pin vs go.mod ───────────────────────────
dcgo_df="$SCRIPT_DIR/../.devcontainer/Dockerfile"
dcgo_mod="$SCRIPT_DIR/../go.mod"
if [[ -f "$dcgo_df" && -f "$dcgo_mod" ]]; then
    dcgo_pin=$(grep -oE '^[[:space:]]*ver=[0-9]+\.[0-9]+(\.[0-9]+)?' "$dcgo_df" | head -1 | sed 's/.*ver=//' || true)
    dcgo_want=$(sed -n 's/^go //p' "$dcgo_mod" | head -1 || true)
    dcgo_mod_branch="$dcgo_want"
    # The working tree's go.mod is ALWAYS the requirement for the tree under test,
    # so it is always a valid basis and this check never needs to skip. On a
    # pull_request, actions/checkout resolves the MERGE commit, so that go.mod is
    # already the merge-target one. On a branch checkout it is the branch's, which
    # origin/main then tightens when the ref happens to be present.
    #
    # It skipped before, whenever origin/main was unfetched — and preflight-selftest
    # checks out at depth 1 without it, so the one check built to be UN-GATED never
    # ran in CI at all. MEASURED on the merge commit: `235 passed, 0 failed,
    # 1 skipped`, and that 1 was this. The basis is named in the message so the log
    # says which go.mod was used rather than the result depending silently on what
    # the developer happened to fetch.
    dcgo_basis="working-tree go.mod (${dcgo_mod_branch:-?})"
    if git -C "$SCRIPT_DIR/.." rev-parse --verify --quiet origin/main >/dev/null 2>&1; then
        dcgo_main=$(git -C "$SCRIPT_DIR/.." show origin/main:go.mod 2>/dev/null | sed -n 's/^go //p' | head -1 || true)
        if [[ -n "$dcgo_main" && -n "$dcgo_want" ]]; then
            dcgo_want=$(printf '%s\n%s\n' "$dcgo_want" "$dcgo_main" | sort -V | tail -1)
            dcgo_basis="stricter of branch (${dcgo_mod_branch:-?}) and origin/main (${dcgo_main})"
        fi
    fi
    if [[ -z "$dcgo_pin" || -z "$dcgo_want" ]]; then
        fail "could not read the Dockerfile Go pin (got '${dcgo_pin}') or go.mod's go directive (got '${dcgo_want}') — the un-gated toolchain check would be vacuous"
    else
        dcgo_oldest=$(printf '%s\n%s\n' "$dcgo_want" "$dcgo_pin" | sort -V | head -1)
        if [[ "$dcgo_oldest" == "$dcgo_want" ]]; then
            pass "the .devcontainer/Dockerfile Go pin (${dcgo_pin}) satisfies go.mod (>= ${dcgo_want}, basis: ${dcgo_basis}) — checked un-gated, on every PR"
        else
            fail "the .devcontainer/Dockerfile pins Go ${dcgo_pin} but go.mod requires >= ${dcgo_want} — under GOTOOLCHAIN=local every Go step in the devcontainer fails with 'go.mod requires go >= ${dcgo_want}'; bump ver= in the Dockerfile's Go layer"
        fi
    fi
else
    fail "missing .devcontainer/Dockerfile or go.mod — the un-gated devcontainer toolchain check cannot run"
fi

# ── (B) the in-image gate, lifted whole and executed ──────────────────────────
#
# Scoped to the conformance STEP, not grepped file-wide. An earlier version
# matched the lines anywhere in live-tests.yml, so moving the gate out of the
# `devcontainer exec` block into a host-side run: step of the same job left every
# case passing — and the runner ships its own conforming Go, so it would pass
# there forever while the image rotted. That is the same defeat this suite
# already blocks for the two chrome scripts by requiring `--workspace-folder`.
dcgo_step=$(yq_query '.jobs["devcontainer-image"].steps[] | select(.name == "Assert the container matches devcontainer.json") | .run' -r)
case "$dcgo_step" in
    __NO_YQ__)    fail_no_yq "the devcontainer conformance step"
                  skip "devcontainer conformance step properties (yq unavailable)" 1
                  skip "devcontainer Go gate executed cases (yq unavailable)" 4 ;;
    __YQ_ERROR__) fail_yq_error "the devcontainer conformance step"
                  skip "devcontainer conformance step properties (workflow unparseable)" 1
                  skip "devcontainer Go gate executed cases (workflow unparseable)" 4 ;;
    "")           fail "devcontainer-image has no step named 'Assert the container matches devcontainer.json' — the conformance and Go-toolchain assertions below would be vacuous"
                  skip "devcontainer conformance step properties (step absent)" 1
                  skip "devcontainer Go gate executed cases (step absent)" 4 ;;
    *)
        # Each property as its own requirement. The loop this replaced grepped the
        # token 'id -un', which appears TWICE in this step (the check and its error
        # message), so it survived deleting every other assertion in the step it
        # claimed to pin.
        #
        # The rows must be tokens that appear ONLY in the check, and the first
        # version of THIS table repeated the same mistake twice: '/dev/shm'
        # occurs 3x in the step (the df command, the comparison, and the success
        # echo) and 'go.mod' occurs 8x, mostly in comments — so deleting the
        # /dev/shm guard left the suite at 182/0. MEASURED. Each row is now a
        # string that occurs exactly once, verified against the parsed step; the
        # go.mod row is gone because the five-line gate check below already pins
        # the toolchain comparison far more strongly than a token match could.
        #
        # The spec-validator row matters most: the workflow's own comment says it
        # is the only thing that detects a failing onCreateCommand, because the
        # devcontainers CLI does not report that as a non-zero exit from `up`.
        dcgo_prop_missing=""; dcgo_prop_n=0
        dcgo_table=$(cat <<'DCPROPS'
[ "$(id -un)" = vscode ]|remoteUser is vscode
${VESPASIAN_NO_SANDBOX:-}|containerEnv VESPASIAN_NO_SANDBOX
[ "$shm" -ge 1000000000 ]|runArgs --shm-size (the size comparison, not the word /dev/shm)
test/spec-validators/node_modules/|onCreateCommand spec-validator entry points
DCPROPS
        )
        while IFS='|' read -r dcgo_pat dcgo_label; do
            [ -z "$dcgo_pat" ] && continue
            dcgo_prop_n=$((dcgo_prop_n + 1))
            printf '%s\n' "$dcgo_step" | grep -qF -- "$dcgo_pat" \
                || dcgo_prop_missing="${dcgo_prop_missing} ${dcgo_label}"
        done <<< "$dcgo_table"
        # A table that consumes zero rows finds nothing missing and passes. Emptying
        # the heredoc left the suite at 187/0 still printing "5 pinned individually"
        # — a vacuous check whose message actively misreported it. MEASURED. The
        # count is derived and floored.
        # Content, not count. A row-count floor was satisfied by four junk rows
        # (`e|row1` ... `e|row4`), which match almost anything, leaving the suite at
        # 188/0 still printing "4 pinned individually". MEASURED. Require the
        # specific properties by name.
        dcgo_want_props=""
        for dcgo_req in 'id -un' 'VESPASIAN_NO_SANDBOX' 'shm' 'spec-validators'; do
            printf '%s\n' "$dcgo_table" | grep -qF -- "$dcgo_req" || dcgo_want_props="${dcgo_want_props} ${dcgo_req}"
        done
        if [ -n "$dcgo_want_props" ]; then
            fail "the DCPROPS table no longer names:${dcgo_want_props} — the conformance check would assert almost nothing; restore the rows rather than letting it pass vacuously"
        elif [ -z "$dcgo_prop_missing" ]; then
            pass "the devcontainer conformance step still asserts every property devcontainer.json promises (${dcgo_prop_n} pinned individually, not by one shared token)"
        else
            fail "the devcontainer conformance step no longer asserts:${dcgo_prop_missing} — each is the only check of that devcontainer.json setting, and the spec-validator one is the only detector of a failing onCreateCommand"
        fi

        # Lift ALL FOUR gate lines — want=, have=, oldest= and the guard — from
        # THIS step. The earlier harness lifted only the last two and injected
        # want/have itself, so the lines that actually read the artifacts were
        # untested: mutating have= to `$want`, or to `go env GOVERSION` (whose
        # output keeps the "go" prefix, putting 1.27.0 first under sort -V),
        # accepted every stale image with the suite still green.
        # All FIVE lines, including the emptiness guard: `[ -n "$want" ]` is not
        # decoration. Without it an unreadable go.mod leaves want and have both
        # empty, sort -V calls two empty strings equal, and the gate accepts any
        # toolchain. Lifting only the other four made the harness test a gate
        # that does not exist — caught by case (5) below on its first run.
        dcgo_lines=$(printf '%s\n' "$dcgo_step" \
            | grep -E '^[[:space:]]*(want=|have=|\[ -n "\$want" \]|oldest=|\[ "\$oldest" = "\$want" \])' || true)
        dcgo_n=$(printf '%s\n' "$dcgo_lines" | grep -c . || true)
        if [ "${dcgo_n:-0}" -lt 5 ]; then
            fail "found only ${dcgo_n:-0} of the 5 Go-gate lines (want=/have=/emptiness guard/oldest=/comparison guard) inside the conformance step — either part of the gate was removed, or it was moved OUT of the devcontainer exec block onto the host runner, which ships its own conforming Go and would pass forever"
            skip "devcontainer Go gate executed cases (gate not inside the conformance step)" 4
        else
            dcgo_tmp=$(mktemp -d); mkdir -p "$dcgo_tmp/bin"
            # run_dcgo <stub go version> <go.mod version> -> exit code of the real gate
            run_dcgo() {
                cat > "$dcgo_tmp/bin/go" <<STUB
#!/usr/bin/env bash
echo "go version go$1 linux/amd64"
STUB
                chmod 0755 "$dcgo_tmp/bin/go"
                printf 'module x\n\ngo %s\n' "$2" > "$dcgo_tmp/go.mod"
                ( cd "$dcgo_tmp" && PATH="$dcgo_tmp/bin:$PATH" bash -c "
                    set -u
                    $dcgo_lines
                  " ) >/dev/null 2>&1
                echo $?
            }
            # (1) the measured break: image older than go.mod must be REJECTED
            if [ "$(run_dcgo 1.25.12 1.27.0)" -ne 0 ]; then
                pass "the devcontainer Go gate rejects an image older than go.mod (stub go1.25.12 vs go.mod 1.27.0 — the exact break, executed end to end)"
            else
                fail "the devcontainer Go gate ACCEPTS Go 1.25.12 against a go.mod asking 1.27.0 — this is the break that took AC2 down; the gate does not discriminate"
            fi
            # (2) exact match accepted, or (1) is satisfied by a gate that rejects everything
            if [ "$(run_dcgo 1.27.0 1.27.0)" -eq 0 ]; then
                pass "the devcontainer Go gate accepts an exact go.mod match (stub go1.27.0 vs go.mod 1.27.0)"
            else
                fail "the devcontainer Go gate rejects an exact match — it would fail every conforming image"
            fi
            # (3) newer accepted, or (1)+(2) are satisfied by a string equality test
            if [ "$(run_dcgo 1.28.1 1.27.0)" -eq 0 ]; then
                pass "the devcontainer Go gate accepts a NEWER image than go.mod (stub go1.28.1 vs go.mod 1.27.0)"
            else
                fail "the devcontainer Go gate rejects Go 1.28.1 against go.mod 1.27.0 — it demands an exact match rather than a minimum"
            fi
            # (4) the case that makes sort -V load-bearing: 1.9.5 is OLDER than
            #     1.27.0 but sorts lexically AFTER it, so a plain `sort` accepts
            #     it. Cases (1)-(3) all pass under a lexical sort; only this fails.
            if [ "$(run_dcgo 1.9.5 1.27.0)" -ne 0 ]; then
                pass "the devcontainer Go gate rejects Go 1.9.5 against go.mod 1.27.0 (version-aware, not lexical: 1.9.5 sorts after 1.27.0 as a string)"
            else
                fail "the devcontainer Go gate ACCEPTS Go 1.9.5 against go.mod 1.27.0 — the comparison is lexical; sort -V has been lost"
            fi
            # (5) The gate's own empty-input arm. `[ -n "$want" ] && [ -n "$have" ]`
            #     exists so an unreadable go.mod or an unparseable `go version`
            #     fails LOUDLY rather than comparing two empty strings — which
            #     `sort -V` would call equal, making the gate accept anything.
            #     Driven by pointing it at a directory with no go.mod at all.
            rm -f "$dcgo_tmp/go.mod"
            cat > "$dcgo_tmp/bin/go" <<'STUBEMPTY'
#!/usr/bin/env bash
echo "go version go1.27.0 linux/amd64"
STUBEMPTY
            chmod 0755 "$dcgo_tmp/bin/go"
            dcgo_rc=$( ( cd "$dcgo_tmp" && PATH="$dcgo_tmp/bin:$PATH" bash -c "
                set -u
                $dcgo_lines
              " ) >/dev/null 2>&1; echo $? )
            if [ "$dcgo_rc" -ne 0 ]; then
                pass "the devcontainer Go gate fails closed when go.mod cannot be read (empty want/have arm exercised)"
            else
                fail "the devcontainer Go gate exits 0 with an unreadable go.mod — two empty strings compare equal under sort -V, so the gate would accept any toolchain"
            fi
            rm -rf "$dcgo_tmp"
            unset -f run_dcgo
        fi
        ;;
esac



# Set HERE, not 1119 lines earlier where it used to sit. The trap suppresses its
# "terminated before reaching the summary" warning once this is 1, so setting it
# early meant a death anywhere in the rest of the suite exited 1 with no summary,
# no diagnostic, and the accounting pin unrun. MEASURED: on an unparseable
# live-tests.yml the suite died at `hr_steps=$(grep -c ...)` and printed nothing
# at all. Every line above this point is now covered by the trap.
SUITE_COMPLETED=1

echo "=== Summary ==="
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
# ── Assertion ledger ─────────────────────────────────────────────────────────
#
# EXPECTED_ASSERTIONS is a pin, not a target: PASS + FAIL + SKIP_CREDIT must equal
# it exactly. A wrong value does not merely annoy — it fires an "accounting drift"
# message that NAMES THE WRONG DEFECT, sending the reader to reconcile a ledger
# when the real cause is elsewhere. Re-measure after any change; never adjust to
# make a run pass.
#
# This ledger was rewritten at 189 because it had grown by accretion across four
# review rounds and its arithmetic no longer summed — successive rounds appended
# their deltas without repairing the running totals, so it stated 135 -> 170,
# 135 + 16 + 3 + 12 = 166, and 172 -> 185 in three places that disagreed. Rather
# than append a fifth inconsistent line, the history is stated as bands.
#
#   135   the pre-LAB-5766 baseline (target-group/dispatch drift, the un-gated
#         job's own step list, browser-target classification, the config and
#         override guards, and the ambient-VESPASIAN notice).
#
#   +37   LAB-5766 review rounds 1-3: the devcontainer wiring. The image job's
#         gate arms and paths filter, the arm64 leg, harden-runner counts and SHA
#         lockstep, the Dockerfile COPY / .dockerignore pair, VESPASIAN_TEST_ROOT
#         staying a test-only seam, and assert-devcontainer-lookpath.sh driven
#         against a stub `go`.
#
#   +15   rounds 4-6: the Go toolchain and the executed harnesses. An un-gated
#         Dockerfile-pin-vs-go.mod check; the in-image gate lifted WHOLE from the
#         named conformance step and run against a stub `go`; the conformance
#         step's properties pinned individually after a shared token proved to
#         match three places; the paths filter executed against a stubbed git;
#         on-create.sh executed on a genuinely npm-free PATH; the AC3 matcher
#         executed, and its ENFORCEMENT pinned separately after deleting the
#         `exit 1` alone left the suite green; and a Dockerfile RUN-continuation
#         comment guard.
#
#   +2    round 7: the yq-less guard step pinned so its deletion is not silent,
#         and the Dockerfile-pin check comparing against the working-tree go.mod,
#         which is always the requirement for the tree under test. It briefly
#         reported a SKIP when origin/main was unfetched — honest about the
#         ambiguity, but preflight-selftest checks out at depth 1 without that
#         ref, so the one check built to be UN-GATED never ran in CI. It runs
#         now, and origin/main only tightens it when present.
#
#   +47   main, merged in: LAB-5549 and the commits alongside it (the gRPC live
#         target, the AC4 compile check, the setup/live-group seam guard). Its
#         narrative is preserved verbatim below. The band is MEASURED, not
#         assumed: main and this branch both grew from 135 independently — main
#         to 182, this branch to 189 — so neither number survives the merge and
#         the merged total is neither. 135 + 37 + 15 + 2 + 47 = 236.
#
#   = 236  MEASURED, in a clean child shell (`env -u 'BASH_FUNC_grep%%' bash
#         test/test-runner-args.sh`) — a plain `bash` here inherits an exported
#         ugrep `grep` function that gives different answers than CI.
#
# The recurring lesson, recorded because it cost six rounds: when a block gains a
# counted outcome, its vacuity-sentinel arms must gain the matching credit in the
# same edit. That was missed five times, each time caught by RUNNING a degraded
# configuration and never by reading. preflight-selftest now runs this suite with
# yq removed for that reason.

# ── merged from main (LAB-5549 and neighbours), verbatim ─────────────────────
#
# 135 -> 136. MEASURED. +1 for the setup/live-group seam guard (LAB-5549):
# grpc-server moved into LIVE_TARGETS, so `--group live` now runs it on every PR
# with no TARGETS_SETUP or --targets override. That only works because a bare
# `./test/setup-live-targets.sh` starts it, via --targets defaulting to
# ALL_TARGETS. Dropping grpc-server from setup's ALL_TARGETS while leaving it in
# LIVE_TARGETS would make the runner probe a server nobody started, so the target
# would fail on an unset port rather than on anything about gRPC. Nothing else
# pins that cross-script pairing: the coverage guards check groups against the
# dispatch block, and the browser-classification guard checks ALL_TARGETS
# membership, but neither relates a live-group member to its startability.
# 136 -> 147. MEASURED. +11 for the gRPC preflight coverage the LAB-5549 review
# found missing: _probe_grpc_target and preflight_test_host's case dispatch were
# both new behaviour with no test at all.
#
# +8 for _probe_grpc_target (1 extraction sentinel, 5 arms, 2 for injection).
# Its arms are mutually exclusive on tool availability, so at most one ever runs
# on a given machine and CI covered whichever of grpcurl/nc/timeout the runner
# image ships — the other four were dead in practice. They are driven here on a
# sandboxed PATH holding only bash, so "grpcurl absent" and "no bounded probe
# available" are reachable at all. Two of the eight are the /dev/tcp injection
# pair: TEST_HOST must not reach the `bash -c` PARSER, and the positive control
# proves the payload fires against the interpolated form, so the negative
# assertion cannot pass because the payload was inert.
#
# +3 for preflight_test_host (1 extraction sentinel, 2 dispatch). grpc-server and
# concat-spa shared one `case` statement and `case` stops at the first match, so
# every run selecting both silently skipped concat-spa's probe. The fix (separate
# `case` blocks) had only a one-off manual run behind it. The generalised arm
# asserts the whole live group probes every target, so a future target folded
# into an existing arm is caught too — the skip produces no output and no
# failure, which is why the original survived from PR #159.
# 147 -> 154. MEASURED. +7 closing regression gaps a review DEMONSTRATED, not
# hypothesised: each mutation below was run against the previous tree and
# survived at 147/0, so every one of these assertions is known to catch
# something nothing else caught.
#
# +2 timeout bounds (grpcurl `-max-time 5`, nc `-w 5`). The probe fixtures now
# record their argv, because outcome-and-exit-status assertions cannot see a
# deleted bound: dropping `-max-time`, dropping `-w`, or widening `budget` all
# kept the suite green while restoring the hang the bounds exist to prevent.
# Failing FAST is this probe's whole purpose, so the bound is the behaviour.
#
# +1 /dev/tcp closed-port outcome. Pins that arm's `return 1`; flipping it to
# `return 0` made an unreachable gRPC target report success and survived.
# Hermetic -- port 1 on loopback needs no listener, so the suite still starts
# nothing. The /dev/tcp SUCCESS outcome stays unasserted deliberately: it needs a
# live listener, which would break this file's no-services property and add a
# skip/credit arm, i.e. the vespasian#197 hazard.
#
# +2 AC4 unconditionality. LAB-5549's deliverable is that the compile assertion
# cannot skip; prefixing the elif with `! command -v protoc ||` restored the
# original defect verbatim and survived. One arm rejects any capability gate,
# the other requires the multi-file arm to count a failure so it cannot report
# PASS with AC4 unevaluated. Comments are stripped before matching -- the block
# narrates the removed gate, and grepping raw text reported that history as a
# live gate.
#
# +2 ci.yml proto-validate-tests wiring. That job is the ONLY thing running the
# nested module's tests in CI (a root `go test ./...` cannot reach a separate
# module), so `if: false` on it silently disabled that entire suite and survived.
# 154 -> 161. MEASURED. +7 closing gaps a second review round found in the
# round-1 FIX code -- every one of them a guard that could not fail.
#
# +3 env-seam validation (TEST_HOST hostile / TEST_HOST documented-value /
# GRPC_SERVER_PORT out of range). The seam shipped with no assertion at all;
# deleting the whole validation block left the suite green. The documented-value
# case is the counterweight: a validator that rejects host.docker.internal would
# break every devcontainer run, so both directions are pinned.
#
# +1 AC4 extraction fidelity sentinel, matching the four siblings in this file.
# The AC4 "no capability gate" assertion passes when it finds no gate, so an
# anchor that stops matching yields an empty block and a vacuous pass.
#
# +3 ci.yml wiring (file present / paths filter reaches the nested manifests /
# no step-level neutering). The job-level `if:` check alone was insufficient:
# ci.yml is paths-filtered and the root-scoped go.mod pattern does not match
# test/proto-validate/go.mod, so the job that tests the nested module could stop
# firing for changes to that module; and continue-on-error, a trailing `|| true`
# or a step-level `if:` each keep the job green while running nothing.
# 161 -> 169. MEASURED. +8 closing gaps a third review round found in the
# round-2 fix code -- again, mostly guards that pinned TEXT rather than BEHAVIOUR.
#
# +4 env-seam hostile inputs (-X, embedded space, $(...), backticks) and +1 for
# asserting the REFUSAL rather than the message: the single earlier payload ended
# in '#', so only the trailing character class was ever exercised, and matching
# the message alone meant deleting `exit 1` left the suite green.
#
# +2 accept-direction seam cases (127.0.0.1 and the bracketed IPv6 literal) plus
# +1 asserting host_bare strips those brackets before nc sees them. All the IPv6
# handling had shipped with zero coverage in both directions: deleting the seam's
# bracket alternative, or the stripping itself, changed no assertion.
#
# +1 timeout-fixture fidelity: reverting it to `shift; exec "$@"` changed no
# assertion, so the block proving this probe cannot hang ran unbounded itself.
#
# The AC4 capability-gate check is now BEHAVIOURAL rather than a grep over the
# block's source (net zero, it replaces the textual one). Three textual revisions
# each mis-fired on prose. It now runs the validator on a stripped PATH with
# protoc genuinely absent -- CI's normal state -- against a malformed spec.
#
# ci.yml's presence check now GATES its block with a skip credit of 3 instead of
# emitting a bare fail(): as a bare fail it reported correctly and then let
# extract_job_block's unguarded awk abort the suite before this pin was reached.
# 169 -> 174. MEASURED. +5 for the two surfaces the round-4 review found
# unguarded, both created by this PR.
#
# +4 security.yml proto-validate-security wiring (presence, gated with skip
# credit 3; job unconditional; the govulncheck STEP's own working-directory; no
# step-level neutering). With go.work gone, that job is the only place the nested
# module's dependency graph is scanned, and its correctness rested on two
# working-directory lines nothing pinned -- deleting one makes govulncheck
# re-scan the repo root the reusable job already covers and exit 0, leaving the
# nested module unscanned with every suite green. Its ci.yml twin already had
# this block; the security twin had nothing.
#
# +1 asserting go.work is ABSENT. The workspace coupled the product's MVS list to
# a live-test helper's manifest, and the GOWORK=off belt that used to mask that
# was removed when the workspace went -- so recreating the file now re-couples
# them with no override left, and silently.
# 174 -> 179. MEASURED. Round 4 found the guard added in round 3 for the AC4 gate
# was itself VACUOUS, plus two wrong skip credits. Net +5:
#
# +1 AC4 extraction bound (empty / oversized / missing-call sentinel) and the
# behavioural check now asserts BOTH directions -- a malformed spec must fail AND a
# valid one must pass. The previous version sourced the extracted block at top
# level, where its `local` declarations are a hard error: proto_err stayed empty,
# `2>"$proto_err"` was an invalid redirect, the compound command failed before
# `go run` ran, and failures=1 came back for EVERY input. Asserting only the
# malformed direction is what let that through. The block is now wrapped in a
# function so `local` is legal.
#
# +3 GRPC_SERVER_PORT cases (0, -1, abc alongside 99999). With only 99999 pinned,
# deleting both the shape check and the lower bound left the suite green.
#
# +1 Makefile test-target invocation. ci.yml's equivalent is pinned five ways; the
# Makefile path a developer actually runs was pinned zero ways.
#
# Also corrected, net zero: the ci.yml gate's skip credit 3 -> 5 and security.yml's
# 3 -> 4 (both MEASURED by renaming the workflow -- the wrong credits made a missing
# workflow report as assertion-accounting drift), and the ci.yml step assertion now
# uses yq instead of an awk truncation that pinned YAML key order.
# 179 -> 181. MEASURED. +2 closing a hole in the guard round 4 added for
# security.yml's scan job -- the guard could not fail.
#
# Its govulncheck assertion extracted an awk slice starting at
# `- name: govulncheck (nested module)` and then grepped that slice for
# "govulncheck", which the NAME LINE satisfies. Measured: replacing
# `run: govulncheck ./...` with `run: true` kept the suite at 179/179 with the
# nested module entirely unscanned. Both scanners are now pinned by their `run:`
# COMMAND via yq (`select(.run | test("^govulncheck "))`), which also makes the
# check independent of YAML key order -- the false positive the ci.yml twin
# already hit. +1 for pinning gosec, which was named load-bearing in a comment
# and pinned nowhere, and +1 for a block-extraction fidelity sentinel matching
# the AC4 and live-tests.yml extractions.
#
# The gate's skip credit moves 4 -> 6 to match the six counted outcomes.
# 181 -> 182. MEASURED. Round 5 found two defects in round 4's own guards, plus a
# CI-environment problem this guard created.
#
# The AC4 guard is now driven by a STUB validator rather than a real `go run`. The
# real-toolchain form required Go AND a module-proxy fetch inside live-tests.yml's
# preflight-selftest job, which has no setup-go and whose documented property is
# that these suites need "no Go, Node or Chrome" -- measured RED under GOPROXY=off
# with an empty module cache, which the LAB-4732 egress audit->block flip would
# have made CI's steady state. The stub is also stronger: +1 asserts the validator
# was actually INVOKED (the round-4 vacuity failed before reaching it and still
# reported failures=1), and the verdict assertion covers both directions.
#
# Net zero, not counted: the ci.yml go-test step assertion now checks
# working-directory AND -race again. The awk form it replaced checked both; the
# first yq rewrite kept only working-directory, so dropping -race from the only job
# that runs the nested module's tests survived at 179/0.
# ── end merged-from-main history ─────────────────────────────────────────────

EXPECTED_ASSERTIONS=236
if [[ $((PASS + FAIL + SKIP_CREDIT)) -ne "$EXPECTED_ASSERTIONS" ]]; then
    echo "test-runner-args: FAIL — assertion accounting drift: expected ${EXPECTED_ASSERTIONS} assertions (pass+fail+skip credit), saw $((PASS + FAIL + SKIP_CREDIT))."
    echo "  A case was added or removed without updating EXPECTED_ASSERTIONS."
    exit 1
fi
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
