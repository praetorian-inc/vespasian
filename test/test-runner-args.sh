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
# Adjacency, not mere presence. Two independent greps pass on `-max-time 99 ...
# 5` whenever a bare "5" appears anywhere else in argv -- for the nc arm that is
# the PORT, so budget 99 with port 5 slipped through. Compare the line that
# FOLLOWS the flag.
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
# Adjacency for the same reason as the grpcurl bound above; this is the arm where
# the port made the independent form pass with a mutated budget.
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
seam_hostile=$(TEST_HOST='x/1; id #' bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) || true
if [[ "$seam_hostile" == *"refusing to run"* ]]; then
    pass "env seam: TEST_HOST carrying shell metacharacters is refused"
else
    fail "env seam: a TEST_HOST containing ';' and '#' was NOT refused; got: $seam_hostile"
fi

seam_ok=$(TEST_HOST='host.docker.internal' bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) || true
if [[ "$seam_ok" != *"refusing to run"* && "$seam_ok" == *"targets="* ]]; then
    pass "env seam: the documented devcontainer TEST_HOST is still accepted"
else
    fail "env seam: TEST_HOST=host.docker.internal must be accepted — the validator cannot reject a documented value; got: $seam_ok"
fi

seam_port=$(GRPC_SERVER_PORT=99999 bash -c "source '$RUNNER' --group offline --dry-run" 2>&1) || true
if [[ "$seam_port" == *"refusing to run"* ]]; then
    pass "env seam: an out-of-range GRPC_SERVER_PORT is refused"
else
    fail "env seam: GRPC_SERVER_PORT=99999 was NOT refused; got: $seam_port"
fi

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

# (a) No capability gate may guard the compile invocation. This is the exact
# shape that was removed: `command -v <tool>` deciding whether the assertion runs.
if printf '%s' "$ac4_block" | grep -qE 'command -v|which |type -p'; then
    fail "AC4 compile check reintroduced a capability gate (command -v/which/type) — the assertion can skip again, which is the defect LAB-5549 removed"
else
    pass "AC4 compile check has no capability gate — it cannot skip on a missing tool"
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

grpc_count=$(echo "$setup_output" | tr ',' '\n' | grep -cx 'grpc-server')
if [[ "$grpc_count" -eq 1 ]]; then
    pass "TARGETS_SETUP merge: grpc-server appears exactly once"
else
    fail "TARGETS_SETUP merge: grpc-server count=$grpc_count, expected 1"
fi

rest_count=$(echo "$setup_output" | tr ',' '\n' | grep -cx 'rest-api')
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
    direct_exec_scripts=$(grep -oE 'run: \./(test/[a-zA-Z0-9_.-]+\.sh)' "$WORKFLOW" | sed 's|run: \./||' | sort -u)
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
        if printf '%s\n' "$e2e_block" | grep -qE 'run:[[:space:]]*(\./|bash )?test/install-chrome\.sh'; then
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
        if printf '%s\n' "$e2e_block" | grep -qE '^[[:space:]]*if:.*workflow_dispatch' \
           && printf '%s\n' "$e2e_block" | grep -qE '^[[:space:]]*if:.*refs/heads/main'; then
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
        e2e_runlines=$(printf '%s\n' "$e2e_block" | grep -vE '^[[:space:]]*#')
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
if [ -f "$WORKFLOW" ]; then
    pass "ci.yml is present and readable"
else
    fail "ci.yml not found at $WORKFLOW — the proto-validate-tests assertions below cannot be evaluated"
fi

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
pv_block=$(extract_job_block proto-validate-tests)
if printf '%s' "$pv_block" | grep -q 'go test .*\./test/proto-validate/\.\.\.'; then
    pass "ci.yml proto-validate-tests actually runs go test against ./test/proto-validate/..."
else
    fail "ci.yml proto-validate-tests no longer runs 'go test ./test/proto-validate/...' — the nested module's tests would not run in CI"
fi

# A job-level `if:` is not the only way to switch this off. A step-level `if:`,
# `continue-on-error: true`, or a trailing `|| true` on the test command each
# leave the job green while running nothing that can fail -- the same neutering
# the live-tests.yml block above already checks for.
if printf '%s' "$pv_block" | grep -qE 'continue-on-error:[[:space:]]*true|\|\|[[:space:]]*(true|exit 0|:)[[:space:]]*$|^[[:space:]]+if:'; then
    fail "ci.yml proto-validate-tests contains step-level neutering (continue-on-error, a trailing '|| true', or a step if:) — the job would stay green while testing nothing"
else
    pass "ci.yml proto-validate-tests has no step-level neutering"
fi

WORKFLOW="$_WORKFLOW_SAVED"

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

SUITE_COMPLETED=1

echo ""
echo "=== Summary ==="
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
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
EXPECTED_ASSERTIONS=161
if [[ $((PASS + FAIL + SKIP_CREDIT)) -ne "$EXPECTED_ASSERTIONS" ]]; then
    echo "test-runner-args: FAIL — assertion accounting drift: expected ${EXPECTED_ASSERTIONS} assertions (pass+fail+skip credit), saw $((PASS + FAIL + SKIP_CREDIT))."
    echo "  A case was added or removed without updating EXPECTED_ASSERTIONS."
    exit 1
fi
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
