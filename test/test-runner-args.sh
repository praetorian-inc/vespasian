#!/usr/bin/env bash
# Tests for run-live-tests.sh target group consistency and the --group flag,
# plus the setup-live-targets.sh run-guidance selector. Does NOT run actual live
# tests — only validates that the group arrays stay in sync with the case
# dispatch block, that --group resolves the correct target set (via --dry-run,
# no binary required), and that setup-complete guidance steers full vs partial
# setups correctly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run-live-tests.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1" >&2; }

# All temp configs live under one directory removed by a single EXIT trap, so
# they are cleaned up no matter where the script exits (including a `set -e`
# abort mid-assertion). A directory — not an in-shell array — is used precisely
# because new_tmp is called via command substitution ($(new_tmp)), whose
# subshell would discard any array registration; a filesystem dir created in the
# parent and torn down by the trap has no such scoping problem.
TMPDIR_T="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_T"' EXIT
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

# Targets that are intentionally not in either group (config-driven).
CONFIG_ONLY=(grpc-server)

# ungrouped_dispatch_targets prints any of the given targets that are absent
# from OFFLINE_TARGETS, LIVE_TARGETS, and CONFIG_ONLY. This is the real
# coverage check shared by the drift guard and its negative self-test, so a
# regression here trips both — not just a hand-written copy of the loop.
ungrouped_dispatch_targets() {
    local grouped=("${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}" "${CONFIG_ONLY[@]}")
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
        fail "Group member '$target' has no case-dispatch entry in run-live-tests.sh"
    done < <(undispatched_group_members "$@")
}

report_ungrouped_dispatch_targets() {
    local target
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        fail "Dispatch target '$target' is not in OFFLINE_TARGETS, LIVE_TARGETS, or CONFIG_ONLY"
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

# Every group member must have a case-dispatch entry (direction a).
report_undispatched_group_members "${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}"

# Every dispatch target must be in a group or in CONFIG_ONLY (direction b).
report_ungrouped_dispatch_targets "${DISPATCH_TARGETS[@]}"

# No target should appear in both groups.
for target in "${OFFLINE_TARGETS[@]}"; do
    if printf '%s\n' "${LIVE_TARGETS[@]}" | grep -qx "$target"; then
        fail "'$target' appears in both OFFLINE_TARGETS and LIVE_TARGETS"
    fi
done

group_count=$(( ${#OFFLINE_TARGETS[@]} + ${#LIVE_TARGETS[@]} ))
dispatch_count=${#DISPATCH_TARGETS[@]}
config_count=${#CONFIG_ONLY[@]}

# Belt-and-suspenders count assertion: with robust extraction the arm count must
# equal grouped + config-only. This catches drift the per-target loops cannot —
# e.g. an accidental duplicate arm, or a target both grouped and extracted but
# miscounted — by comparing totals directly instead of per-target membership.
if [[ $(( group_count + config_count )) -ne "$dispatch_count" ]]; then
    fail "Coverage count mismatch: groups (${group_count}) + config-only (${config_count}) != dispatch (${dispatch_count})"
fi

if [[ "$FAIL" -eq "$drift_fail_before" ]]; then
    pass "Groups (${group_count}) + config-only (${config_count}) cover all dispatch targets (${dispatch_count})"
fi

echo ""
echo "=== Absolute group-size anchors (AC#3: 19 offline + 6 live = 25) ==="

# Pin concrete group sizes as literals, independent of the sourced arrays. The
# behavioral --group tests derive expected from the same OFFLINE_TARGETS/
# LIVE_TARGETS under test, so a coordinated silent target drop shrinks expected
# and actual in lockstep and passes green. These literals encode the LAB-4773
# AC#3 contract ("all 25 targets still run") so any such drop trips here.
if [[ "${#OFFLINE_TARGETS[@]}" -eq 19 ]]; then
    pass "OFFLINE_TARGETS has exactly 19 members"
else
    fail "OFFLINE_TARGETS count drifted: expected 19, got ${#OFFLINE_TARGETS[@]}"
fi
if [[ "${#LIVE_TARGETS[@]}" -eq 6 ]]; then
    pass "LIVE_TARGETS has exactly 6 members"
else
    fail "LIVE_TARGETS count drifted: expected 6, got ${#LIVE_TARGETS[@]}"
fi
if [[ "$group_count" -eq 25 ]]; then
    pass "Grouped targets total 25 (AC#3: all 25 targets still run)"
else
    fail "Grouped-target total drifted: expected 25, got $group_count"
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
if [[ "$dup_count" -eq 0 ]]; then
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
# must ignore it entirely (no config-only targets leak in).
tmpconfig_scoped=$(new_tmp)
echo "TARGETS_SETUP=grpc-server" > "$tmpconfig_scoped"
scoped_offline=$(env CONFIG_FILE="$tmpconfig_scoped" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
scoped_live=$(env CONFIG_FILE="$tmpconfig_scoped" bash -c "source '$RUNNER' --group live --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//') || true
if [[ "$scoped_offline" == "$(join_targets "${OFFLINE_TARGETS[@]}")" && "$scoped_live" == "$(join_targets "${LIVE_TARGETS[@]}")" ]]; then
    pass "TARGETS_SETUP ignored for --group offline/live (grpc-server absent)"
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
echo "=== Summary ==="
echo "  $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
