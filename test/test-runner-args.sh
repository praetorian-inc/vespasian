#!/usr/bin/env bash
# Tests for run-live-tests.sh target group consistency and --group flag.
# Does NOT run actual live tests — only validates that the group arrays
# stay in sync with the case dispatch block, and that --group resolves
# the correct target set (via --dry-run, no binary required).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run-live-tests.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1" >&2; }

# ── Source the target arrays and helper from the runner ──────────

source <(sed -n '/^OFFLINE_TARGETS=(/,/^)/p' "$RUNNER")
source <(sed -n '/^LIVE_TARGETS=(/,/^)/p' "$RUNNER")
source <(grep '^join_targets()' "$RUNNER")

# ── Extract case-dispatch targets from the runner ────────────────
# Matches lines like:  rest-api)      test_rest_api ;;

mapfile -t DISPATCH_TARGETS < <(
    sed -nE 's/^[[:space:]]+([^)]+)\)[[:space:]]+test_.*/\1/p' "$RUNNER" | sort
)

# Targets that are intentionally not in either group (config-driven).
CONFIG_ONLY=(grpc-server)

echo "=== Drift guard: groups vs case dispatch ==="
drift_fail_before=$FAIL

# Every group member must have a case-dispatch entry.
for target in "${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}"; do
    if printf '%s\n' "${DISPATCH_TARGETS[@]}" | grep -qx "$target"; then
        : # ok
    else
        fail "Group member '$target' has no case-dispatch entry in run-live-tests.sh"
    fi
done

# Every dispatch target must be in a group or in CONFIG_ONLY.
all_grouped=("${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}" "${CONFIG_ONLY[@]}")
for target in "${DISPATCH_TARGETS[@]}"; do
    if printf '%s\n' "${all_grouped[@]}" | grep -qx "$target"; then
        : # ok
    else
        fail "Dispatch target '$target' is not in OFFLINE_TARGETS, LIVE_TARGETS, or CONFIG_ONLY"
    fi
done

# No target should appear in both groups.
for target in "${OFFLINE_TARGETS[@]}"; do
    if printf '%s\n' "${LIVE_TARGETS[@]}" | grep -qx "$target"; then
        fail "'$target' appears in both OFFLINE_TARGETS and LIVE_TARGETS"
    fi
done

group_count=$(( ${#OFFLINE_TARGETS[@]} + ${#LIVE_TARGETS[@]} ))
dispatch_count=${#DISPATCH_TARGETS[@]}
config_count=${#CONFIG_ONLY[@]}
if [[ "$FAIL" -eq "$drift_fail_before" ]]; then
    pass "Groups (${group_count}) + config-only (${config_count}) cover all dispatch targets (${dispatch_count})"
fi

echo ""
echo "=== Drift guard self-test (negative case) ==="

# Verify the guard actually catches a missing target by feeding it a
# synthetic DISPATCH_TARGETS that includes an entry absent from all groups.
synthetic_dispatch=("${DISPATCH_TARGETS[@]}" "phantom-target")
guard_caught=false
all_grouped_with_config=("${OFFLINE_TARGETS[@]}" "${LIVE_TARGETS[@]}" "${CONFIG_ONLY[@]}")
for target in "${synthetic_dispatch[@]}"; do
    if ! printf '%s\n' "${all_grouped_with_config[@]}" | grep -qx "$target"; then
        guard_caught=true
        break
    fi
done
if [[ "$guard_caught" == true ]]; then
    pass "Drift guard detects ungrouped dispatch target (phantom-target)"
else
    fail "Drift guard did NOT detect ungrouped dispatch target"
fi

echo ""
echo "=== Target group construction ==="

# --group all includes every group member without duplicates.
all="$(join_targets "${OFFLINE_TARGETS[@]}"),$(join_targets "${LIVE_TARGETS[@]}")"
dup_count=$(echo "$all" | tr ',' '\n' | sort | uniq -d | wc -l | tr -d ' ')
if [[ "$dup_count" -eq 0 ]]; then
    pass "--group all: no duplicates"
else
    fail "--group all: found $dup_count duplicate(s)"
fi

# TARGETS_SETUP merge deduplicates correctly (scoped to avoid leaking).
(
    TARGETS_SETUP="rest-api,soap-service,graphql-server,grpc-server,concat-spa"
    merged="${TARGETS_SETUP},${all}"
    deduped=$(echo "$merged" | tr ',' '\n' | awk '!s[$0]++' | paste -sd, -)
    dup_count=$(echo "$deduped" | tr ',' '\n' | sort | uniq -d | wc -l | tr -d ' ')
    if [[ "$dup_count" -eq 0 ]]; then
        echo "  PASS: TARGETS_SETUP merge: no duplicates after dedup"
    else
        echo "  FAIL: TARGETS_SETUP merge: found $dup_count duplicate(s)" >&2
        exit 1
    fi
    if echo "$deduped" | grep -q 'grpc-server'; then
        echo "  PASS: TARGETS_SETUP merge: grpc-server included"
    else
        echo "  FAIL: TARGETS_SETUP merge: grpc-server missing" >&2
        exit 1
    fi
) && PASS=$((PASS + 2)) || FAIL=$((FAIL + 1))

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
tmpconfig=$(mktemp)
echo "TARGETS_SETUP=" > "$tmpconfig"
invalid_output=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group bogus" 2>&1 || true)
if [[ "$invalid_output" == *"Unknown group"* ]]; then
    pass "Invalid --group: rejected with 'Unknown group' message"
else
    fail "Invalid --group: expected 'Unknown group' in output, got: $invalid_output"
fi
rm -f "$tmpconfig"

# --group without a value exits non-zero with the expected error message.
tmpconfig=$(mktemp)
echo "TARGETS_SETUP=" > "$tmpconfig"
novalue_output=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group" 2>&1 || true)
if [[ "$novalue_output" == *"--group requires a value"* ]]; then
    pass "--group (no value): rejected with '--group requires a value'"
else
    fail "--group (no value): expected '--group requires a value' in output, got: $novalue_output"
fi
rm -f "$tmpconfig"

# --targets without a value exits non-zero with the expected error message.
tmpconfig=$(mktemp)
echo "TARGETS_SETUP=" > "$tmpconfig"
novalue_output=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --targets" 2>&1 || true)
if [[ "$novalue_output" == *"--targets requires a value"* ]]; then
    pass "--targets (no value): rejected with '--targets requires a value'"
else
    fail "--targets (no value): expected '--targets requires a value' in output, got: $novalue_output"
fi
rm -f "$tmpconfig"

echo ""
echo "=== Behavioral --group resolution (via --dry-run) ==="

# These tests invoke the runner with --dry-run to verify the actual
# group-resolution code path without requiring a binary or running tests.

tmpconfig=$(mktemp)
echo "TARGETS_SETUP=" > "$tmpconfig"

# --group offline resolves to exactly OFFLINE_TARGETS.
expected_offline="$(join_targets "${OFFLINE_TARGETS[@]}")"
actual_offline=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group offline --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//')
if [[ "$actual_offline" == "$expected_offline" ]]; then
    pass "--group offline resolves to OFFLINE_TARGETS (${#OFFLINE_TARGETS[@]} targets)"
else
    fail "--group offline: expected '$expected_offline', got '$actual_offline'"
fi

# --group live resolves to exactly LIVE_TARGETS.
expected_live="$(join_targets "${LIVE_TARGETS[@]}")"
actual_live=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --group live --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//')
if [[ "$actual_live" == "$expected_live" ]]; then
    pass "--group live resolves to LIVE_TARGETS (${#LIVE_TARGETS[@]} targets)"
else
    fail "--group live: expected '$expected_live', got '$actual_live'"
fi

# --group all (default) resolves to OFFLINE + LIVE.
expected_all="$(join_targets "${OFFLINE_TARGETS[@]}"),$(join_targets "${LIVE_TARGETS[@]}")"
actual_all=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//')
if [[ "$actual_all" == "$expected_all" ]]; then
    pass "--group all resolves to OFFLINE + LIVE ($(echo "$expected_all" | tr ',' '\n' | wc -l | tr -d ' ') targets)"
else
    fail "--group all: expected '$expected_all', got '$actual_all'"
fi

# --targets overrides --group.
actual_override=$(env CONFIG_FILE="$tmpconfig" bash -c "source '$RUNNER' --targets rest-api --group offline --dry-run" 2>&1 | grep '^targets=' | sed 's/^targets=//')
if [[ "$actual_override" == "rest-api" ]]; then
    pass "--targets overrides --group: resolved to 'rest-api' only"
else
    fail "--targets overrides --group: expected 'rest-api', got '$actual_override'"
fi

rm -f "$tmpconfig"

echo ""
echo "=== Summary ==="
echo "  $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
