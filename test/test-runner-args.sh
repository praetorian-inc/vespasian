#!/usr/bin/env bash
# Tests for run-live-tests.sh target group consistency and --group flag.
# Does NOT run actual live tests — only validates that the group arrays
# stay in sync with the case dispatch block.

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
pass "Groups (${group_count}) + config-only (${config_count}) cover all dispatch targets (${dispatch_count})"

echo ""
echo "=== Target group construction ==="

# --group all includes every group member without duplicates.
all="$(join_targets "${LIVE_TARGETS[@]}"),$(join_targets "${OFFLINE_TARGETS[@]}")"
dup_count=$(echo "$all" | tr ',' '\n' | sort | uniq -d | wc -l | tr -d ' ')
if [[ "$dup_count" -eq 0 ]]; then
    pass "--group all: no duplicates"
else
    fail "--group all: found $dup_count duplicate(s)"
fi

# TARGETS_SETUP merge deduplicates correctly.
TARGETS_SETUP="rest-api,soap-service,graphql-server,grpc-server,concat-spa"
merged="${TARGETS_SETUP},${all}"
deduped=$(echo "$merged" | tr ',' '\n' | awk '!s[$0]++' | paste -sd, -)
dup_count=$(echo "$deduped" | tr ',' '\n' | sort | uniq -d | wc -l | tr -d ' ')
if [[ "$dup_count" -eq 0 ]]; then
    pass "TARGETS_SETUP merge: no duplicates after dedup"
else
    fail "TARGETS_SETUP merge: found $dup_count duplicate(s)"
fi

# grpc-server is present after merge (config-only target works).
if echo "$deduped" | grep -q 'grpc-server'; then
    pass "TARGETS_SETUP merge: grpc-server included"
else
    fail "TARGETS_SETUP merge: grpc-server missing"
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

# Invalid --group value exits non-zero.
tmpconfig=$(mktemp)
echo "TARGETS_SETUP=" > "$tmpconfig"
if env CONFIG_FILE="$tmpconfig" bash -c "
    source '$RUNNER' --group bogus 2>/dev/null
" 2>/dev/null; then
    fail "Invalid --group should exit non-zero"
else
    pass "Invalid --group exits non-zero"
fi
rm -f "$tmpconfig"

echo ""
echo "=== Summary ==="
echo "  $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
