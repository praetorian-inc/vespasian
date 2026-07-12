#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Regression test for test/setup-live-targets.sh hardening (LAB-2893).
#
# Verifies:
#   * Teardown kills EVERY started generation, not just the most recent
#     (orphan-PID accumulation across repeated setup runs).
#   * Legacy single-PID files (.<name>.pid) are still honoured.
#   * Orphans with no pid log are swept by basename (Go services) and by
#     listening port (node/graphql), never by pkill-ing `node` by name.
#   * Stale processes are cleaned up on setup startup.
#   * Port exhaustion is detected (find_available_port returns empty) so the
#     caller's failure message runs instead of a silent `set -e` exit.
#
# No Go build, Node, or Chrome required — the test spawns lightweight stand-ins,
# so it runs in the offline CI job. Run directly:
#
#   ./test/setup-live-targets_test.sh

set -uo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_UNDER_TEST="${THIS_DIR}/setup-live-targets.sh"

# Isolate all PID/state files in a temp dir so we never touch the real test/ tree.
STATE_DIR="$(mktemp -d)"
cp "${THIS_DIR}/common.sh" "${STATE_DIR}/common.sh"

# Track every PID we spawn so cleanup is guaranteed even if an assertion fails.
SPAWNED_PIDS=()

cleanup() {
    local pid
    for pid in "${SPAWNED_PIDS[@]:-}"; do
        if [ -n "$pid" ]; then kill -9 "$pid" 2>/dev/null || true; fi
    done
    rm -rf "${STATE_DIR}"
}
trap cleanup EXIT

# Source the script with an overridden SCRIPT_DIR. The main() guard means only
# the functions load — nothing is started.
export SCRIPT_DIR="${STATE_DIR}"
# shellcheck source=/dev/null
source "${SCRIPT_UNDER_TEST}"

# The sourced script enables `set -euo pipefail`; relax it so assertions that
# probe for dead processes (expected non-zero exits) don't abort the harness.
set +e +u

# ── Test harness ──────────────────────────────────────────────────────────
PASS=0
FAIL=0

ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

is_alive() { kill -0 "$1" 2>/dev/null; }

assert_dead() {
    # Give the async kill a moment to land.
    local pid=$1 desc=$2 _
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! is_alive "$pid"; then ok "$desc"; return; fi
        sleep 0.2
    done
    fail "$desc (PID $pid still alive)"
}

assert_alive() {
    if is_alive "$1"; then ok "$2"; else fail "$2 (PID $1 already dead)"; fi
}

assert_no_file() {
    if [ ! -e "$1" ]; then ok "$2"; else fail "$2 (file $1 still present)"; fi
}

assert_eq() {
    if [ "$1" = "$2" ]; then ok "$3"; else fail "$3 (expected '$2', got '$1')"; fi
}

# Spawn a long-lived background process; sets REPLY to its PID and records it.
spawn_sleep() {
    sleep 600 &
    REPLY=$!
    SPAWNED_PIDS+=("$REPLY")
}

# Spawn a long-lived process whose executable basename is $1 (so `pgrep -x`
# matches it, mirroring a real compiled Go target). Copies the real `sleep`.
spawn_named() {
    cp "$(command -v sleep)" "${STATE_DIR}/$1"
    "${STATE_DIR}/$1" 600 &
    REPLY=$!
    SPAWNED_PIDS+=("$REPLY")
}

# ── Test 1: teardown kills every generation (append-log) ────────────────────
echo "Test 1: teardown kills every started generation"
spawn_sleep; p1=$REPLY
spawn_sleep; p2=$REPLY
spawn_sleep; p3=$REPLY
record_pid rest-api "$p1"
record_pid rest-api "$p2"
record_pid rest-api "$p3"
stop_service rest-api >/dev/null 2>&1
assert_dead "$p1" "generation 1 killed"
assert_dead "$p2" "generation 2 killed"
assert_dead "$p3" "generation 3 (latest) killed"
assert_no_file "${STATE_DIR}/.rest-api.pids" "pid log removed after teardown"

# ── Test 2: legacy single-PID file is honoured ──────────────────────────────
echo "Test 2: legacy .pid file is still killed"
spawn_sleep; p=$REPLY
echo "$p" > "${STATE_DIR}/.soap-service.pid"
stop_service soap-service >/dev/null 2>&1
assert_dead "$p" "legacy-pidfile process killed"
assert_no_file "${STATE_DIR}/.soap-service.pid" "legacy pid file removed"

# ── Test 3: orphan with no pid log swept by basename (Go service) ───────────
echo "Test 3: untracked orphan swept by basename"
if command -v pgrep >/dev/null 2>&1; then
    spawn_named grpc-server; p=$REPLY   # comm == grpc-server, no pid log recorded
    assert_alive "$p" "orphan running before sweep"
    stop_service grpc-server >/dev/null 2>&1
    assert_dead "$p" "orphan swept by exact basename"
else
    echo "  skip - pgrep not available"
fi

# ── Test 4: graphql orphan swept by port, never by pkill node ───────────────
echo "Test 4: graphql orphan swept by listening port (not by killing node)"
if command -v lsof >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
   && ! port_in_use "$DEFAULT_GRAPHQL_SERVER_PORT"; then
    python3 -m http.server "$DEFAULT_GRAPHQL_SERVER_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
    p=$!
    SPAWNED_PIDS+=("$p")
    # Wait for the listener to bind.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if port_in_use "$DEFAULT_GRAPHQL_SERVER_PORT"; then break; fi
        sleep 0.2
    done
    assert_alive "$p" "port listener running before sweep"
    stop_service graphql-server >/dev/null 2>&1
    assert_dead "$p" "listener swept by port"
else
    echo "  skip - lsof/python3 unavailable or default graphql port busy"
fi

# ── Test 5: setup → setup → teardown leaves zero processes (acceptance) ──────
echo "Test 5: two setup generations accumulate, teardown kills all"
gen_pids=()
for _round in 1 2; do
    for svc in rest-api soap-service concat-spa; do
        spawn_sleep
        record_pid "$svc" "$REPLY"
        gen_pids+=("$REPLY")
    done
done
do_teardown >/dev/null 2>&1
all_dead=1
for gp in "${gen_pids[@]}"; do
    if is_alive "$gp"; then all_dead=0; fi
done
assert_eq "$all_dead" "1" "all 6 processes across 2 generations killed"

# ── Test 6: stale-state cleanup on setup startup ────────────────────────────
echo "Test 6: cleanup_stale_state kills leftovers and clears pid logs"
spawn_sleep; p=$REPLY
record_pid rest-api "$p"
cleanup_stale_state >/dev/null 2>&1
assert_dead "$p" "stale process killed at startup"
assert_no_file "${STATE_DIR}/.rest-api.pids" "stale pid log cleared at startup"

# ── Test 7: port exhaustion is detectable (Bug 2) ───────────────────────────
echo "Test 7: find_available_port returns empty when the window is exhausted"
# Force every probed port to look occupied.
# shellcheck disable=SC2317  # invoked indirectly by find_available_port
port_in_use() { return 0; }
result=$(find_available_port 19000) || true
assert_eq "$result" "" "exhausted range yields empty string (caller check runs)"
# And the happy path still returns the base port when free.
# shellcheck disable=SC2317  # invoked indirectly by find_available_port
port_in_use() { return 1; }
result=$(find_available_port 19000) || true
assert_eq "$result" "19000" "free base port returned"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────"
echo "Passed: ${PASS}   Failed: ${FAIL}"
echo "──────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
