#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Regression test for test/setup-live-targets.sh hardening (LAB-2893).
#
# Verifies:
#   * Teardown kills EVERY started generation, not just the most recent
#     (orphan-PID accumulation across repeated setup runs).
#   * Legacy single-PID files (.<name>.pid) are still honoured.
#   * Recorded/stale PIDs are killed only when they still belong to the service
#     (identity check), so a recycled PID is never killed.
#   * Orphans with no pid log are swept by basename (Go services) and by
#     listening port (node/graphql), never by pkill-ing `node` by name.
#   * Stale processes are cleaned up on setup startup.
#   * Port exhaustion is detected AND the caller's failure path runs under
#     `set -e` (Bug 2) instead of a silent exit.
#   * show_port_holders lists the processes holding an exhausted range (AC2).
#   * graphql-server (node) is matched only when node AND listening in its port
#     window; kill_pid escalates SIGTERM -> SIGKILL.
#   * parse_args maps the CLI flags (esp. --sweep -> SWEEP_ORPHANS, default off).
#   * An already-dead recorded PID is handled gracefully (not counted stopped).
#   * The real orphan-discovery seams filter by node-in-port-window and by exact
#     basename + current user.
#
# No Go build, Node, or Chrome required — the test spawns lightweight stand-ins,
# so it runs in the offline CI job. Run directly:
#
#   ./test/setup-live-targets_test.sh

set -uo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_UNDER_TEST="${THIS_DIR}/setup-live-targets.sh"

# Isolate all PID/state files in a temp dir so we never touch the real test/
# tree. This uses the dedicated state-dir override, NOT SCRIPT_DIR — the script
# always resolves SCRIPT_DIR from its own location and sources common.sh there.
STATE_DIR="$(mktemp -d)"

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

# Source the script with the state dir redirected to our temp dir. The main()
# guard means only the functions load — nothing is started.
export SETUP_LIVE_TARGETS_STATE_DIR="${STATE_DIR}"
# shellcheck source=/dev/null
source "${SCRIPT_UNDER_TEST}"

# The sourced script enables `set -euo pipefail`; relax it so assertions that
# probe for dead processes (expected non-zero exits) don't abort the harness.
set +e +u

# Preserve the REAL seam implementations before we sandbox them, under aliased
# names, so Tests 16-17 can exercise the actual node-in-port-window and
# exact-name/user filters (the security-relevant guards) instead of the stub.
# `declare -f` renders the sourced function body; prefixing renames the copy.
eval "real_$(declare -f orphan_pids_by_port)"
eval "real_$(declare -f orphan_pids_by_name)"

# Sandbox the orphan-discovery seams for the entire run so a sweep can NEVER
# reach the developer's real process table (`pgrep -x rest-api` / an lsof port
# scan would otherwise match a dev's own service). Each test that exercises a
# sweep sets the matching _sweep_* variable to its OWN stand-in PID; the real
# pgrep/lsof discovery in the seams is exercised only by Tests 16-17, each
# confined to a stand-in the harness spawns itself.
_name_sweep_pid=""
_port_sweep_pid=""
orphan_pids_by_name() { [ -n "$_name_sweep_pid" ] && echo "$_name_sweep_pid"; return 0; }
orphan_pids_by_port() { [ -n "$_port_sweep_pid" ] && echo "$_port_sweep_pid"; return 0; }

# SWEEP_ORPHANS is defined by the sourced script and read by stop_service; tests
# toggle it to gate the opt-in sweep. Marked exported so shellcheck sees it as
# consumed externally (the reader is in the sourced file, not this one).
export SWEEP_ORPHANS

# ── Test harness ──────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0

ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }
# Tool-prerequisite skips are counted so the summary can surface dropped coverage
# (a bare "Passed: N Failed: 0" would otherwise hide silently skipped tests).
skip() { echo "  skip - $1"; SKIP=$((SKIP + 1)); }

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

assert_contains() {
    case "$1" in
        *"$2"*) ok "$3" ;;
        *)      fail "$3 (missing '$2' in output)" ;;
    esac
}

# Spawn a long-lived process whose executable basename is $1, so both `pgrep -x`
# and the pid_matches_service identity check see it as that service (mirrors a
# real compiled Go target). Copies the real `sleep`. Sets REPLY to its PID.
spawn_named() {
    # Reuse an existing stand-in binary — copying over one that is still running
    # fails with "Text file busy" and is unnecessary (same bytes).
    [ -x "${STATE_DIR}/$1" ] || cp "$(command -v sleep)" "${STATE_DIR}/$1"
    "${STATE_DIR}/$1" 600 &
    REPLY=$!
    SPAWNED_PIDS+=("$REPLY")
    disown "$REPLY" 2>/dev/null || true   # silence async "Killed" job notices
}

# Find a free localhost TCP port for a test listener (independent of any stub of
# port_in_use later in the file).
free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# ── Test 1: teardown kills every generation (append-log) ────────────────────
echo "Test 1: teardown kills every started generation"
spawn_named rest-api; p1=$REPLY
spawn_named rest-api; p2=$REPLY
spawn_named rest-api; p3=$REPLY
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
spawn_named soap-service; p=$REPLY
echo "$p" > "${STATE_DIR}/.soap-service.pid"
stop_service soap-service >/dev/null 2>&1
assert_dead "$p" "legacy-pidfile process killed"
assert_no_file "${STATE_DIR}/.soap-service.pid" "legacy pid file removed"

# ── Test 3: recorded PID that is NOT the service is spared (recycled PID) ────
echo "Test 3: recycled PID (identity mismatch) is not killed"
spawn_sleep_pid() { sleep 600 & REPLY=$!; SPAWNED_PIDS+=("$REPLY"); disown "$REPLY" 2>/dev/null || true; }
spawn_sleep_pid; imposter=$REPLY   # comm == 'sleep', not 'rest-api'
record_pid rest-api "$imposter"
stop_service rest-api >/dev/null 2>&1
assert_alive "$imposter" "process whose comm != service basename is spared"
kill -9 "$imposter" 2>/dev/null || true

# ── Test 4: untracked orphan swept by basename under --sweep (Go service) ────
echo "Test 4: untracked orphan swept by basename when --sweep is enabled"
spawn_named grpc-server; p=$REPLY   # comm == grpc-server, no pid log recorded
_name_sweep_pid="$p"                 # sandbox: sweep sees only this stand-in
SWEEP_ORPHANS=true                   # opt in to the fallback sweep
assert_alive "$p" "orphan running before sweep"
stop_service grpc-server >/dev/null 2>&1
assert_dead "$p" "orphan swept via name seam (no pid log, --sweep on)"
SWEEP_ORPHANS=false
_name_sweep_pid=""

# ── Test 5: graphql orphan swept by port seam under --sweep, never pkill node ─
echo "Test 5: graphql orphan swept by listening-port seam when --sweep is enabled"
if command -v python3 >/dev/null 2>&1; then
    port="$(free_port)"
    python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 &
    p=$!
    SPAWNED_PIDS+=("$p")
    disown "$p" 2>/dev/null || true
    _port_sweep_pid="$p"             # sandbox: sweep sees only this stand-in
    SWEEP_ORPHANS=true               # opt in to the fallback sweep
    assert_alive "$p" "port listener running before sweep"
    stop_service graphql-server >/dev/null 2>&1
    assert_dead "$p" "listener swept via port seam (no pid log, --sweep on)"
    SWEEP_ORPHANS=false
    _port_sweep_pid=""
else
    skip "python3 unavailable"
fi

# ── Test 6: setup → setup → teardown leaves zero processes (acceptance) ──────
echo "Test 6: two setup generations accumulate, teardown kills all"
# All Go-style services (unique executable basename) share the identical
# do_teardown loop, so covering four of them exercises the accumulation path.
# graphql-server is intentionally omitted here: its identity check requires a
# node-named process listening in its port window (covered dedicated in Test 13).
gen_pids=()
for _round in 1 2; do
    for svc in rest-api soap-service concat-spa grpc-server; do
        spawn_named "$svc"
        record_pid "$svc" "$REPLY"
        gen_pids+=("$REPLY")
    done
done
do_teardown >/dev/null 2>&1
all_dead=1
for gp in "${gen_pids[@]}"; do
    if is_alive "$gp"; then all_dead=0; fi
done
assert_eq "$all_dead" "1" "all 8 processes across 2 generations killed"

# ── Test 7: stale-state cleanup on setup startup ────────────────────────────
echo "Test 7: cleanup_stale_state kills leftovers and clears pid logs"
spawn_named rest-api; p=$REPLY
record_pid rest-api "$p"
out="$(cleanup_stale_state 2>&1)"
assert_dead "$p" "stale process killed at startup"
assert_contains "$out" "Killing stale process rest-api" "explicit stale-kill log line (AC3)"
assert_no_file "${STATE_DIR}/.rest-api.pids" "stale pid log cleared at startup"

# ── Test 8: show_port_holders lists processes holding the range (AC2) ────────
echo "Test 8: show_port_holders reports listeners on the port window"
if command -v python3 >/dev/null 2>&1 \
   && { command -v lsof >/dev/null 2>&1 || command -v ss >/dev/null 2>&1; }; then
    hp="$(free_port)"
    python3 -m http.server "$hp" --bind 127.0.0.1 >/dev/null 2>&1 &
    lp=$!
    SPAWNED_PIDS+=("$lp")
    disown "$lp" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if lsof -nP -iTCP:"$hp" -sTCP:LISTEN >/dev/null 2>&1 \
           || ss -ltnH 2>/dev/null | grep -q ":$hp "; then break; fi
        sleep 0.2
    done
    out="$(show_port_holders "$hp" 2>&1)"
    assert_contains "$out" "Listening processes on TCP ${hp}-$((hp + 20))" "prints the scanned window header"
    assert_contains "$out" ":${hp}" "lists the listener holding the base port"
    kill -9 "$lp" 2>/dev/null || true
else
    skip "python3 and (lsof or ss) required"
fi

# ── Test 9: find_available_port increments past busy ports to the next free ──
echo "Test 9: find_available_port returns the first free port in the window"
# The port_in_use overrides are scoped to the command-substitution subshells so
# they never leak into later tests (test isolation); the assertions run in the
# parent shell so the PASS/FAIL counters persist.
# Busy for 19000..19002, free from 19003 on.
result=$(
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by find_available_port
    port_in_use() { [ "$1" -lt 19003 ]; }
    find_available_port 19000
) || true
assert_eq "$result" "19003" "skips 3 busy ports, returns base+3"
# Busy across the whole 21-port window (19000..19020); free only at base+21.
result=$(
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by find_available_port
    port_in_use() { [ "$1" -le 19020 ]; }
    find_available_port 19000
) || true
assert_eq "$result" "" "does not overrun the window edge (base+20)"

# ── Test 10: exhaustion failure path runs under set -e (Bug 2 regression) ────
echo "Test 10: resolve_port_or_die logs and exits 1 under set -e (not silent)"
# Simulate an exhausted range. This must FAIL if the `|| true` in
# resolve_port_or_die is removed: set -e would then abort the command
# substitution before log_fail runs, so no message would be printed. The
# find_available_port override is scoped to the subshell so it does not leak.
out="$(
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by resolve_port_or_die
    find_available_port() { echo ""; return 1; }
    set -e
    resolve_port_or_die rest-api 19000 2>&1
)"
rc=$?
# NOTE: rc==1 alone does NOT prove the fix — with `|| true` removed, set -e also
# aborts the subshell with status 1. The discriminating (red-green) guard is the
# message assertion below: reverting `|| true` makes set -e exit BEFORE log_fail,
# so the message disappears and this assertion fails.
assert_eq "$rc" "1" "exits 1 on exhaustion"
assert_contains "$out" "Cannot find available port for rest-api" "prints failure message instead of dying silently"

# ── Test 11: kill_pid escalates to SIGKILL when SIGTERM is ignored ──────────
echo "Test 11: a SIGTERM-ignoring process is force-killed (SIGKILL escalation)"
# A copy of bash named 'concat-spa' (so pid_matches_service accepts it) that
# traps and ignores SIGTERM — only kill_pid's SIGKILL fallback can end it.
rm -f "${STATE_DIR}/concat-spa"
cp "$(command -v bash)" "${STATE_DIR}/concat-spa"
"${STATE_DIR}/concat-spa" -c "trap '' TERM; while :; do sleep 1; done" &
stubborn=$!
SPAWNED_PIDS+=("$stubborn")
disown "$stubborn" 2>/dev/null || true
record_pid concat-spa "$stubborn"
stop_service concat-spa >/dev/null 2>&1
assert_dead "$stubborn" "SIGTERM-ignoring process force-killed via SIGKILL escalation"

# ── Test 12: default teardown does NOT sweep untracked processes ────────────
echo "Test 12: without --sweep, an untracked same-named process is left alone"
spawn_named grpc-server; safe=$REPLY   # comm == grpc-server, NO pid log recorded
_name_sweep_pid="$safe"                # if the sweep ran, this is what it would kill
# SWEEP_ORPHANS is false here (default) — the sweep must NOT run.
stop_service grpc-server >/dev/null 2>&1
assert_alive "$safe" "untracked process spared when --sweep is off (footgun closed by default)"
_name_sweep_pid=""
kill -9 "$safe" 2>/dev/null || true

# ── Test 13: graphql-server node fallback identity check ────────────────────
echo "Test 13: graphql-server recorded PID matched only as node AND in its window"
# graphql-server has no unique binary; pid_matches_service accepts a recorded PID
# only when comm == 'node' AND it holds a port in the service window. The window
# check reuses orphan_pids_by_port, stubbed above to echo $_port_sweep_pid.

# (a) node process listening in the window → identity-verified → killed.
spawn_named node; gqp=$REPLY            # comm == 'node'
_port_sweep_pid="$gqp"                  # stub: this node PID holds a window port
record_pid graphql-server "$gqp"
stop_service graphql-server >/dev/null 2>&1
assert_dead "$gqp" "node PID listening in the graphql window is matched and killed"
_port_sweep_pid=""

# (b) node process NOT in the window → recycled-PID guard spares it.
spawn_named node; nowin=$REPLY          # comm == 'node' but not in the window
_port_sweep_pid=""                      # stub: no window listeners
record_pid graphql-server "$nowin"
stop_service graphql-server >/dev/null 2>&1
assert_alive "$nowin" "node PID not in the graphql window is spared"
kill -9 "$nowin" 2>/dev/null || true

# (c) non-node process recorded as graphql-server → comm mismatch → spared.
spawn_sleep_pid; notnode=$REPLY         # comm == 'sleep'
_port_sweep_pid="$notnode"              # even if it "held" a port, comm != node
record_pid graphql-server "$notnode"
stop_service graphql-server >/dev/null 2>&1
assert_alive "$notnode" "non-node PID recorded as graphql-server is spared"
_port_sweep_pid=""
kill -9 "$notnode" 2>/dev/null || true

# ── Test 14: parse_args wires the CLI flags (esp. --sweep → SWEEP_ORPHANS) ───
echo "Test 14: parse_args maps CLI flags to their variables"
# main()'s arg parsing lives in parse_args() so the flag→variable contract is
# testable without running the side-effecting setup/teardown (or the real sweep).
# Seed SWEEP_ORPHANS=true first so this discriminates the reset: parse_args must
# clear it back to false when --sweep is absent (deleting that reset fails here).
SWEEP_ORPHANS=true; parse_args --teardown
assert_eq "$PARSED_TEARDOWN" "true" "--teardown sets teardown"
assert_eq "$SWEEP_ORPHANS" "false" "parse_args resets SWEEP_ORPHANS off when --sweep absent (footgun stays closed)"
SWEEP_ORPHANS=false; parse_args --teardown --sweep
assert_eq "$SWEEP_ORPHANS" "true" "--sweep opts into the orphan sweep"
SWEEP_ORPHANS=false; parse_args --skip-start
assert_eq "$PARSED_SKIP_START" "true" "--skip-start sets skip_start"
SWEEP_ORPHANS=false; parse_args --targets rest-api,soap-service
assert_eq "$PARSED_TARGETS" "rest-api,soap-service" "--targets captures the list"
# Unknown option exits 1 (run in a subshell so the exit does not abort the harness).
( parse_args --bogus >/dev/null 2>&1 ); rc=$?
assert_eq "$rc" "1" "unknown option exits 1"
SWEEP_ORPHANS=false

# ── Test 15: a recorded PID from a generation that already exited is handled ──
echo "Test 15: an already-dead recorded PID is handled gracefully, not counted as stopped"
# A generation that exited on its own leaves its PID in the log. stop_service
# must decline it (identity check yields empty comm), so it is NOT reported as a
# process it stopped, it clears the log, and it does not error under set -euo
# pipefail. (The recycled-PID guarantee — a LIVE PID whose comm mismatches — is
# pinned separately by Tests 3 and 13.)
spawn_sleep_pid; dead=$REPLY
kill -9 "$dead" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do is_alive "$dead" || break; sleep 0.2; done
record_pid rest-api "$dead"
out="$(stop_service rest-api 2>&1)"
assert_contains "$out" "no running processes found" "dead recorded PID: nothing reported stopped"
case "$out" in
    *"Stopped rest-api"*) fail "dead recorded PID must not be counted as stopped" ;;
    *)                    ok "dead recorded PID not counted as stopped" ;;
esac
assert_no_file "${STATE_DIR}/.rest-api.pids" "pid log cleared after declining a dead PID"

# ── Test 16: real orphan_pids_by_port keeps the node-only port-window filter ──
echo "Test 16: real orphan_pids_by_port returns node listeners, excludes non-node"
if command -v lsof >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    # A non-node listener in the window must be EXCLUDED (the guard against
    # killing an unrelated service that merely listens in the range).
    nnport="$(free_port)"
    python3 -m http.server "$nnport" --bind 127.0.0.1 >/dev/null 2>&1 &
    nn=$!; SPAWNED_PIDS+=("$nn"); disown "$nn" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do lsof -nP -iTCP:"$nnport" -sTCP:LISTEN >/dev/null 2>&1 && break; sleep 0.2; done
    got="$(real_orphan_pids_by_port "$nnport")"
    case " $got " in
        *" $nn "*) fail "non-node listener excluded by node filter (got '$got')" ;;
        *)         ok "non-node listener excluded by node filter" ;;
    esac
    kill -9 "$nn" 2>/dev/null || true

    # A node-named listener in the window must be RETURNED. Copy the python
    # interpreter to a binary literally named 'node' so its comm == 'node'.
    # rm -f first: a prior 'node' copy (Test 13) may still be exiting, and cp
    # over a running executable fails "Text file busy"; unlinking then creating a
    # fresh file avoids that. Skip the sub-case if the copy cannot be made.
    rm -f "${STATE_DIR}/node"
    if ! cp "$(command -v python3)" "${STATE_DIR}/node"; then
        fail "could not stage node stand-in (cp failed)"
    else
        nport="$(free_port)"
        "${STATE_DIR}/node" -m http.server "$nport" --bind 127.0.0.1 >/dev/null 2>&1 &
        np=$!; SPAWNED_PIDS+=("$np"); disown "$np" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do lsof -nP -iTCP:"$nport" -sTCP:LISTEN >/dev/null 2>&1 && break; sleep 0.2; done
        got="$(real_orphan_pids_by_port "$nport")"
        case " $got " in
            *" $np "*) ok "node listener in window is returned" ;;
            *)         fail "node listener in window is returned (got '$got')" ;;
        esac
        kill -9 "$np" 2>/dev/null || true
    fi
else
    skip "lsof and python3 required"
fi

# ── Test 17: real orphan_pids_by_name matches by exact basename, current user ─
echo "Test 17: real orphan_pids_by_name returns only the exact-named stand-in"
if command -v pgrep >/dev/null 2>&1; then
    # Improbable name so the real pgrep can never match a developer's process.
    # Kept <=15 chars: `pgrep -x` matches the truncated comm, not the full argv.
    uniq="zzcap$$"
    cp "$(command -v sleep)" "${STATE_DIR}/${uniq}"
    "${STATE_DIR}/${uniq}" 600 &
    up=$!; SPAWNED_PIDS+=("$up"); disown "$up" 2>/dev/null || true
    got="$(real_orphan_pids_by_name "$uniq")"
    case " $got " in
        *" $up "*) ok "exact-named stand-in returned by name seam" ;;
        *)         fail "exact-named stand-in returned (got '$got')" ;;
    esac
    got="$(real_orphan_pids_by_name "${uniq}-nope")"
    assert_eq "$got" "" "a non-matching name returns nothing"
    kill -9 "$up" 2>/dev/null || true
else
    skip "pgrep required"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────"
echo "Passed: ${PASS}   Skipped: ${SKIP}   Failed: ${FAIL}"
echo "──────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
