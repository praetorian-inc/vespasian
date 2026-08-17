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
# SEC-BE-006: pin the parent instead of inheriting $TMPDIR. This tree holds
# executable fixtures that get PATH-prepended and RUN, so an inherited TMPDIR
# pointing at a non-sticky directory a second local user can write to would let
# them rename it away between creation and use and choose the binaries this suite
# executes. /tmp's sticky bit is the property being relied on.
STATE_DIR="$(TMPDIR=/tmp mktemp -d)"

# Track every PID we spawn so cleanup is guaranteed even if an assertion fails.
SPAWNED_PIDS=()

cleanup() {
    local pid
    for pid in "${SPAWNED_PIDS[@]:-}"; do
        if [ -n "$pid" ]; then kill -9 "$pid" 2>/dev/null || true; fi
    done
    rm -rf "${STATE_DIR}"
    # The completion sentinel is folded into THIS trap rather than registered
    # as a second one (TEST-006): bash keeps a single EXIT trap, so a separate
    # `trap ... EXIT` declared anywhere else would silently REPLACE this one
    # and never fire — exactly the inert-assertion failure mode this suite
    # exists to catch.
    if [ "${SUITE_COMPLETED}" != 1 ]; then
        echo "setup-live-targets_test: FAIL — suite terminated before reaching the summary; results are incomplete" >&2
        exit 1
    fi
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
SKIP_CREDIT=0
# TEST-006: flips to 1 immediately before the Summary section runs, matching
# install-chrome-selftest.sh and test-runner-args.sh. This file runs under
# `set -uo pipefail` (no -e), but an explicit `exit` anywhere above the
# summary — or a bare-variable/unset-command abort under -u — would otherwise
# print "ok"/"FAIL" lines for whatever ran and then a green CI check with no
# summary and no accounting for what never ran.
SUITE_COMPLETED=0

ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }
# Tool-prerequisite skips are counted so the summary can surface dropped coverage
# (a bare "Passed: N Failed: 0" would otherwise hide silently skipped tests).
skip() { echo "  skip - $1"; SKIP=$((SKIP + 1)); SKIP_CREDIT=$((SKIP_CREDIT + ${2:-0})); }

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
    skip "python3 unavailable" 2
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
    skip "python3 and (lsof or ss) required" 2
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
    nn_listening=false
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        lsof -nP -iTCP:"$nnport" -sTCP:LISTEN >/dev/null 2>&1 && { nn_listening=true; break; }
        sleep 0.2
    done
    # TEST-014: the readiness loop above is best-effort — if the fixture never
    # actually binds (e.g. free_port's TOCTOU window let something else grab
    # the port first, or the process failed to start), the loop just falls
    # through and the exclusion check below would trivially pass for the WRONG
    # reason ("nothing is listening" looks identical to "the filter excluded
    # it"). Measured: swapping the listener for `python3 -c pass` (exits
    # immediately, never binds) still printed `ok` here before this guard was
    # added. Prove the premise — the fixture is actually listening — before
    # trusting the exclusion result.
    if [ "$nn_listening" != true ]; then
        fail "non-node listener excluded by node filter (fixture never became LISTEN on port $nnport; cannot prove exclusion)"
    else
        got="$(real_orphan_pids_by_port "$nnport")"
        case " $got " in
            *" $nn "*) fail "non-node listener excluded by node filter (got '$got')" ;;
            *)         ok "non-node listener excluded by node filter" ;;
        esac
    fi
    kill -9 "$nn" 2>/dev/null || true

    # A node-named listener in the window must be RETURNED. Copy the python
    # interpreter to a binary literally named 'node' so its comm == 'node'.
    # rm -f first: a prior 'node' copy (Test 13) may still be exiting, and cp
    # over a running executable fails "Text file busy"; unlinking then creating a
    # fresh file avoids that. Skip the sub-case if the copy cannot be made.
    rm -f "${STATE_DIR}/node"
    if ! cp "$(command -v python3)" "${STATE_DIR}/node"; then
        fail "could not stage node stand-in (cp failed)"
        # Both arms of this block must emit 3 counted outcomes or the accounting
        # sentinel fires a second, misleading failure (TEST-008). The two node-listener
        # sub-cases below cannot run without the stand-in, so they are credited here.
        skip "node-listener sub-cases need the staged stand-in" 1
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

        # A node listener OFF the base port (mid-window) must also be returned.
        # This pins the range SPAN: collapsing the query back to only the base
        # port (dropping the `-${end}`) would miss this and fail here.
        offport="$(free_port)"
        "${STATE_DIR}/node" -m http.server "$offport" --bind 127.0.0.1 >/dev/null 2>&1 &
        op=$!; SPAWNED_PIDS+=("$op"); disown "$op" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do lsof -nP -iTCP:"$offport" -sTCP:LISTEN >/dev/null 2>&1 && break; sleep 0.2; done
        got="$(real_orphan_pids_by_port "$((offport - 5))")"   # listener sits at base+5
        case " $got " in
            *" $op "*) ok "node listener mid-window (base+5) is returned (range span)" ;;
            *)         fail "node listener mid-window (base+5) is returned (got '$got')" ;;
        esac
        kill -9 "$op" 2>/dev/null || true
    fi
else
    skip "lsof and python3 required" 3
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
    skip "pgrep required" 2
fi

# ── Test 17b: no lsof means "cannot determine", not "no match" (SEC-BE-008) ──
#
# orphan_pids_by_port used to `return 0` with no output when lsof was absent, which
# is indistinguishable from "looked, found nothing". pid_matches_service's
# graphql-server arm requires a listening socket in the port window, so on any host
# without lsof it always answered "not a match": stop_service skipped the kill,
# cleared the pid record anyway, and reported "no running processes found" while an
# unauthenticated Apollo server kept listening with its only record erased.
#
# Driven with a PATH that deliberately lacks lsof, built by symlinking just the
# tools the seam itself needs, so `command -v lsof` genuinely misses.
echo "Test 17b: teardown can still identify graphql-server on a host without lsof (SEC-BE-008)"
nolsof_bin="${STATE_DIR}/nolsof-bin"
mkdir -p "${nolsof_bin}"
for t in ps basename sleep grep sed awk cat head cut tr sort; do
    src="$(command -v "$t" 2>/dev/null)" || continue
    ln -sf "$src" "${nolsof_bin}/${t}" 2>/dev/null || true
done
if [ -x "${nolsof_bin}/ps" ] && ! PATH="${nolsof_bin}" command -v lsof >/dev/null 2>&1; then
    cp "$(command -v sleep)" "${STATE_DIR}/node"
    "${STATE_DIR}/node" 60 &
    nl_pid=$!; SPAWNED_PIDS+=("$nl_pid"); disown "$nl_pid" 2>/dev/null || true
    # The seam must report "cannot determine" (rc 2), not success-with-no-output.
    ( PATH="${nolsof_bin}"; real_orphan_pids_by_port 8992 >/dev/null 2>&1 )
    assert_eq "$?" "2" "real orphan_pids_by_port returns 2 (cannot determine) when lsof is absent"
    # And pid_matches_service must therefore ACCEPT a node process recorded in our
    # own pid log, so teardown proceeds to kill it instead of silently declining.
    #
    # The harness sandboxes orphan_pids_by_port for the whole run (see the top of
    # this file) so a stray sweep can never reach a developer's real process table.
    # That stub always returns 0, which is exactly the value under test here, so this
    # one subshell points the seam back at the real implementation.
    (
        PATH="${nolsof_bin}"
        orphan_pids_by_port() { real_orphan_pids_by_port "$@"; }
        pid_matches_service "$nl_pid" graphql-server >/dev/null 2>&1
    )
    assert_eq "$?" "0" "pid_matches_service accepts a recorded node PID when the port check cannot look"
    kill -9 "$nl_pid" 2>/dev/null || true
else
    skip "could not build an lsof-free PATH for the SEC-BE-008 check" 2
fi

# ── Test 18: LIVE_TARGET_BIND_HOST seam reaches every non-hardened target ────
echo "Test 18: rest-api/soap-service/concat-spa/graphql-server pass an explicit bind host (SEC-BE-015)"
for fn in start_rest_api start_soap_service start_concat_spa start_graphql_server; do
    case "$(declare -f "$fn")" in
        *'BIND_HOST="${LIVE_TARGET_BIND_HOST:-127.0.0.1}"'*)
            ok "${fn} passes an explicit BIND_HOST seam" ;;
        *)
            fail "${fn} passes an explicit BIND_HOST seam (source changed)" ;;
    esac
done
# TEST-009: the four names above are hand-picked and never include grpc-server,
# which IS a first-class ALL_TARGETS member. Being on the exemption list below
# is not itself a finding — an UNLISTED, UNCHECKED target is.
#   forms-target  — uses its own FORMS_TARGET_BIND_HOST seam; pinned by Test 19.
#   grpc-server   — passes no bind host at all; its literal bind is pinned in
#                   Test 18b below.
BIND_SEAM_EXEMPT="forms-target grpc-server"
# ROUND-16 fidelity sentinel. ALL_TARGETS arrives by SOURCING the script under
# test, so if it is ever renamed, moved below the main() guard, or emptied, the
# loop below iterates zero times, `unchecked` stays empty, and the exhaustiveness
# check PASSES having verified nothing. Same shape as the sentinels the sibling
# suites carry on every extraction (test-runner-args.sh:1763 is the model).
# BIDIRECTIONAL, not just live. Checking `-z` alone catches an emptied or renamed
# ALL_TARGETS but NOT a SHRUNK one: MUTATION-PROVEN, ALL_TARGETS="rest-api" printed
# ok, iterated once, found it classified, and passed vacuously — the exhaustiveness
# claim held over a list that had lost five of six targets. The loop below asks
# "is every ALL_TARGETS member covered"; this asks the converse, "is every name we
# rely on still IN ALL_TARGETS", which is the direction a shrink breaks. Same
# two-directional shape as test-runner-args.sh's browser-classification check.
ALL_TARGETS_EXPECTED="rest-api soap-service graphql-server grpc-server concat-spa forms-target"
missing_from_all=""
for t in $ALL_TARGETS_EXPECTED; do
    case ",${ALL_TARGETS}," in
        *",$t,"*) ;;
        *) missing_from_all="$missing_from_all $t" ;;
    esac
done
if [ -z "${ALL_TARGETS:-}" ]; then
    fail "ALL_TARGETS is empty or unset after sourcing setup-live-targets.sh — the exhaustiveness check below would pass having iterated nothing; fix the extraction rather than deleting the check"
elif [ -n "$missing_from_all" ]; then
    fail "target(s) dropped out of ALL_TARGETS:${missing_from_all} — the exhaustiveness loop below only checks that members ARE classified, so a shrunk list passes while the dropped targets lose every assertion that iterates it. If a target was deliberately retired, remove it from ALL_TARGETS_EXPECTED here and say why"
else
    ok "ALL_TARGETS still carries all $(set -- $ALL_TARGETS_EXPECTED; echo $#) expected targets (a shrunk list cannot pass the loop below vacuously)"
fi
unchecked=""
for t in ${ALL_TARGETS//,/ }; do
    case " rest-api soap-service concat-spa graphql-server $BIND_SEAM_EXEMPT " in
        *" $t "*) ;;
        *) unchecked="$unchecked $t" ;;
    esac
done
if [ -n "$unchecked" ]; then
    fail "target(s) in ALL_TARGETS have no bind-host assertion and are not on the exemption list:$unchecked — add a check here or an exemption with the reason"
else
    ok "every ALL_TARGETS member is either bind-host-asserted or on the documented exemption list"
fi

# ── Test 18b: the TARGETS THEMSELVES honour the seam (TEST-007) ─────────────
#
# Test 18 above asserts only that the SHELL passes BIND_HOST. That is half the
# contract and it was the half that hid the bug: no suite referenced
# rest-api/main.go, soap-service/main.go, concat-spa/main.go or
# graphql-server/server.js at all, so reverting the four targets to their old
# wildcard bind — `addr := ":" + port` / `listen(port)` — left every assertion
# in every suite green while the exposure SEC-BE-015 was filed for came back.
# The seam is inert unless BOTH ends exist, so both ends are asserted.
#
# This is a source-level check, not a socket-level one, and that is a deliberate
# limit: the preflight-selftest CI job installs no Go and no Node, so a test that
# built and started a target would skip in exactly the environment that runs the
# guards. It fails on the mutation the finding named, which a behavioural test
# in an unreachable job would not.
echo "Test 18b: the loopback default lives in one asserted place and every target uses it (SEC-BE-015 / TEST-014 / QUAL-007)"
# QUAL-007 moved the BIND_HOST resolution out of four byte-identical copies into
# test/internal/target. That changes what this test must pin, and makes the pin
# stronger: the security-relevant default is asserted ONCE, and each target is
# asserted to DELEGATE rather than to re-derive it.
#
# TEST-014, why a literal grep is not enough. The previous version grepped each
# target for `host = "127.0.0.1"`. That caught rewriting the literal to "0.0.0.0"
# (measured: 72 passed / 4 FAILED, exit 1) but NOT a logic inversion, because the
# inversion leaves the literal exactly where it was: flipping `if host == ""` to
# `if host != ""` in all three Go targets and dropping the `host` argument from
# server.js's `listen(port, host, …)` left the suite at 76/0, exit 0 while printing
# "defaults to loopback" for every target — and the mutated rest-api genuinely
# logged `listening on :18777`, i.e. every interface. So the shared default is
# matched as a whole STRUCTURE, comment-stripped and whitespace-collapsed.
#
# Source-level rather than socket-level, deliberately: the preflight-selftest job
# that runs this suite installs no Go and no Node, so a test that built and started
# a target would skip in exactly the environment the guard is for.
# TEST-015: strip `/* */` BLOCK comments as well as `//` and `#` line comments.
#
# Stripping only line comments was the same defect this file was hardened against
# one round earlier, regenerated one level down. The earlier fix taught the
# chrome_available guard in test-runner-args.sh to drop `#` lines, because leaving
# "previously delegated to detect_chrome_binary" in a comment kept that assertion
# green while the delegation was gone. The identical trick worked here through a
# block comment: parking `addr := target.Addr(port)` inside `/* ... */` and
# re-implementing the bind inline left every assertion below green.
#
# A tighter grep is still a grep. What makes the checks below sound is that the
# question they ask — "does this file CALL the shared helper" — is genuinely a
# source-text question that behaviour cannot answer, since an inline copy behaves
# identically. So the text has to be comment-free before it is matched.
collapse_code() {
    awk '
        {
            if (inblk) { if (sub(/^.*\*\//, "")) inblk = 0; else next }
            while (sub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, " ")) { }
            if (sub(/\/\*.*$/, " ")) inblk = 1
        }
        /^[[:space:]]*(\/\/|#)/ { next }
        { print }
    ' "$1" | tr '\n' ' ' | tr -s '[:space:]' ' '
}

SHARED_TARGET="${THIS_DIR}/internal/target/target.go"
if [ ! -f "${SHARED_TARGET}" ]; then
    fail "test/internal/target/target.go not found — the shared loopback default is gone and every target below resolves its own bind"
    fail "test/internal/target/target.go not found — cannot verify the shared server timeout"
else
    shared_code=$(collapse_code "${SHARED_TARGET}")

    # TEST-010 / D2. Both a structural pin over the collapsed source AND the Go
    # behavioural tests in target_test.go are kept deliberately — this is the
    # defence-in-depth the review found was lost, not a choice between the two:
    # the shell pin below runs in the Go-less preflight-selftest job, the Go
    # tests run under `make test`. This pin was deleted once on the theory that
    # a /* */ block comment could satisfy it undetected, but collapse_code
    # strips block comments in the very commit that theory rested on, so the
    # pin is sound again as a fixed-string whole-structure match.
    # SELF-5: ANCHORED, not containment. `grep -qF` asks only whether the text
    # appears SOMEWHERE — so a new code path prepended AHEAD of the pinned block
    # leaves it matching. MUTATION-PROVEN: adding
    #   if os.Getenv("BIND_ALL") != "" { return net.JoinHostPort("0.0.0.0", port) }
    # at the top of Addr left BOTH this suite AND `go test` green, because the
    # pinned text is still present and no Go test sets BIND_ALL. Matching the
    # whole function body — from `func Addr` to its closing return — is what makes
    # the comment's "whole-structure match" claim actually true.
    if printf '%s' "${shared_code}" | grep -qF 'func Addr(port string) string { host := os.Getenv("BIND_HOST") if host == "" { host = "127.0.0.1" } return net.JoinHostPort(host, port) }'; then
        ok "shared target.Addr's whole body is the loopback default (no other code path can reach the bind) (SEC-BE-015)"
    else
        fail "shared target.Addr's body is no longer exactly the loopback-default structure — either the default changed, or another code path was added that can return a different host before it. These targets are unauthenticated, so a wildcard bind exposes them to the local network for the lifetime of a test run (SEC-BE-015)"
    fi

    # TWO conditions, deliberately. The quantifier is [1-9][0-9]*, not [0-9]+:
    # the round-13 predecessor used [0-9]+, which matches the literal `0` it
    # claimed to forbid.
    #
    # SELF-3: the second condition is NOT optional and was wrongly dropped when
    # this pin was restored. The first proves the CONSTANT is declared non-zero;
    # only the second proves Server() still APPLIES it. MUTATION-PROVEN: deleting
    # `ReadHeaderTimeout: ReadHeaderTimeout,` from the Server struct left this
    # suite green with the constant check alone. The round-13 pin had both; the
    # restoration kept one. Do not drop it again.
    if printf '%s' "${shared_code}" | grep -qE 'ReadHeaderTimeout = [1-9][0-9]* \* time\.Second' \
       && printf '%s' "${shared_code}" | grep -qF 'ReadHeaderTimeout: ReadHeaderTimeout'; then
        ok "shared target server declares a non-zero ReadHeaderTimeout AND applies it in Server() (SEC-BE-007)"
    else
        fail "shared target server's ReadHeaderTimeout is zero, gone, or no longer applied by Server() — an unbounded header read is a slow-loris against a developer machine or CI runner once LIVE_TARGET_BIND_HOST widens the bind (SEC-BE-007)"
    fi
fi

# The Go behavioural layer. target_test.go carries the same two properties as
# real tests against the real functions, closing what the source-text pins
# above cannot: a comparison inversion, and (for the timeout) the exact-zero
# value the old, looser regex used to accept. This check does not depend on
# target.go existing, so it is its own top-level check rather than nested
# inside the block above (TEST-008): target.go being absent does not prevent
# checking whether target_test.go still asserts these things, and folding it
# into the "target.go missing" arm would falsely claim that it does.
#
# This job installs no Go, so it cannot run target_test.go itself. It asserts
# the file EXISTS and carries those behavioural assertions, so deleting the Go
# test to dodge it fails here instead of silently removing the coverage.
shared_test="${THIS_DIR}/internal/target/target_test.go"
if [ ! -f "${shared_test}" ]; then
    fail "test/internal/target/target_test.go is gone — the loopback default and the header-read bound have no behavioural assertion left, and the source greps that used to stand in for one were mutation-proven defeatable"
else
    missing=""
    for needle in 'func TestAddrDefaultsToLoopbackWhenEmpty' \
                  'func TestAddrDefaultsToLoopbackWhenUnset' \
                  'func TestServerAppliesNonZeroReadHeaderTimeout'; do
        grep -qF -- "$needle" "${shared_test}" || missing="${missing} ${needle#func }"
    done
    if [ -n "$missing" ]; then
        fail "target_test.go no longer asserts:${missing} — these are the behavioural pins for SEC-BE-015 and SEC-BE-007"
    else
        ok "target_test.go carries the behavioural pins for the loopback default and the header-read bound (run by 'make test', not by this job)"
    fi
fi

# Each Go target must DELEGATE, not re-derive. A target that grows its own
# os.Getenv("BIND_HOST") block again is drift even if that block happens to be
# correct today, because the assertion above would then be pinning a default the
# target no longer uses.
for src in rest-api/main.go soap-service/main.go concat-spa/main.go forms-target/main.go; do
    f="${THIS_DIR}/${src}"
    if [ ! -f "$f" ]; then
        fail "${src} not found — cannot verify it delegates its bind to test/internal/target"
        continue
    fi
    code=$(collapse_code "$f")
    if printf '%s' "${code}" | grep -qF 'addr := target.Addr(port)' \
       && printf '%s' "${code}" | grep -qF 'srv := target.Server(addr, mux)'; then
        if printf '%s' "${code}" | grep -qF 'os.Getenv("BIND_HOST")'; then
            fail "${src} calls target.Addr but ALSO resolves BIND_HOST itself — two sources of truth for the loopback default"
        else
            ok "${src} delegates both its bind address and its server timeout to test/internal/target"
        fi
    else
        fail "${src} no longer delegates to test/internal/target — it resolves its own bind and/or builds its own server, so the shared loopback default and timeout do not apply to it"
    fi
done
# TEST-009: the four `src` entries above are hand-picked; grpc-server and any
# future ALL_TARGETS member are invisible to this loop unless named here.
#   graphql-server — Node, cannot share the Go helper; pinned by its own arm below.
#   grpc-server    — builds no http.Server, so target.Server is inapplicable;
#                    its literal bind is pinned by its own arm below.
DELEGATION_EXEMPT="graphql-server grpc-server"
unchecked_delegation=""
for t in ${ALL_TARGETS//,/ }; do
    case " rest-api soap-service concat-spa forms-target $DELEGATION_EXEMPT " in
        *" $t "*) ;;
        *) unchecked_delegation="$unchecked_delegation $t" ;;
    esac
done
if [ -n "$unchecked_delegation" ]; then
    fail "target(s) in ALL_TARGETS have no delegation assertion and are not on the exemption list:$unchecked_delegation — add a check here or an exemption with the reason"
else
    ok "every ALL_TARGETS member is either delegation-asserted or on the documented exemption list"
fi

# graphql-server is Node and cannot share the Go helper, so it keeps a structural
# check of its own: the defaulting expression AND the listen() call that actually
# PASSES host. Dropping that argument is the pre-PR shape and binds every interface
# while the defaulting line sits there untouched.
gql="${THIS_DIR}/graphql-server/server.js"
if [ ! -f "$gql" ]; then
    fail "graphql-server/server.js not found — cannot verify its loopback default"
else
    if printf '%s' "$(collapse_code "$gql")" | grep -qF 'const host = process.env.BIND_HOST || "127.0.0.1"; httpServer.listen(port, host,'; then
        ok "graphql-server/server.js defaults to loopback AND passes host to listen()"
    else
        fail "graphql-server/server.js no longer defaults to loopback or no longer passes host to listen() — the unset path exposes it on every interface"
    fi
fi

# grpc-server builds no http.Server, so it cannot use target.Server, and it
# takes no BIND_HOST — its bind is a branch-free literal. A fixed-string
# structural match is therefore complete for it: there is no logic to invert
# (TEST-009).
grpcsrc="${THIS_DIR}/grpc-server/main.go"
if [ ! -f "$grpcsrc" ]; then
    fail "grpc-server/main.go not found — cannot verify its loopback bind"
else
    if printf '%s' "$(collapse_code "$grpcsrc")" | grep -qF 'net.Listen("tcp", "127.0.0.1:"+resolved)'; then
        ok "grpc-server/main.go binds loopback explicitly (SEC-BE-015)"
    else
        fail "grpc-server/main.go no longer binds 127.0.0.1 — the gRPC live target is unauthenticated, so a wildcard bind exposes it to the local network for the lifetime of a test run (SEC-BE-015)"
    fi
fi

# ── Test 18c: the graphql dep install stays script-free (TEST-011) ──────────
#
# SEC-BE-007 changed `npm install --silent` to `npm ci --ignore-scripts --silent`
# in build_graphql_server, and nothing guarded it. `npm install` runs package
# lifecycle scripts — arbitrary registry code on a developer's machine and on the
# CI runner — and resolves loosely instead of honouring the committed lockfile,
# so a silent revert reintroduces both. The sibling BIND_HOST seam got a guard in
# the same PR; this call site did not.
#
# Scoped to build_graphql_server()'s own body, not the whole file: the flag name
# appears in this script's comments and in the workflow, and a whole-file grep
# would be satisfied by prose while the call itself regressed — the exact defect
# TEST-003 records against install-chrome-selftest case f.
echo "Test 18c: build_graphql_server installs deps with npm ci --ignore-scripts"
gql_fn_body="$(awk '/^build_graphql_server\(\) \{/,/^\}/' "${SCRIPT_UNDER_TEST}")"
gql_npm_lines="$(printf '%s\n' "${gql_fn_body}" | grep -E '^[[:space:]]*npm ' || true)"
if [ -n "${gql_npm_lines}" ]; then
    ok "build_graphql_server still contains an npm invocation (the checks below are not vacuous)"
else
    fail "build_graphql_server contains no npm invocation — the --ignore-scripts checks below are vacuous, fix the extraction rather than deleting it"
fi
if printf '%s\n' "${gql_npm_lines}" | grep -qF -- 'npm ci --ignore-scripts'; then
    ok "the dep install uses npm ci --ignore-scripts (lockfile honoured, lifecycle scripts blocked)"
else
    fail "the dep install no longer uses npm ci --ignore-scripts — registry lifecycle scripts execute and the committed lockfile is bypassed (SEC-BE-007)"
fi
if printf '%s\n' "${gql_npm_lines}" | grep -qE '^[[:space:]]*npm install\b'; then
    fail "build_graphql_server has reverted to npm install — lifecycle scripts run again (SEC-BE-007)"
else
    ok "build_graphql_server does not use npm install"
fi

# ── Test 19: forms-target's own bind default is loopback (TEST-019) ─────────
echo "Test 19: forms-target defaults its bind host to loopback"
case "$(declare -f start_forms_target)" in
    *'BIND_HOST="${FORMS_TARGET_BIND_HOST:-127.0.0.1}"'*)
        ok "start_forms_target defaults BIND_HOST to 127.0.0.1" ;;
    *)
        fail "start_forms_target defaults BIND_HOST to 127.0.0.1 (source changed)" ;;
esac
# TEST-008: the check above covers only the SHELL half. forms-target is the
# target this seam was modelled on, so it gets the same both-halves treatment as
# Test 18b: the value the shell passes is inert unless the target reads it, and
# asserting one without the other is how the four siblings' inert seam went
# unnoticed for a whole review round. Source-level for the same reason 18b is —
# the preflight-selftest CI job installs no Go, so a build-and-start assertion
# would skip in exactly the job that runs the guards.
# QUAL-007: forms-target no longer reads BIND_HOST itself — the resolution moved to
# test/internal/target, which Test 18b above asserts once (the loopback default AND
# that every target including this one delegates to it). Re-grepping this file for
# `os.Getenv("BIND_HOST")` here would now FAIL on correct code, and re-asserting the
# default would duplicate 18b. What is still specific to forms-target, and still
# worth pinning, is that BOTH halves of ITS seam exist: the shell passes
# FORMS_TARGET_BIND_HOST (asserted above) and the target consumes a bind address at
# all rather than hardcoding one.
if grep -qF 'target.Addr(port)' "${THIS_DIR}/forms-target/main.go"; then
    ok "forms-target/main.go resolves its bind through the shared, asserted helper"
else
    fail "forms-target/main.go no longer resolves its bind through test/internal/target — the FORMS_TARGET_BIND_HOST seam the shell half passes may be inert"
fi
if grep -qE '^[[:space:]]*(port|addr)' "${THIS_DIR}/forms-target/main.go" \
   && ! grep -qE 'net\.Listen(AndServe)?\("tcp", *"127\.0\.0\.1' "${THIS_DIR}/forms-target/main.go"; then
    ok "forms-target/main.go does not hardcode a bind address (the seam is live)"
else
    fail "forms-target/main.go hardcodes its bind address — FORMS_TARGET_BIND_HOST cannot widen it and the shell half above is inert"
fi

# ── Test 20: wait_for_http bounds its curl probe (TEST-017, SEC-BE-012) ─────
#
# TEST-008: a source-text match cannot tell "curl has --max-time and it works"
# from "curl has --max-time and something else swallowed the effect" — the
# property is directly observable, so it is observed instead: a listener that
# accepts the TCP handshake and then never responds is exactly the SEC-BE-012
# scenario the function's own comment names, so wait_for_http is driven
# against one for real. The whole call is wrapped in an outer `timeout` (the
# same belt-and-suspenders shape Test 21 uses): if a mutation deletes
# --max-time, curl blocks on the unread response forever, the outer `timeout`
# kills the subshell before it ever prints "rc=", and the assertion below
# goes red instead of the suite hanging until CI's own job timeout.
echo "Test 20: wait_for_http bounds its curl probe with --max-time"
if { command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1; } \
   && command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    t_bin20="$(command -v timeout || command -v gtimeout)"
    hport="$(free_port)"
    python3 - "$hport" <<'PY' >/dev/null 2>&1 &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
while True:
    conn, _ = s.accept()   # accept and hold — never read, never write, never close
PY
    hsp=$!
    SPAWNED_PIDS+=("$hsp")
    disown "$hsp" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        (exec 3<>"/dev/tcp/127.0.0.1/${hport}") 2>/dev/null && { exec 3>&- 3<&-; break; }
        sleep 0.2
    done

    out20="$("$t_bin20" 6 bash -c '
        source "'"${SCRIPT_UNDER_TEST}"'"
        rc=0
        wait_for_http "http://127.0.0.1:'"${hport}"'/" 2 || rc=$?
        echo "rc=$rc"
    ' 2>&1)"
    kill -9 "$hsp" 2>/dev/null || true
    assert_contains "$out20" "rc=1" "wait_for_http's curl probe is bounded by --max-time against a handshake-then-silent listener"
else
    skip "timeout/gtimeout, curl, and python3 required" 1
fi

# ── Test 21: wait_for_grpc's timeout-wrapped /dev/tcp arm (TEST-020) ────────
echo "Test 21: wait_for_grpc connects via the timeout-wrapped /dev/tcp arm when grpcurl/nc are absent"
# python3 is required too (TEST-009): the body below spawns a python3
# http.server as the listener the /dev/tcp arm connects to, and every other
# environment-gated block in this file guards python3 explicitly for the same
# reason — without the guard this hard-fails on a host without python3
# instead of skipping like its siblings do.
if { command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1; } \
   && command -v dirname >/dev/null 2>&1 && command -v sleep >/dev/null 2>&1 \
   && command -v python3 >/dev/null 2>&1; then
    # A minimal PATH containing only the tools this arm (plus sourcing) needs —
    # NOT grpcurl or nc — so the third arm is exercised regardless of what is
    # actually installed on the host running this suite.
    mini_bin="$(TMPDIR=/tmp mktemp -d)"
    t_bin="$(command -v timeout || command -v gtimeout)"
    ln -s "$t_bin" "${mini_bin}/$(basename "$t_bin")"
    ln -s "$(command -v dirname)" "${mini_bin}/dirname"
    ln -s "$(command -v sleep)" "${mini_bin}/sleep"
    ln -s "$(command -v bash)" "${mini_bin}/bash"

    gport="$(free_port)"
    python3 -m http.server "$gport" --bind 127.0.0.1 >/dev/null 2>&1 &
    gsp=$!
    SPAWNED_PIDS+=("$gsp")
    disown "$gsp" 2>/dev/null || true
    # TEST-010: poll for the listener to actually accept a connection instead
    # of a fixed `sleep 0.3` — on a loaded runner 0.3s can be short of the
    # interpreter's own startup, which would make the rc=0 arm below flake
    # red for a reason that has nothing to do with wait_for_grpc. Same
    # bounded-retry shape Test 16 already uses for a listener it starts.
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        (exec 3<>"/dev/tcp/127.0.0.1/${gport}") 2>/dev/null && { exec 3>&- 3<&-; break; }
        sleep 0.2
    done

    out="$(PATH="$mini_bin" bash -c '
        command -v grpcurl >/dev/null 2>&1 && { echo "grpcurl still on PATH"; exit 99; }
        command -v nc >/dev/null 2>&1 && { echo "nc still on PATH"; exit 98; }
        # shellcheck source=/dev/null
        source "'"${SCRIPT_UNDER_TEST}"'"
        rc=0
        wait_for_grpc 127.0.0.1 "'"$gport"'" 3 || rc=$?
        echo "rc=$rc"
    ' 2>&1)"
    kill -9 "$gsp" 2>/dev/null || true
    assert_contains "$out" "rc=0" "connects via the timeout-wrapped /dev/tcp arm with grpcurl/nc absent"

    # TEST-010: no wall-clock upper-bound assertion here (a "returns within
    # roughly the outer timeout" check computed from $SECONDS was removed —
    # a 2s outer timeout with only 2s of headroom flakes on a loaded runner).
    # The rc=1 assertion below already proves the call does not hang: it
    # cannot return "rc=1" at all unless wait_for_grpc actually returned
    # rather than blocking forever against a closed port.
    out2="$(PATH="$mini_bin" bash -c '
        # shellcheck source=/dev/null
        source "'"${SCRIPT_UNDER_TEST}"'"
        rc=0
        wait_for_grpc 127.0.0.1 1 2 || rc=$?
        echo "rc=$rc"
    ' 2>&1)"
    assert_contains "$out2" "rc=1" "returns non-zero against a closed port instead of hanging"

    rm -rf "$mini_bin"
else
    skip "timeout/gtimeout, dirname, and sleep required" 2
fi

# ── Test 22: write_config lands the config at 0644 regardless of umask ──────
echo "Test 22: write_config lands .live-test-config at mode 644 under umask 0 (SEC-BE-017, TEST-021)"
if command -v stat >/dev/null 2>&1; then
    (
        umask 0
        write_config 1111 2222 3333 4444 5555 6666 "rest-api,soap-service" >/dev/null 2>&1
        record_pid modetest 4242
    )
    mode="$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null)"
    assert_eq "$mode" "644" "config file lands at mode 644 even under umask 0"
    contents="$(cat "$CONFIG_FILE" 2>/dev/null)"
    assert_contains "$contents" "REST_API_PORT=1111" "config carries the written port value"
    rm -f "$CONFIG_FILE"
    pidmode="$(stat -c '%a' "${STATE_DIR}/.modetest.pids" 2>/dev/null)"
    assert_eq "$pidmode" "600" "pid log lands at mode 600 even under umask 0 (SEC-BE-003)"
    rm -f "${STATE_DIR}/.modetest.pids"

    # ROUND-16: the graphql log's mode had NO assertion at all. Its sibling
    # write (record_pid, above) was hardened AND pinned in the same round; this
    # one was hardened and left unguarded, which is this suite's own defect class
    # -- a control shipped with nothing exercising it. Asserted the same way and
    # in the same block, so the two cannot drift apart again.
    #
    # start_graphql_server is not called here (it would launch node); the
    # `install -m 0600 /dev/null` line it runs is driven directly, which is the
    # whole of the mode behaviour being pinned.
    # ROUND-16, corrected after a mutation defeated the first attempt. The first
    # version ran `install -m 0600` ITSELF and asserted the result -- a tautology
    # testing install(1), not the production code -- and separately grepped
    # start_graphql_server for the literal `install -m 0600 /dev/null`.
    # MUTATION-PROVEN defeat: keeping that exact literal but pointing it at a
    # DIFFERENT file (`.decoy.log`) satisfied the grep while the real log went
    # back to being created by the bare redirection at the caller's umask. Both
    # halves passed. That is the "assertion names the control" shape this suite
    # exists to catch, reproduced in the assertion meant to close it.
    #
    # The fix executes the PRODUCTION line rather than imitating it: extract the
    # install command from the live function body and run it under umask 0, then
    # stat the real filename. Mode AND target path are then both pinned, because
    # a line pointing elsewhere leaves .graphql-server.log absent.
    rm -f "${STATE_DIR}/.graphql-server.log"
    gql_install_line="$(declare -f start_graphql_server | grep -F 'install -m' | head -1)"
    if [ -z "$gql_install_line" ]; then
        fail "start_graphql_server no longer pre-creates its log with install(1) — a bare redirection lands at the caller's umask, so under umask 0 the log holding service output would be world-writable (SEC-BE-003)"
    else
        ( umask 0; eval "$gql_install_line" ) >/dev/null 2>&1
        logmode="$(stat -c '%a' "${STATE_DIR}/.graphql-server.log" 2>/dev/null)"
        assert_eq "$logmode" "600" "start_graphql_server's own install line creates .graphql-server.log at mode 600 under umask 0 — pinning the path too, so an install pointed at another file cannot satisfy this (SEC-BE-003)"

        # ORDERING. The mode only holds if nothing between the install and the
        # truncating redirect removes the file: `>` on an EXISTING file truncates
        # and keeps its mode, but on a missing one it creates at the caller's
        # umask. MUTATION-PROVEN: inserting `rm -f "$log"  # rotate` after the
        # install left the assertion above green while the log went back to the
        # ambient umask. Executing the install line proves mode and path; only
        # inspecting the function body can prove nothing UNDOES it in between.
        # The span is install-line -> redirect-line: sed searches the END pattern
        # from the line AFTER the start, so the install line (which also contains
        # graphql-server.log) does not terminate its own range. Verified.
        #
        # Function calls in that span are RESOLVED, not just scanned: a rotation
        # moved into a helper defeated the text-only version. MUTATION-PROVEN,
        # `rotate_gql_log() { rm -f "$log"; }` plus a call to it between the
        # install and the redirect passed, because the body only contained the
        # CALL. Every word in the span that names a defined shell function has
        # that function's own body appended before the scan.
        gql_body="$(declare -f start_graphql_server)"
        gql_between="$(printf '%s\n' "$gql_body" | sed -n '/install -m/,/graphql-server\.log/p')"
        for w in $(printf '%s\n' "$gql_between" | tr -cs 'A-Za-z0-9_-' '\n'); do
            if declare -F "$w" >/dev/null 2>&1; then
                gql_between="${gql_between}
$(declare -f "$w")"
            fi
        done
        # declare -F only resolves TOP-LEVEL helpers. A helper defined INSIDE
        # start_graphql_server does not exist until that function runs, so the
        # resolution above cannot see it and the first version of this guard was
        # defeated by exactly that: `rotate_gql_log() { rm -f "$log"; }` declared
        # in the body, called between the install and the redirect. The nested
        # definition also sits BEFORE the install line, so the span misses it too.
        #
        # So the span check is paired with a whole-body one: no statement anywhere
        # in this function may remove or rename the log. That is a stronger claim
        # than the span needs and is correct regardless — the function has no
        # legitimate reason to delete the file it just created with an explicit
        # mode. Together they cover inline, nested-helper, and top-level-helper.
        if printf '%s\n' "$gql_body" | grep -qE '(rm|unlink|mv|truncate)[[:space:]][^;]*graphql-server\.log'; then
            fail "start_graphql_server removes or renames .graphql-server.log somewhere in its body (possibly via a helper defined inside it) — the redirect then RE-CREATES the file at the caller's umask and the explicit 0600 mode is lost (SEC-BE-003)"
        elif printf '%s\n' "$gql_between" | grep -qE '(rm|unlink|mv|truncate|:>)[[:space:]]'; then
            fail "start_graphql_server removes or replaces .graphql-server.log between the install(1) that sets its 0600 mode and the redirect that writes it — the redirect then RE-CREATES the file at the caller's umask, so the mode is lost (SEC-BE-003)"
        else
            ok "nothing removes or replaces .graphql-server.log between its install(1) and the redirect, so the 0600 mode survives to the write (SEC-BE-003)"
        fi
    fi
    rm -f "${STATE_DIR}/.graphql-server.log"
else
    skip "stat required" 4
fi

# ── Test 23: teardown_on_failure EXIT trap tears down a failed partial setup ─
# Exercises the exact call chain SEC-BE-015 added: EXIT trap -> teardown_on_
# failure -> do_teardown -> stop_service -> pid_matches_service, with the trap
# firing from a genuinely non-zero exit (so $? at trap-entry is 1, the specific
# condition TEST-018 says pid_matches_service's bare-return bug depended on).
echo "Test 23: teardown_on_failure tears down services started before a failed setup exits (TEST-022, TEST-018)"
spawn_named rest-api; trap_pid=$REPLY
record_pid rest-api "$trap_pid"
(
    SETUP_IN_PROGRESS=true
    trap 'teardown_on_failure' EXIT
    exit 1
) >/dev/null 2>&1
assert_dead "$trap_pid" "EXIT trap's do_teardown kills the service this run started"
assert_no_file "${STATE_DIR}/.rest-api.pids" "EXIT trap's do_teardown clears the pid log"

# ── Test 24: the same trap is a no-op once SETUP_IN_PROGRESS is cleared ─────
# Covers the OTHER arm TEST-022 calls out: a successful setup clears
# SETUP_IN_PROGRESS after write_config, so the trap must not tear down the
# services it just started on a normal, successful exit.
echo "Test 24: the teardown_on_failure trap is a no-op once SETUP_IN_PROGRESS is cleared"
spawn_named soap-service; safe_pid=$REPLY
record_pid soap-service "$safe_pid"
(
    SETUP_IN_PROGRESS=true
    trap 'teardown_on_failure' EXIT
    SETUP_IN_PROGRESS=false   # mirrors main() clearing it right after write_config
    exit 0
) >/dev/null 2>&1
assert_alive "$safe_pid" "disarmed trap leaves a successfully-started service running"
kill -9 "$safe_pid" 2>/dev/null || true
clear_recorded_pids soap-service

# Test 24b (TEST-011): Tests 23/24 above register `trap 'teardown_on_failure'
# EXIT` THEMSELVES, inside their own subshell — real coverage of what the
# function does, but none of the regression TEST-022 names (a failed partial
# setup leaving unauthenticated listeners running) depends on main() actually
# performing that registration. MEASURED on a scratch copy: deleting
# `SETUP_IN_PROGRESS=true` and `trap 'teardown_on_failure' EXIT` from main()
# gives Passed: 61 Skipped: 0 Failed: 0 — Tests 23/24 stay green because they
# never touch main() at all. Mirrors install-chrome-selftest.sh case p, which
# extracts main()'s body with awk rather than trusting a whole-file grep.
#
# TEST-014: the three checks below were unordered PRESENCE greps, and the
# property that matters is POSITION. MEASURED: hoisting `SETUP_IN_PROGRESS=false`
# from after write_config up to just after the trap arm makes the failure
# teardown a no-op across the entire service-start span -- fully restoring the
# TEST-022 regression -- and all three greps still matched, so the suite stayed
# at 65/0/0 and exited 0 while the third assertion's own message ("clears ...
# AFTER a successful write_config") had become false. Line numbers inside the
# same awk-extracted body settle it, the way install-chrome-selftest case u does
# for INSTALL_SUCCEEDED.
echo "Test 24b: main() actually arms the SETUP_IN_PROGRESS/teardown_on_failure trap it relies on"
main_body_24b="$(awk '/^main\(\) \{/,/^\}/' "${SCRIPT_UNDER_TEST}")"
arm_at=$(printf '%s\n' "${main_body_24b}" | grep -nE '^[[:space:]]*SETUP_IN_PROGRESS=true$' | head -1 | cut -d: -f1 || true)
trap_at=$(printf '%s\n' "${main_body_24b}" | grep -nE "^[[:space:]]*trap 'teardown_on_failure' EXIT\$" | head -1 | cut -d: -f1 || true)
disarm_at=$(printf '%s\n' "${main_body_24b}" | grep -nE '^[[:space:]]*SETUP_IN_PROGRESS=false$' | head -1 | cut -d: -f1 || true)
firststart_at=$(printf '%s\n' "${main_body_24b}" | grep -nE '^[[:space:]]*start_[a-z_]+ "\$' | head -1 | cut -d: -f1 || true)
writecfg_at=$(printf '%s\n' "${main_body_24b}" | grep -nE '^[[:space:]]*write_config ' | head -1 | cut -d: -f1 || true)

# Fidelity sentinel: an extraction that finds nothing must FAIL loudly rather
# than let every ordering comparison below pass vacuously on empty strings.
if [ -n "${arm_at}" ] && [ -n "${trap_at}" ] && [ -n "${disarm_at}" ] \
   && [ -n "${firststart_at}" ] && [ -n "${writecfg_at}" ]; then
    ok "Test 24b located main()'s arm, trap, disarm, first service start and write_config"
else
    fail "Test 24b could not locate one of main()'s arm/trap/disarm/start/write_config statements — the ordering assertions below are vacuous, fix the extraction rather than deleting it"
fi

if [ -n "${arm_at}" ]; then
    ok "main() sets SETUP_IN_PROGRESS=true"
else
    fail "main() sets SETUP_IN_PROGRESS=true (registration missing)"
fi
if [ -n "${trap_at}" ]; then
    ok "main() registers trap 'teardown_on_failure' EXIT"
else
    fail "main() registers trap 'teardown_on_failure' EXIT (registration missing)"
fi
if [ -n "${disarm_at}" ]; then
    ok "main() clears SETUP_IN_PROGRESS=false"
else
    fail "main() clears SETUP_IN_PROGRESS=false (disarm missing)"
fi

# The three ordering claims the presence greps left unchecked.
if [ -n "${arm_at}" ] && [ -n "${firststart_at}" ] && [ "${arm_at}" -lt "${firststart_at}" ]; then
    ok "SETUP_IN_PROGRESS=true precedes the first service start"
else
    fail "SETUP_IN_PROGRESS=true does not precede the first service start — a service that fails before the arm is never torn down"
fi
if [ -n "${trap_at}" ] && [ -n "${firststart_at}" ] && [ "${trap_at}" -lt "${firststart_at}" ]; then
    ok "the teardown_on_failure trap is armed before the first service start"
else
    fail "the teardown_on_failure trap is armed after the first service start — an early failure leaks listeners"
fi
# TEST-015: reworded, because the old text ("AFTER write_config succeeds") claimed
# more than a line-number comparison can know. This assertion compares POSITIONS
# inside main()'s body; it says nothing about execution or exit status. Measured:
# wrapping main()'s write_config call in a never-true conditional left the suite at
# 76/0, exit 0 while still printing "cleared only AFTER write_config succeeds" —
# with write_config unreachable and never running at all.
if [ -n "${disarm_at}" ] && [ -n "${writecfg_at}" ] && [ "${disarm_at}" -gt "${writecfg_at}" ]; then
    ok "SETUP_IN_PROGRESS=false is positioned AFTER main()'s write_config call"
else
    fail "SETUP_IN_PROGRESS=false is cleared before write_config completes — the trap is a no-op for the whole start span, restoring the TEST-022 regression"
fi
# And the claim the position comparison cannot make: that the call is REACHED.
# main()'s statements sit at one level of indentation; a call nested deeper is
# inside a conditional or loop and may never run, which is exactly the mutation
# above. Pinning the indentation is the cheapest honest check available to a
# source-level test, and it is the shape the sibling assertions already rely on.
writecfg_indent=$(printf '%s\n' "${main_body_24b}" | grep -E '^[[:space:]]*write_config ' | head -1 | sed -E 's/[^[:space:]].*//' | awk '{ print length }')
start_indent=$(printf '%s\n' "${main_body_24b}" | grep -E '^[[:space:]]*SETUP_IN_PROGRESS=true$' | head -1 | sed -E 's/[^[:space:]].*//' | awk '{ print length }')
if [ -n "${writecfg_indent}" ] && [ -n "${start_indent}" ] && [ "${writecfg_indent}" -eq "${start_indent}" ]; then
    ok "main()'s write_config call is unconditional (same nesting depth as the trap arm)"
else
    fail "main()'s write_config call is nested deeper than main()'s own statements (indent ${writecfg_indent} vs ${start_indent}) — it sits inside a conditional and may never run, so the ordering claim above is about a call that does not happen"
fi

# ── Skip-credit register (self-verifying; see the rationale below the pin) ──
# PER-SITE, not just a total. Pinning only the sum was defeated by a zero-sum
# swap: MUTATION-PROVEN, moving 1 credit from "lsof and python3 required" (3->2)
# onto "python3 unavailable" (2->3) kept the total at 19 and passed, while both
# arms now mis-credit their blocks — which is exactly the drift this register
# exists to catch, since a wrong per-site credit breaks the pin on precisely the
# degraded host that fires that arm. The register is each site's own credit,
# keyed by its message, derived from the file at runtime.
EXPECTED_SKIP_REGISTER='python3 unavailable=2
python3 and (lsof or ss) required=2
node-listener sub-cases need the staged stand-in=1
lsof and python3 required=3
pgrep required=2
could not build an lsof-free PATH for the SEC-BE-008 check=2
timeout/gtimeout, curl, and python3 required=1
timeout/gtimeout, dirname, and sleep required=2
stat required=4'
actual_skip_register=$(grep -oE '^[[:space:]]*skip "[^"]*" [0-9]+' "$THIS_DIR/setup-live-targets_test.sh" \
    | sed -E 's/^[[:space:]]*skip "([^"]*)" ([0-9]+)$/\1=\2/')
# Sites WITHOUT an explicit credit default to 0 and would silently not appear
# above, so they are counted separately rather than being invisible.
actual_skip_sites=$(grep -cE '^[[:space:]]*skip "' "$THIS_DIR/setup-live-targets_test.sh")
expected_sites=$(printf '%s\n' "$EXPECTED_SKIP_REGISTER" | wc -l)
if [ "$actual_skip_register" = "$EXPECTED_SKIP_REGISTER" ] && [ "$actual_skip_sites" -eq "$expected_sites" ]; then
    ok "skip-credit register is current: ${actual_skip_sites} sites, each credit matching its recorded value"
else
    fail "skip-credit register drifted — a skip was added, removed, re-credited, re-worded, or written without an explicit credit. Expected:
${EXPECTED_SKIP_REGISTER}
Found (${actual_skip_sites} total sites, credited ones listed):
${actual_skip_register}
Per-site credits are pinned, not just their sum: a zero-sum swap between two arms leaves the total correct while both mis-credit their blocks, breaking the unconditional pin below on exactly the degraded host that fires them."
fi

# ── Summary ─────────────────────────────────────────────────────────────────
SUITE_COMPLETED=1
echo ""
echo "──────────────────────────────────────────"
echo "Passed: ${PASS}   Skipped: ${SKIP}   Failed: ${FAIL}"
echo "──────────────────────────────────────────"
# Assertion accounting (TEST-006): this file had no EXPECTED_ASSERTIONS pin at
# all before this line, so deleting a whole Test block silently shrank PASS
# with nothing to compare it against — the exact deletion-detection gap
# install-chrome-selftest.sh and test-runner-args.sh already close for
# themselves.
#
# TEST-015: the pin used to be gated on `SKIP -eq 0`, which switched it OFF in
# precisely the environments most likely to differ from the author's. Every
# trigger here is ambient (python3/lsof/ss/pgrep/curl/timeout/stat), so on a host
# missing any one of them the pin stopped being checked at all: deleting a whole
# Test block AND running without pgrep reported "Passed: 60 Failed: 0" and
# exited 0. It is now enforced UNCONDITIONALLY against pass+fail+credit.
#
# The credits are a DERIVED INVARIANT, not a frozen literal list (this record
# went stale once already — see TEST-002's twin in install-chrome-selftest.sh):
# the credits of the skip arms that actually fired, plus the observed
# pass+fail, always total EXPECTED_ASSERTIONS. Each credit equals the number of
# counted outcomes its guarded block would have emitted on a fully-equipped
# host.
#
# The register below USED to be a prose list of `skip "` sites with their line
# numbers. It went stale in the same commit whose own comment warned that it had
# gone stale once already — three of its nine line numbers were off by 27 after
# an insertion above them, and one credit no longer matched its site. A record of
# where the code is, written next to the code, is the same defect this suite
# exists to catch: it DESCRIBES rather than EXERCISES, so nothing fails when it
# drifts.
#
# So it is derived and asserted instead. The counts below are read out of this
# file at runtime; if a skip site is added, removed, or has its credit changed
# without updating these two numbers, the assertion fails and names the delta.
# Line numbers are deliberately absent — they are what rots.
#
# 80 = 74 (round-15 baseline) + 2 (C1: the two Test 18b structural pins
# restored, D2 — both layers, source pin and Go behavioural test, are kept
# deliberately) + 3 (C3: TEST-009's two ALL_TARGETS-exhaustiveness assertions
# plus the grpc-server loopback-bind pin) + 1 (C4: the SEC-BE-003 pid-log mode
# assertion in Test 22). C2 and C5 are net zero: C2 rebalances Test 16's
# cp-failure arm with a credited skip instead of adding a real assertion; C5
# trades one Go test for another with no shell-side pin at all.
# ROUND-16: 80 -> 83. MEASURED. +2 in the Test 22 mode block (the graphql log's
# 0600 mode, and that start_graphql_server still creates it with install(1)
# rather than a bare redirection) -- that write was hardened last round with NO
# assertion at all, unlike its record_pid sibling which was hardened AND pinned
# in the same change. +1 for the ALL_TARGETS non-empty fidelity sentinel, without
# which the exhaustiveness loop below it passes having iterated nothing.
# The Test 22 skip credit moves 3 -> 4 to match.
#
# 83 -> 82 after the graphql assertion was CORRECTED: the first version used two
# assertions (a tautological install(1) run, plus a literal grep) and a mutation
# defeated the pair by keeping the literal and retargeting the path. The
# replacement is ONE assertion that executes the production install line and
# stats the real filename, pinning mode and path together.
# ROUND-16 final: 82 -> 84. MEASURED. +1 for the ordering check (nothing may
# remove .graphql-server.log between its install(1) and the redirect, which a
# `rm -f  # rotate` mutation proved was unguarded). +1 for the self-verifying
# skip-credit register, which replaced a prose list of line numbers that had
# already gone stale twice. The ALL_TARGETS bidirectional check is net zero — it
# replaced the liveness-only sentinel rather than adding to it.
EXPECTED_ASSERTIONS=84
if [ "$((PASS + FAIL + SKIP_CREDIT))" -ne "${EXPECTED_ASSERTIONS}" ]; then
    echo "setup-live-targets_test: FAIL — assertion accounting drift: expected ${EXPECTED_ASSERTIONS} assertions (Passed+Failed+skip credit), saw $((PASS + FAIL + SKIP_CREDIT))."
    echo "  A Test block was added or removed without updating EXPECTED_ASSERTIONS."
    exit 1
fi
[ "$FAIL" -eq 0 ]
