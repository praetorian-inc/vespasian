#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Setup script for vespasian live test targets.
# Builds binaries, resolves port conflicts, starts services, and writes config.
#
# Usage:
#   ./test/setup-live-targets.sh [options]
#
# Options:
#   --targets <list>   Comma-separated targets (default: all)
#                      Valid: rest-api,soap-service,graphql-server,concat-spa
#   --skip-start       Only build, don't start services
#   --teardown         Stop all running targets and clean up
#   --sweep            With --teardown, also sweep untracked orphans by name/port
#                      (off by default; can match unrelated processes)
#   --help             Show this help message

set -euo pipefail

# Directory this script lives in. Resolved from BASH_SOURCE only — never trusted
# from the environment, since it decides where common.sh is sourced from and
# where the service binaries are executed.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Directory for mutable state: PID logs, config, service logs. Defaults to
# SCRIPT_DIR. The regression test points this at a temp dir (via the dedicated
# SETUP_LIVE_TARGETS_STATE_DIR override) to isolate state, without redirecting
# where the script sources code from.
STATE_DIR="${SETUP_LIVE_TARGETS_STATE_DIR:-$SCRIPT_DIR}"

# Services managed by this script. Kept in one place so teardown, stale-state
# cleanup, and orphan sweeps all iterate the same set.
MANAGED_SERVICES="rest-api soap-service graphql-server grpc-server concat-spa"
CONFIG_FILE="${STATE_DIR}/.live-test-config"

# Whether teardown may fall back to the broad orphan sweep (kill by executable
# basename / listening port) for a service that has no pid log. OFF by default:
# the pid log records every started generation, so a normal teardown never needs
# it, and the sweep can match UNRELATED processes — a developer's own same-named
# service, or any `node` listening in the graphql port window. Enable explicitly
# with `--sweep` for the rare pre-existing-orphan / lost-pid-log case.
SWEEP_ORPHANS=false

# Default ports
DEFAULT_REST_API_PORT=8990
DEFAULT_SOAP_SERVICE_PORT=8991
DEFAULT_GRAPHQL_SERVER_PORT=8992
DEFAULT_GRPC_SERVER_PORT=50051
DEFAULT_CONCAT_SPA_PORT=8993

# All available targets
ALL_TARGETS="rest-api,soap-service,graphql-server,grpc-server,concat-spa"

# Source shared colors and logging
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

# ──────────────────────────────────────────────────────────────
# Port resolution
# ──────────────────────────────────────────────────────────────

port_in_use() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :"$1" >/dev/null 2>&1
    elif command -v ss >/dev/null 2>&1; then
        ss -ltn | grep -q ":$1 "
    else
        (echo >/dev/tcp/localhost/"$1") 2>/dev/null
    fi
}

find_available_port() {
    local base_port=$1
    local port=$base_port
    while port_in_use "$port"; do
        port=$((port + 1))
        if [ $((port - base_port)) -gt 20 ]; then
            echo ""
            return 1
        fi
    done
    echo "$port"
}

# Print the processes holding the port window [base, base+20] so an exhausted
# range points the engineer straight at the offending orphans.
show_port_holders() {
    local base=$1
    local end=$((base + 20))
    log_info "Listening processes on TCP ${base}-${end}:"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${base}-${end}" -sTCP:LISTEN 2>/dev/null | sed 's/^/    /' || true
    elif command -v ss >/dev/null 2>&1; then
        ss -ltnH 2>/dev/null | awk -v b="$base" -v e="$end" \
            '{ n = split($4, a, ":"); p = a[n]; if (p >= b && p <= e) print "    " $0 }' || true
    else
        log_info "    (install lsof or ss to list port holders)"
    fi
}

# Resolve an available port for a service, or exit 1 after logging a diagnostic
# that names the processes holding the range. On success sets RESOLVED_PORT.
#
# Callers MUST invoke this as a statement, never inside `$(...)`: `exit` in a
# command substitution kills only the subshell, so the script would carry on
# with an empty port. The `|| true` disarms `set -e` for the command
# substitution so the `[ -z ]` check runs instead of the script dying silently
# on an exhausted range (LAB-2893 Bug 2).
RESOLVED_PORT=""
resolve_port_or_die() {
    local name=$1 default_port=$2
    RESOLVED_PORT="$(find_available_port "$default_port")" || true
    if [ -z "$RESOLVED_PORT" ]; then
        log_fail "Cannot find available port for ${name} (tried ${default_port}-$((default_port + 20)))"
        show_port_holders "$default_port"
        exit 1
    fi
}

# ──────────────────────────────────────────────────────────────
# Prerequisites
# ──────────────────────────────────────────────────────────────

# Candidate browsers, in priority order. Overridable by tests.
CHROME_CANDIDATES=(
    google-chrome chromium-browser chromium chrome
    /usr/bin/google-chrome /usr/bin/chromium-browser /usr/bin/chromium
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    /snap/bin/chromium
)

# Probe a candidate for actual runnability. --version is fast and needs no X/DBus.
chrome_runnable() {
    local t=""
    if command -v timeout >/dev/null 2>&1; then
        t=timeout
    elif command -v gtimeout >/dev/null 2>&1; then   # macOS + coreutils
        t=gtimeout
    fi
    if [ -n "$t" ]; then
        "$t" 2 "$1" --version >/dev/null 2>&1
    else
        # No timeout available (e.g. stock macOS): probe directly. A binary that
        # hangs on --version would block here — known limitation, documented in
        # test/README.md.
        "$1" --version >/dev/null 2>&1
    fi
}

# Resolve + probe candidates. On success: echo the runnable binary, return 0.
# On "present but not runnable": echo the first broken binary, return 2.
# On "nothing found": echo nothing, return 1.
detect_chrome_binary() {
    local browser bin stub=""
    for browser in "${CHROME_CANDIDATES[@]}"; do
        bin=$(command -v "$browser" 2>/dev/null) || continue
        if chrome_runnable "$bin"; then
            printf '%s\n' "$bin"
            return 0
        fi
        [ -z "$stub" ] && stub="$bin"
    done
    [ -n "$stub" ] && { printf '%s\n' "$stub"; return 2; }
    return 1
}

check_prerequisites() {
    log_header "Checking Prerequisites"
    local failed=0

    # Go
    if command -v go >/dev/null 2>&1; then
        log_ok "Go $(go version | awk '{print $3}')"
    else
        log_fail "Go is not installed. Install from https://go.dev/dl/"
        failed=1
    fi

    # Chrome/Chromium — presence alone is not enough (snap stubs satisfy
    # command -v / -x but fail at runtime). detect_chrome_binary probes
    # runnability so preflight fails loudly here, not during `vespasian crawl`.
    # Note: `chrome_bin=$(detect_chrome_binary) || rc=$?` (not `; rc=$?`) — under
    # this script's `set -e`, a bare `chrome_bin=$(cmd); rc=$?` would abort the
    # script the instant detect_chrome_binary returns non-zero, before rc=$?
    # ever ran, and the elif/else branches below would never execute.
    local chrome_bin rc=0
    chrome_bin=$(detect_chrome_binary) || rc=$?
    if [ $rc -eq 0 ]; then
        log_ok "Browser: $chrome_bin"
    elif [ $rc -eq 2 ]; then
        log_fail "Found ${chrome_bin} but it is not runnable"
        case "$chrome_bin" in
            */snap/*|*/chromium-browser|*/chromium)
                log_info "(looks like the Ubuntu snap stub — install the chromium snap: 'snap install chromium', or use google-chrome)."
                ;;
            *)
                log_info "(the binary exists but failed to run — check permissions, missing shared libraries, or reinstall the browser)."
                ;;
        esac
        failed=1
    else
        log_fail "Chrome/Chromium not found. Required for headless crawling."
        log_info "Install: https://www.google.com/chrome/ or 'apt install chromium-browser'"
        failed=1
    fi

    # python3
    if command -v python3 >/dev/null 2>&1; then
        log_ok "Python3 $(python3 --version 2>&1 | awk '{print $2}')"
    else
        log_fail "python3 is not installed. Required for test validation."
        failed=1
    fi

    # Node.js (required for graphql-server)
    if command -v node >/dev/null 2>&1; then
        log_ok "Node.js $(node --version 2>&1)"
    else
        log_warn "Node.js not found. Required for graphql-server target."
    fi

    if [ $failed -ne 0 ]; then
        log_fail "Prerequisites check failed. Install missing dependencies and retry."
        exit 1
    fi

    log_ok "All prerequisites met"
}

# ──────────────────────────────────────────────────────────────
# Build
# ──────────────────────────────────────────────────────────────

build_vespasian() {
    log_info "Building vespasian..."
    cd "$PROJECT_ROOT"
    go build -o bin/vespasian ./cmd/vespasian
    log_ok "Built bin/vespasian"
}

build_rest_api() {
    log_info "Building rest-api..."
    cd "${SCRIPT_DIR}/rest-api"
    go build -o rest-api .
    log_ok "Built test/rest-api/rest-api"
}

build_soap_service() {
    log_info "Building soap-service..."
    cd "${SCRIPT_DIR}/soap-service"
    go build -o soap-service .
    log_ok "Built test/soap-service/soap-service"
}

build_concat_spa() {
    log_info "Building concat-spa..."
    cd "${SCRIPT_DIR}/concat-spa"
    go build -o concat-spa .
    log_ok "Built test/concat-spa/concat-spa"
}

build_graphql_server() {
    log_info "Installing graphql-server dependencies..."
    cd "${SCRIPT_DIR}/graphql-server"
    if [ ! -d "node_modules" ]; then
        npm install --silent
    fi
    log_ok "graphql-server dependencies installed"
}

build_grpc_server() {
    log_info "Building grpc-server..."
    cd "${SCRIPT_DIR}/grpc-server"
    go build -o grpc-server .
    log_ok "Built test/grpc-server/grpc-server"
}

# ──────────────────────────────────────────────────────────────
# Start/Stop services
# ──────────────────────────────────────────────────────────────

wait_for_http() {
    local url=$1
    local timeout=${2:-30}
    local start=$SECONDS

    while true; do
        if curl -sf -o /dev/null "$url" 2>/dev/null; then
            return 0
        fi
        if [ $((SECONDS - start)) -ge "$timeout" ]; then
            return 1
        fi
        sleep 0.5
    done
}

# Append a started PID to the service's pid log. Every generation is recorded
# (append, not overwrite) so teardown can kill them all, not just the latest.
record_pid() {
    local name=$1 pid=$2
    echo "$pid" >> "${STATE_DIR}/.${name}.pids"
}

# Kill a PID if it is alive: TERM, brief grace period, then KILL. Works for
# processes started by a *previous* setup run (not children of this shell), so
# it polls for exit instead of relying on `wait`. Returns 0 if the PID was
# alive (and is now signalled), 1 if it was already gone.
kill_pid() {
    local pid=$1
    kill -0 "$pid" 2>/dev/null || return 1
    kill "$pid" 2>/dev/null || true
    local _
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.2
    done
    kill -9 "$pid" 2>/dev/null || true
    return 0
}

# Exact process basename to sweep for a service, or empty when it must be swept
# by port instead. graphql-server runs as `node server.js`, so sweeping it by
# name would kill unrelated node processes — it is swept by port in stop_service.
service_binary() {
    case "$1" in
        rest-api)     echo "rest-api" ;;
        soap-service) echo "soap-service" ;;
        concat-spa)   echo "concat-spa" ;;
        grpc-server)  echo "grpc-server" ;;
        *)            echo "" ;;
    esac
}

# Default base port for a service, used for port-based orphan sweeps.
service_default_port() {
    case "$1" in
        rest-api)       echo "$DEFAULT_REST_API_PORT" ;;
        soap-service)   echo "$DEFAULT_SOAP_SERVICE_PORT" ;;
        graphql-server) echo "$DEFAULT_GRAPHQL_SERVER_PORT" ;;
        grpc-server)    echo "$DEFAULT_GRPC_SERVER_PORT" ;;
        concat-spa)     echo "$DEFAULT_CONCAT_SPA_PORT" ;;
        *)              echo "" ;;
    esac
}

# True if $pid is alive AND its command matches the identity expected for service
# $name. PID logs and PID files can outlive a reboot, after which the OS may
# recycle a recorded PID onto an unrelated process; this guard stops us from
# killing that innocent process. `comm` is compared by basename to tolerate macOS
# returning a full path where Linux returns the bare (≤15 char) name.
#
# Services with a unique executable (the Go targets) match by exact basename.
# graphql-server has no unique name — it runs as `node server.js`, and `comm` for
# any node process is just `node` — so an exact-name match alone would accept ANY
# of the user's node processes onto which the recorded PID may have been recycled.
# For it we additionally require the PID to be listening in the service's port
# window, reusing the same node-in-window identity filter as the orphan sweep
# (orphan_pids_by_port). If that check cannot run (e.g. lsof unavailable) we
# decline the match rather than kill an unverified node process.
pid_matches_service() {
    local pid=$1 name=$2 comm binary base wpid
    comm="$(ps -p "$pid" -o comm= 2>/dev/null)"
    comm="$(basename "$comm" 2>/dev/null)"
    [ -n "$comm" ] || return 1

    binary="$(service_binary "$name")"
    if [ -n "$binary" ]; then
        [ "$comm" = "$binary" ]
        return
    fi

    # No unique binary → node-based graphql-server: require node AND a listening
    # socket in the service's port window before treating it as a match.
    [ "$comm" = "node" ] || return 1
    base="$(service_default_port "$name")"
    [ -n "$base" ] || return 1
    for wpid in $(orphan_pids_by_port "$base"); do
        [ "$wpid" = "$pid" ] && return 0
    done
    return 1
}

start_rest_api() {
    local port=$1
    log_info "Starting rest-api on port ${port}..."
    cd "${SCRIPT_DIR}/rest-api"
    PORT="$port" ./rest-api &
    local pid=$!
    record_pid rest-api "$pid"

    if wait_for_http "http://localhost:${port}/api/health" 15; then
        log_ok "rest-api started (PID: ${pid}, port: ${port})"
    else
        log_fail "rest-api failed to start within 15s"
        kill "$pid" 2>/dev/null || true
        return 1
    fi
}

start_concat_spa() {
    local port=$1
    log_info "Starting concat-spa on port ${port}..."
    cd "${SCRIPT_DIR}/concat-spa"
    PORT="$port" ./concat-spa &
    local pid=$!
    record_pid concat-spa "$pid"

    if wait_for_http "http://localhost:${port}/healthz" 15; then
        log_ok "concat-spa started (PID: ${pid}, port: ${port})"
    else
        log_fail "concat-spa failed to start within 15s"
        kill "$pid" 2>/dev/null || true
        return 1
    fi
}

start_soap_service() {
    local port=$1
    log_info "Starting soap-service on port ${port}..."
    cd "${SCRIPT_DIR}/soap-service"
    PORT="$port" WSDL_PATH="${SCRIPT_DIR}/soap-service/service.wsdl" ./soap-service &
    local pid=$!
    record_pid soap-service "$pid"

    if wait_for_http "http://localhost:${port}/service.wsdl" 15; then
        log_ok "soap-service started (PID: ${pid}, port: ${port})"
    else
        log_fail "soap-service failed to start within 15s"
        kill "$pid" 2>/dev/null || true
        return 1
    fi
}

start_graphql_server() {
    local port=$1
    log_info "Starting graphql-server on port ${port}..."
    cd "${SCRIPT_DIR}/graphql-server"
    PORT="$port" node server.js > "${STATE_DIR}/.graphql-server.log" 2>&1 &
    local pid=$!
    record_pid graphql-server "$pid"

    if wait_for_http "http://localhost:${port}/" 15; then
        log_ok "graphql-server started (PID: ${pid}, port: ${port})"
    else
        log_fail "graphql-server failed to start within 15s"
        kill "$pid" 2>/dev/null || true
        return 1
    fi
}

wait_for_grpc() {
    local host=$1
    local port=$2
    local timeout=${3:-30}
    local start=$SECONDS

    while true; do
        if command -v grpcurl >/dev/null 2>&1; then
            if grpcurl -plaintext "${host}:${port}" list >/dev/null 2>&1; then
                return 0
            fi
        elif command -v nc >/dev/null 2>&1; then
            if nc -z "${host}" "${port}" 2>/dev/null; then
                return 0
            fi
        else
            if (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
                return 0
            fi
        fi
        if [ $((SECONDS - start)) -ge "$timeout" ]; then
            return 1
        fi
        sleep 0.5
    done
}

start_grpc_server() {
    local port=$1
    log_info "Starting grpc-server on port ${port}..."
    cd "${SCRIPT_DIR}/grpc-server"
    GRPC_PORT="$port" ./grpc-server &
    local pid=$!
    record_pid grpc-server "$pid"

    if wait_for_grpc "localhost" "${port}" 15; then
        log_ok "grpc-server started (PID: ${pid}, port: ${port})"
    else
        log_fail "grpc-server failed to start within 15s"
        kill "$pid" 2>/dev/null || true
        return 1
    fi
}

# Echo every PID recorded for a service, one per line, skipping blanks. Reads
# both the append-log (.pids, current format) and any legacy single-PID file
# (.pid) left by older setups. Read-only — the caller decides when to clear.
recorded_pids() {
    local name=$1 pidfile pid
    for pidfile in "${STATE_DIR}/.${name}.pids" "${STATE_DIR}/.${name}.pid"; do
        [ -f "$pidfile" ] || continue
        while read -r pid || [ -n "$pid" ]; do
            [ -n "${pid//[[:space:]]/}" ] || continue
            echo "$pid"
        done < "$pidfile"
    done
}

# Remove both pid-log formats for a service.
clear_recorded_pids() {
    local name=$1
    rm -f "${STATE_DIR}/.${name}.pids" "${STATE_DIR}/.${name}.pid"
}

# True if a pid log (either format) exists for a service.
has_recorded_pids() {
    local name=$1
    [ -f "${STATE_DIR}/.${name}.pids" ] || [ -f "${STATE_DIR}/.${name}.pid" ]
}

# Orphan-discovery seams. Overridable when the script is sourced: the regression
# test stubs these so its sweeps stay confined to the test's own stand-ins and
# never touch the developer's real process table.
#
# By exact executable basename, current user only. `pgrep -x` matches the whole
# name (not a substring), so only a process actually named "$1" is returned.
orphan_pids_by_name() {
    command -v pgrep >/dev/null 2>&1 || return 0
    pgrep -x -U "$(id -u)" "$1" 2>/dev/null || true
}

# By listening-port window [base, base+20], restricted to `node` processes: the
# graphql-server runs as `node`, and the identity filter avoids killing an
# unrelated service that merely listens in the same range. `-nP` skips the
# reverse-DNS / port-name lookups that could otherwise hang teardown.
orphan_pids_by_port() {
    local base=$1
    local end=$((base + 20)) pid comm
    command -v lsof >/dev/null 2>&1 || return 0
    # One ranged lsof call (mirrors show_port_holders) instead of 21 per-port
    # invocations; -t yields de-duplicated PIDs, which we then filter to node.
    for pid in $(lsof -nP -tiTCP:"${base}-${end}" -sTCP:LISTEN 2>/dev/null || true); do
        comm="$(ps -p "$pid" -o comm= 2>/dev/null)"
        [ "$(basename "$comm" 2>/dev/null)" = "node" ] && echo "$pid"
    done
}

# Kill orphaned processes for a service whose pid log was lost. Go services have
# unique executable names and are swept by exact basename; graphql-server runs
# as `node`, so it is swept by its listening-port window. Echoes the number of
# processes killed. Called by stop_service ONLY under --sweep AND when no pid log
# existed — the pid log is the primary, reliable mechanism; this opt-in fallback
# can match unrelated processes, so it is never run by default.
sweep_orphans() {
    local name=$1 killed=0 binary base pid
    binary="$(service_binary "$name")"

    if [ -n "$binary" ]; then
        for pid in $(orphan_pids_by_name "$binary"); do
            if kill_pid "$pid"; then
                log_warn "Swept orphan ${name} (PID: ${pid}, matched '${binary}')" >&2
                killed=$((killed + 1))
            fi
        done
    else
        base="$(service_default_port "$name")"
        if [ -n "$base" ]; then
            for pid in $(orphan_pids_by_port "$base"); do
                if kill_pid "$pid"; then
                    log_warn "Swept orphan ${name} (PID: ${pid}, node in port window)" >&2
                    killed=$((killed + 1))
                fi
            done
        fi
    fi

    echo "$killed"
}

# Kill every PID recorded for a service across all setup generations, then — only
# if no pid log was found — sweep orphans left by a run whose log was lost. Every
# recorded PID is identity-checked before signalling (see pid_matches_service),
# so a recycled PID is skipped rather than killed. Idempotent.
stop_service() {
    local name=$1 stopped=0 pid no_log=1
    has_recorded_pids "$name" && no_log=0

    while read -r pid; do
        pid_matches_service "$pid" "$name" || continue
        if kill_pid "$pid"; then
            log_ok "Stopped ${name} (PID: ${pid})"
            stopped=$((stopped + 1))
        fi
    done < <(recorded_pids "$name")
    clear_recorded_pids "$name"

    # Fallback orphan sweep: opt-in (--sweep) AND only when this service has no
    # pid log. Off by default because the sweep matches by name/port and can hit
    # unrelated processes; the pid log already covers every normal teardown.
    if [ "$no_log" -ne 0 ] && [ "$SWEEP_ORPHANS" = true ]; then
        stopped=$((stopped + $(sweep_orphans "$name")))
    fi

    if [ "$stopped" -eq 0 ]; then
        log_info "${name}: no running processes found"
    fi
}

# Detect and kill processes left behind by a previous setup that did not tear
# down (e.g. "ran setup twice"). Logs an explicit line per stale process so the
# accidental-double-setup case is no longer silent. Each recorded PID is
# identity-checked first, so a recycled PID is skipped rather than killed.
#
# By design this relies solely on the pid log — it deliberately does NOT run the
# broad basename/port orphan sweep that stop_service uses. Keeping the aggressive
# sweep confined to the explicit teardown escape hatch avoids killing unrelated
# processes on every routine setup. If a prior run's pid log was lost while its
# process still holds a port, find_available_port simply steps past the occupied
# port, and a truly exhausted range is reported by show_port_holders — so a fresh
# setup still proceeds. Run `--teardown` to reap such an orphan.
cleanup_stale_state() {
    local found=0 name pid
    for name in $MANAGED_SERVICES; do
        while read -r pid; do
            pid_matches_service "$pid" "$name" || continue
            log_warn "Killing stale process ${name} (PID: ${pid}) from a previous setup"
            kill_pid "$pid" || true
            found=1
        done < <(recorded_pids "$name")
        clear_recorded_pids "$name"
    done
    if [ "$found" -eq 1 ]; then
        log_ok "Cleared stale processes from a previous run"
    fi
}

# ──────────────────────────────────────────────────────────────
# Teardown
# ──────────────────────────────────────────────────────────────

do_teardown() {
    log_header "Tearing Down Live Targets"

    local name
    for name in $MANAGED_SERVICES; do
        stop_service "$name"
    done

    # Clean up config, PID logs (both formats), and other state.
    rm -f "${CONFIG_FILE}"
    for name in $MANAGED_SERVICES; do
        clear_recorded_pids "$name"
    done
    rm -f "${STATE_DIR}/.graphql-server.log"
    rm -rf "${STATE_DIR}/.results"

    log_ok "Teardown complete"
}

# ──────────────────────────────────────────────────────────────
# Config file
# ──────────────────────────────────────────────────────────────

write_config() {
    local rest_port=$1
    local soap_port=$2
    local graphql_port=$3
    local grpc_port=$4
    local concat_port=$5
    local targets=$6

    cat > "$CONFIG_FILE" <<EOF
# Auto-generated by setup-live-targets.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Source this or let run-live-tests.sh read it automatically.
REST_API_PORT=${rest_port}
SOAP_SERVICE_PORT=${soap_port}
GRAPHQL_SERVER_PORT=${graphql_port}
GRPC_SERVER_PORT=${grpc_port}
CONCAT_SPA_PORT=${concat_port}
TARGETS_SETUP=${targets}
EOF
    log_ok "Wrote config to ${CONFIG_FILE}"
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --targets <list>   Comma-separated targets (default: all)"
    echo "                     Valid: rest-api,soap-service,graphql-server,grpc-server,concat-spa"
    echo "  --skip-start       Only build, don't start services"
    echo "  --teardown         Stop all running targets and clean up"
    echo "  --sweep            With --teardown, also sweep untracked orphans by"
    echo "                     name/port (off by default; can match unrelated processes)"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Build and start all targets"
    echo "  $0 --targets rest-api           # Only set up rest-api"
    echo "  $0 --teardown                   # Stop everything and clean up"
    echo "  $0 --teardown --sweep           # Also sweep untracked orphans (last resort)"
}

# Parse CLI arguments into globals, separated from main() so the flag→variable
# wiring (notably --sweep → SWEEP_ORPHANS) is unit-testable without running the
# side-effecting setup/teardown main() performs. Sets PARSED_TARGETS,
# PARSED_SKIP_START, PARSED_TEARDOWN and (on --sweep) SWEEP_ORPHANS. Exits on
# --help (0) and unknown option (1), matching the original inline behaviour.
parse_args() {
    PARSED_TARGETS="$ALL_TARGETS"
    PARSED_SKIP_START=false
    PARSED_TEARDOWN=false
    SWEEP_ORPHANS=false   # reset with the other parsed flags so parse_args is idempotent

    while [ $# -gt 0 ]; do
        case "$1" in
            --targets)
                PARSED_TARGETS="$2"
                shift 2
                ;;
            --skip-start)
                PARSED_SKIP_START=true
                shift
                ;;
            --teardown)
                PARSED_TEARDOWN=true
                shift
                ;;
            --sweep)
                SWEEP_ORPHANS=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_fail "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Pipeline orchestrator: parse args → teardown? → prereqs → build → stale
# cleanup → resolve ports + start → write config. Intentionally longer than the
# ~60-line guideline: each stage is a distinct sequential step that delegates to
# a helper, with no shared state worth extracting into further functions.
# run_tests_guidance echoes the "how to run what you just set up" lines for a
# completed setup, one command hint per line. It is intentionally side-effect
# free (echo only, no service calls) so test/test-runner-args.sh can assert the
# guidance without starting any target — the same testability pattern
# run-live-tests.sh uses for resolve_targets via --dry-run.
#
# A full setup (targets == ALL_TARGETS) steers to a bare run. A partial setup
# steers to an explicit --targets run so it does not probe services that were
# never started: TARGETS_SETUP is additive, not restrictive (see
# run-live-tests.sh), so a bare run would resolve the full "all" group.
run_tests_guidance() {
    local targets="$1"
    if [ "$targets" = "$ALL_TARGETS" ]; then
        echo "Run tests with: ./test/run-live-tests.sh"
    else
        echo "Run the targets you set up: ./test/run-live-tests.sh --targets ${targets}"
        echo "Offline-only checks (no services needed): ./test/run-live-tests.sh --group offline"
    fi
}

main() {
    parse_args "$@"
    local targets="$PARSED_TARGETS"
    local skip_start="$PARSED_SKIP_START"
    local teardown="$PARSED_TEARDOWN"

    if [ "$teardown" = true ]; then
        do_teardown
        exit 0
    fi

    log_header "Vespasian Live Test Setup"

    check_prerequisites

    # ── Build phase ──
    log_header "Building Binaries"
    build_vespasian

    IFS=',' read -ra TARGET_ARRAY <<< "$targets"
    for target in "${TARGET_ARRAY[@]}"; do
        case "$target" in
            rest-api)        build_rest_api ;;
            soap-service)    build_soap_service ;;
            graphql-server)  build_graphql_server ;;
            grpc-server)     build_grpc_server ;;
            concat-spa)      build_concat_spa ;;
            *)
                log_fail "Unknown target: $target"
                exit 1
                ;;
        esac
    done

    if [ "$skip_start" = true ]; then
        log_ok "Build complete (--skip-start: services not started)"
        exit 0
    fi

    # ── Clear any leftovers from a previous setup that never tore down ──
    # Frees ports held by stale orphans before we probe for availability.
    cleanup_stale_state

    # ── Resolve ports and start services ──
    # Each port is resolved immediately before starting that service so the
    # next service's port check sees the previous one as occupied.
    log_header "Starting Services"

    local start_failed=0
    REST_API_PORT="" SOAP_SERVICE_PORT="" GRAPHQL_SERVER_PORT="" GRPC_SERVER_PORT="" CONCAT_SPA_PORT=""
    for target in "${TARGET_ARRAY[@]}"; do
        case "$target" in
            rest-api)
                resolve_port_or_die rest-api "$DEFAULT_REST_API_PORT"
                REST_API_PORT=$RESOLVED_PORT
                log_ok "rest-api: port ${REST_API_PORT}"
                start_rest_api "$REST_API_PORT" || start_failed=1
                ;;
            soap-service)
                resolve_port_or_die soap-service "$DEFAULT_SOAP_SERVICE_PORT"
                SOAP_SERVICE_PORT=$RESOLVED_PORT
                log_ok "soap-service: port ${SOAP_SERVICE_PORT}"
                start_soap_service "$SOAP_SERVICE_PORT" || start_failed=1
                ;;
            graphql-server)
                resolve_port_or_die graphql-server "$DEFAULT_GRAPHQL_SERVER_PORT"
                GRAPHQL_SERVER_PORT=$RESOLVED_PORT
                log_ok "graphql-server: port ${GRAPHQL_SERVER_PORT}"
                start_graphql_server "$GRAPHQL_SERVER_PORT" || start_failed=1
                ;;
            grpc-server)
                resolve_port_or_die grpc-server "$DEFAULT_GRPC_SERVER_PORT"
                GRPC_SERVER_PORT=$RESOLVED_PORT
                log_ok "grpc-server: port ${GRPC_SERVER_PORT}"
                start_grpc_server "$GRPC_SERVER_PORT" || start_failed=1
                ;;
            concat-spa)
                resolve_port_or_die concat-spa "$DEFAULT_CONCAT_SPA_PORT"
                CONCAT_SPA_PORT=$RESOLVED_PORT
                log_ok "concat-spa: port ${CONCAT_SPA_PORT}"
                start_concat_spa "$CONCAT_SPA_PORT" || start_failed=1
                ;;
        esac
    done

    if [ $start_failed -ne 0 ]; then
        log_fail "One or more services failed to start. Run --teardown and retry."
        exit 1
    fi

    # ── Write config ──
    write_config "${REST_API_PORT:-}" "${SOAP_SERVICE_PORT:-}" "${GRAPHQL_SERVER_PORT:-}" "${GRPC_SERVER_PORT:-}" "${CONCAT_SPA_PORT:-}" "$targets"

    log_header "Setup Complete"
    # Emit the run guidance (full vs partial setup) via the shared, testable
    # selector; log_info each line so output matches the previous inline form.
    local guidance_line
    while IFS= read -r guidance_line; do
        log_info "$guidance_line"
    done < <(run_tests_guidance "$targets")
    log_info "Tear down with: ./test/setup-live-targets.sh --teardown"
}

# Run main only when executed directly. When sourced (by the regression test)
# the functions are defined but main does not run.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
