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
#   --help             Show this help message

set -euo pipefail

# SCRIPT_DIR may be pre-set by the regression test to isolate PID/state files in
# a temp dir; default to the directory this script lives in.
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Services managed by this script. Kept in one place so teardown, stale-state
# cleanup, and orphan sweeps all iterate the same set.
MANAGED_SERVICES="rest-api soap-service graphql-server grpc-server concat-spa"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"

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

# ──────────────────────────────────────────────────────────────
# Prerequisites
# ──────────────────────────────────────────────────────────────

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

    # Chrome/Chromium
    local chrome_found=0
    for browser in google-chrome chromium-browser chromium chrome; do
        if command -v "$browser" >/dev/null 2>&1; then
            log_ok "Browser: $browser"
            chrome_found=1
            break
        fi
    done
    # Also check common installation paths
    if [ $chrome_found -eq 0 ]; then
        for path in /usr/bin/google-chrome /usr/bin/chromium-browser /usr/bin/chromium \
                    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
                    /snap/bin/chromium; do
            if [ -x "$path" ]; then
                log_ok "Browser: $path"
                chrome_found=1
                break
            fi
        done
    fi
    if [ $chrome_found -eq 0 ]; then
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
    echo "$pid" >> "${SCRIPT_DIR}/.${name}.pids"
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
    PORT="$port" node server.js > "${SCRIPT_DIR}/.graphql-server.log" 2>&1 &
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

# Kill every PID recorded for a service, across all setup generations, then
# sweep any orphans whose pid log was lost. Idempotent.
stop_service() {
    local name=$1
    local stopped=0
    local pidfile pid

    # 1. Kill every recorded generation. Read both the append-log (.pids, current
    #    format) and any legacy single-PID file (.pid) left by older setups.
    for pidfile in "${SCRIPT_DIR}/.${name}.pids" "${SCRIPT_DIR}/.${name}.pid"; do
        [ -f "$pidfile" ] || continue
        while read -r pid || [ -n "$pid" ]; do
            [ -n "${pid//[[:space:]]/}" ] || continue
            if kill_pid "$pid"; then
                log_ok "Stopped ${name} (PID: ${pid})"
                stopped=$((stopped + 1))
            fi
        done < "$pidfile"
        rm -f "$pidfile"
    done

    # 2. Belt-and-suspenders sweep for orphans not covered by a pid log.
    stopped=$((stopped + $(sweep_orphans "$name")))

    if [ "$stopped" -eq 0 ]; then
        log_info "${name}: no running processes found"
    fi
}

# Kill orphaned processes for a service that are not tracked in a pid log.
# Go services have unique executable names and are swept by exact basename
# (current user only). graphql-server runs as `node`, so it is swept by its
# listening-port window instead — sweeping `node` by name is unsafe.
# Echoes the number of processes killed.
sweep_orphans() {
    local name=$1
    local killed=0
    local binary pid
    binary=$(service_binary "$name")

    if [ -n "$binary" ] && command -v pgrep >/dev/null 2>&1; then
        for pid in $(pgrep -x -U "$(id -u)" "$binary" 2>/dev/null || true); do
            if kill_pid "$pid"; then
                log_warn "Swept orphan ${name} (PID: ${pid}, matched '${binary}')" >&2
                killed=$((killed + 1))
            fi
        done
    else
        # Port-based sweep across the window setup could have used (base..base+20).
        local base port
        base=$(service_default_port "$name")
        if [ -n "$base" ] && command -v lsof >/dev/null 2>&1; then
            for port in $(seq "$base" $((base + 20))); do
                for pid in $(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true); do
                    if kill_pid "$pid"; then
                        log_warn "Swept orphan ${name} (PID: ${pid}, port ${port})" >&2
                        killed=$((killed + 1))
                    fi
                done
            done
        fi
    fi

    echo "$killed"
}

# Detect and kill processes left behind by a previous setup that did not tear
# down (e.g. "ran setup twice"). Logs an explicit line per stale process so the
# accidental-double-setup case is no longer silent.
cleanup_stale_state() {
    local found=0
    local name pidfile pid
    for name in $MANAGED_SERVICES; do
        for pidfile in "${SCRIPT_DIR}/.${name}.pids" "${SCRIPT_DIR}/.${name}.pid"; do
            [ -f "$pidfile" ] || continue
            while read -r pid || [ -n "$pid" ]; do
                [ -n "${pid//[[:space:]]/}" ] || continue
                if kill -0 "$pid" 2>/dev/null; then
                    log_warn "Killing stale process ${name} (PID: ${pid}) from a previous setup"
                    kill_pid "$pid" || true
                    found=1
                fi
            done < "$pidfile"
            rm -f "$pidfile"
        done
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
        rm -f "${SCRIPT_DIR}/.${name}.pid" "${SCRIPT_DIR}/.${name}.pids"
    done
    rm -f "${SCRIPT_DIR}/.graphql-server.log"
    rm -rf "${SCRIPT_DIR}/.results"

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
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Build and start all targets"
    echo "  $0 --targets rest-api           # Only set up rest-api"
    echo "  $0 --teardown                   # Stop everything and clean up"
}

main() {
    local targets="$ALL_TARGETS"
    local skip_start=false
    local teardown=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --targets)
                targets="$2"
                shift 2
                ;;
            --skip-start)
                skip_start=true
                shift
                ;;
            --teardown)
                teardown=true
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
                # `|| true` disarms `set -e` for this substitution so the
                # `[ -z ]` check below runs instead of the script dying silently.
                REST_API_PORT=$(find_available_port "$DEFAULT_REST_API_PORT") || true
                if [ -z "$REST_API_PORT" ]; then
                    log_fail "Cannot find available port for rest-api (tried ${DEFAULT_REST_API_PORT}-$((DEFAULT_REST_API_PORT + 20)))"
                    show_port_holders "$DEFAULT_REST_API_PORT"
                    exit 1
                fi
                log_ok "rest-api: port ${REST_API_PORT}"
                start_rest_api "$REST_API_PORT" || start_failed=1
                ;;
            soap-service)
                SOAP_SERVICE_PORT=$(find_available_port "$DEFAULT_SOAP_SERVICE_PORT") || true
                if [ -z "$SOAP_SERVICE_PORT" ]; then
                    log_fail "Cannot find available port for soap-service (tried ${DEFAULT_SOAP_SERVICE_PORT}-$((DEFAULT_SOAP_SERVICE_PORT + 20)))"
                    show_port_holders "$DEFAULT_SOAP_SERVICE_PORT"
                    exit 1
                fi
                log_ok "soap-service: port ${SOAP_SERVICE_PORT}"
                start_soap_service "$SOAP_SERVICE_PORT" || start_failed=1
                ;;
            graphql-server)
                GRAPHQL_SERVER_PORT=$(find_available_port "$DEFAULT_GRAPHQL_SERVER_PORT") || true
                if [ -z "$GRAPHQL_SERVER_PORT" ]; then
                    log_fail "Cannot find available port for graphql-server (tried ${DEFAULT_GRAPHQL_SERVER_PORT}-$((DEFAULT_GRAPHQL_SERVER_PORT + 20)))"
                    show_port_holders "$DEFAULT_GRAPHQL_SERVER_PORT"
                    exit 1
                fi
                log_ok "graphql-server: port ${GRAPHQL_SERVER_PORT}"
                start_graphql_server "$GRAPHQL_SERVER_PORT" || start_failed=1
                ;;
            grpc-server)
                GRPC_SERVER_PORT=$(find_available_port "$DEFAULT_GRPC_SERVER_PORT") || true
                if [ -z "$GRPC_SERVER_PORT" ]; then
                    log_fail "Cannot find available port for grpc-server (tried ${DEFAULT_GRPC_SERVER_PORT}-$((DEFAULT_GRPC_SERVER_PORT + 20)))"
                    show_port_holders "$DEFAULT_GRPC_SERVER_PORT"
                    exit 1
                fi
                log_ok "grpc-server: port ${GRPC_SERVER_PORT}"
                start_grpc_server "$GRPC_SERVER_PORT" || start_failed=1
                ;;
            concat-spa)
                CONCAT_SPA_PORT=$(find_available_port "$DEFAULT_CONCAT_SPA_PORT") || true
                if [ -z "$CONCAT_SPA_PORT" ]; then
                    log_fail "Cannot find available port for concat-spa (tried ${DEFAULT_CONCAT_SPA_PORT}-$((DEFAULT_CONCAT_SPA_PORT + 20)))"
                    show_port_holders "$DEFAULT_CONCAT_SPA_PORT"
                    exit 1
                fi
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
    log_info "Run tests with: ./test/run-live-tests.sh"
    log_info "Tear down with: ./test/setup-live-targets.sh --teardown"
}

# Run main only when executed directly. When sourced (by the regression test)
# the functions are defined but main does not run.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
