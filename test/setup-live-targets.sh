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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
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

start_rest_api() {
    local port=$1
    log_info "Starting rest-api on port ${port}..."
    cd "${SCRIPT_DIR}/rest-api"
    PORT="$port" ./rest-api &
    local pid=$!
    echo "$pid" > "${SCRIPT_DIR}/.rest-api.pid"

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
    echo "$pid" > "${SCRIPT_DIR}/.concat-spa.pid"

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
    echo "$pid" > "${SCRIPT_DIR}/.soap-service.pid"

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
    echo "$pid" > "${SCRIPT_DIR}/.graphql-server.pid"

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
    echo "$pid" > "${SCRIPT_DIR}/.grpc-server.pid"

    if wait_for_grpc "localhost" "${port}" 15; then
        log_ok "grpc-server started (PID: ${pid}, port: ${port})"
    else
        log_fail "grpc-server failed to start within 15s"
        kill "$pid" 2>/dev/null || true
        return 1
    fi
}

stop_service() {
    local name=$1
    local pidfile="${SCRIPT_DIR}/.${name}.pid"

    if [ -f "$pidfile" ]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            log_ok "Stopped ${name} (PID: ${pid})"
        else
            log_info "${name} already stopped"
        fi
        rm -f "$pidfile"
    else
        # Try pkill as fallback
        pkill -f "${SCRIPT_DIR}/${name}" 2>/dev/null && log_ok "Stopped ${name} via pkill" || true
    fi
}

# ──────────────────────────────────────────────────────────────
# Teardown
# ──────────────────────────────────────────────────────────────

do_teardown() {
    log_header "Tearing Down Live Targets"

    stop_service "rest-api"
    stop_service "soap-service"
    stop_service "graphql-server"
    stop_service "grpc-server"
    stop_service "concat-spa"

    # Clean up config and PID files
    rm -f "${CONFIG_FILE}"
    rm -f "${SCRIPT_DIR}/.rest-api.pid"
    rm -f "${SCRIPT_DIR}/.soap-service.pid"
    rm -f "${SCRIPT_DIR}/.graphql-server.pid"
    rm -f "${SCRIPT_DIR}/.concat-spa.pid"
    rm -f "${SCRIPT_DIR}/.graphql-server.log"
    rm -f "${SCRIPT_DIR}/.grpc-server.pid"
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

    # ── Resolve ports and start services ──
    # Each port is resolved immediately before starting that service so the
    # next service's port check sees the previous one as occupied.
    log_header "Starting Services"

    local start_failed=0
    REST_API_PORT="" SOAP_SERVICE_PORT="" GRAPHQL_SERVER_PORT="" GRPC_SERVER_PORT="" CONCAT_SPA_PORT=""
    for target in "${TARGET_ARRAY[@]}"; do
        case "$target" in
            rest-api)
                REST_API_PORT=$(find_available_port "$DEFAULT_REST_API_PORT")
                if [ -z "$REST_API_PORT" ]; then
                    log_fail "Cannot find available port for rest-api (tried ${DEFAULT_REST_API_PORT}-$((DEFAULT_REST_API_PORT + 20)))"
                    exit 1
                fi
                log_ok "rest-api: port ${REST_API_PORT}"
                start_rest_api "$REST_API_PORT" || start_failed=1
                ;;
            soap-service)
                SOAP_SERVICE_PORT=$(find_available_port "$DEFAULT_SOAP_SERVICE_PORT")
                if [ -z "$SOAP_SERVICE_PORT" ]; then
                    log_fail "Cannot find available port for soap-service (tried ${DEFAULT_SOAP_SERVICE_PORT}-$((DEFAULT_SOAP_SERVICE_PORT + 20)))"
                    exit 1
                fi
                log_ok "soap-service: port ${SOAP_SERVICE_PORT}"
                start_soap_service "$SOAP_SERVICE_PORT" || start_failed=1
                ;;
            graphql-server)
                GRAPHQL_SERVER_PORT=$(find_available_port "$DEFAULT_GRAPHQL_SERVER_PORT")
                if [ -z "$GRAPHQL_SERVER_PORT" ]; then
                    log_fail "Cannot find available port for graphql-server (tried ${DEFAULT_GRAPHQL_SERVER_PORT}-$((DEFAULT_GRAPHQL_SERVER_PORT + 20)))"
                    exit 1
                fi
                log_ok "graphql-server: port ${GRAPHQL_SERVER_PORT}"
                start_graphql_server "$GRAPHQL_SERVER_PORT" || start_failed=1
                ;;
            grpc-server)
                GRPC_SERVER_PORT=$(find_available_port "$DEFAULT_GRPC_SERVER_PORT")
                if [ -z "$GRPC_SERVER_PORT" ]; then
                    log_fail "Cannot find available port for grpc-server (tried ${DEFAULT_GRPC_SERVER_PORT}-$((DEFAULT_GRPC_SERVER_PORT + 20)))"
                    exit 1
                fi
                log_ok "grpc-server: port ${GRPC_SERVER_PORT}"
                start_grpc_server "$GRPC_SERVER_PORT" || start_failed=1
                ;;
            concat-spa)
                CONCAT_SPA_PORT=$(find_available_port "$DEFAULT_CONCAT_SPA_PORT")
                if [ -z "$CONCAT_SPA_PORT" ]; then
                    log_fail "Cannot find available port for concat-spa (tried ${DEFAULT_CONCAT_SPA_PORT}-$((DEFAULT_CONCAT_SPA_PORT + 20)))"
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

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
