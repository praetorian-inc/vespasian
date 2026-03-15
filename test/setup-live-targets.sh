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
#                      Valid: rest-api,soap-service
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

# All available targets
ALL_TARGETS="rest-api,soap-service"

# ──────────────────────────────────────────────────────────────
# Colors and logging
# ──────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

log_info()   { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()     { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail()   { echo -e "${RED}[FAIL]${NC} $1"; }

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
        pkill -f "${name}$" 2>/dev/null && log_ok "Stopped ${name} via pkill" || true
    fi
}

# ──────────────────────────────────────────────────────────────
# Teardown
# ──────────────────────────────────────────────────────────────

do_teardown() {
    log_header "Tearing Down Live Targets"

    stop_service "rest-api"
    stop_service "soap-service"

    # Clean up config and PID files
    rm -f "${CONFIG_FILE}"
    rm -f "${SCRIPT_DIR}/.rest-api.pid"
    rm -f "${SCRIPT_DIR}/.soap-service.pid"
    rm -rf "${SCRIPT_DIR}/.results"

    log_ok "Teardown complete"
}

# ──────────────────────────────────────────────────────────────
# Config file
# ──────────────────────────────────────────────────────────────

write_config() {
    local rest_port=$1
    local soap_port=$2
    local targets=$3

    cat > "$CONFIG_FILE" <<EOF
# Auto-generated by setup-live-targets.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Source this or let run-live-tests.sh read it automatically.
REST_API_PORT=${rest_port}
SOAP_SERVICE_PORT=${soap_port}
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
    echo "                     Valid: rest-api,soap-service"
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
            rest-api)      build_rest_api ;;
            soap-service)  build_soap_service ;;
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

    # ── Port resolution ──
    log_header "Resolving Ports"

    REST_API_PORT=$(find_available_port "$DEFAULT_REST_API_PORT")
    if [ -z "$REST_API_PORT" ]; then
        log_fail "Cannot find available port for rest-api (tried ${DEFAULT_REST_API_PORT}-$((DEFAULT_REST_API_PORT + 20)))"
        exit 1
    fi
    log_ok "rest-api: port ${REST_API_PORT}"

    SOAP_SERVICE_PORT=$(find_available_port "$DEFAULT_SOAP_SERVICE_PORT")
    if [ -z "$SOAP_SERVICE_PORT" ]; then
        log_fail "Cannot find available port for soap-service (tried ${DEFAULT_SOAP_SERVICE_PORT}-$((DEFAULT_SOAP_SERVICE_PORT + 20)))"
        exit 1
    fi
    log_ok "soap-service: port ${SOAP_SERVICE_PORT}"

    # ── Start services ──
    log_header "Starting Services"

    for target in "${TARGET_ARRAY[@]}"; do
        case "$target" in
            rest-api)      start_rest_api "$REST_API_PORT" ;;
            soap-service)  start_soap_service "$SOAP_SERVICE_PORT" ;;
        esac
    done

    # ── Write config ──
    write_config "$REST_API_PORT" "$SOAP_SERVICE_PORT" "$targets"

    log_header "Setup Complete"
    log_info "Run tests with: ./test/run-live-tests.sh"
    log_info "Tear down with: ./test/setup-live-targets.sh --teardown"
}

main "$@"
