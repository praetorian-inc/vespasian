#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Shared colors and logging functions for vespasian live tests.
# Source this file from setup-live-targets.sh and run-live-tests.sh.

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
# Browser detection (LAB-3893)
#
# Lives here, not in setup-live-targets.sh, because three callers need the same
# answer to "is there a REAL browser on this host": setup-live-targets.sh
# (preflight gate), install-chrome.sh (idempotency — skip the install when a
# runnable browser already exists), and preflight-selftest.sh (regression
# coverage). A second copy of the probe would drift from the first.
# ──────────────────────────────────────────────────────────────

# Candidate browsers, in priority order. Overridable by tests.
CHROME_CANDIDATES=(
    google-chrome chromium-browser chromium chrome
    /usr/bin/google-chrome /usr/bin/chromium-browser /usr/bin/chromium
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    /snap/bin/chromium
)

# Probe a candidate for actual runnability. --version is fast and needs no X/DBus.
#
# Note this EXECUTES whatever the ambient PATH resolves for the bare-name
# candidates, and install-chrome.sh calls it while running under sudo. That is
# accepted: anyone who can place a binary earlier on root's PATH already has
# the privilege the probe would grant, so it crosses no trust boundary.
#
# The probe budget defaults to 2s but honours CHROME_PROBE_TIMEOUT: on a
# cold or throttled container mount a slow first exec can outlive a fixed
# budget, and the miss surfaces as a fatal "not runnable" — the same
# false-positive class LAB-3893 exists to prevent.
chrome_runnable() {
    local t=""
    if command -v timeout >/dev/null 2>&1; then
        t=timeout
    elif command -v gtimeout >/dev/null 2>&1; then   # macOS + coreutils
        t=gtimeout
    fi
    if [ -n "$t" ]; then
        "$t" "${CHROME_PROBE_TIMEOUT:-2}" "$1" --version >/dev/null 2>&1
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
