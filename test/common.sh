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

# %b for the colour constants (they carry real escapes), %s for the MESSAGE.
# `echo -e` interpreted escapes in the message too, so any externally-derived
# string — gpg's stderr, a browser path, an apt error — could smuggle \n, \r or
# \e through the log and forge output lines or rewrite the terminal. printf with
# %s makes the data inert without losing the colour.
log_info()   { printf '%b[INFO]%b %s\n' "$CYAN" "$NC" "$1"; }
log_ok()     { printf '%b[OK]%b %s\n' "$GREEN" "$NC" "$1"; }
log_warn()   { printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$1"; }
log_fail()   { printf '%b[FAIL]%b %s\n' "$RED" "$NC" "$1"; }

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
#
# The override is validated rather than passed through. Two reasons, and the
# first is the one that bites: an unparseable value makes timeout(1) exit 125
# without ever running the browser, which chrome_runnable reports as "not
# runnable" — reintroducing exactly the false positive the override exists to
# cure, and pointing the blame at the browser instead of the typo. Second, an
# unvalidated value reaches timeout's OPTION position, so a leading dash would
# be parsed as a flag rather than a duration. Anything that is not a bare
# decimal falls back to the default with a warning.
chrome_runnable() {
    local t="" budget="${CHROME_PROBE_TIMEOUT:-2}"
    # Two rejections, and they are separate questions:
    #   * not a plain decimal  -> timeout(1) would exit 125 without running the
    #     browser, which the caller reads as "not runnable" — the LAB-3893
    #     false positive this override exists to cure.
    #   * numerically zero     -> GNU timeout reads 0 as "no timeout at all",
    #     silently disabling the guard; a hanging browser would then block
    #     preflight forever.
    # Zero is tested by stripping the zeros and dots and asking whether anything
    # is left, rather than by globbing. A glob for zero over-rejected every
    # leading-zero duration that is NOT zero — `007`, `00.1`, `0.05` are all
    # perfectly good budgets and were being thrown away.
    _stripped=${budget//[0.]/}
    case "$budget" in
        ''|*[!0-9.]*|*.*.*|.)
            printf 'CHROME_PROBE_TIMEOUT=%s is not a usable timeout (positive seconds); using 2s.\n' \
                "$budget" >&2
            budget=2
            ;;
        *)  if [ -z "${_stripped}" ]; then
                # Nothing but zeros and dots remain -> numerically zero.
                printf 'CHROME_PROBE_TIMEOUT=%s is zero, which disables the timeout; using 2s.\n' \
                    "$budget" >&2
                budget=2
            fi
            ;;
    esac
    unset _stripped
    if command -v timeout >/dev/null 2>&1; then
        t=timeout
    elif command -v gtimeout >/dev/null 2>&1; then   # macOS + coreutils
        t=gtimeout
    fi
    if [ -n "$t" ]; then
        "$t" "$budget" "$1" --version >/dev/null 2>&1
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
