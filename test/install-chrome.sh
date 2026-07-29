#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Installs a real, non-snap Google Chrome so the live suite and the
# `//go:build integration` browser tests in pkg/crawl can run inside a
# container (LAB-5064).
#
# Why this exists: a stock Ubuntu devcontainer ships /usr/bin/chromium-browser
# as a snap LAUNCHER STUB, and snapd is unavailable in-container. The stub
# satisfies `command -v` and `-x` but fails the moment it is executed, so
# go-rod's launcher.LookPath() resolves a binary that cannot start. The fix is
# a .deb-packaged browser, which needs no snapd.
#
# Egress note: the google-chrome-stable package normally leaves behind two
# background phone-home mechanisms — Google's apt source
# (/etc/apt/sources.list.d/google-chrome.list), which is contacted on every
# `apt-get update`, and a daily update pinger (/etc/cron.daily/google-chrome).
# Neither is wanted in a pinned test image, and neither has anything to do with
# the browser the tests drive. This script suppresses the apt source at install
# time and removes both afterwards, so merely having Chrome present adds no
# background egress. Telemetry of the browser vespasian LAUNCHES is a separate,
# already-solved concern: crawls go through NewBrowserManager, which applies
# disableChromeTelemetry's flags (LAB-4999).
#
# Idempotent: exits 0 without touching the system when a runnable browser is
# already present. Safe to call from a Dockerfile RUN, a devcontainer
# postCreateCommand, or by hand.
#
# Usage:
#   ./test/install-chrome.sh            # install if needed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared colors, logging, and the browser probe (CHROME_CANDIDATES,
# chrome_runnable, detect_chrome_binary) that setup-live-targets.sh's preflight
# uses, so "already installed" here means exactly what "prerequisite satisfied"
# means there.
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

# Google publishes google-chrome-stable as a direct .deb for both Linux
# architectures we care about; CHROME_DEB_URL is resolved per-arch by
# resolve_deb_url below. Ubuntu's own `chromium`/`chromium-browser` packages are
# NOT an option: on noble both are transitional stubs that Pre-Depend on snapd
# ("Transitional package - chromium-browser -> chromium snap"), which is exactly
# the unrunnable binary this script exists to replace.
CHROME_DEB_BASE="https://dl.google.com/linux/direct/google-chrome-stable_current"
CHROME_DEB_URL=""

for arg in "$@"; do
    case "$arg" in
        --help)
            sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            log_fail "Unknown option: $arg (try --help)"
            exit 1
            ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# Preconditions
# ──────────────────────────────────────────────────────────────

# SUDO is the privilege prefix for every mutating command: empty when already
# root (the usual Dockerfile case), "sudo" otherwise.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        log_fail "Not running as root and sudo is unavailable — cannot install packages."
        exit 1
    fi
fi

# Sets CHROME_DEB_URL for the host architecture, or exits with a clear message.
# Bailing here beats an arch-mismatch dpkg error three steps later.
resolve_deb_url() {
    if ! command -v apt-get >/dev/null 2>&1; then
        log_fail "install-chrome.sh supports Debian/Ubuntu (apt-get) only."
        log_info "On macOS install Google Chrome normally; on other distros use your package manager."
        exit 1
    fi
    local arch
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64|arm64)
            CHROME_DEB_URL="${CHROME_DEB_BASE}_${arch}.deb"
            ;;
        *)
            log_fail "No google-chrome-stable .deb for architecture '${arch}' (amd64 and arm64 only)."
            exit 1
            ;;
    esac
    log_info "Architecture: ${arch}"
}

# ──────────────────────────────────────────────────────────────
# Phone-home neutralization
# ──────────────────────────────────────────────────────────────

# The package's postinst adds Google's apt source unless repo_add_once is
# already false in /etc/default/google-chrome. Pre-seeding that file is the
# clean route: the source is never added, rather than added and then deleted.
suppress_apt_source() {
    $SUDO install -d -m 0755 /etc/default
    if [ ! -f /etc/default/google-chrome ]; then
        printf 'repo_add_once=false\n' | $SUDO tee /etc/default/google-chrome >/dev/null
    elif ! grep -q '^repo_add_once=' /etc/default/google-chrome 2>/dev/null; then
        printf 'repo_add_once=false\n' | $SUDO tee -a /etc/default/google-chrome >/dev/null
    else
        $SUDO sed -i 's/^repo_add_once=.*/repo_add_once=false/' /etc/default/google-chrome
    fi
}

# Defense in depth behind suppress_apt_source: remove anything the postinst
# dropped anyway (older package revisions, or a source added by a previous
# install of Chrome in this image). Idempotent — every removal tolerates the
# file already being absent.
remove_phone_home() {
    $SUDO rm -f /etc/apt/sources.list.d/google-chrome.list
    $SUDO rm -f /etc/cron.daily/google-chrome
    # The keyring alone is inert once no source references it, but it exists
    # only to verify that source, so it goes too.
    $SUDO rm -f /etc/apt/trusted.gpg.d/google-chrome.gpg
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

log_header "Installing Chrome for vespasian tests"

# Idempotency: a browser that actually RUNS (not merely a snap stub that
# resolves) means there is nothing to do.
existing=""
rc=0
existing=$(detect_chrome_binary) || rc=$?
if [ $rc -eq 0 ]; then
    log_ok "Runnable browser already present: ${existing}"
    exit 0
fi
if [ $rc -eq 2 ]; then
    log_info "Found ${existing} but it is not runnable (snap stub?) — installing a real Chrome."
fi

resolve_deb_url

DEB_TMP="$(mktemp -d)"
trap 'rm -rf "${DEB_TMP}"' EXIT
DEB_PATH="${DEB_TMP}/google-chrome-stable.deb"

log_info "Downloading ${CHROME_DEB_URL}"
# --fail so an HTML error page never lands on disk as a "package"; the .deb is
# fetched directly rather than via Google's apt repo precisely so that repo is
# never wired into the image (see the egress note in the header).
if ! curl -fsSL --retry 3 --retry-delay 2 -o "${DEB_PATH}" "${CHROME_DEB_URL}"; then
    log_fail "Download failed: ${CHROME_DEB_URL}"
    exit 1
fi

suppress_apt_source

log_info "Installing google-chrome-stable (with dependencies)"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
# `apt-get install ./file.deb` resolves the package's dependencies from the
# already-configured distro sources; plain `dpkg -i` would leave them unmet.
$SUDO apt-get install -y --no-install-recommends "${DEB_PATH}"

remove_phone_home
$SUDO rm -rf /var/lib/apt/lists/*

# ──────────────────────────────────────────────────────────────
# Verify
# ──────────────────────────────────────────────────────────────

rc=0
installed=$(detect_chrome_binary) || rc=$?
if [ $rc -ne 0 ]; then
    log_fail "Install completed but no runnable browser was detected."
    exit 1
fi
log_ok "Browser: ${installed} ($("${installed}" --version 2>/dev/null || echo 'version unknown'))"

for leftover in /etc/apt/sources.list.d/google-chrome.list /etc/cron.daily/google-chrome; do
    if [ -e "$leftover" ]; then
        log_fail "Phone-home artifact still present: ${leftover}"
        exit 1
    fi
done
log_ok "No Google apt source or update pinger left behind"

log_info "Containers usually need a sandbox opt-out: export VESPASIAN_NO_SANDBOX=true"
