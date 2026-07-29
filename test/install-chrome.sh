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
# go-rod's launcher.LookPath() resolves a binary that cannot start. Ubuntu's
# own `chromium` / `chromium-browser` packages are not an alternative: on noble
# both are transitional stubs that Pre-Depend on snapd. The fix is a
# .deb-packaged browser, which needs no snapd.
#
# How the package is trusted: Google's apt repository is added TEMPORARILY,
# with its signing key pinned by primary-key fingerprint (GOOGLE_KEY_FPR). apt
# then verifies the chain — Release signature -> Packages digest -> .deb digest
# — before dpkg runs the package's maintainer scripts as root. Downloading the
# .deb directly instead would mean TLS was the ONLY control, with no signature
# check at all: `apt-get install ./local.deb` does not authenticate a local
# file argument. Pinning the fingerprint is what makes this meaningful; a key
# fetched over the same channel as the package, unpinned, would buy nothing
# against an attacker who controls that channel.
#
# Egress note: the repo and key are removed again once the install finishes, so
# nothing persists to phone home. The google-chrome-stable package also tries
# to install its own permanent apt source (/etc/apt/sources.list.d/google-chrome.list)
# and a daily update pinger (/etc/cron.daily/google-chrome); both are suppressed
# and then verified absent. Telemetry of the browser vespasian LAUNCHES is a
# separate, already-solved concern: crawls go through NewBrowserManager, which
# applies disableChromeTelemetry's flags (LAB-4999).
#
# Version policy: this tracks Chrome *stable* rather than pinning a version.
# For a test-only layer that is the right trade — a pinned version goes stale
# and eventually 404s — but it does mean the installed build is not reproducible
# from this script alone. The installed version is therefore logged on success
# so an image build record identifies exactly what landed.
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

# Google's Linux package signing key and the apt repo it signs. The fingerprint
# is the PRIMARY key's — Google rotates signing subkeys under it, so pinning the
# primary survives rotation while still rejecting a substituted key. If Google
# ever rolls the primary, this script fails loudly and the constant must be
# updated deliberately (that is the intended behaviour, not a bug).
GOOGLE_KEY_URL="https://dl.google.com/linux/linux_signing_key.pub"
GOOGLE_KEY_FPR="EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"
GOOGLE_APT_URL="https://dl.google.com/linux/chrome/deb/"

# Temporary apt wiring, removed by cleanup_apt_wiring on every exit path.
TMP_LIST="/etc/apt/sources.list.d/google-chrome-vespasian-temp.list"
TMP_KEYRING="/usr/share/keyrings/google-chrome-vespasian-temp.gpg"

# Artifacts the google-chrome-stable package drops that phone home.
PHONE_HOME_PATHS=(
    /etc/apt/sources.list.d/google-chrome.list
    /etc/cron.daily/google-chrome
)

# ──────────────────────────────────────────────────────────────
# Pure helpers (exercised by test/install-chrome-selftest.sh)
# ──────────────────────────────────────────────────────────────

# resolve_arch echoes the dpkg architecture when Google publishes a Chrome
# build for it, or returns 1. Bailing here beats an arch-mismatch apt error
# several steps later.
resolve_arch() {
    local arch
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64|arm64)
            printf '%s\n' "$arch"
            return 0
            ;;
    esac
    log_fail "No google-chrome-stable build for architecture '${arch}' (amd64 and arm64 only)."
    return 1
}

usage() {
    # Print the leading comment block, delimiter-driven: skip the shebang, emit
    # every consecutive `#` line, stop at the first line that is not a comment.
    # A hardcoded line range would silently truncate --help the moment the
    # header grew or shrank.
    awk 'NR==1 && /^#!/ { next }
         /^#/            { sub(/^# ?/, ""); print; next }
                         { exit }' "${BASH_SOURCE[0]}"
}

parse_args() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            --help)
                usage
                exit 0
                ;;
            *)
                # printf, not log_fail: $arg is caller-supplied and log_fail
                # runs `echo -e`, which would interpret \e sequences the caller
                # embedded and hand them control of the terminal.
                printf 'Unknown option: %s (try --help)\n' "$arg" >&2
                exit 1
                ;;
        esac
    done
}

# ──────────────────────────────────────────────────────────────
# Privilege
# ──────────────────────────────────────────────────────────────

# SUDO is the privilege prefix for every mutating command: empty when already
# root (the usual Dockerfile case), "sudo" otherwise.
resolve_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        return 0
    fi
    log_fail "Not running as root and sudo is unavailable — cannot install packages."
    return 1
}

require_apt() {
    if ! command -v apt-get >/dev/null 2>&1; then
        log_fail "install-chrome.sh supports Debian/Ubuntu (apt-get) only."
        log_info "On macOS install Google Chrome normally; on other distros use your package manager."
        return 1
    fi
}

# ──────────────────────────────────────────────────────────────
# Trusted apt wiring
# ──────────────────────────────────────────────────────────────

# Fetch Google's signing key, verify it against the pinned PRIMARY fingerprint,
# and install it as a dedicated keyring. Refuses to proceed on any mismatch —
# an unpinned key would make the whole signature check ornamental.
install_pinned_key() {
    local tmp_key="$1/google.pub" tmp_gpg="$1/google.gpg" fprs
    # --proto/--proto-redir '=https': a downgrade redirect is a hard failure,
    # never a silent cleartext fetch. --max-time bounds the whole transfer so a
    # tarpitted mirror surfaces as an error instead of a wedged image build.
    if ! curl -fsSL --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 120 --retry 3 --retry-delay 2 \
        -o "$tmp_key" "$GOOGLE_KEY_URL"; then
        log_fail "Could not fetch Google's signing key: ${GOOGLE_KEY_URL}"
        return 1
    fi

    if ! gpg --dearmor < "$tmp_key" > "$tmp_gpg" 2>/dev/null; then
        log_fail "Fetched signing key is not a valid PGP key."
        return 1
    fi

    # Compare against the primary key's fingerprint only (the `pub` record);
    # subkey fingerprints rotate and are not the trust anchor.
    fprs=$(gpg --show-keys --with-colons --with-fingerprint "$tmp_key" 2>/dev/null \
        | awk -F: '$1=="pub"{want=1} $1=="fpr" && want{print $10; want=0}')
    if [ "$fprs" != "$GOOGLE_KEY_FPR" ]; then
        log_fail "Google signing key fingerprint mismatch — refusing to install."
        log_info "  expected: ${GOOGLE_KEY_FPR}"
        log_info "  got:      ${fprs:-<none>}"
        log_info "If Google rotated their primary key, update GOOGLE_KEY_FPR deliberately."
        return 1
    fi
    log_ok "Signing key matches pinned fingerprint ${GOOGLE_KEY_FPR}"

    $SUDO install -m 0644 "$tmp_gpg" "$TMP_KEYRING"
    printf 'deb [arch=%s signed-by=%s] %s stable main\n' "$ARCH" "$TMP_KEYRING" "$GOOGLE_APT_URL" \
        | $SUDO tee "$TMP_LIST" >/dev/null
}

# Remove the temporary repo + keyring. Registered as a trap so a failure
# between adding and installing cannot leave the source behind — that source
# persisting is exactly the phone-home the ticket is trying to prevent.
cleanup_apt_wiring() {
    $SUDO rm -f "$TMP_LIST" "$TMP_KEYRING"
}

# The package's postinst re-adds Google's permanent apt source unless
# repo_add_once is already false. Pre-seeding is cleaner than adding-then-
# deleting: the source is never created in the first place.
suppress_permanent_repo() {
    # Overridable purely so install-chrome-selftest.sh can exercise the symlink
    # guard and the rewrite branches against a fixture path. Production callers
    # never set it.
    local f="${CHROME_DEFAULTS_FILE:-/etc/default/google-chrome}"
    # An unexpected symlink here would redirect a root-privileged write to a
    # target of the planter's choosing; fail loudly rather than write through.
    #
    # Only this path is guarded: TMP_KEYRING and TMP_LIST live in
    # /usr/share/keyrings and /etc/apt/sources.list.d, which are root-owned and
    # root-writable only, so planting a symlink there already requires the
    # privilege the write would grant. /etc/default is the same in a stock
    # image — the guard is defence in depth for images that loosen it.
    if [ -L "$f" ]; then
        log_fail "${f} is a symlink — refusing to write through it."
        return 1
    fi
    # No -m on install -d: an existing /etc/default keeps whatever mode it has.
    $SUDO install -d "$(dirname "$f")"
    if [ ! -f "$f" ]; then
        printf 'repo_add_once=false\n' | $SUDO tee "$f" >/dev/null
    elif ! grep -q '^repo_add_once=' "$f" 2>/dev/null; then
        printf 'repo_add_once=false\n' | $SUDO tee -a "$f" >/dev/null
    else
        $SUDO sed -i 's/^repo_add_once=.*/repo_add_once=false/' "$f"
    fi
}

remove_phone_home() {
    $SUDO rm -f "${PHONE_HOME_PATHS[@]}"
}

# in_container reports whether this looks like a throwaway image, which is the
# only place it is safe to wipe the apt cache — doing that on a developer's own
# machine destroys whole-system apt index state they never consented to lose.
# Both probes are overridable so the selftest can drive each arm.
in_container() {
    [ -f "${DOCKERENV_PATH:-/.dockerenv}" ] || [ -n "${REMOTE_CONTAINERS:-}" ]
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    log_header "Installing Chrome for vespasian tests"

    # Idempotency: a browser that actually RUNS (not merely a snap stub that
    # resolves) means there is nothing to do.
    local existing rc=0
    existing=$(detect_chrome_binary) || rc=$?
    if [ $rc -eq 0 ]; then
        log_ok "Runnable browser already present: ${existing}"
        exit 0
    fi
    if [ $rc -eq 2 ]; then
        log_info "Found ${existing} but it is not runnable (snap stub?) — installing a real Chrome."
    fi

    require_apt
    resolve_sudo
    ARCH="$(resolve_arch)"
    log_info "Architecture: ${ARCH}"

    local tmpdir
    tmpdir="$(mktemp -d)"
    # Single trap covers both the scratch dir and the apt wiring, so an abort
    # anywhere below still tears the temporary repo down.
    # shellcheck disable=SC2064  # tmpdir is expanded now on purpose
    trap "rm -rf '${tmpdir}'; cleanup_apt_wiring" EXIT

    # Trust check FIRST: install_pinned_key aborts on a fingerprint mismatch, so
    # ordering it ahead of suppress_permanent_repo means a run that never earns
    # trust also never mutates /etc/default. Suppression is only required before
    # `apt-get install` (it is the package postinst that re-adds the repo), so
    # nothing is lost by deferring it.
    install_pinned_key "$tmpdir"
    suppress_permanent_repo

    log_info "Installing google-chrome-stable via apt (signature-verified)"
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends google-chrome-stable

    cleanup_apt_wiring
    remove_phone_home

    if in_container; then
        $SUDO rm -rf /var/lib/apt/lists/*
    else
        log_info "Not in a container — leaving /var/lib/apt/lists intact."
    fi

    verify_install
}

verify_install() {
    local installed rc=0
    installed=$(detect_chrome_binary) || rc=$?
    if [ $rc -ne 0 ]; then
        log_fail "Install completed but no runnable browser was detected."
        exit 1
    fi
    # Log the exact version: this script tracks stable rather than pinning, so
    # the version string is the only record of what actually landed.
    log_ok "Browser: ${installed} ($("${installed}" --version 2>/dev/null || echo 'version unknown'))"

    local leftover
    for leftover in "${PHONE_HOME_PATHS[@]}" "$TMP_LIST" "$TMP_KEYRING"; do
        if [ -e "$leftover" ]; then
            log_fail "Phone-home / temporary artifact still present: ${leftover}"
            exit 1
        fi
    done
    log_ok "No Google apt source, keyring, or update pinger left behind"

    log_info "Containers usually need a sandbox opt-out: export VESPASIAN_NO_SANDBOX=true"
}

# Run main only when executed directly. When sourced (by the selftest) the
# functions are defined but main does not run — same guard setup-live-targets.sh
# uses.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
