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
# Egress note: the repo and key THIS SCRIPT adds are removed again once the
# install finishes, so nothing this script itself wired up persists to phone
# home. The google-chrome-stable package also tries to install its own
# permanent apt source (/etc/apt/sources.list.d/google-chrome.list) and a daily
# update pinger (/etc/cron.daily/google-chrome); this script always pre-seeds
# the package's own opt-out so neither is ever created. Inside a throwaway
# image (in_container()) it goes further and also removes + verifies absent
# whatever the package planted anyway — that is AC4. Outside a container,
# removing artifacts the package owns is not this script's call: they are the
# normal update channel for a browser the operator is going to keep using, so
# this script leaves them alone there once suppression has already stopped
# them being created. Telemetry of the browser vespasian LAUNCHES is a
# separate, already-solved concern: crawls go through NewBrowserManager, which
# applies disableChromeTelemetry's flags (LAB-4999).
#
# Version policy: this tracks Chrome *stable* rather than pinning a version.
# For a test-only layer that is the right trade — a pinned version goes stale
# and eventually 404s — but it does mean the installed build is not reproducible
# from this script alone. The installed version is therefore logged on success
# so an image build record identifies exactly what landed.
#
# Idempotent: exits 0 when a runnable browser is already present, after
# clearing this script's own leftover apt wiring (and, in a container, the
# package's phone-home artifacts) — no new installation is attempted. Safe to
# call from a Dockerfile RUN, a devcontainer postCreateCommand, or by hand.
#
# Trust assumption for the test seam: VESPASIAN_TEST_ROOT exists only so
# install-chrome-selftest.sh can reach the symlink guard, the container gate, and
# the phone-home removal/verification chain unprivileged. It is read from the
# environment and feeds root-privileged operations, so it is an input from an
# ALREADY-PRIVILEGED caller — either the script runs as root (whoever set it was
# already root), or it runs unprivileged and the caller must already hold the
# sudo rights it uses. Default sudoers (`Defaults env_reset`) drops it. This
# script must therefore never be exposed through a narrowly-scoped sudoers grant
# that also permits environment passing (SETENV, `sudo -E`, or an env_keep
# entry): that would be the one configuration in which the seam could steer a
# privileged write. Nothing in this repo creates or recommends such a grant.
#
# The name is deliberately namespaced. The earlier CHROME_DEFAULTS_FILE /
# DOCKERENV_PATH pair was generic enough to be set by unrelated ambient tooling
# in a devcontainer or image build, which would have pointed a privileged write
# at an unintended path or run the apt-cache wipe on a non-container host.
#
# What the validation below does and does NOT close, stated so future readers
# stop re-deriving it. CLOSED: a relative path, characters outside
# [A-Za-z0-9._/-], any ".." component, a root that does not exist, and any
# spelling that RESOLVES to the filesystem root ("/", "//", "/.", a root that is
# itself a symlink to /). ACCEPTED RESIDUALS, all of which require the caller to
# already hold the privilege the write would grant: a symlink planted INSIDE the
# root after validation, a bind mount at the root, and a directory swapped
# between canonicalization and the privileged write (TOCTOU). Those are not
# defended against, because the seam's whole trust model is that its caller is
# already privileged — see the paragraph above.
#
# Usage:
#   ./test/install-chrome.sh            # install if needed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared colors, logging, and the browser probe (CHROME_CANDIDATES,
# chrome_runnable, detect_chrome_binary) that setup-live-targets.sh's preflight
# uses, so "already installed" here means exactly what "prerequisite satisfied"
# means there.
#
# Convention: log_fail() writes to stdout by default (see common.sh), so every
# call site in this file redirects it to stderr with `>&2` — diagnostics belong
# on stderr regardless of whether the caller happens to be a command
# substitution that would otherwise swallow them (resolve_arch's is the one
# case where that is load-bearing rather than merely stylistic).
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

# VESPASIAN_TEST_ROOT reroots every absolute system path this script reads or
# writes. It exists so install-chrome-selftest.sh can drive the privileged
# branches — the defaults-file rewrite, the phone-home removal, and the
# post-install verification — against fixtures, unprivileged. Production callers
# never set it, and it replaces the earlier CHROME_DEFAULTS_FILE / DOCKERENV_PATH
# pair: one namespaced seam instead of two un-namespaced ones that could collide
# with ambient tooling in a devcontainer.
#
# It feeds root-privileged writes, so it is an input from an ALREADY-PRIVILEGED
# caller — see the trust note in the header block.
TEST_ROOT="${VESPASIAN_TEST_ROOT:-}"

# Enforce the documented assumption instead of only stating it. TEST_ROOT is
# prefixed onto paths that are later written with sudo, so a value containing
# whitespace, a quote, or a glob character would reshape those paths. Production
# callers leave it empty; a test caller passes a mktemp -d path, which always
# satisfies this. Fail closed rather than sanitize: silently rewriting a path
# that feeds a privileged write is worse than refusing it.
#
# The charset check alone was NOT enough, and the gap is worth stating because
# it looks closed: `.` and `/` are both legal characters, so `/tmp/x/../..`
# passed every test above and then resolved to `/` — which would prefix nothing
# at all and point TMP_LIST, the defaults file, and the phone-home removal at
# the REAL system paths. A test root that IS a symlink reaches the same place
# (canonicalization resolves it); a symlink planted inside the root afterwards
# is an accepted residual — see the trust note above.
#
# Two later holes of the same shape are closed here too, because "resolves to
# the real root" has more than one spelling and more than one route:
#   * `//` is NOT `/`. POSIX leaves a leading double slash implementation-
#     defined and bash's `pwd -P` preserves it, so a `= "/"` comparison let
#     `//` through and every derived path became `//etc/...` — the real system.
#     Both spellings are refused.
#   * A root that does not EXIST skipped canonicalization entirely, so
#     `<symlink-to-/>/nope` was never resolved and the guard never ran. The
#     root must therefore exist; requiring that removes the branch rather than
#     trying to resolve a path that is not there.
case "$TEST_ROOT" in
    "") ;;                                  # unset — the production case
    /*) case "$TEST_ROOT" in
            *[!A-Za-z0-9._/-]*)
                log_fail "VESPASIAN_TEST_ROOT contains characters outside [A-Za-z0-9._/-]: ${TEST_ROOT}" >&2
                exit 1
                ;;
        esac
        # No `..` component: the cheap string-level half, and the only half that
        # can speak about a path before it is resolved.
        case "/${TEST_ROOT}/" in
            */../*)
                log_fail "VESPASIAN_TEST_ROOT must not contain a \"..\" component: ${TEST_ROOT}" >&2
                exit 1
                ;;
        esac
        # Must exist, so canonicalization always runs. A fixture root is created
        # by the caller before use, so this costs a real caller nothing.
        if [ ! -d "$TEST_ROOT" ]; then
            log_fail "VESPASIAN_TEST_ROOT must be an existing directory: ${TEST_ROOT}" >&2
            exit 1
        fi
        _resolved=$(cd -P -- "$TEST_ROOT" 2>/dev/null && pwd -P) || _resolved=""
        if [ -z "$_resolved" ]; then
            log_fail "VESPASIAN_TEST_ROOT could not be resolved: ${TEST_ROOT}" >&2
            exit 1
        fi
        case "$_resolved" in
            /|//)
                log_fail "VESPASIAN_TEST_ROOT resolves to the filesystem root (no confinement): ${TEST_ROOT}" >&2
                exit 1
                ;;
        esac
        TEST_ROOT="$_resolved"
        unset _resolved
        ;;
    *)  log_fail "VESPASIAN_TEST_ROOT must be an absolute path: ${TEST_ROOT}" >&2
        exit 1
        ;;
esac

# ARCH is set by main() from resolve_arch and read by install_pinned_key when it
# writes the apt source line. It is a cross-function global rather than a
# parameter because it is derived once per run and never varies after; declared
# here so the coupling is visible at the top of the file instead of only at the
# two sites that use it.
ARCH=""

# Temporary apt wiring, removed by cleanup_apt_wiring on every exit path.
TMP_LIST="${TEST_ROOT}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list"
TMP_KEYRING="${TEST_ROOT}/usr/share/keyrings/google-chrome-vespasian-temp.gpg"
# Pins the package NAME to the origin this script vouched for. Without this,
# `apt-get install google-chrome-stable` resolves the name across every
# configured source — a leftover permanent google-chrome.sources from an
# earlier install, or any other third-party repo offering the same name —
# and the fingerprint pin above never gates the artifact dpkg actually
# unpacks. Pin-Priority 1001 outranks even an already-installed version, so
# a stale local package cannot win over the origin this run trusts either.
TMP_PREF="${TEST_ROOT}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref"

# Mutual exclusion for the whole apt-wiring lifecycle (SEC-BE-007). TMP_LIST,
# TMP_KEYRING and TMP_PREF above are FIXED filenames, not per-run, so two
# concurrent invocations of this script — a postCreateCommand racing a
# developer's manual run, or two parallel provisioning steps, both patterns
# this script's header advertises as safe — would otherwise let one run's
# "self-healing" cleanup (see cleanup_apt_wiring's call sites in main()) strip
# the OTHER run's live apt wiring out from under it, including the origin pin
# between its `apt-get update` and `apt-get install`. Acquired in main(),
# before the idempotency check's own cleanup call.
LOCK_FILE="${TEST_ROOT}/tmp/vespasian-install-chrome.lock"

# The package's own opt-out file, and a durable record of what version landed.
CHROME_DEFAULTS_FILE="${TEST_ROOT}/etc/default/google-chrome"
CHROME_VERSION_RECORD="${TEST_ROOT}/usr/share/vespasian/chrome-version"

# Artifacts the google-chrome-stable package drops that phone home.
#
# Both apt source spellings are listed. The current package (150.x) writes the
# deb822 `google-chrome.sources` — its postinst sets
# SOURCES_FILE="$APT_SOURCESDIR/google-chrome.sources" and treats
# `google-chrome.list` purely as a legacy path to migrate away from. Removing
# only the legacy name meant verify_install could report "no Google apt source"
# while the file the package actually writes sat untouched. The package's own
# keyring is listed for the same reason: verify_install's message claims no
# keyring is left behind, so it has to actually check for one.
PHONE_HOME_PATHS=(
    "${TEST_ROOT}/etc/apt/sources.list.d/google-chrome.list"
    "${TEST_ROOT}/etc/apt/sources.list.d/google-chrome.sources"
    "${TEST_ROOT}/etc/cron.daily/google-chrome"
    "${TEST_ROOT}/usr/share/keyrings/google-chrome.gpg"
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
    # >&2 is load-bearing: the caller is `ARCH="$(resolve_arch)"`, so anything
    # this writes to stdout is swallowed by the command substitution and the
    # operator sees an empty terminal before set -e aborts. Diagnostics have to
    # bypass the capture to be diagnostics at all.
    log_fail "No google-chrome-stable build for architecture '${arch}' (amd64 and arm64 only)." >&2
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
                # printf, not log_fail, keeps this usage error independent of the
                # log helpers entirely. (log_fail is printf-based now and would
                # also be safe; it was `echo -e` when this branch was written,
                # which would have interpreted \e sequences in caller-supplied
                # $arg and handed them control of the terminal.)
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
    log_fail "Not running as root and sudo is unavailable — cannot install packages." >&2
    return 1
}

require_apt() {
    if ! command -v apt-get >/dev/null 2>&1; then
        log_fail "install-chrome.sh supports Debian/Ubuntu (apt-get) only." >&2
        log_info "On macOS install Google Chrome normally; on other distros use your package manager."
        return 1
    fi
}

# Fail on a missing curl/gpg with a message that names the missing package.
# Without this the absence of gnupg surfaced from `gpg --dearmor` as "Fetched
# signing key is not a valid PGP key" — an accusation that Google's key is
# forged, whose tempting remedy is to bypass the verification. Wrong diagnosis
# in the most dangerous possible direction.
require_tools() {
    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v gpg  >/dev/null 2>&1 || missing+=("gnupg")
    if [ ${#missing[@]} -gt 0 ]; then
        log_fail "Missing required tool(s): ${missing[*]}" >&2
        log_info "Install them first: apt-get install -y ${missing[*]}"
        return 1
    fi
}

# ──────────────────────────────────────────────────────────────
# Trusted apt wiring
# ──────────────────────────────────────────────────────────────

# Fetch Google's signing key, verify it against the pinned PRIMARY fingerprint,
# and install it as a dedicated keyring. Refuses to proceed on any mismatch —
# an unpinned key would make the whole signature check ornamental.
#
# Intentionally longer than the ~60-line guideline, like main(): fetch, import,
# fingerprint-check, export, and the three privileged writes (keyring, source
# list, origin pin) are one linear trust chain where each step's failure must
# abort before the next runs. Splitting fetch+verify from the writes would
# still leave a >60-line write half (three staged-then-install calls, each with
# its own rationale comment) and would scatter that ordering across two
# functions instead of removing it from either.
install_pinned_key() {
    local tmp_key="$1/google.pub" tmp_gpg="$1/google.gpg" tmp_ring="$1/google.kbx" tmp_list="$1/google-chrome.list"
    local gpg_err="$1/gpg.err" gpg_home="$1/gnupg" fprs
    # A private homedir for every gpg call below. Without it gpg falls back to
    # the caller's ~/.gnupg — creating and locking a trustdb in root's home on
    # first use, which both mutates state this script has no business touching
    # and makes the outcome depend on whether that directory already existed.
    # Separate chmod, not `mkdir -m`: with -p the mode applies only to the
    # deepest directory created (SC2174), which would leave an intermediate at
    # the default umask.
    mkdir -p "$gpg_home"
    chmod 700 "$gpg_home"
    # --proto/--proto-redir '=https': a downgrade redirect is a hard failure,
    # never a silent cleartext fetch. --max-time bounds the whole transfer so a
    # tarpitted mirror surfaces as an error instead of a wedged image build.
    if ! curl -fsSL --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 120 --retry 3 --retry-delay 2 \
        -o "$tmp_key" "$GOOGLE_KEY_URL"; then
        log_fail "Could not fetch Google's signing key: ${GOOGLE_KEY_URL}" >&2
        return 1
    fi

    # Import into a scratch keyring rather than dearmoring in place. gpg's own
    # stderr is kept and echoed on failure: discarding it is what turned a
    # missing gnupg into a bogus "the key is forged" report.
    if ! gpg --homedir "$gpg_home" --no-default-keyring --keyring "$tmp_ring" \
        --batch --quiet --import "$tmp_key" 2>"$gpg_err"; then
        log_fail "Fetched signing key is not a valid PGP key." >&2
        [ -s "$gpg_err" ] && log_info "  gpg: $(tr '\n' ' ' < "$gpg_err")"
        return 1
    fi

    # Compare against the primary key's fingerprint only (the `pub` record);
    # subkey fingerprints rotate and are not the trust anchor.
    #
    # MEMBERSHIP, not equality: Google documents publishing its active and
    # obsolete primary keys in one bundle, and a key transition would legitimately
    # ship two `pub` records. Equality would refuse that outright. Membership is
    # only safe because of the export below — we hand apt exactly the pinned key,
    # so extra keys in the bundle are inspected and then discarded rather than
    # trusted. Widening this check without keeping that export would silently
    # extend apt's trust to whatever else the endpoint returned.
    # stderr is captured, not discarded, for the same reason the import above
    # keeps it: a gpg that fails to RUN produces no fingerprints, which is
    # indistinguishable from a key whose fingerprints do not match unless the
    # tool's own complaint survives. Reporting a broken toolchain as "the key is
    # substituted" sends the reader hunting a supply-chain attack that is not there.
    fprs=$(gpg --homedir "$gpg_home" --no-default-keyring --keyring "$tmp_ring" \
        --with-colons --fingerprint 2>"$gpg_err" \
        | awk -F: '$1=="pub"{want=1} $1=="fpr" && want{print $10; want=0}')
    if [ -z "$fprs" ]; then
        log_fail "Could not read any key fingerprint from the fetched key — refusing to install." >&2
        [ -s "$gpg_err" ] && log_info "  gpg: $(tr '\n' ' ' < "$gpg_err")"
        return 1
    fi
    if ! printf '%s\n' "$fprs" | grep -qxF -- "$GOOGLE_KEY_FPR"; then
        log_fail "Google signing key fingerprint mismatch — refusing to install." >&2
        log_info "  expected: ${GOOGLE_KEY_FPR}"
        log_info "  got:      ${fprs}"
        log_info "If Google rotated their primary key, update GOOGLE_KEY_FPR deliberately."
        return 1
    fi

    # Export ONLY the pinned fingerprint. Installing the whole fetched blob would
    # tell apt to trust every key the endpoint chose to return.
    if ! gpg --homedir "$gpg_home" --no-default-keyring --keyring "$tmp_ring" \
        --batch --yes --export "$GOOGLE_KEY_FPR" > "$tmp_gpg" 2>"$gpg_err" || [ ! -s "$tmp_gpg" ]; then
        log_fail "Could not export the pinned key ${GOOGLE_KEY_FPR} — refusing to install." >&2
        [ -s "$gpg_err" ] && log_info "  gpg: $(tr '\n' ' ' < "$gpg_err")"
        return 1
    fi
    log_ok "Signing key matches pinned fingerprint ${GOOGLE_KEY_FPR}"

    $SUDO install -d -- "$(dirname -- "$TMP_KEYRING")" "$(dirname -- "$TMP_LIST")"
    $SUDO install -m 0644 -- "$tmp_gpg" "$TMP_KEYRING"
    # signed-by= is the whole point: it scopes verification of this source to the
    # fingerprint-pinned keyring. Without it apt would fall back to any key in
    # the system-wide trusted set and the pin would be ornamental.
    #
    # Staged then `install -m 0644`, matching the keyring write immediately
    # above: the mode is stated at the call site instead of being left to the
    # caller's umask, and the file lands atomically. `| $SUDO tee` did neither
    # — under `umask 0` (a Dockerfile RUN commonly runs with one) it would have
    # landed this apt source world-writable in /etc/apt/sources.list.d/,
    # letting any local user repoint it — swap the URL, or `signed-by=` for
    # `[trusted=yes]` — before the apt-get install a few lines down runs it as
    # root. The fingerprint pin does not help there: the attacker rewrites the
    # very line that names the pinned keyring.
    printf 'deb [arch=%s signed-by=%s] %s stable main\n' "$ARCH" "$TMP_KEYRING" "$GOOGLE_APT_URL" \
        > "$tmp_list"
    $SUDO install -m 0644 -- "$tmp_list" "$TMP_LIST"

    # Constrain resolution of the package NAME to the origin just pinned above
    # (see TMP_PREF's declaration) — same staged-then-install pattern as the
    # keyring and the source line.
    local tmp_pref="$1/google-chrome.pref"
    printf 'Package: google-chrome-stable\nPin: origin dl.google.com\nPin-Priority: 1001\n' \
        > "$tmp_pref"
    $SUDO install -d -- "$(dirname -- "$TMP_PREF")"
    $SUDO install -m 0644 -- "$tmp_pref" "$TMP_PREF"
}

# Remove the temporary repo + keyring + pin. Registered as a trap so a failure
# between adding and installing cannot leave the source behind — that source
# persisting is exactly the phone-home the ticket is trying to prevent.
cleanup_apt_wiring() {
    $SUDO rm -f -- "$TMP_LIST" "$TMP_KEYRING" "$TMP_PREF"
}

# Confirms apt actually satisfied google-chrome-stable from dl.google.com —
# the origin TMP_PREF pins — rather than from a stale permanent source left by
# an earlier install, or any other third-party repo already offering a
# package by this name. The fingerprint pin only gates a SOURCE's signature;
# it never gated which source apt picked for the package NAME, and the pin
# file alone raises that source's priority but does not prove apt actually
# used it. `apt-cache policy` is read-only, so this needs no $SUDO.
verify_apt_origin() {
    local policy candidate origin host
    # `|| policy=""` guards the assignment itself: under `set -euo pipefail`, a
    # failing apt-cache (a held dpkg lock, a corrupted cache) would otherwise
    # abort the script here with no diagnostic instead of reaching the
    # log_fail below.
    policy=$(apt-cache policy google-chrome-stable 2>/dev/null) || policy=""

    # Read the CANDIDATE's version, not the `***` marker (SEC-BE-002). `***`
    # flags ONLY the installed version, and a package that is not yet
    # installed has no `***` line in its version table at all — anchoring
    # there made this check refuse on every host BEFORE the package was
    # installed, which is exactly when the pre-install call site (main(),
    # before `apt-get install`) needs an answer. `Candidate:` is populated
    # whenever apt can resolve the package at all, installed or not, and
    # names the version dpkg is about to unpack (or already has).
    candidate=$(printf '%s\n' "$policy" | awk -F': ' '/^  Candidate:/ { print $2; exit }')
    if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
        log_fail "google-chrome-stable was satisfied from an unexpected origin: unknown (expected dl.google.com)" >&2
        return 1
    fi

    # Find the version-table entry for exactly that candidate version —
    # matched as a whole field, not a substring, so "1.0" cannot match
    # "1.0.1" — and read the first (highest-priority) source line beneath it,
    # which is the one apt actually uses. The entry is prefixed with `***`
    # only when it is also the installed version; matching $1 either with or
    # without that prefix is what makes this work whether or not the package
    # is installed yet.
    #
    # SEC-BE-001: `$1 == ver` alone cannot tell a VERSION row from a SOURCE
    # row. `apt-cache policy`'s version table alternates
    # `<version> <priority>` lines with `   <priority> <scheme>://...` lines
    # beneath them, and a bare-integer Debian version ("500", "1001" are both
    # syntactically valid) has the exact same shape as a priority column — so
    # `$1 == ver` could match a source line whose priority happens to equal
    # the candidate string, set `want` there, and read $2 of whatever line
    # follows (an unrelated block) as the "origin". `$NF ~ /^[0-9]+$/`
    # disambiguates structurally rather than by value: a version row's last
    # field is always its priority (digits); a source row's last field is
    # always "Packages" or a local path (e.g. /var/lib/dpkg/status) — never a
    # bare number — so this excludes every source row regardless of what its
    # priority column contains. The origin row itself is now validated the
    # same way before being trusted: `$1` must be the priority (digits) and
    # `$2` must look like `scheme://...`, so a following line of unexpected
    # shape yields an empty origin (fail-closed via the host check below)
    # rather than a garbage host taken on faith.
    origin=$(printf '%s\n' "$policy" | awk -v ver="$candidate" '
        want {
            if ($1 ~ /^[0-9]+$/ && $2 ~ /^[a-z][a-z0-9+.-]*:\/\//) { print $2 }
            exit
        }
        (($1 == "***" && $2 == ver) || $1 == ver) && $NF ~ /^[0-9]+$/ { want = 1 }
    ')
    # Anchor on the URL's host component, not a substring of the whole URL.
    # `grep -qF 'dl.google.com'` also matched a lookalike host such as
    # "dl.google.com.attacker.example" or "mirror.example/dl.google.com/...",
    # which defeats the whole point of this check.
    host="${origin#*://}"
    host="${host%%/*}"
    if [ "$host" != "dl.google.com" ]; then
        log_fail "google-chrome-stable was satisfied from an unexpected origin: ${origin:-unknown} (expected dl.google.com)" >&2
        return 1
    fi
}

# The package's postinst re-adds Google's permanent apt source unless
# repo_add_once is already false. Pre-seeding is cleaner than adding-then-
# deleting: the source is never created in the first place.
suppress_permanent_repo() {
    local f="$CHROME_DEFAULTS_FILE" staged
    # An unexpected symlink here would redirect a root-privileged write to a
    # target of the planter's choosing; fail loudly rather than write through.
    #
    # Only this path is guarded: TMP_KEYRING and TMP_LIST live in
    # /usr/share/keyrings and /etc/apt/sources.list.d, which are root-owned and
    # root-writable only, so planting a symlink there already requires the
    # privilege the write would grant. /etc/default is the same in a stock
    # image — the guard is defence in depth for images that loosen it.
    if [ -L "$f" ]; then
        log_fail "${f} is a symlink — refusing to write through it." >&2
        return 1
    fi
    # A hardlink is neither a symlink nor caught by [ -L ], and it defeats the
    # guard above from the READ side rather than the write side: the $SUDO
    # grep below reads "$f" as root and the unprivileged caller's own shell
    # redirects that output into $staged, so a hardlink planted at "$f" turns
    # this into an arbitrary root-readable-file read into a caller-owned file.
    # stat needs no $SUDO — nlink is available without read permission on the
    # file itself, same as the [ -L ] test above.
    if [ -e "$f" ]; then
        local nlink
        nlink=$(stat -c '%h' -- "$f" 2>/dev/null) || nlink=""
        if [ -n "$nlink" ] && [ "$nlink" -ne 1 ]; then
            log_fail "${f} has multiple hard links (${nlink}) — refusing to write through it." >&2
            return 1
        fi
    fi
    # No -m on install -d: an existing /etc/default keeps whatever mode it has.
    $SUDO install -d -- "$(dirname -- "$f")"

    # Render the whole desired file, then land it with a single `install`.
    #
    # This replaces a create/append/rewrite branch trio that had two problems.
    # The branch predicates ran WITHOUT $SUDO while the writes ran WITH it, so an
    # unreadable-but-existing file (root-owned 0600) sent an unprivileged caller
    # down the append arm and duplicated the key instead of rewriting it. And
    # `tee`/`sed -i` follow symlinks by name, leaving a check-then-write window
    # after the [ -L ] guard. One rewrite fixes both: the read that decides the
    # content runs at the same privilege as the write, and `install` unlinks the
    # destination before creating the new file rather than writing through a
    # symlink.
    staged="${SCRATCH_DIR}/google-chrome.defaults"
    : > "$staged"
    if $SUDO test -f "$f"; then
        # Drop any existing setting, keep everything else, then re-add ours.
        #
        # grep's exit status is three-valued and the difference matters: 0 = lines
        # kept, 1 = no lines matched (a file that held nothing but repo_add_once,
        # which is normal), 2 = an actual error such as an unreadable file. A bare
        # `|| true` would treat 2 exactly like 1 and silently write out a file
        # containing only our opt-out, discarding whatever settings we could not
        # read. Only 0 and 1 are acceptable here.
        # SEC-BE-002: re-verify the link guards INSIDE the privileged read.
        #
        # The [ -L ] and nlink checks above run in the caller's shell, minutes of
        # wall-clock and several privileged commands before this read. That is a
        # classic check-then-use gap: a planter who wins the race between the
        # guard and this line turns a root-privileged read of $f into an
        # arbitrary root-readable-file read, landing in $staged, which the
        # unprivileged caller owns. Re-checking here does not make the window
        # zero — nothing in shell can — but it collapses it from "the whole
        # guard-to-read span" to "inside one `sh -c`", and it means BOTH ends of
        # the window are guarded rather than just the entry.
        #
        # Exit codes are passed through deliberately: grep's 0/1/2 distinction is
        # load-bearing below (0 = lines kept, 1 = nothing matched, which is
        # normal, 2 = a real read error), so the guard uses 3 and 4 to stay out
        # of grep's range.
        local grep_rc=0
        $SUDO sh -c '
            f="$1"
            [ -L "$f" ] && exit 3
            [ "$(stat -c "%h" -- "$f" 2>/dev/null || echo 1)" -ne 1 ] && exit 4
            exec grep -v "^repo_add_once=" -- "$f"
        ' _ "$f" > "$staged" || grep_rc=$?
        case "$grep_rc" in
            0|1) ;;
            3)  log_fail "${f} became a symlink between the guard and the read — refusing to rewrite it." >&2
                return 1 ;;
            4)  log_fail "${f} gained a hard link between the guard and the read — refusing to rewrite it." >&2
                return 1 ;;
            *)  log_fail "Could not read ${f} (grep exit ${grep_rc}) — refusing to rewrite it." >&2
                return 1 ;;
        esac
    fi
    printf 'repo_add_once=false\n' >> "$staged"
    # A single `install`, not a stage-then-`mv`: install already unlinks the
    # destination before opening (verified above the symlink guard does not
    # get bypassed), so the two-step's atomicity is preserved without a second
    # privileged path — the earlier two-step left a root-owned
    # "${f}.vespasian-tmp" with no release if the `mv` step failed.
    $SUDO install -m 0644 -- "$staged" "$f"
}

remove_phone_home() {
    $SUDO rm -f -- "${PHONE_HOME_PATHS[@]}"
}

# in_container reports whether this looks like a throwaway image, which is the
# only place it is safe to wipe the apt cache, remove the package's phone-home
# artifacts (AC4), and skip auditing them — doing any of that on a developer's
# own machine destroys state they never consented to lose. Docker and VS Code
# Dev Containers were the only two runtimes probed; every other build path
# (Podman/Buildah, rootless `podman build`, kaniko/img, plain containerd/CRI-O/
# Kubernetes) answered false here, so an image built by any of THOSE shipped
# the exact standing egress AC4 exists to eliminate — silently, since
# verify_install shares this same predicate for its audit (see its call site).
# All four probes are reachable from the selftest: the two marker paths are
# rerooted by VESPASIAN_TEST_ROOT, and REMOTE_CONTAINERS / container are read
# from the environment.
in_container() {
    [ -f "${TEST_ROOT}/.dockerenv" ] && return 0
    [ -f "${TEST_ROOT}/run/.containerenv" ] && return 0
    [ -n "${REMOTE_CONTAINERS:-}" ] && return 0
    # $container is validated against known runtime names (SEC-BE-004), not
    # accepted as any non-empty value: it is a bare, lowercase,
    # un-namespaced systemd convention -- far more collidable than the two
    # marker paths above, and unlike VESPASIAN_TEST_ROOT it is read straight
    # from the ambient environment with no validation at all. An unrelated
    # tool exporting a same-named variable (a Makefile, a CI shim) would
    # otherwise win the destructive branch (remove_phone_home, the apt-cache
    # wipe) on a developer's own machine.
    case "${container:-}" in
        docker | podman | lxc | lxc-libvirt | systemd-nspawn | rkt | oci | \
        buildah | kaniko | containerd | crio | pouch | proot)
            return 0
            ;;
    esac
    return 1
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

# SCRATCH_DIR is a script-level global, not a local in main, for two reasons:
# suppress_permanent_repo stages its rewrite there, and the EXIT trap needs the
# path still in scope when it fires.
SCRATCH_DIR=""

# Set to 1 immediately before the apt install runs. It is what lets cleanup_all
# distinguish "this run created the package's phone-home artifacts" from "they
# were already on the machine", so the trap removes only what this run caused.
INSTALL_ATTEMPTED=0

# Set to 1 once apt-get install has actually returned success (i.e. main() is
# past the point set -e would have aborted it). This is what lets cleanup_all
# tell apart "the install finished and main() itself already made the
# container-aware call on whether to remove the phone-home artifacts" from
# "the install died before main() ever reached that call". The trap must
# handle only the second case: re-deciding on the first would run on every
# successful exit and silently undo main()'s choice to leave a developer's
# machine alone.
INSTALL_SUCCEEDED=0

# Set to 1 only once flock has actually granted THIS run exclusive ownership
# of the shared apt-wiring lifecycle (SEC-BE-008) — see the lock acquisition
# in main() for where. A run that never held the lock (the 300s timeout
# branch, or the flock-absent degrade) cannot tell its OWN temporary wiring
# apart from a CONCURRENT run's, so cleanup_all must not blindly tear either
# down in that case: doing so on the timeout path was the exact race the lock
# exists to prevent, reopened on the lock's own failure path.
LOCK_HELD=0

cleanup_all() {
    # Failure-tolerant end to end, via `|| true` on every step, and ordered so
    # the security-relevant removal runs FIRST. This handler executes under
    # the script's own `set -euo pipefail` — errexit is NOT suspended inside a
    # trap — so an earlier step failing (an expired sudo credential cache
    # between the last privileged command and the trap firing; `rm -rf` on a
    # read-only /tmp mount or an immutable file) used to abort the whole
    # handler before it ever reached remove_phone_home below, leaving a
    # permanently trusted Google apt source and a root-run daily cron pinger
    # on the host — exactly the standing egress this script exists to remove
    # on its failure paths. `|| true` is what stops one step's failure from
    # skipping the rest; the reorder is what stops it from skipping the most
    # security-relevant one specifically.
    #
    # AC4 on the FAILURE path too: an install that died after dpkg ran the
    # package's postinst — the exact moment the permanent Google source and the
    # daily pinger appear — left both behind, so a failed run was the one case
    # that ADDED standing egress. remove_phone_home is an rm -f of fixed paths,
    # so it is idempotent and safe to reach twice.
    #
    # Gated on in_container() too (SEC-BE-006): a run that died mid-install
    # never reached main()'s own container-aware removal below, so this is the
    # only place that decision gets made for a failed run — but "a failed run
    # leaves no working Chrome whose update channel is worth preserving" is
    # only true INSIDE a container. Outside one, `apt-get install` can already
    # have succeeded (dpkg's postinst plants the phone-home artifacts during
    # apt-get, before verify_apt_origin or anything after it ever runs), so an
    # abort between those two points would otherwise strip a WORKING, just-
    # installed Chrome's update channel on a developer's own machine — the
    # same thing the in_container() gate already prevents on every other call
    # site in this file. INSTALL_SUCCEEDED is what keeps this from also firing
    # on every SUCCESSFUL exit: main() already made the real, container-aware
    # decision there, and re-deciding here would silently remove the
    # artifacts main() had just chosen to leave alone outside a container.
    #
    # Guarded on INSTALL_ATTEMPTED too, rather than run unconditionally: without
    # that, this trap would fire on the browser-already-present early exit and
    # delete a pre-existing Chrome's update channel on a developer's machine —
    # undoing the in_container check on that path by the back door.
    #
    # Guarded on LOCK_HELD too (SEC-BE-008): TMP_LIST/TMP_KEYRING/TMP_PREF and
    # the phone-home paths are FIXED filenames shared by every run, and this
    # trap fires on the lock-timeout `exit 1` too — at which point THIS run
    # never held the lock and cannot tell its own wiring apart from a
    # concurrent run's. Tearing either down unconditionally there strips the
    # OTHER run's live apt source, pinned keyring and origin pin between its
    # `apt-get update` and `apt-get install`, which is the exact race the lock
    # exists to prevent, reopened on the lock's own failure path.
    #
    # This gate is sound only because flock is now REQUIRED (SEC-BE-003): with
    # the old degrade path, LOCK_HELD also stayed 0 on a host without flock —
    # while that run still wrote the wiring and still ran apt-get install — so
    # the gate silently disabled the AC4 teardown on exactly the hosts that
    # needed it. main() now refuses to run without flock, and the lock is taken
    # above every write site, so LOCK_HELD=0 means precisely "never acquired,
    # therefore never wrote anything to clean up".
    if [ "$LOCK_HELD" -eq 1 ]; then
        if [ "$INSTALL_ATTEMPTED" -eq 1 ] && [ "$INSTALL_SUCCEEDED" -ne 1 ]; then
            if in_container; then
                # log_warn, not a bare `|| true` (SEC-BE-005): the tolerance
                # itself must stay (an expired sudo credential cache, a
                # read-only mount, or an immutable attribute must not abort
                # the rest of this handler under errexit), but a removal that
                # fails here leaves a permanently trusted Google apt source
                # and a root-run daily cron pinger on the host with nothing
                # said about it — the same state verify_install treats as
                # fatal on the success path. log_warn always itself succeeds
                # (a printf), so the tolerance is unchanged; only the silence
                # is fixed.
                remove_phone_home || log_warn "Could not remove all google-chrome phone-home artifacts — a Google apt source, keyring, or update pinger may remain. Remove ${PHONE_HOME_PATHS[*]} by hand."
            else
                log_warn "Failed install left the google-chrome apt source and updater in place (not a container — see SEC-BE-006)."
            fi
        fi
        cleanup_apt_wiring || log_warn "Could not remove this run's temporary apt wiring — ${TMP_LIST}, ${TMP_KEYRING}, and/or ${TMP_PREF} may remain. Remove them by hand."
    fi
    if [ -n "$SCRATCH_DIR" ]; then
        rm -rf -- "$SCRATCH_DIR" || true
    fi
    return 0
}

# Pipeline orchestrator: parse args → idempotency check (+ its own AC4 cleanup)
# → prereqs → trust setup → install → verify. Intentionally longer than the
# ~60-line guideline: each stage is a distinct sequential step that delegates
# to a helper, and the two script-level state flags (INSTALL_ATTEMPTED,
# INSTALL_SUCCEEDED) that the EXIT trap reads have to be set at exact points in
# this one sequence — splitting it would scatter that ordering across
# functions rather than removing it.
main() {
    parse_args "$@"

    log_header "Installing Chrome for vespasian tests"

    # NOTE: require_tools is deliberately NOT called here. curl and gpg are
    # needed only by the install path, and gating the idempotency check on them
    # made a host that already HAS a runnable browser fail for want of a tool it
    # was never going to use. It is called on the install path instead, below.
    resolve_sudo

    # The scratch dir and its teardown are set up BEFORE the idempotency check,
    # because that path now also removes phone-home artifacts and so needs both.
    SCRATCH_DIR="$(mktemp -d)"
    # Single-quoted trap bodies: they are re-parsed as commands when the trap
    # fires, so interpolating the path here would let a quote in $TMPDIR (which
    # mktemp honours) break out into the trap body. Expanding $SCRATCH_DIR at
    # fire time instead removes that surface entirely.
    #
    # INT and TERM are handled as well as EXIT, because an interrupted run that
    # had already written the temporary apt source would otherwise leave a live,
    # trusted Google source on the host — exactly the persistent egress this
    # script exists to avoid.
    #
    # They `exit` rather than calling cleanup_all directly, and that is the whole
    # point: a bash signal handler RETURNS TO THE INTERRUPTED CODE when it
    # finishes. `trap 'cleanup_all' EXIT INT TERM` therefore tore the apt wiring
    # down and then carried straight on into `apt-get install` with its
    # repository already deleted, finally exiting 0 as though nothing had
    # happened. Exiting from the handler routes through the EXIT trap, so
    # cleanup_all runs exactly once and the status reports the signal (130/143
    # per the shell convention of 128+signo).
    trap 'cleanup_all' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # Acquire the install lock before the idempotency check's own cleanup call
    # below — see LOCK_FILE's declaration for why.
    #
    # flock is REQUIRED, not optional (SEC-BE-003). This used to degrade with a
    # warning when flock was absent, and that degrade path was the bug: LOCK_HELD
    # stayed 0 for the whole run while the run still wrote TMP_LIST/TMP_KEYRING/
    # TMP_PREF and still ran `apt-get install`, so cleanup_all — gated on
    # LOCK_HELD — did nothing, and any later failure stranded a permanently
    # trusted Google apt source and the package's root-run daily cron pinger.
    # A degrade that silently disables the AC4 teardown is worse than a refusal,
    # and no test covered it. flock ships in util-linux, which is Priority:
    # required on every Debian/Ubuntu base this script targets, so refusing
    # costs nothing real. Checked here rather than in require_tools because
    # require_tools runs on the install path, below the lock.
    if ! command -v flock >/dev/null 2>&1; then
        log_fail "flock not found — refusing to run without mutual exclusion (util-linux provides it)." >&2
        exit 1
    fi
    {
        mkdir -p -- "$(dirname -- "$LOCK_FILE")"
        # LOCK_FILE is a FIXED, world-guessable path under /tmp in production,
        # and this whole block runs as root whenever the script itself does (a
        # Dockerfile RUN, a devcontainer postCreateCommand, or install-chrome-e2e)
        # — the same guard suppress_permanent_repo applies to the defaults file,
        # for the same two reasons (SEC-BE-006). A symlink here would redirect
        # a root-owned open at a target of the planter's choosing; a hardlink
        # defeats the symlink guard from the read side the same way it does for
        # the defaults file. Checked AND recreated: the check gives a named,
        # fail-closed diagnostic instead of silently overwriting evidence of
        # the attempt, and `install` below unlinks-then-creates regardless, so
        # a plant that lands in the gap between the check and the install still
        # cannot be opened through.
        if [ -L "$LOCK_FILE" ]; then
            log_fail "${LOCK_FILE} is a symlink — refusing to lock through it." >&2
            exit 1
        fi
        if [ -e "$LOCK_FILE" ]; then
            local lock_nlink
            lock_nlink=$(stat -c '%h' -- "$LOCK_FILE" 2>/dev/null) || lock_nlink=""
            if [ -n "$lock_nlink" ] && [ "$lock_nlink" -ne 1 ]; then
                log_fail "${LOCK_FILE} has multiple hard links (${lock_nlink}) — refusing to lock through it." >&2
                exit 1
            fi
        fi
        # Create ONLY when absent (SEC-BE-004). The previous line here was an
        # unconditional `install -m 0644 -- /dev/null "$LOCK_FILE"`, and
        # `install(1)` unlinks the destination before creating it — so every run
        # got a FRESH INODE and `flock` serialised nothing. Reproduced directly:
        # two concurrent runs of that sequence both acquired the lock, on
        # different inodes. A lock is the one file that must NOT be replaced.
        #
        # Mode is still stated explicitly on the create so the caller's umask
        # cannot leave it world-writable under `umask 0`, and the open below is
        # read-only: flock needs no write access to the fd it locks, so a
        # root-created 0644 lock stays lockable by a later non-root run. (A
        # write-mode open would fail EACCES there, and a failed redirection on
        # `exec` kills a non-interactive shell before any diagnostic runs.)
        #
        # Residual, stated rather than hidden: two runs racing the very FIRST
        # creation can still each create-and-open before the other's flock, so
        # the very first run on a fresh host is not serialised. Every run after
        # it is, because the inode then persists. Closing that last gap needs an
        # atomic create-or-open primitive shell does not offer without either a
        # world-writable mode or a spin loop on mkdir, neither of which is worth
        # it here.
        if [ ! -e "$LOCK_FILE" ]; then
            $SUDO install -m 0644 -- /dev/null "$LOCK_FILE"
        fi
        exec {LOCK_FD}<"$LOCK_FILE"
        if ! flock -w 300 "$LOCK_FD"; then
            log_fail "Could not acquire the install lock (${LOCK_FILE}) within 300s — another run appears stuck." >&2
            exit 1
        fi
        # Only now does this run own the shared apt-wiring lifecycle
        # (SEC-BE-008) — see LOCK_HELD's declaration for why cleanup_all reads
        # this before touching TMP_LIST/TMP_KEYRING/TMP_PREF or the phone-home
        # paths. With the degrade path gone, LOCK_HELD=0 now means exactly one
        # thing: this run never acquired the lock, and therefore never wrote any
        # wiring (the lock is taken above every write site in main()). That is
        # what makes the gate in cleanup_all sound rather than over-broad.
        LOCK_HELD=1
    }

    # Idempotency: a browser that actually RUNS (not merely a snap stub that
    # resolves) means there is no install to do.
    local existing rc=0
    existing=$(detect_chrome_binary) || rc=$?
    if [ $rc -eq 0 ]; then
        log_ok "Runnable browser already present: ${existing}"
        # cleanup_apt_wiring is unconditional, and only ever removes artifacts
        # THIS script created. That makes the script self-healing: a previous run
        # killed between writing the temporary apt source and removing it (OOM,
        # cancelled CI job, aborted docker build) leaves a live Google source
        # behind, and this early exit is the path every later run takes.
        cleanup_apt_wiring

        # AC4 enforcement, but only where this script owns the machine.
        #
        # remove_phone_home deletes artifacts the google-chrome PACKAGE owns —
        # /etc/apt/sources.list.d/google-chrome.list and the daily updater — which
        # this script did not necessarily create. In a throwaway image that is the
        # point: the image must add no standing egress. On a developer's own
        # machine it is not ours to do. Someone who installed Chrome by hand and
        # then ran this script to check for a browser would have silently had
        # Chrome's update channel removed, a system-wide change they never asked
        # for and would not think to look for. Same reasoning as the apt-cache
        # wipe that in_container already guards.
        if in_container; then
            remove_phone_home
        else
            log_info "Not a container — leaving the google-chrome apt source and updater alone."
            log_info "  (run inside the devcontainer image, or remove them by hand, to enforce AC4)"
        fi
        verify_install
        exit 0
    fi
    if [ $rc -eq 2 ]; then
        log_info "Found ${existing} but it is not runnable (snap stub?) — installing a real Chrome."
    fi

    require_apt
    # curl and gpg are needed from here down and nowhere above, which is why the
    # check lives on the install path rather than at the top of main().
    require_tools
    # Explicit status check rather than a bare `ARCH="$(resolve_arch)"`: the
    # assignment form makes set -e abort with the reason still trapped inside the
    # substitution. resolve_arch writes its diagnostic to stderr, which reaches
    # the operator, and this makes the exit deliberate rather than incidental.
    if ! ARCH="$(resolve_arch)"; then
        exit 1
    fi
    log_info "Architecture: ${ARCH}"

    # Trust check FIRST: install_pinned_key aborts on a fingerprint mismatch, so
    # ordering it ahead of suppress_permanent_repo means a run that never earns
    # trust also never mutates /etc/default. Suppression is only required before
    # `apt-get install` (it is the package postinst that re-adds the repo), so
    # nothing is lost by deferring it.
    install_pinned_key "$SCRATCH_DIR"
    suppress_permanent_repo

    log_info "Installing google-chrome-stable via apt (signature-verified)"
    export DEBIAN_FRONTEND=noninteractive
    # Set BEFORE apt runs, not after: the postinst that plants the phone-home
    # artifacts runs inside this command, so a failure part-way through must
    # still count as "this run caused them" for cleanup_all.
    INSTALL_ATTEMPTED=1
    # Both apt invocations are bounded, the same reasoning as the key fetch
    # above: a held dpkg/apt lock or a tarpitted mirror would otherwise wedge
    # this run indefinitely with the temporary Google source still live in
    # /etc (SEC-BE-008). DPkg::Lock::Timeout turns a held lock into a
    # diagnosable apt error instead of a silent hang; `timeout` is the outer
    # backstop for every other way an apt run can wedge.
    #
    # $SUDO in the COMMAND-NAME position, not `timeout $SUDO apt-get` (SEC-BE-010):
    # on the unprivileged path $SUDO is "sudo", and `timeout N $SUDO apt-get`
    # ran `timeout` itself as the invoking user while `sudo`/`apt-get` ran as
    # root — signal permission requires the sender's UID to match the
    # receiver's, so `timeout`'s SIGTERM on expiry was silently refused by the
    # kernel and it just kept waiting for a child it could never kill. `$SUDO
    # timeout N apt-get` makes the timeout process itself privileged, so it
    # can actually signal the process it bounds. This also puts $SUDO back in
    # the position every other call site in this file already unquotes
    # without a shellcheck exemption, so none is needed here either.
    #
    # `-k 30` (SEC-BE-006): apt defers SIGTERM while a dpkg transaction is in
    # flight, so the plain TERM on expiry can leave the process still running
    # at the 300s/900s mark. `-k 30` has timeout follow up with SIGKILL 30s
    # later if apt-get is still alive, so a wedged run is bounded even when it
    # ignores the first signal. Residual, stated rather than hidden: timeout
    # signals only its direct child (apt-get), not the dpkg subprocess apt-get
    # forks — a dpkg maintainer script already running when either signal
    # lands can still outlive this bound. Reaching dpkg's own descendants
    # would need `setsid`/`--foreground` process-group signalling, which is a
    # larger behavioural change than this fix; the kill-after backstop at
    # least guarantees apt-get itself does not wait forever.
    if ! $SUDO timeout -k 30 300 apt-get update -qq -o DPkg::Lock::Timeout=120; then
        log_fail "apt-get update failed or timed out (held dpkg lock, or an unreachable mirror)." >&2
        exit 1
    fi
    # Gate BEFORE dpkg ever runs a maintainer script, not only after (SEC-
    # BE-009). `apt-get update -qq` exits 0 even when the just-pinned source
    # failed to fetch — apt only warns — so without this, `apt-get install`
    # below could still resolve the package NAME from whatever OTHER source
    # already offers it, and dpkg would run that package's postinst as root
    # before the post-install check further down ever gets a say.
    # `apt-cache policy` is read-only and reports the CANDIDATE's origin, so
    # this needs no install to answer.
    if ! verify_apt_origin; then
        exit 1
    fi
    if ! $SUDO timeout -k 30 900 apt-get install -y --no-install-recommends \
        -o DPkg::Lock::Timeout=120 google-chrome-stable; then
        log_fail "apt-get install failed or timed out." >&2
        exit 1
    fi
    # Re-check after install too: confirms dpkg actually unpacked what the
    # gate above approved, rather than trusting the gate alone.
    if ! verify_apt_origin; then
        exit 1
    fi

    cleanup_apt_wiring

    # AC4 (no phone-home from the devcontainer image) only obligates removing
    # the PACKAGE's own artifacts inside a throwaway image — same policy as the
    # idempotent early exit above and the audit in verify_install below.
    # Ungated, this was the one place a developer's own machine had the update
    # channel for the Chrome it JUST installed removed, silently and
    # unconditionally — the same mistake the early-exit branch above already
    # guards against, just reached from the other side of the install.
    if in_container; then
        remove_phone_home
    else
        # NOT "leaving the apt source and updater alone" (SEC-BE-009): unlike
        # the idempotent early-exit branch above, suppress_permanent_repo
        # already ran on THIS path (unconditionally, before apt-get install),
        # so the package's postinst never created its own apt source or daily
        # pinger in the first place — there is nothing left to leave alone.
        # The message says what actually happened instead: this install has
        # no update channel, on purpose, until the operator restores one.
        log_info "Not a container — google-chrome-stable was installed with no apt update channel (repo_add_once=false in ${CHROME_DEFAULTS_FILE})."
        log_info "  To restore Chrome's normal update channel: remove that setting (or the whole file) and re-add Google's source."
    fi

    # Set HERE, immediately after the container-aware removal above, and NOT
    # earlier next to apt-get: this flag means "main() has already made the
    # container-aware AC4 decision", which is only true once that branch has
    # actually run. Setting it right after `apt-get install` succeeded opened a
    # hole on the failure path — dpkg's postinst plants the phone-home artifacts
    # DURING apt-get, so an `exit 1` from verify_apt_origin between the two
    # points left the trap looking at INSTALL_SUCCEEDED=1, skipping its own
    # removal, and stranding a permanently trusted Google apt source plus the
    # root-run daily pinger on the host. Any new early-exit added between
    # apt-get and this line is covered by the trap precisely because the flag is
    # still 0 there.
    INSTALL_SUCCEEDED=1

    if in_container; then
        $SUDO rm -rf -- "${TEST_ROOT}/var/lib/apt/lists"/*
    else
        log_info "Not in a container — leaving /var/lib/apt/lists intact."
    fi

    verify_install
}

# Persists the installed version durably (called only from verify_install, for
# a run that actually installed something). Logging alone was not enough: a
# Dockerfile RUN or postCreateCommand that discards stdout left the image with
# no evidence of which Chrome build it shipped, so a bad stable release could
# not be correlated to an image or rolled back to a known-good one. Staged
# then `install -m 0644`, matching how the keyring is written: the mode is
# stated at the call site instead of being left to the caller's umask, and the
# file lands atomically. `tee` did neither.
record_chrome_version() {
    local version="$1" staged_version="${SCRATCH_DIR}/chrome-version"
    # -m 0755 on the parent: unlike suppress_permanent_repo's /etc/default
    # (which usually already exists and so keeps whatever mode it has),
    # /usr/share/vespasian is a directory THIS script creates, so its mode is
    # ours to state rather than leave to the caller's umask (SEC-BE-003).
    if printf '%s\n' "$version" > "$staged_version" &&
       $SUDO install -d -m 0755 -- "$(dirname -- "$CHROME_VERSION_RECORD")" &&
       $SUDO install -m 0644 -- "$staged_version" "$CHROME_VERSION_RECORD"; then
        log_info "Recorded build in ${CHROME_VERSION_RECORD}"
    else
        # Non-fatal: the browser is installed and working, and the record is an
        # audit convenience rather than a correctness requirement.
        log_warn "Could not write the version record to ${CHROME_VERSION_RECORD}"
    fi
}

verify_install() {
    local installed rc=0
    installed=$(detect_chrome_binary) || rc=$?
    if [ $rc -ne 0 ]; then
        log_fail "Install completed but no runnable browser was detected." >&2
        exit 1
    fi
    # Log the exact version: this script tracks stable rather than pinning, so
    # the version string is the only record of what actually landed.
    local version
    version="$("${installed}" --version 2>/dev/null || echo 'version unknown')"
    log_ok "Browser: ${installed} (${version})"

    # Only when this run actually installed something. On the browser-already-
    # present early exit the script promises to touch nothing it does not own,
    # and a root-owned write into /usr/share is exactly such a touch — it also
    # would overwrite the record of the build a PREVIOUS run installed with
    # whatever the ambient browser happens to report.
    if [ "$INSTALL_ATTEMPTED" -ne 1 ]; then
        log_info "Not recording a version (no install performed this run)."
    else
        record_chrome_version "$version"
    fi

    # This script's OWN temporary artifacts are always fatal if they survive:
    # they exist only because this run created them, so one left behind is a
    # teardown bug and a standing trusted apt source.
    local leftover
    for leftover in "$TMP_LIST" "$TMP_KEYRING" "$TMP_PREF"; do
        if [ -e "$leftover" ]; then
            log_fail "Temporary apt artifact still present: ${leftover}" >&2
            exit 1
        fi
    done

    # The PACKAGE's phone-home artifacts are only fatal where we undertook to
    # remove them, which is the same condition that governs the removal itself.
    # Checking them unconditionally contradicted the in_container() gate: on a
    # developer's machine the script would announce "leaving the google-chrome
    # apt source and updater alone" and then exit 1 for finding exactly the
    # thing it had just said it would leave — turning a normal Chrome install
    # into a hard failure. The check and the removal have to share one predicate.
    if in_container; then
        for leftover in "${PHONE_HOME_PATHS[@]}"; do
            if [ -e "$leftover" ]; then
                log_fail "Phone-home artifact still present: ${leftover}" >&2
                exit 1
            fi
        done
        log_ok "No Google apt source, keyring, or update pinger left behind"
    else
        log_ok "No temporary apt artifacts left behind"
        log_info "Package-owned apt source / updater not audited (not a container)."
    fi

    log_info "Containers usually need a sandbox opt-out: export VESPASIAN_NO_SANDBOX=true"
}

# Run main only when executed directly. When sourced (by the selftest) the
# functions are defined but main does not run — same guard setup-live-targets.sh
# uses.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
