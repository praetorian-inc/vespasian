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
# the REAL system paths. A symlinked test root reaches the same place. So the
# value is canonicalized and a resolved `/` is refused outright.
case "$TEST_ROOT" in
    "") ;;                                  # unset — the production case
    /*) case "$TEST_ROOT" in
            *[!A-Za-z0-9._/-]*)
                printf '[FAIL] VESPASIAN_TEST_ROOT contains characters outside [A-Za-z0-9._/-]: %s\n' \
                    "$TEST_ROOT" >&2
                exit 1
                ;;
        esac
        # No `..` component: it is the cheap, string-level half of the check and
        # it rejects the traversal even when the path does not exist yet, which
        # the canonicalization below cannot do.
        case "/${TEST_ROOT}/" in
            */../*)
                printf '[FAIL] VESPASIAN_TEST_ROOT must not contain a ".." component: %s\n' \
                    "$TEST_ROOT" >&2
                exit 1
                ;;
        esac
        # Then resolve symlinks for a root that exists, and refuse "/" however
        # it was spelled. A test root of / is never legitimate: the seam exists
        # to confine privileged writes to a fixture tree, and / is the absence
        # of confinement.
        if [ -d "$TEST_ROOT" ]; then
            _resolved=$(cd -P -- "$TEST_ROOT" 2>/dev/null && pwd -P) || _resolved=""
            if [ -z "$_resolved" ]; then
                printf '[FAIL] VESPASIAN_TEST_ROOT could not be resolved: %s\n' "$TEST_ROOT" >&2
                exit 1
            fi
            if [ "$_resolved" = "/" ]; then
                printf '[FAIL] VESPASIAN_TEST_ROOT resolves to / (no confinement): %s\n' "$TEST_ROOT" >&2
                exit 1
            fi
            TEST_ROOT="$_resolved"
            unset _resolved
        fi
        ;;
    *)  printf '[FAIL] VESPASIAN_TEST_ROOT must be an absolute path: %s\n' "$TEST_ROOT" >&2
        exit 1
        ;;
esac

# Temporary apt wiring, removed by cleanup_apt_wiring on every exit path.
TMP_LIST="${TEST_ROOT}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list"
TMP_KEYRING="${TEST_ROOT}/usr/share/keyrings/google-chrome-vespasian-temp.gpg"

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
        log_fail "Missing required tool(s): ${missing[*]}"
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
install_pinned_key() {
    local tmp_key="$1/google.pub" tmp_gpg="$1/google.gpg" tmp_ring="$1/google.kbx"
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
        log_fail "Could not fetch Google's signing key: ${GOOGLE_KEY_URL}"
        return 1
    fi

    # Import into a scratch keyring rather than dearmoring in place. gpg's own
    # stderr is kept and echoed on failure: discarding it is what turned a
    # missing gnupg into a bogus "the key is forged" report.
    if ! gpg --homedir "$gpg_home" --no-default-keyring --keyring "$tmp_ring" \
        --batch --quiet --import "$tmp_key" 2>"$gpg_err"; then
        log_fail "Fetched signing key is not a valid PGP key."
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
        log_fail "Could not read any key fingerprint from the fetched key — refusing to install."
        [ -s "$gpg_err" ] && log_info "  gpg: $(tr '\n' ' ' < "$gpg_err")"
        return 1
    fi
    if ! printf '%s\n' "$fprs" | grep -qxF -- "$GOOGLE_KEY_FPR"; then
        log_fail "Google signing key fingerprint mismatch — refusing to install."
        log_info "  expected: ${GOOGLE_KEY_FPR}"
        log_info "  got:      ${fprs}"
        log_info "If Google rotated their primary key, update GOOGLE_KEY_FPR deliberately."
        return 1
    fi

    # Export ONLY the pinned fingerprint. Installing the whole fetched blob would
    # tell apt to trust every key the endpoint chose to return.
    if ! gpg --homedir "$gpg_home" --no-default-keyring --keyring "$tmp_ring" \
        --batch --yes --export "$GOOGLE_KEY_FPR" > "$tmp_gpg" 2>"$gpg_err" || [ ! -s "$tmp_gpg" ]; then
        log_fail "Could not export the pinned key ${GOOGLE_KEY_FPR} — refusing to install."
        [ -s "$gpg_err" ] && log_info "  gpg: $(tr '\n' ' ' < "$gpg_err")"
        return 1
    fi
    log_ok "Signing key matches pinned fingerprint ${GOOGLE_KEY_FPR}"

    $SUDO install -d -- "$(dirname -- "$TMP_KEYRING")" "$(dirname -- "$TMP_LIST")"
    $SUDO install -m 0644 -- "$tmp_gpg" "$TMP_KEYRING"
    # signed-by= is the whole point: it scopes verification of this source to the
    # fingerprint-pinned keyring. Without it apt would fall back to any key in
    # the system-wide trusted set and the pin would be ornamental.
    printf 'deb [arch=%s signed-by=%s] %s stable main\n' "$ARCH" "$TMP_KEYRING" "$GOOGLE_APT_URL" \
        | $SUDO tee "$TMP_LIST" >/dev/null
}

# Remove the temporary repo + keyring. Registered as a trap so a failure
# between adding and installing cannot leave the source behind — that source
# persisting is exactly the phone-home the ticket is trying to prevent.
cleanup_apt_wiring() {
    $SUDO rm -f -- "$TMP_LIST" "$TMP_KEYRING"
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
        log_fail "${f} is a symlink — refusing to write through it."
        return 1
    fi
    # No -m on install -d: an existing /etc/default keeps whatever mode it has.
    $SUDO install -d -- "$(dirname -- "$f")"

    # Render the whole desired file, then land it with a single atomic rename.
    #
    # This replaces a create/append/rewrite branch trio that had two problems.
    # The branch predicates ran WITHOUT $SUDO while the writes ran WITH it, so an
    # unreadable-but-existing file (root-owned 0600) sent an unprivileged caller
    # down the append arm and duplicated the key instead of rewriting it. And
    # `tee`/`sed -i` follow symlinks by name, leaving a check-then-write window
    # after the [ -L ] guard. One rewrite fixes both: the read that decides the
    # content runs at the same privilege as the write, and rename(2) replaces a
    # symlink rather than writing through it.
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
        local grep_rc=0
        $SUDO grep -v '^repo_add_once=' -- "$f" > "$staged" || grep_rc=$?
        if [ "$grep_rc" -gt 1 ]; then
            log_fail "Could not read ${f} (grep exit ${grep_rc}) — refusing to rewrite it."
            return 1
        fi
    fi
    printf 'repo_add_once=false\n' >> "$staged"
    $SUDO install -m 0644 -- "$staged" "${f}.vespasian-tmp"
    $SUDO mv -f -- "${f}.vespasian-tmp" "$f"
}

remove_phone_home() {
    $SUDO rm -f -- "${PHONE_HOME_PATHS[@]}"
}

# in_container reports whether this looks like a throwaway image, which is the
# only place it is safe to wipe the apt cache — doing that on a developer's own
# machine destroys whole-system apt index state they never consented to lose.
# Both probes are reachable from the selftest: the marker path is rerooted by
# VESPASIAN_TEST_ROOT, and REMOTE_CONTAINERS is read from the environment.
in_container() {
    [ -f "${TEST_ROOT}/.dockerenv" ] || [ -n "${REMOTE_CONTAINERS:-}" ]
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

cleanup_all() {
    [ -n "$SCRATCH_DIR" ] && rm -rf -- "$SCRATCH_DIR"
    cleanup_apt_wiring
    # AC4 on the FAILURE paths too. Every success path already calls this, but an
    # install that died after dpkg ran the package's postinst — the exact moment
    # the permanent Google source and the daily pinger appear — left both behind,
    # so a failed run was the one case that ADDED standing egress. It is an rm -f
    # of fixed paths, so it is idempotent and safe to reach twice.
    #
    # Guarded on INSTALL_ATTEMPTED rather than run unconditionally: without that,
    # this trap would fire on the browser-already-present early exit and delete a
    # pre-existing Chrome's update channel on a developer's machine — undoing the
    # in_container check on that path by the back door.
    [ "$INSTALL_ATTEMPTED" -eq 1 ] && remove_phone_home
    return 0
}

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
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends google-chrome-stable

    cleanup_apt_wiring
    remove_phone_home

    if in_container; then
        $SUDO rm -rf -- "${TEST_ROOT}/var/lib/apt/lists"/*
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
    local version
    version="$("${installed}" --version 2>/dev/null || echo 'version unknown')"
    log_ok "Browser: ${installed} (${version})"

    # ...and record it durably. Logging alone was not enough: a Dockerfile RUN or
    # postCreateCommand that discards stdout left the image with no evidence of
    # which Chrome build it shipped, so a bad stable release could not be
    # correlated to an image or rolled back to a known-good one.
    # Staged then `install -m 0644`, matching how the keyring is written: the mode
    # is stated at the call site instead of being left to the caller's umask, and
    # the file lands atomically. `tee` did neither.
    #
    # Only when this run actually installed something. On the browser-already-
    # present early exit the script promises to touch nothing it does not own,
    # and a root-owned write into /usr/share is exactly such a touch — it also
    # overwrote the record of the build a PREVIOUS run installed with whatever
    # the ambient browser happens to report.
    local staged_version="${SCRATCH_DIR}/chrome-version"
    if [ "$INSTALL_ATTEMPTED" -ne 1 ]; then
        log_info "Not recording a version (no install performed this run)."
    elif printf '%s\n' "$version" > "$staged_version" &&
       $SUDO install -d -- "$(dirname -- "$CHROME_VERSION_RECORD")" 2>/dev/null &&
       $SUDO install -m 0644 -- "$staged_version" "$CHROME_VERSION_RECORD"; then
        log_info "Recorded build in ${CHROME_VERSION_RECORD}"
    else
        # Non-fatal: the browser is installed and working, and the record is an
        # audit convenience rather than a correctness requirement.
        log_warn "Could not write the version record to ${CHROME_VERSION_RECORD}"
    fi

    # This script's OWN temporary artifacts are always fatal if they survive:
    # they exist only because this run created them, so one left behind is a
    # teardown bug and a standing trusted apt source.
    local leftover
    for leftover in "$TMP_LIST" "$TMP_KEYRING"; do
        if [ -e "$leftover" ]; then
            log_fail "Temporary apt artifact still present: ${leftover}"
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
                log_fail "Phone-home artifact still present: ${leftover}"
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
