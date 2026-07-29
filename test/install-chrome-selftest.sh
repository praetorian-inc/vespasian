#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Self-test for test/install-chrome.sh (LAB-5064). Plain bash, no framework —
# same shape as preflight-selftest.sh: source the script (its BASH_SOURCE guard
# means main() does not run), then exercise the pure helpers.
#
# Covered: argument handling (a-c), architecture resolution (d), the pinned
# signing-key trust anchor (e-f), the defaults-file symlink guard and its
# rewrite branches (g), and container detection for the apt-cache wipe (h).
# Cases f and g are the behavioural tests for the two security controls: both
# fail if their check is removed, which case e alone does not.
#
# DELIBERATELY UNTESTED: the actual download, `apt-get install`, and the
# system-wide mutations that follow a successful key verification. Those need
# root, network, and destructive changes to system state, so exercising them in
# CI would cost more than it proves. Every rejection path IS reachable
# unprivileged, because each one returns before the first $SUDO.
#
# Usage: bash test/install-chrome-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install-chrome.sh"

pass_count=0
fail_count=0

assert_eq() {
    local desc=$1 expected=$2 actual=$3
    if [ "$expected" = "$actual" ]; then
        echo "PASS: ${desc}"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: ${desc} (expected [${expected}], got [${actual}])"
        fail_count=$((fail_count + 1))
    fi
}

assert_contains() {
    local desc=$1 needle=$2 haystack=$3
    if printf '%s' "${haystack}" | grep -qF -- "${needle}"; then
        echo "PASS: ${desc}"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: ${desc} (output did not contain [${needle}])"
        fail_count=$((fail_count + 1))
    fi
}

FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "${FIXTURE_DIR}"' EXIT

# ── Case a: --help prints exactly the header comment block ─────
# usage() walks the leading `#` lines and stops at the first non-comment, so
# the assertions pin both ends of that block: a sentinel from the first and
# last content lines, plus a negative check that it stopped at the comment
# boundary instead of spilling code into the help text.
help_out=$(bash "${INSTALL_SCRIPT}" --help 2>&1) && help_rc=0 || help_rc=$?
assert_eq "case a: --help exits 0" "0" "${help_rc}"
assert_contains "case a: --help includes the first header line" \
    "Installs a real, non-snap Google Chrome" "${help_out}"
assert_contains "case a: --help includes the last header line" \
    "install if needed" "${help_out}"
if printf '%s' "${help_out}" | grep -q "set -euo pipefail"; then
    echo "FAIL: case a: --help spilled past the header into script body"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case a: --help stops at the end of the header comment block"
    pass_count=$((pass_count + 1))
fi

# ── Case b: unknown flag is rejected ───────────────────────────
bad_out=$(bash "${INSTALL_SCRIPT}" --not-a-real-flag 2>&1) && bad_rc=0 || bad_rc=$?
assert_eq "case b: unknown flag exits 1" "1" "${bad_rc}"
assert_contains "case b: unknown flag names the offending argument" \
    "Unknown option: --not-a-real-flag" "${bad_out}"

# ── Case c: a caller-supplied arg cannot emit terminal escapes ─
# The rejected argument is echoed back to the user; it must be printed
# literally, never interpreted. A raw ESC byte in the output would mean the
# caller controls the terminal.
esc_out=$(bash "${INSTALL_SCRIPT}" '--x\e[31mRED' 2>&1) || true
if printf '%s' "${esc_out}" | grep -q '\\e\[31mRED'; then
    echo "PASS: case c: caller-supplied escape sequence is printed literally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case c: escape sequence was interpreted or dropped"
    fail_count=$((fail_count + 1))
fi

# ── Case d: resolve_arch maps dpkg's architecture ──────────────
# Stub `dpkg` on PATH so the mapping is exercised without caring what the host
# actually is. resolve_arch echoes the arch on success and returns non-zero on
# an unsupported one.
mkdir -p "${FIXTURE_DIR}/bin"
make_dpkg_stub() {
    cat > "${FIXTURE_DIR}/bin/dpkg" <<EOF
#!/bin/bash
[ "\$1" = "--print-architecture" ] && { echo "$1"; exit 0; }
exit 1
EOF
    chmod +x "${FIXTURE_DIR}/bin/dpkg"
}

run_resolve_arch() {
    make_dpkg_stub "$1"
    # shellcheck disable=SC2030,SC2031  # subshell-local PATH is the isolation mechanism, not a bug
    (
        PATH="${FIXTURE_DIR}/bin:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        set +e
        out=$(resolve_arch 2>/dev/null)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
}

for arch in amd64 arm64; do
    result=$(run_resolve_arch "${arch}")
    assert_eq "case d: resolve_arch accepts ${arch} (rc 0)" "0" "$(echo "${result}" | sed -n '1p')"
    assert_eq "case d: resolve_arch echoes ${arch}" "${arch}" "$(echo "${result}" | sed -n '2p')"
done

result=$(run_resolve_arch riscv64)
assert_eq "case d: resolve_arch rejects an unsupported arch (rc 1)" \
    "1" "$(echo "${result}" | sed -n '1p')"

# ── Case e: the pinned Google signing-key fingerprint is present ─
# Tripwire only: catches an accidental edit to the constant. It deliberately
# does NOT prove the check works — deleting the comparison in
# install_pinned_key leaves this case green. Case f is what tests the control.
fpr=$(
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    printf '%s' "${GOOGLE_KEY_FPR}"
)
assert_eq "case e: pinned signing-key fingerprint constant is unchanged" \
    "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796" "${fpr}"

# ── Case f: install_pinned_key REFUSES an unexpected key ───────
# The behavioural test for the trust anchor. install_pinned_key fetches the key
# with curl, so a curl stub on PATH makes both failure arms reachable with no
# network and no root — every rejection path returns before the first $SUDO.
#
# This is the case that fails if the fingerprint comparison is removed.
run_install_pinned_key() {
    local stub_body=$1
    cat > "${FIXTURE_DIR}/bin/curl" <<EOF
#!/bin/bash
# Ignore curl's flags; the last argument is the URL, the -o target is what
# install_pinned_key reads back.
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
${stub_body}
EOF
    chmod +x "${FIXTURE_DIR}/bin/curl"
    # shellcheck disable=SC2030,SC2031  # subshell-local PATH/SUDO overrides are deliberate
    (
        PATH="${FIXTURE_DIR}/bin:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO="/bin/false"   # any privileged call would fail loudly, proving we never reach one
        ARCH="amd64"
        set +e
        out=$(install_pinned_key "${FIXTURE_DIR}" 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

# f1: the endpoint returns something that is not a PGP key at all.
# shellcheck disable=SC2016  # $out is expanded inside the stub at run time, not here
res_f1=$(run_install_pinned_key 'printf "definitely not a pgp key\n" > "$out"')
assert_eq "case f: non-PGP key body is rejected (rc 1)" "1" "$(echo "${res_f1}" | sed -n '1p')"
assert_contains "case f: non-PGP key body is diagnosed" \
    "not a valid PGP key" "${res_f1}"

# f2: a well-formed key whose primary fingerprint is NOT the pinned one. This is
# the substituted-key scenario the pin exists to stop.
#
# NOTE on the rc check: on its own it is NOT load-bearing. With the comparison
# deleted, install_pinned_key still returns non-zero — but only because the
# SUDO=/bin/false stub fails on the write that follows. The assertions that
# actually pin the control are the two message checks below plus the negative
# "did not accept" check: a mutated build emits the ACCEPTANCE message for a key
# it should have refused, and that is what fails.
# shellcheck disable=SC2031  # SCRIPT_DIR is read, not modified; false positive here
res_f2=$(run_install_pinned_key "cat '${SCRIPT_DIR}/fixtures/not-google-signing-key.asc' > \"\$out\"")
assert_eq "case f: a valid but unexpected key does not succeed (rc 1)" "1" "$(echo "${res_f2}" | sed -n '1p')"
assert_contains "case f: unexpected key is diagnosed as a fingerprint mismatch" \
    "fingerprint mismatch" "${res_f2}"
assert_contains "case f: the rejection reports the fingerprint actually seen" \
    "790BC7277767219C42C86F933B4FE6ACC0B21F32" "${res_f2}"
if printf '%s' "${res_f2}" | grep -q "matches pinned fingerprint"; then
    echo "FAIL: case f: an unexpected key was ACCEPTED (pin is not gating)"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case f: an unexpected key is never reported as matching the pin"
    pass_count=$((pass_count + 1))
fi

# ── Case g: the symlink guard on the defaults file ─────────────
# CHROME_DEFAULTS_FILE redirects the one root-privileged write outside
# /etc so the guard and the rewrite branches are reachable unprivileged.
run_suppress() {
    # shellcheck disable=SC2030,SC2031  # subshell-local CHROME_DEFAULTS_FILE is deliberate
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        CHROME_DEFAULTS_FILE="$1"
        set +e
        out=$(suppress_permanent_repo 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

ln -sf "${FIXTURE_DIR}/symlink-victim" "${FIXTURE_DIR}/defaults-symlink"
res_g=$(run_suppress "${FIXTURE_DIR}/defaults-symlink")
assert_eq "case g: a symlinked defaults file is refused (rc 1)" "1" "$(echo "${res_g}" | sed -n '1p')"
assert_contains "case g: the refusal names the reason" "refusing to write through it" "${res_g}"
if [ -e "${FIXTURE_DIR}/symlink-victim" ]; then
    echo "FAIL: case g: wrote through the symlink to its target"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case g: symlink target was not created"
    pass_count=$((pass_count + 1))
fi

# g2: an existing file that opts INTO the repo must be rewritten to opt out —
# the branch that actually suppresses the phone-home on a re-run.
printf 'repo_add_once=true\n' > "${FIXTURE_DIR}/defaults-existing"
res_g2=$(run_suppress "${FIXTURE_DIR}/defaults-existing")
assert_eq "case g: an existing defaults file is accepted (rc 0)" "0" "$(echo "${res_g2}" | sed -n '1p')"
assert_eq "case g: repo_add_once=true is rewritten to false" \
    "repo_add_once=false" "$(cat "${FIXTURE_DIR}/defaults-existing")"

# g3: absent file is created opted-out.
res_g3=$(run_suppress "${FIXTURE_DIR}/defaults-new")
assert_eq "case g: an absent defaults file is created (rc 0)" "0" "$(echo "${res_g3}" | sed -n '1p')"
assert_eq "case g: the created file opts out of the repo" \
    "repo_add_once=false" "$(cat "${FIXTURE_DIR}/defaults-new")"

# ── Case h: container detection gates the apt-cache wipe ───────
# Wiping /var/lib/apt/lists is safe in a throwaway image and destructive on a
# developer's own machine, so both arms are pinned.
run_in_container() {
    # shellcheck disable=SC2030,SC2031  # subshell-local env overrides are deliberate
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        DOCKERENV_PATH="$1"
        REMOTE_CONTAINERS="$2"
        set +e
        in_container
        printf '%s\n' "$?"
    )
}
touch "${FIXTURE_DIR}/dockerenv"
assert_eq "case h: /.dockerenv present means container" \
    "0" "$(run_in_container "${FIXTURE_DIR}/dockerenv" "")"
assert_eq "case h: REMOTE_CONTAINERS set means container" \
    "0" "$(run_in_container "${FIXTURE_DIR}/absent" "true")"
assert_eq "case h: neither signal means NOT a container (cache is left alone)" \
    "1" "$(run_in_container "${FIXTURE_DIR}/absent" "")"

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "install-chrome-selftest: ${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
