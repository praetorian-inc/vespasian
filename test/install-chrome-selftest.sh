#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Self-test for test/install-chrome.sh (LAB-5064). Plain bash, no framework —
# same shape as preflight-selftest.sh: source the script (its BASH_SOURCE guard
# means main() does not run), then exercise the pure helpers.
#
# DELIBERATELY UNTESTED: the download / apt / privileged-mutation paths. They
# need root, network, and destructive changes to system state, so exercising
# them in CI would cost more than it proves. What IS covered here is everything
# reachable without privilege: argument handling and architecture resolution.
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

# ── Case a: --help exits 0 and prints the whole header block ───
# Two sentinels, one from the FIRST and one from the LAST line of the intended
# range. The help text is sliced out of the header with a hardcoded `sed -n`
# line range, so a comment edit that shifts the header silently truncates the
# help output. Pinning both ends turns that into a test failure.
help_out=$(bash "${INSTALL_SCRIPT}" --help 2>&1) && help_rc=0 || help_rc=$?
assert_eq "case a: --help exits 0" "0" "${help_rc}"
assert_contains "case a: --help includes the first header line" \
    "Installs a real, non-snap Google Chrome" "${help_out}"
assert_contains "case a: --help includes the last header line (sed range intact)" \
    "install if needed" "${help_out}"

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
# The fingerprint is the script's entire trust anchor for the package: apt
# verifies the repo's Release signature against this key. An empty or
# reformatted constant would silently disable that check, so pin its exact
# value here (40 uppercase hex chars, no spaces).
fpr=$(
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    printf '%s' "${GOOGLE_KEY_FPR}"
)
assert_eq "case e: pinned signing-key fingerprint is the expected value" \
    "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796" "${fpr}"

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "install-chrome-selftest: ${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
