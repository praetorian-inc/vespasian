#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Self-test for test/install-chrome.sh (LAB-5064). Plain bash, no framework —
# same shape as preflight-selftest.sh: source the script (its BASH_SOURCE guard
# means main() does not run), then exercise the pure helpers.
#
# Covered: argument handling (a-c), architecture resolution (d), the pinned
# signing-key trust anchor including its success path from a committed fixture
# (e-f, j-j2), the defaults-file symlink guard and its rewrite branches (g, q),
# container detection for the apt-cache wipe (h), the phone-home removal and
# verification chain on both the container and non-container arms (n, o, o2),
# cleanup_all's failed-install arm (u), VESPASIAN_TEST_ROOT containment (t),
# the log helpers' escape hardening (s), and the browser-present-without-
# curl/gpg path (r). Each of those is behavioural: it fails if its check is
# removed, which an assertion on the message alone does not.
#
# NOT COVERED HERE: the actual download, `apt-get install`, and the system-wide
# mutations that follow a successful key verification. Those need root, network,
# and destructive changes to system state, so this suite stops before the first
# $SUDO — every rejection path returns before it. That region is covered instead
# by the `install-chrome-e2e` CI job, which runs the installer end-to-end as
# root in a disposable container.
#
# This suite needs NO network: the Google key it verifies against is the
# committed fixture test/fixtures/google-linux-signing-key.asc.
#
# Usage: bash test/install-chrome-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install-chrome.sh"

pass_count=0
fail_count=0
skip_count=0
# Skips that represent a real coverage hole rather than an unsuitable
# environment. Only the trust-anchor success path qualifies; see the policy at
# the end of this file.
trust_anchor_skips=0

# A check that could not run is NOT a pass. Tallied separately so the summary
# distinguishes "verified" from "unverifiable here", following the
# pass/fail/skip precedent in test/run-live-tests.sh's result table.
skip() {
    echo "SKIP: $1"
    skip_count=$((skip_count + 1))
}

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
# INT/TERM as well as EXIT, mirroring install-chrome.sh: a bash signal handler
# returns to the interrupted code, so without an explicit exit a Ctrl-C left the
# fixture tree behind in $TMPDIR. Exiting from the handler routes through EXIT so
# cleanup runs exactly once.
trap 'rm -rf "${FIXTURE_DIR}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A throwaway GNUPGHOME for the assertion helpers below. `gpg --show-keys` on a
# keyring still initialises the caller's ~/.gnupg (creating it, and taking its
# lock) — install_pinned_key is careful to pass --homedir for exactly that
# reason, and the assertions that check its work should be no less careful.
GNUPG_ASSERT_HOME="${FIXTURE_DIR}/gnupg-assert"
mkdir -p "${GNUPG_ASSERT_HOME}"
chmod 700 "${GNUPG_ASSERT_HOME}"

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
# Overrun check. An earlier version grepped for "set -euo pipefail" here, which
# was VACUOUS: the awk walk only ever prints lines matching /^#/, so a
# non-comment line can never appear no matter how far the walk runs. Dropping
# the `{ exit }` grew --help from 56 to 101 lines with every assertion still
# green. The real failure mode is column-0 comments from further down the file
# leaking in, so the sentinel has to be one of those.
#
# OVERRUN_SENTINEL is asserted to still EXIST in the source first — otherwise a
# reword would silently disarm this check rather than failing it.
OVERRUN_SENTINEL="signature check ornamental"
if grep -qF -- "${OVERRUN_SENTINEL}" "${INSTALL_SCRIPT}"; then
    echo "PASS: case a: overrun sentinel still present in the source (check has teeth)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case a: overrun sentinel '${OVERRUN_SENTINEL}' no longer in install-chrome.sh — pick a new one"
    fail_count=$((fail_count + 1))
fi
if printf '%s' "${help_out}" | grep -qF -- "${OVERRUN_SENTINEL}"; then
    echo "FAIL: case a: --help ran past the header into body comments"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case a: --help stops at the end of the header comment block"
    pass_count=$((pass_count + 1))
fi
# Positive end-pin: the last non-blank line must still be the usage example.
assert_contains "case a: --help ends on the usage line" \
    "install if needed" "$(printf '%s' "${help_out}" | grep -v '^[[:space:]]*$' | tail -1)"

# ── Case a2: the script is committed executable ────────────────
# setup-live-targets.sh's browserless hint tells operators to run
# `./test/install-chrome.sh` directly. A lost exec bit makes that rc=126 while
# every other case here still passes, because they all invoke it via `bash`.
#
# Asserted against the GIT INDEX mode, not `[ -x ]`, for two reasons. First,
# the committed mode is what actually reaches other clones and CI — a
# working-tree chmod that was never staged helps nobody. Second, `[ -x ]` is
# not trustworthy here: on the overlay filesystem this devcontainer uses it
# returned true for this very file while it sat at mode 644 and `./` gave 126.
# Skips cleanly outside a git checkout rather than failing spuriously.
if git -C "${SCRIPT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    mode=$(git -C "${SCRIPT_DIR}" ls-files -s -- install-chrome.sh | awk '{print $1}')
    assert_eq "case a2: install-chrome.sh is committed executable (100755)" "100755" "${mode}"
else
    # SKIP, not PASS: a git-less copy (tarball, `git archive`, docker COPY
    # without .git) cannot answer this, and counting it as a pass made the
    # summary indistinguishable from a real run.
    skip "case a2: committed-mode check (not a git checkout)"
fi

# Direct-exec companion to the index check above (see its rationale); this one
# covers core.fileMode=false's blind spot, where a working-tree `chmod -x`
# leaves the index at 100755 and `git status` empty while ./ returns 126.
# Invoked via the ABSOLUTE "${INSTALL_SCRIPT}" and deliberately NOT through
# `bash`: only a direct exec consults the mode bit, and an absolute path keeps
# the result identical from the repo root or from inside test/.
"${INSTALL_SCRIPT}" --help >/dev/null 2>&1 && direct_rc=0 || direct_rc=$?
assert_eq "case a2: install-chrome.sh runs by direct exec, not 126" "0" "${direct_rc}"

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
# CHROME_DEFAULTS_FILE (derived from VESPASIAN_TEST_ROOT in production, set
# directly here) redirects the one root-privileged write outside /etc so the
# guard and the rewrite branches are reachable unprivileged.
run_suppress() {
    # shellcheck disable=SC2030,SC2031  # subshell-local overrides are deliberate
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        CHROME_DEFAULTS_FILE="$1"
        # suppress_permanent_repo stages its atomic rewrite here; main() would
        # have created it via mktemp.
        SCRATCH_DIR="${FIXTURE_DIR}/scratch"
        mkdir -p "${SCRATCH_DIR}"
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
# $1 is a VESPASIAN_TEST_ROOT under which /.dockerenv may or may not exist.
run_in_container() {
    # shellcheck disable=SC2030,SC2031  # subshell-local env overrides are deliberate
    (
        VESPASIAN_TEST_ROOT="$1"
        export VESPASIAN_TEST_ROOT
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        REMOTE_CONTAINERS="$2"
        set +e
        in_container
        printf '%s\n' "$?"
    )
}
mkdir -p "${FIXTURE_DIR}/root-container" "${FIXTURE_DIR}/root-host"
touch "${FIXTURE_DIR}/root-container/.dockerenv"
assert_eq "case h: /.dockerenv present means container" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-container" "")"
assert_eq "case h: REMOTE_CONTAINERS set means container" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-host" "true")"
assert_eq "case h: neither signal means NOT a container (cache is left alone)" \
    "1" "$(run_in_container "${FIXTURE_DIR}/root-host" "")"

# ── Case i: the unsupported-arch diagnostic reaches the operator ─
# Case d proves resolve_arch REJECTS an unsupported arch; it says nothing about
# whether the operator ever learns why. That gap was real: log_fail wrote to
# stdout and main()'s `ARCH="$(resolve_arch)"` captured it, so the script died
# with an empty terminal. Run the SCRIPT (not the function) so the call site is
# in scope, and assert the reason appears in the combined output.
make_dpkg_stub riscv64
# CHROME_CANDIDATES is emptied rather than relying on PATH isolation: the array
# holds ABSOLUTE paths (/usr/bin/google-chrome …), which `command -v` resolves
# regardless of PATH, so a host with a real Chrome would take the idempotency
# exit and never reach resolve_arch. Overriding the array is what makes this case
# give the same answer on a browserless CI runner and on a dev box with Chrome.
mkdir -p "${FIXTURE_DIR}/root-arch"
arch_result=$(
    VESPASIAN_TEST_ROOT="${FIXTURE_DIR}/root-arch"
    export VESPASIAN_TEST_ROOT
    PATH="${FIXTURE_DIR}/bin:${PATH}"
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    CHROME_CANDIDATES=()
    set +e
    out=$(main 2>&1)
    printf '%s\n%s' "$?" "${out}"
)
arch_rc=$(echo "${arch_result}" | sed -n '1p')
arch_out=$(echo "${arch_result}" | tail -n +2)
assert_eq "case i: an unsupported arch aborts the script (rc 1)" "1" "${arch_rc}"
assert_contains "case i: the unsupported arch is named in the output" \
    "riscv64" "${arch_out}"
assert_contains "case i: the reason is explained, not just a bare exit" \
    "No google-chrome-stable build for architecture" "${arch_out}"

# ── Case j: install_pinned_key WIRES apt to the pinned keyring ──
# Case f covers both rejection arms but nothing covered the success path, so the
# content of the emitted source line was unasserted — dropping `signed-by=` from
# it left the whole suite green while silently degrading apt back to "any key
# already trusted". These assertions pin the line's text and the keyring mode.
#
# Runs with SUDO="" and VESPASIAN_TEST_ROOT so the two privileged writes land in
# fixtures. The curl stub serves the REAL Google key, so the fingerprint pin is
# genuinely satisfied rather than bypassed.
# The key comes from a COMMITTED FIXTURE, not the network. It is public data
# (no secret material — same class as not-google-signing-key.asc next to it),
# and it only goes stale when GOOGLE_KEY_FPR has to be updated deliberately,
# which is the same event. Fetching it live made these — the ONLY assertions
# covering the trust anchor's success path — silently skip on any runner without
# egress to dl.google.com, so an egress change could disarm them while the suite
# stayed green.
GOOGLE_KEY_CACHE="${SCRIPT_DIR}/fixtures/google-linux-signing-key.asc"
if [ -s "${GOOGLE_KEY_CACHE}" ]; then
    have_real_key=1
else
    have_real_key=0
fi

# Guard the fixture itself: if it ever stops containing the pinned primary key,
# cases j/j2 would be testing nothing. Assert that before relying on it.
if [ "${have_real_key}" -eq 1 ]; then
    fixture_fprs=$(gpg --homedir "${GNUPG_ASSERT_HOME}" --show-keys --with-colons \
        --with-fingerprint "${GOOGLE_KEY_CACHE}" 2>/dev/null \
        | awk -F: '$1=="pub"{w=1} $1=="fpr"&&w{print $10; w=0}')
    if printf '%s\n' "${fixture_fprs}" | grep -qxF -- "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"; then
        echo "PASS: fixture google-linux-signing-key.asc carries the pinned primary key"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: fixture google-linux-signing-key.asc no longer carries the pinned key — j/j2 would be vacuous"
        fail_count=$((fail_count + 1))
    fi
fi

if [ "${have_real_key}" -eq 1 ]; then
    root_j="${FIXTURE_DIR}/root-j"
    mkdir -p "${root_j}/etc/apt/sources.list.d" "${root_j}/usr/share/keyrings"
    res_j=$(
        VESPASIAN_TEST_ROOT="${root_j}"
        export VESPASIAN_TEST_ROOT
        PATH="${FIXTURE_DIR}/bin:${PATH}"
        cat > "${FIXTURE_DIR}/bin/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${GOOGLE_KEY_CACHE}' > "\$out"
EOF
        chmod +x "${FIXTURE_DIR}/bin/curl"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        ARCH="amd64"
        set +e
        out=$(install_pinned_key "${FIXTURE_DIR}" 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
    assert_eq "case j: the real Google key satisfies the pin (rc 0)" \
        "0" "$(echo "${res_j}" | sed -n '1p')"
    # The load-bearing assertion: signed-by= is what makes the pin gate apt.
    assert_contains "case j: the emitted apt source pins signed-by to our keyring" \
        "signed-by=${root_j}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" \
        "$(cat "${root_j}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" 2>/dev/null)"
    assert_contains "case j: the emitted apt source pins the architecture" \
        "arch=amd64" \
        "$(cat "${root_j}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" 2>/dev/null)"
    assert_eq "case j: the installed keyring is world-readable but not writable (0644)" \
        "644" "$(stat -c '%a' "${root_j}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" 2>/dev/null)"
    # Only the pinned key may end up in the keyring: exporting the whole fetched
    # bundle would hand apt every key the endpoint chose to return.
    exported_fprs=$(gpg --homedir "${GNUPG_ASSERT_HOME}" --show-keys --with-colons --with-fingerprint \
        "${root_j}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" 2>/dev/null \
        | awk -F: '$1=="pub"{want=1} $1=="fpr" && want{print $10; want=0}')
    assert_eq "case j: the keyring holds exactly the pinned key, nothing else" \
        "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796" "${exported_fprs}"

    # j2: a MULTI-key bundle. Google documents shipping its active and obsolete
    # primary keys together, and a key transition would legitimately serve two
    # `pub` records — which is why the fingerprint check tests MEMBERSHIP rather
    # than equality. Membership on its own would be a trust widening, so the
    # export must still narrow the keyring to the pinned key alone.
    #
    # This is also what gives the "nothing else" assertion above teeth: with
    # today's single-key bundle, exporting the whole blob and exporting just the
    # pinned key produce identical keyrings, so only a two-key bundle can tell
    # the two implementations apart.
    root_j2="${FIXTURE_DIR}/root-j2"
    mkdir -p "${root_j2}/etc/apt/sources.list.d" "${root_j2}/usr/share/keyrings"
    cat "${GOOGLE_KEY_CACHE}" "${SCRIPT_DIR}/fixtures/not-google-signing-key.asc" \
        > "${FIXTURE_DIR}/two-key-bundle.asc"
    res_j2=$(
        VESPASIAN_TEST_ROOT="${root_j2}"
        export VESPASIAN_TEST_ROOT
        PATH="${FIXTURE_DIR}/bin:${PATH}"
        cat > "${FIXTURE_DIR}/bin/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${FIXTURE_DIR}/two-key-bundle.asc' > "\$out"
EOF
        chmod +x "${FIXTURE_DIR}/bin/curl"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        ARCH="amd64"
        set +e
        out=$(install_pinned_key "${FIXTURE_DIR}/j2scratch" 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
    assert_eq "case j2: a bundle CONTAINING the pinned key is accepted (rc 0)" \
        "0" "$(echo "${res_j2}" | sed -n '1p')"
    j2_fprs=$(gpg --homedir "${GNUPG_ASSERT_HOME}" --show-keys --with-colons --with-fingerprint \
        "${root_j2}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" 2>/dev/null \
        | awk -F: '$1=="pub"{want=1} $1=="fpr" && want{print $10; want=0}')
    assert_eq "case j2: only the pinned key is exported, the co-bundled key is dropped" \
        "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796" "${j2_fprs}"
    if printf '%s' "${j2_fprs}" | grep -qF "790BC7277767219C42C86F933B4FE6ACC0B21F32"; then
        echo "FAIL: case j2: a co-bundled non-Google key was handed to apt as trusted"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case j2: the co-bundled non-Google key never reaches apt's trust"
        pass_count=$((pass_count + 1))
    fi
else
    # Counted separately: this is the trust anchor's ONLY success-path coverage,
    # so skipping it is a coverage hole rather than an unsuitable environment.
    skip "case j/j2: trust-anchor success path (fixture test/fixtures/google-linux-signing-key.asc missing or empty)"
    trust_anchor_skips=$((trust_anchor_skips + 1))
fi

# ── Case k: suppress_permanent_repo's append branch ─────────────
# g2 covers rewrite and g3 covers create; a file that exists WITHOUT the key was
# the untested middle branch. It is not hypothetical — any host with prior
# Chrome packaging can have /etc/default/google-chrome present without it, and
# if suppression silently no-ops there the package re-adds Google's permanent
# apt source. Asserts on FULL content so an overwrite-instead-of-preserve
# regression also trips.
printf 'SOMETHING_ELSE=1\n' > "${FIXTURE_DIR}/defaults-no-key"
res_k=$(run_suppress "${FIXTURE_DIR}/defaults-no-key")
assert_eq "case k: a defaults file lacking the key is accepted (rc 0)" \
    "0" "$(echo "${res_k}" | sed -n '1p')"
assert_contains "case k: the pre-existing unrelated setting is preserved" \
    "SOMETHING_ELSE=1" "$(cat "${FIXTURE_DIR}/defaults-no-key")"
assert_contains "case k: the opt-out is appended" \
    "repo_add_once=false" "$(cat "${FIXTURE_DIR}/defaults-no-key")"

# ── Case l: resolve_sudo and require_apt refusals ───────────────
# Both are pure precondition paths that return before any mutation, and neither
# had a test. The selftest header claims every rejection path is reachable
# unprivileged — these make that true rather than aspirational.
run_resolve_sudo() {
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        PATH="$1"
        set +e
        resolve_sudo >/dev/null 2>&1
        printf '%s\n%s\n' "$?" "${SUDO-unset}"
    )
}
# A PATH with neither sudo nor anything else: non-root + no sudo must refuse.
if [ "$(id -u)" -ne 0 ]; then
    res_l=$(run_resolve_sudo "${FIXTURE_DIR}/empty-bin")
    assert_eq "case l: non-root without sudo refuses (rc 1)" \
        "1" "$(echo "${res_l}" | sed -n '1p')"
else
    skip "case l: non-root sudo refusal (running as root)"
fi

run_require_apt() {
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        PATH="$1"
        set +e
        out=$(require_apt 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}
mkdir -p "${FIXTURE_DIR}/empty-bin"
res_l2=$(run_require_apt "${FIXTURE_DIR}/empty-bin")
assert_eq "case l: a non-apt distro is refused (rc 1)" "1" "$(echo "${res_l2}" | sed -n '1p')"
assert_contains "case l: the refusal names the supported distros" \
    "Debian/Ubuntu" "${res_l2}"

# ── Case m: curl and gpg are checked before they are used ───────
# Without this, a base image lacking gnupg got "Fetched signing key is not a
# valid PGP key" — a message that accuses Google's key of being forged when the
# real problem is a missing package, and whose natural remedy is to work around
# the verification.
run_require_tools() {
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        PATH="$1"
        set +e
        out=$(require_tools 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}
res_m=$(run_require_tools "${FIXTURE_DIR}/empty-bin")
assert_eq "case m: a missing gpg/curl is refused before any fetch (rc 1)" \
    "1" "$(echo "${res_m}" | sed -n '1p')"
assert_contains "case m: the missing dependency is named, not blamed on the key" \
    "gnupg" "${res_m}"
if printf '%s' "${res_m}" | grep -q "not a valid PGP key"; then
    echo "FAIL: case m: a missing tool is still misreported as a bad signing key"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case m: a missing tool is not misreported as a bad signing key"
    pass_count=$((pass_count + 1))
fi

# ── Case n: the phone-home removal + verification chain ─────────
# AC4's three controls (remove_phone_home, cleanup_apt_wiring, and
# verify_install's absence loop) had NO test between them: neutering any of the
# three left the suite green. VESPASIAN_TEST_ROOT reroots every system path the
# script touches, so the whole chain runs unprivileged against fixtures.
root_n="${FIXTURE_DIR}/root-n"
plant_phone_home() {
    rm -rf "${root_n}"
    mkdir -p "${root_n}/etc/apt/sources.list.d" "${root_n}/etc/cron.daily" \
             "${root_n}/usr/share/keyrings"
    # Both the legacy .list and the deb822 .sources the current package writes.
    touch "${root_n}/etc/apt/sources.list.d/google-chrome.list" \
          "${root_n}/etc/apt/sources.list.d/google-chrome.sources" \
          "${root_n}/etc/cron.daily/google-chrome" \
          "${root_n}/usr/share/keyrings/google-chrome.gpg" \
          "${root_n}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" \
          "${root_n}/usr/share/keyrings/google-chrome-vespasian-temp.gpg"
}

# A fake browser so verify_install gets past detect_chrome_binary.
mkdir -p "${FIXTURE_DIR}/fakebin"
cat > "${FIXTURE_DIR}/fakebin/google-chrome" <<'EOF'
#!/bin/bash
[ "$1" = "--version" ] && { echo "Google Chrome 1.2.3"; exit 0; }
exit 0
EOF
chmod +x "${FIXTURE_DIR}/fakebin/google-chrome"

# n1: remove_phone_home actually unlinks every path it claims to.
plant_phone_home
res_n1=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    SUDO=""
    set +e
    remove_phone_home
    printf '%s\n' "$?"
)
assert_eq "case n: remove_phone_home succeeds (rc 0)" "0" "${res_n1}"
for leftover in etc/apt/sources.list.d/google-chrome.list \
                etc/apt/sources.list.d/google-chrome.sources \
                etc/cron.daily/google-chrome \
                usr/share/keyrings/google-chrome.gpg; do
    if [ -e "${root_n}/${leftover}" ]; then
        echo "FAIL: case n: remove_phone_home left ${leftover} behind"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case n: remove_phone_home unlinked ${leftover}"
        pass_count=$((pass_count + 1))
    fi
done

# n2: cleanup_apt_wiring removes the temporary repo AND its keyring. The header
# calls a persisted temp source "exactly the phone-home the ticket is trying to
# prevent", so this is the assertion behind that claim.
plant_phone_home
res_n2=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    SUDO=""
    set +e
    cleanup_apt_wiring
    printf '%s\n' "$?"
)
assert_eq "case n: cleanup_apt_wiring succeeds (rc 0)" "0" "${res_n2}"
for tmpart in etc/apt/sources.list.d/google-chrome-vespasian-temp.list \
              usr/share/keyrings/google-chrome-vespasian-temp.gpg; do
    if [ -e "${root_n}/${tmpart}" ]; then
        echo "FAIL: case n: cleanup_apt_wiring left ${tmpart} behind"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case n: cleanup_apt_wiring unlinked ${tmpart}"
        pass_count=$((pass_count + 1))
    fi
done

# n3: verify_install must FAIL when a phone-home artifact survives. This is the
# assertion that makes the "No Google apt source ... left behind" message mean
# something instead of merely being printed.
plant_phone_home
res_n3=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    PATH="${FIXTURE_DIR}/fakebin:${PATH}"
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    SUDO=""
    set +e
    out=$(verify_install 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case n: verify_install fails when an artifact survives (rc 1)" \
    "1" "$(echo "${res_n3}" | sed -n '1p')"
assert_contains "case n: verify_install names the surviving artifact" \
    "still present" "${res_n3}"

# n4: and it must PASS once the chain has actually cleaned up — otherwise n3
# could be satisfied by a verify_install that always fails.
res_n4=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    PATH="${FIXTURE_DIR}/fakebin:${PATH}"
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    SUDO=""
    set +e
    remove_phone_home
    cleanup_apt_wiring
    out=$(verify_install 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case n: verify_install passes on a clean tree (rc 0)" \
    "0" "$(echo "${res_n4}" | sed -n '1p')"
assert_contains "case n: the clean tree is reported as such" \
    "left behind" "${res_n4}"

# n5: verify_install's OTHER failure arm — no runnable browser after an install
# that reported success. Cases n3/n4 only pin the surviving-artifact arm, so
# deleting this one left the suite fully green while the script would happily
# report a successful install of a browser that is not there.
res_n5=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    SUDO=""
    # No candidate resolves, so detect_chrome_binary returns 1.
    CHROME_CANDIDATES=("${FIXTURE_DIR}/definitely-not-a-browser")
    set +e
    out=$(verify_install 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case n5: verify_install fails when no browser is detectable (rc 1)" \
    "1" "$(echo "${res_n5}" | sed -n '1p')"
assert_contains "case n5: it says the install produced no runnable browser" \
    "no runnable browser was detected" "${res_n5}"

# ── Case o: the idempotent early exit still enforces AC4 ────────
# main() returns 0 the moment any runnable browser is found. That short-circuit
# used to skip remove_phone_home and verify_install entirely, so on a host where
# Chrome came from another layer the script reported success while a permanent
# Google apt source and a root-run daily pinger were still installed. The exit
# must now mean "a browser exists AND nothing phones home".
# main() calls resolve_sudo, which overwrites any SUDO we preset, so a bare
# override cannot keep these writes unprivileged. A passthrough `sudo` stub on
# PATH is what does: resolve_sudo finds it and every $SUDO call runs as the test
# user, leaving no root-owned files in the fixture tree.
cat > "${FIXTURE_DIR}/bin/sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF
chmod +x "${FIXTURE_DIR}/bin/sudo"

plant_phone_home
# The container marker is planted EXPLICITLY. Phone-home removal on the early
# exit is gated on in_container(), which reads "${TEST_ROOT}/.dockerenv" or an
# ambient REMOTE_CONTAINERS. Relying on the ambient variable made this case pass
# in a devcontainer (which exports it) and FAIL on a GitHub-hosted runner, where
# it is unset — a test whose result depended on who ran it. Planting the marker
# under the fixture root pins the container arm on every host.
: > "${root_n}/.dockerenv"
res_o=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    # Unset so the fixture's own marker is the only thing in_container() can be
    # answering; otherwise an ambient value would mask a broken marker.
    unset REMOTE_CONTAINERS
    PATH="${FIXTURE_DIR}/bin:${PATH}"
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    # Pin the candidate to the fake so the early exit is taken deterministically
    # whether or not the host happens to have a real browser.
    CHROME_CANDIDATES=("${FIXTURE_DIR}/fakebin/google-chrome")
    set +e
    out=$(main 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case o: the early exit reports success (rc 0)" "0" "$(echo "${res_o}" | sed -n '1p')"
assert_contains "case o: the early exit is taken (browser already present)" \
    "already present" "${res_o}"
for leftover in etc/apt/sources.list.d/google-chrome.list \
                etc/apt/sources.list.d/google-chrome.sources \
                etc/cron.daily/google-chrome; do
    if [ -e "${root_n}/${leftover}" ]; then
        echo "FAIL: case o: early exit left phone-home artifact ${leftover} in place"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case o: early exit removed phone-home artifact ${leftover}"
        pass_count=$((pass_count + 1))
    fi
done

# ── Case p: INT/TERM handlers must EXIT, not just clean up ──────
# The temporary Google apt source is live between install_pinned_key and
# cleanup_apt_wiring, and a source left behind there is exactly the standing
# egress AC4 forbids. So an interrupted run must tear it down — and must then
# STOP.
#
# That second half is the subtle part, and it is a documented shell semantic: a
# bash signal handler RETURNS TO THE INTERRUPTED CODE when it finishes. So
# `trap 'cleanup_all' EXIT INT TERM` removed the apt wiring and then carried
# straight on into `apt-get install` with the repository it needed already
# deleted, finally exiting 0 as though the run had succeeded. Verified by hand:
#
#   trap 'cleanup_all' EXIT INT TERM   -> "CLEANUP RAN", then the code after the
#                                         interrupted command still ran, exit 0
#   trap 'cleanup_all' EXIT            -> "CLEANUP RAN" once, no continuation,
#   trap 'exit 130' INT                   exit 130 (SIGINT) / 143 (SIGTERM)
#   trap 'exit 143' TERM
#
# This is asserted STRUCTURALLY, as a drift guard in the same spirit as the
# target-group check in test-runner-args.sh. Driving a real signal here needs a
# blocked foreground child plus process-group job control, and bash defers a trap
# until the running foreground command finishes — a behavioural version was
# written, hung the suite twice on exactly that, and would have been a flaky test
# in CI. A flaky assertion is worth less than a deterministic one plus the
# recorded reasoning above.
trap_setup=$(grep -E "^ *trap " "${INSTALL_SCRIPT}")
if printf '%s' "${trap_setup}" | grep -qE "trap 'exit 130' INT"; then
    echo "PASS: case p: SIGINT exits (130) rather than resuming the interrupted run"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case p: no 'trap \'exit 130\' INT' — an interrupted run would clean up and then continue"
    fail_count=$((fail_count + 1))
fi
if printf '%s' "${trap_setup}" | grep -qE "trap 'exit 143' TERM"; then
    echo "PASS: case p: SIGTERM exits (143) rather than resuming the interrupted run"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case p: no 'trap \'exit 143\' TERM' — an interrupted run would clean up and then continue"
    fail_count=$((fail_count + 1))
fi
# The regression shape: INT/TERM bundled onto the cleanup trap instead of exiting.
if printf '%s' "${trap_setup}" | grep -qE "trap 'cleanup_all'.*(INT|TERM)"; then
    echo "FAIL: case p: INT/TERM are bundled onto the cleanup trap — the handler returns into main()"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case p: INT/TERM are not bundled onto the cleanup-only trap"
    pass_count=$((pass_count + 1))
fi
# And cleanup itself must still run on the ordinary exit path.
if printf '%s' "${trap_setup}" | grep -qE "trap 'cleanup_all' EXIT"; then
    echo "PASS: case p: cleanup_all still runs on EXIT (normal and error paths)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case p: nothing cleans up on EXIT"
    fail_count=$((fail_count + 1))
fi

# ── Case q: an unreadable defaults file is refused, not silently clobbered ─
# suppress_permanent_repo reads the current file to decide what to write back.
# grep exits 2 on a read error and 1 on "no match", and an earlier `|| true`
# collapsed the two — so an unreadable file produced a rewrite containing only
# our opt-out, discarding settings we never managed to read. Simulated with a
# grep stub returning 2, which is reachable unprivileged; the real-world trigger
# is a root-owned 0600 file under a non-root caller.
mkdir -p "${FIXTURE_DIR}/grepfail"
cat > "${FIXTURE_DIR}/grepfail/grep" <<'EOF'
#!/bin/bash
exit 2
EOF
chmod +x "${FIXTURE_DIR}/grepfail/grep"
printf 'KEEP_ME=1\n' > "${FIXTURE_DIR}/defaults-unreadable"
res_q=$(
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        CHROME_DEFAULTS_FILE="${FIXTURE_DIR}/defaults-unreadable"
        SCRATCH_DIR="${FIXTURE_DIR}/scratch-q"
        mkdir -p "${SCRATCH_DIR}"
        PATH="${FIXTURE_DIR}/grepfail:${PATH}"
        set +e
        out=$(suppress_permanent_repo 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
)
assert_eq "case q: an unreadable defaults file is refused (rc 1)" \
    "1" "$(echo "${res_q}" | sed -n '1p')"
assert_contains "case q: the refusal explains it could not read the file" \
    "Could not read" "${res_q}"
assert_eq "case q: the unreadable file is left untouched, not clobbered" \
    "KEEP_ME=1" "$(cat "${FIXTURE_DIR}/defaults-unreadable")"

# ── Case r: browser present + gpg absent still exits 0 ─────────
# require_tools moved off the top of main() onto the install path, because
# curl/gpg are only needed there. This pins that: a host that already HAS a
# runnable browser must succeed even with no gpg on PATH. Before the move it
# exited 1 for want of a tool it was never going to use.
root_r="${FIXTURE_DIR}/root-r"
mkdir -p "${root_r}/etc/apt/sources.list.d" "${root_r}/usr/share/keyrings" "${root_r}/bin"
# Mirror the real PATH into a fixture bin, MINUS exactly curl and gpg. Mirroring
# and subtracting (rather than allow-listing the handful of tools the script is
# thought to need) is what keeps this case honest: an allow-list turns any tool
# the script legitimately gains into a spurious failure that looks like the
# regression this case exists to catch. It has to be absence of curl/gpg that
# fails it, and nothing else.
while IFS= read -r d; do
    [ -d "$d" ] || continue
    for p in "$d"/*; do
        if [ ! -x "$p" ] || [ -d "$p" ]; then continue; fi
        b=$(basename -- "$p")
        # curl/gpg: the absence under test. Browser names: this case supplies its
        # OWN fake browser below, and mirroring a real one from the host would
        # both defeat that and (being a root-owned symlink target) silently
        # swallow the fake — the fixture would then exercise the host's actual
        # Chrome and pass for entirely the wrong reason.
        case "$b" in
            curl|gpg|gpg2|gpgv) continue ;;
            google-chrome|google-chrome-stable|chromium|chromium-browser|chrome) continue ;;
            sudo) continue ;;   # replaced by an unprivileged shim below
        esac
        [ -e "${root_r}/bin/${b}" ] || ln -sf "$p" "${root_r}/bin/${b}"
    done
done <<< "$(printf '%s\n' "$PATH" | tr ':' '\n')"
rm -f "${root_r}/bin/google-chrome"
cat > "${root_r}/bin/google-chrome" <<'EOF'
#!/bin/bash
echo "Fake Chrome 999.0.0.0"
EOF
chmod +x "${root_r}/bin/google-chrome"

# An unprivileged `sudo` shim. Passing SUDO="" is NOT enough here: this case
# executes the script rather than sourcing it, so resolve_sudo runs and
# overwrites SUDO with the real sudo — which made an earlier draft of this case
# perform genuine root-owned writes into the fixture (and leave them behind for
# the cleanup trap to choke on). The shim keeps resolve_sudo's logic exercised
# while confining every "privileged" write to files this user owns.
cat > "${root_r}/bin/sudo" <<'EOF'
#!/bin/bash
while [ "$#" -gt 0 ]; do
    case "$1" in -n|-E|-H) shift ;; --) shift; break ;; *) break ;; esac
done
exec "$@"
EOF
chmod +x "${root_r}/bin/sudo"
# Guard the guard: if curl/gpg leaked into the mirror the case proves nothing.
if PATH="${root_r}/bin" command -v gpg >/dev/null 2>&1 || PATH="${root_r}/bin" command -v curl >/dev/null 2>&1; then
    echo "FAIL: case r: fixture PATH still exposes curl/gpg — the case would pass vacuously"
    fail_count=$((fail_count + 1))
fi
set +e
out_r=$(
    PATH="${root_r}/bin"
    export PATH
    # REMOTE_CONTAINERS is pinned empty: without it this case exercises the
    # container arm on a devcontainer and the non-container arm on CI, so the
    # two environments silently test different code — exactly the dependence
    # that made case o fail on a GitHub runner.
    unset REMOTE_CONTAINERS
    VESPASIAN_TEST_ROOT="${root_r}" \
    bash "${SCRIPT_DIR}/install-chrome.sh" 2>&1
)
rc_r=$?
set -e
assert_eq "case r: browser present + no gpg/curl on PATH still exits 0" "0" "${rc_r}"
assert_contains "case r: it reports the existing browser rather than a missing tool" \
    "already present" "${out_r}"

# ── Case o2: the NON-container early exit leaves the host alone ─
# The mirror of case o, and the arm that regressed. On a machine that is not a
# throwaway image the early exit must NOT delete the package's apt source or
# updater (they are not ours), must NOT exit 1 for finding them, and must say so.
# An earlier version of this fix gated the removal on in_container() but left
# verify_install checking those same paths unconditionally, so a developer's
# machine with a normally-installed Chrome got a hard failure. Only the pair of
# cases o + o2 pins both arms.
plant_phone_home
rm -f "${root_n}/.dockerenv"
res_o2=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    PATH="${FIXTURE_DIR}/bin:${PATH}"
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    CHROME_CANDIDATES=("${FIXTURE_DIR}/fakebin/google-chrome")
    set +e
    out=$(main 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case o2: non-container early exit still succeeds (rc 0)" \
    "0" "$(echo "${res_o2}" | sed -n '1p')"
assert_contains "case o2: it says it is leaving the package's artifacts alone" \
    "Not a container" "${res_o2}"
if [ -f "${root_n}/etc/cron.daily/google-chrome" ] && \
   [ -f "${root_n}/etc/apt/sources.list.d/google-chrome.list" ]; then
    echo "PASS: case o2: the package's apt source and updater SURVIVE outside a container"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case o2: the early exit deleted package-owned artifacts on a non-container host"
    fail_count=$((fail_count + 1))
fi
# And the script's OWN temp artifacts are still torn down on this path.
if [ ! -e "${root_n}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" ]; then
    echo "PASS: case o2: this script's own temporary apt source is still removed"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case o2: a temporary apt source survived the non-container early exit"
    fail_count=$((fail_count + 1))
fi
# No version record on a run that installed nothing.
if [ ! -e "${root_n}/usr/share/vespasian/chrome-version" ]; then
    echo "PASS: case o2: no version record written on a no-install run"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case o2: the no-touch early exit wrote a version record"
    fail_count=$((fail_count + 1))
fi

# ── Case t: VESPASIAN_TEST_ROOT containment ────────────────────
# The seam prefixes every system path this script writes, so a value that
# RESOLVES to the real root removes the confinement it exists to provide.
# Each row pins WHICH guard fired, not merely that something did: asserting the
# shared token "VESPASIAN_TEST_ROOT" would let the charset guard take credit for
# rejecting a traversal, leaving the traversal guard itself unproven.
t_root="${FIXTURE_DIR}/root-t"
mkdir -p "${t_root}"
ln -sfn / "${FIXTURE_DIR}/root-symlink-to-slash"

# bad_root <TAB> expected-substring of the refusal
while IFS=$'\t' read -r bad_root want; do
    [ -n "${bad_root}" ] || continue
    # An empty `want` means the row lost its tab (an editor converting tabs to
    # spaces is the realistic way), and `grep -qF -- ""` matches ANY output — so
    # the row would silently degrade from "the right guard fired" to "something
    # fired". Refuse the row instead of letting it pass vacuously.
    if [ -z "${want}" ]; then
        echo "FAIL: case t: table row for '${bad_root}' has no expected-message column (tab lost?)"
        fail_count=$((fail_count + 1))
        continue
    fi
    set +e
    out_t=$(VESPASIAN_TEST_ROOT="${bad_root}" bash "${INSTALL_SCRIPT}" --help 2>&1)
    rc_t=$?
    set -e
    if [ "${rc_t}" -ne 0 ] && printf '%s' "${out_t}" | grep -qF -- "${want}"; then
        echo "PASS: case t: refuses '${bad_root}' via the expected guard (${want})"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case t: '${bad_root}' rc=${rc_t}, expected refusal containing [${want}], got: $(printf '%s' "${out_t}" | tail -1)"
        fail_count=$((fail_count + 1))
    fi
done <<EOF
${t_root}/../..	must not contain a ".." component
/tmp/../..	must not contain a ".." component
${FIXTURE_DIR}/root-symlink-to-slash	resolves to the filesystem root
/	resolves to the filesystem root
//	resolves to the filesystem root
${FIXTURE_DIR}/root-symlink-to-slash/nonexistent	must be an existing directory
${FIXTURE_DIR}/definitely-not-created	must be an existing directory
relative/path	must be an absolute path
/tmp/has space	characters outside
EOF

# ...and a legitimate fixture root must still be accepted, or the guard has
# simply broken the seam every other case depends on.
set +e
out_t_ok=$(VESPASIAN_TEST_ROOT="${t_root}" bash "${INSTALL_SCRIPT}" --help 2>&1)
rc_t_ok=$?
set -e
assert_eq "case t: a normal fixture root is still accepted" "0" "${rc_t_ok}"
# A trailing slash is a normal spelling and must not be refused.
set +e
out_t_sl=$(VESPASIAN_TEST_ROOT="${t_root}/" bash "${INSTALL_SCRIPT}" --help 2>&1)
rc_t_sl=$?
set -e
assert_eq "case t: a fixture root with a trailing slash is accepted" "0" "${rc_t_sl}"

# ── Case u: cleanup_all removes phone-home after a FAILED install ─
# The EXIT trap is the only thing that clears the package's artifacts when an
# install dies after dpkg ran the postinst — the one window in which a failed
# run ADDS standing egress. It is gated on INSTALL_ATTEMPTED, so both arms need
# pinning: set, it must clean; unset, it must not touch a thing.
root_u="${FIXTURE_DIR}/root-u"
mkdir -p "${root_u}/etc/apt/sources.list.d" "${root_u}/etc/cron.daily" "${root_u}/usr/share/keyrings"
plant_u() {
    printf 'deb x\n' > "${root_u}/etc/apt/sources.list.d/google-chrome.list"
    printf 'deb x\n' > "${root_u}/etc/apt/sources.list.d/google-chrome.sources"
    : > "${root_u}/etc/cron.daily/google-chrome"
    : > "${root_u}/usr/share/keyrings/google-chrome.gpg"
}

plant_u
(
    VESPASIAN_TEST_ROOT="${root_u}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh disable=SC1091
    source "${INSTALL_SCRIPT}"
    SUDO=""
    SCRATCH_DIR="${FIXTURE_DIR}/scratch-u"; mkdir -p "$SCRATCH_DIR"
    INSTALL_ATTEMPTED=1
    cleanup_all
) >/dev/null 2>&1
left_u=0
for f in "${root_u}/etc/apt/sources.list.d/google-chrome.list" \
         "${root_u}/etc/apt/sources.list.d/google-chrome.sources" \
         "${root_u}/etc/cron.daily/google-chrome" \
         "${root_u}/usr/share/keyrings/google-chrome.gpg"; do
    [ -e "$f" ] && left_u=1
done
assert_eq "case u: a failed install (INSTALL_ATTEMPTED=1) has its phone-home artifacts cleaned" \
    "0" "${left_u}"

plant_u
(
    VESPASIAN_TEST_ROOT="${root_u}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh disable=SC1091
    source "${INSTALL_SCRIPT}"
    SUDO=""
    SCRATCH_DIR="${FIXTURE_DIR}/scratch-u2"; mkdir -p "$SCRATCH_DIR"
    INSTALL_ATTEMPTED=0
    cleanup_all
) >/dev/null 2>&1
kept_u=1
for f in "${root_u}/etc/apt/sources.list.d/google-chrome.list" \
         "${root_u}/etc/cron.daily/google-chrome"; do
    [ -e "$f" ] || kept_u=0
done
assert_eq "case u: a run that never installed (INSTALL_ATTEMPTED=0) touches nothing" \
    "1" "${kept_u}"

# ── Case s: log helpers must not interpret escapes in DATA ─────
# log_* render externally-derived strings (gpg stderr, browser paths, apt
# errors). They were `echo -e`, which interprets \e/\n INSIDE the message, so a
# hostile or merely odd string could forge log lines or drive the terminal.
# They are printf '%b[TAG]%b %s' now — colour via %b, message via %s. Without
# this case, reverting to `echo -e` leaves every other assertion green.
log_probe=$(
    # shellcheck source=common.sh
    source "${SCRIPT_DIR}/common.sh"
    log_info 'literal\e[31m and \n stay literal'
    log_fail 'second\tline'
)
if printf '%s' "${log_probe}" | grep -qF 'literal\e[31m and \n stay literal'; then
    echo "PASS: case s: log_info prints backslash escapes in the message literally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case s: log_info interpreted escapes in the message (echo -e regression?)"
    fail_count=$((fail_count + 1))
fi
if printf '%s' "${log_probe}" | grep -qF 'second\tline'; then
    echo "PASS: case s: log_fail prints backslash escapes in the message literally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case s: log_fail interpreted escapes in the message (echo -e regression?)"
    fail_count=$((fail_count + 1))
fi
# The colour codes must STILL render, or the fix broke the logs to pass the test.
if printf '%s' "${log_probe}" | grep -q "$(printf '\033')"; then
    echo "PASS: case s: colour escapes still render (fix did not strip formatting)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case s: colour escapes no longer render"
    fail_count=$((fail_count + 1))
fi

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "install-chrome-selftest: ${pass_count} passed, ${fail_count} failed, ${skip_count} skipped"
# A SKIP is a coverage hole, not a pass. Cases j/j2 are the only assertions that
# cover the trust anchor's SUCCESS path, and they self-skip when the Google key
# cannot be fetched — so an egress change (or a proxy, or an offline runner)
# could silently disarm the pin's positive coverage while the suite stayed green.
# Failing on any skip converts that into a visible CI failure.
# Only j/j2 skipping is a coverage hole worth failing on: they are the sole
# assertions covering the trust anchor's SUCCESS path. Cases a2 (needs a git
# checkout) and l (cannot run as root) skip for environmental reasons that are
# legitimate — a tarball export, or CI running as root — and failing the whole
# suite for those turns a valid environment into a red build. The counter is
# scoped so the policy means what it says.
if [ "${trust_anchor_skips}" -ne 0 ]; then
    echo "install-chrome-selftest: FAIL — the trust-anchor success path (j/j2) was skipped; that is a coverage hole."
    echo "  (cases j/j2 read test/fixtures/google-linux-signing-key.asc; if that fixture is"
    echo "   missing or empty the trust anchor's success path is untested — fix it, do not skip.)"
    exit 1
fi
if [ "${skip_count}" -ne 0 ]; then
    echo "install-chrome-selftest: NOTE — ${skip_count} case(s) skipped for environmental reasons"
    echo "  (a2 needs a git checkout; l cannot run as root). Not a failure, but not coverage either."
fi
[ "${fail_count}" -eq 0 ]
