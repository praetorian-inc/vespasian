#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Self-test for test/install-chrome.sh (LAB-5064). Plain bash, no framework —
# same shape as preflight-selftest.sh: source the script (its BASH_SOURCE guard
# means main() does not run), then exercise the pure helpers.
#
# Covered (TEST-004: kept in sync with the actual case letters, not just the
# ones with the most interesting rationale): argument handling (a-c),
# architecture resolution (d), the pinned signing-key trust anchor including
# its success path from a committed fixture (e-f, j-j2), the symlink/hardlink
# guard on the defaults file and its rewrite branches (g, k, q), container
# detection for the apt-cache wipe (h), the unsupported-arch diagnostic (i),
# the phone-home removal and verification chain on both the container and
# non-container arms (n/n3a/n4a/n4b, o, o2), resolve_sudo/require_apt/curl+gpg
# refusals (l, m), INT/TERM signal handling (p, p2), the browser-present-
# without-curl/gpg path (r), the log helpers' escape hardening (s),
# VESPASIAN_TEST_ROOT containment (t), cleanup_all's failed-install arm (u),
# in_container() gating the MAIN install path (v), verify_apt_origin's accept
# and reject arms (w), cleanup_all's step order/errexit tolerance (x), the
# pre-install origin gate (y), and the install lock's symlink/hardlink guard
# and acquisition-failure handling (z). Each of those is behavioural: it fails
# if its check is removed, which an assertion on the message alone does not.
#
# NOT COVERED HERE: the actual download, `apt-get install`, and the system-wide
# mutations that follow a successful key verification. Those need root,
# network, and destructive changes to system state. This suite still drives
# main() end to end on several cases (o, o2, r, v, w, y, z) via a PASSTHROUGH
# sudo shim that execs its argument as the unprivileged test user rather than
# via a REAL sudo/root escalation — no privileged command actually runs here.
# That region is covered instead by the `install-chrome-e2e` CI job, which
# runs the installer end-to-end as root in a disposable container.
#
# This suite needs NO network: the Google key it verifies against is the
# committed fixture test/fixtures/google-linux-signing-key.asc. It DOES need an
# ambient gpg (to verify that fixture the same way install_pinned_key would);
# an absent gpg is treated as a coverage-hole skip of the trust anchor's
# success path (cases j/j2), not a silent abort (TEST-005).
#
# Usage: bash test/install-chrome-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install-chrome.sh"

# Pin the probe budget for the whole suite (TEST-005 / TEST-014). This suite
# sources install-chrome.sh, which sources common.sh's detect_chrome_binary /
# chrome_runnable — the same probe preflight-selftest.sh pins for exactly this
# reason: an ambient CHROME_PROBE_TIMEOUT (e.g. CHROME_PROBE_TIMEOUT=0.0001)
# makes every real probe against a fixture browser time out and report it as
# "not runnable", turning cases that expect a healthy browser into false
# failures. MEASURED: with that override exported ambiently, this suite drops
# from 180/0 to 144/19 passed/failed.
export CHROME_PROBE_TIMEOUT=2

# Assertion accounting (TEST-008), same idiom as preflight-selftest.sh's
# EXPECTED_ASSERTIONS: deleting a whole case (security-relevant or otherwise)
# left this suite green as long as every SURVIVING case still passed, because
# nothing compared the total against any expectation.
#
# TEST-001: enforced UNCONDITIONALLY, against pass+fail+skip_credit. An earlier
# version gated the pin on `skip_count -eq 0`, which switched the whole check off on
# any host missing one of the tools a skip arm depends on — precisely the hosts most
# likely to differ from the author's. Each skip() call instead carries a CREDIT equal
# to the number of assertions its block would have made, so the total is invariant
# across degraded hosts and a deleted case still fails the suite. The trust anchor's
# own skip is additionally a hard failure via trust_anchor_skips, independently of
# this pin.
#
# Round-15 review: 234 -> 238 (later 239, then 244; see the register below).
# MEASURED by running the suite, not derived — the
# per-task deltas in that round's plan were written without shell access and were
# explicitly flagged untrusted. The +4:
#   +1  case f's curl-pin count now matches EVERY syntactic form of curl in
#       install_pinned_key (assignment-form `k=$(curl …)` and `$SUDO curl`, not
#       just a line-leading `curl`), and its fidelity sentinel was widened in the
#       same edit — the sentinel reuses the count's own regex, so widening one
#       without the other would have left it silently not covering
#   +1  case f5b's apt-get count now scans the WHOLE script rather than main()'s
#       body, closing the bare-`apt-get` and helper-nested evasions
#   +2  case bp3, pinning that the consolidated chrome_probe_budget still
#       validates the budget for _bounded_probe as chrome_runnable does
# See the credit register below for the matching skip_credit accounting.
EXPECTED_ASSERTIONS=244

pass_count=0
fail_count=0
skip_count=0
skip_credit=0
skipped_labels=""
# Skips that represent a real coverage hole rather than an unsuitable
# environment. Only the trust-anchor success path qualifies; see the policy at
# the end of this file.
trust_anchor_skips=0

# Completion sentinel (TEST-009): flips to 1 immediately before the Summary
# section runs. Every case in this file is a flat sequence under this script's
# own `set -euo pipefail`, and several source a production script that calls
# `exit` (install-chrome.sh's parse_args on --help; today every such source
# sits inside a `( ... )` subshell, but nothing enforces that staying true) --
# so a stray `exit 0` anywhere before the summary yields PASS lines, no
# summary, and a green CI check with however many cases never ran. The EXIT
# trap below turns that into a red build by checking the flag was actually
# set before the fixture cleanup it already does.
SUITE_COMPLETED=0

# A check that could not run is NOT a pass. Tallied separately so the summary
# distinguishes "verified" from "unverifiable here", following the
# pass/fail/skip precedent in test/run-live-tests.sh's result table.
# TEST-003: every skip carries a CREDIT — the number of assertions that block
# would have added on a fully-equipped host — so the accounting sentinel below
# can be enforced unconditionally instead of switching itself off the moment
# anything skips. Every skip trigger in this file is ambient (a git checkout, the
# key fixture, gpg, running as root), so the old `skip_count -eq 0` guard meant
# the pin stopped being checked precisely on the hosts most likely to differ from
# the author's, silently.
#
# CREDIT REGISTER — round-15 review, TEST-002. The previous version of this note
# had drifted into being wrong in three ways at once, which is the defect that
# review round recorded: it listed five credits totalling 33 when seven call
# sites declared 35; it omitted case bp entirely (bp landed in d38a81b, the same
# commit that moved the pin to 234, while this note was last touched in eee71b1);
# and it cited "192 on a full run" against a pin that was by then 234. A stale
# provenance record is worse than none — it reads as evidence.
#
# The register is now derived from the call sites themselves, so it can be
# checked against the source rather than believed:
#
#   a2    = 1    not inside a git work tree
#   f2    = 4    gpg absent (real, unstubbed gpg -- unlike f2b's
#                                        own stubbed gpg, which needs no gate)
#   f4    = 3    gpg absent (same reason as f2) OR timeout(1) absent: f4 drives
#                main(), whose require_tools() refuses a timeout-less host
#   j/j2  = 14   key fixture missing or empty
#   j/j2  = 14   gpg absent  (mutually exclusive with the above,
#                                        so j/j2 contributes 14, never 28)
#   l     = 3    running as root
#   v     = 12   needs the same key fixture / gpg as j/j2, OR timeout(1): v
#                drives main(), same require_tools() refusal as f4
#   y     = 3    needs the same key fixture / gpg as j/j2, OR timeout(1): y
#                drives main(), same require_tools() refusal as f4
#   bp    = 4    no timeout/gtimeout on PATH
#   z4    = 3    no flock on PATH (the concurrency half only; z4's source-level
#                ordering assertions need nothing ambient and always run)
#
# Maximum skip_credit on a maximally-degraded host: 1+4+3+14+3+12+3+4+3 = 47.
# f4, v and y each have TWO independent triggers (gpg/fixture, or timeout) but
# one skip() call apiece, so a host missing both tools still credits 3/12/3 --
# never double.
# EXPECTED_ASSERTIONS above is 244, MEASURED on a fully-equipped host (pass+fail+
# skip_credit with every arm live). It moved 238 -> 239 when case cr landed, and
# 239 -> 244 when case z4 gained the four ordering assertions plus the per-site
# register check. Every figure quoted below was re-measured at 244, not carried
# forward: this note has already gone stale twice by being carried forward.
#
# PROVENANCE, stated precisely rather than blanket-claimed as "MEASURED":
#   * f2 = 4, f4 = 3, j/j2 = 14, v = 12 and y = 3 were FORCED this round on a
#     host with no gpg on PATH (every PATH entry containing a gpg binary was
#     replaced by a symlink farm omitting it). RE-MEASURED at the current pin:
#     208 passed, 0 failed, 5 skipped; 208 + 0 + 36 = 244, so the pin held and
#     these five credits are measured rather than declared. f2 and f4 are the
#     two this list previously omitted altogether -- they were added in abc36ed,
#     after the round-8 measurement that the rest of the register inherits.
#   * a2 = 1 and l = 3 remain INHERITED from the round-8 measurement and were
#     not re-forced. Forcing them needs a non-git checkout and a root shell
#     respectively, neither of which the equipped-host run can produce.
#   * f4 = 3, v = 12 and y = 3 were ALSO forced this round on a host with no
#     timeout and no gtimeout on PATH. RE-MEASURED at the current pin: 222
#     passed, 0 failed, 4 skipped, and 222 + 0 + (3+12+3+4) = 244. Before those
#     three gained the timeout gate the
#     same host reported 223/11/1 (at the then-current pin of 238) -- 11 hard
#     failures naming the fingerprint
#     check, the cache wipe and the version record, plus 3 vacuous passes.
#   * bp = 4 is NEW this round: it was 2 (covering case bp2's two assertions) and
#     case bp3 added two more when the probe budget was consolidated into
#     common.sh's chrome_probe_budget. It WAS forced on the timeout-less host
#     described above, where it skipped and credited 4.
# When you next touch a skip arm, force it and read the delta rather than
# extending this list by inference — that inference is exactly what decayed here.
skip() {
    local credit=${2:-0}
    echo "SKIP: $1"
    skip_count=$((skip_count + 1))
    skip_credit=$((skip_credit + credit))
    # Record WHICH case skipped. The summary NOTE used to name a hardcoded pair
    # (a2 and l) whatever the real cause was, so every skip arm added since --
    # f2, f4, j/j2, v, y, bp -- was misattributed by it. `${1%%:*}` takes the
    # "case X" prefix each message already starts with; the full cause stays on
    # the SKIP line itself.
    skipped_labels="${skipped_labels}${skipped_labels:+, }${1%%:*}"
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

# Extract a function's body from the installer with COMMENT LINES REMOVED.
#
# TEST-003 / TEST-005: every source-grep assertion in this file previously ran
# against the raw body, and a comment satisfies a grep exactly as well as the call
# it names. Mutation-proven, twice: stripping `timeout -k 30 300` from the real
# `apt-get update` and leaving the literal on a comment line inside main() kept the
# suite at 201/0, exit 0 while printing "both apt-get calls are bounded"; the same
# trick on `apt-get install` additionally made six of case u's and case v3's
# position anchors resolve to the comment. An assertion that affirms an absent
# control is worse than no assertion, because it is read as proof.
#
# One helper rather than the same two-line pipeline at five call sites: getting the
# strip wrong at any single site silently reintroduces the whole defect class, which
# is the failure mode this file has now hit in three consecutive review rounds.
fn_code() {
    awk "/^$1\\(\\) \\{/,/^\\}/" "${INSTALL_SCRIPT}" | grep -vE '^[[:space:]]*#' || true
}

# SEC-BE-001: pin the fixture tree's parent instead of inheriting $TMPDIR. This
# directory holds ~20 stub EXECUTABLES (curl, sudo, dpkg, gpg, apt-get, browser
# stand-ins) and every case prepends it to PATH before invoking the script under
# test, so whatever lives at those paths runs. Under the default sticky /tmp the
# 0700 directory mktemp creates is safe; the residual was an inherited TMPDIR
# pointing at a non-sticky directory a second local user can write to, who could
# then rename the tree away between creation and use and choose the binaries the
# suite executes. Pinning /tmp closes that without validating anything, and /tmp's
# sticky bit is the property being relied on.
FIXTURE_DIR=$(TMPDIR=/tmp mktemp -d)
# INT/TERM as well as EXIT, mirroring install-chrome.sh: a bash signal handler
# returns to the interrupted code, so without an explicit exit a Ctrl-C left the
# fixture tree behind in $TMPDIR. Exiting from the handler routes through EXIT so
# cleanup runs exactly once.
trap 'rm -rf "${FIXTURE_DIR}"; if [ "${SUITE_COMPLETED}" != 1 ]; then echo "install-chrome-selftest: FAIL — suite terminated before reaching the summary; results are incomplete" >&2; exit 1; fi' EXIT
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
    skip "case a2: committed-mode check (not a git checkout)" 1
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
#
# The stub goes in a dir of its OWN (bin-d), not a shared FIXTURE_DIR/bin --
# see case i's comment on why a shared bin poisons later cases (TEST-002). A
# dpkg last written here for "riscv64" must never leak into any later case.
mkdir -p "${FIXTURE_DIR}/bin-d"
make_dpkg_stub() {
    local dir="${2:-${FIXTURE_DIR}/bin-d}"
    mkdir -p "${dir}"
    cat > "${dir}/dpkg" <<EOF
#!/bin/bash
[ "\$1" = "--print-architecture" ] && { echo "$1"; exit 0; }
exit 1
EOF
    chmod +x "${dir}/dpkg"
}

run_resolve_arch() {
    make_dpkg_stub "$1"
    # shellcheck disable=SC2030,SC2031  # subshell-local PATH is the isolation mechanism, not a bug
    (
        PATH="${FIXTURE_DIR}/bin-d:${PATH}"
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

# f2 and f4 below drive install_pinned_key's REAL gpg --import/--fingerprint
# calls against a real (committed, but non-Google) fixture key -- unlike f2b,
# which stubs its own gpg on PATH and so needs no real binary at all. Without
# this gate, an absent gpg makes --import fail as "command not found" before
# ever reaching the fingerprint comparison, and the assertions that check for
# "fingerprint mismatch" text fail while blaming the pin for what is actually
# a missing tool (f0/f1/f2b are unaffected: f0 never calls gpg at all, f1's
# "not a valid PGP key" message happens to match either failure reason, and
# f2b's gpg is its own stub). Local to this section rather than reusing case
# j/j2's `have_gpg` below: that variable is not computed until
# AFTER this section runs.
HAS_GPG=true
if ! command -v gpg >/dev/null 2>&1; then
    HAS_GPG=false
fi

# Cases below that drive main() (f4, v, y) need timeout(1) as well as gpg.
# require_tools() REFUSES a host without timeout -- deliberately, because it
# bounds the privileged apt calls that run while a temporary trusted Google
# source is live in /etc -- so main() exits at that check before reaching the
# behaviour those cases assert. MEASURED on a PATH with neither timeout nor
# gtimeout: 11 assertions failed naming the fingerprint check, the cache wipe
# and the version record, and 3 more PASSED VACUOUSLY (main() never ran, so
# "removed artifacts it does not own" held trivially) -- the exact defect class
# this suite exists to catch, reproduced by the suite itself.
# j/j2 is deliberately NOT gated on this: it exercises install_pinned_key
# directly rather than through main(), and it passes on a timeout-less host.
HAS_TIMEOUT=true
if ! command -v timeout >/dev/null 2>&1; then
    HAS_TIMEOUT=false
fi

# Names whichever precondition is actually absent, so a skip on a degraded host
# reports its own cause instead of being re-diagnosed by hand.
main_deps_missing() {
    local m=""
    [ "${HAS_GPG}" = true ]     || m="gpg"
    [ "${HAS_TIMEOUT}" = true ] || m="${m:+${m} and }timeout"
    # Cases v and y gate on have_real_key, which is gpg AND a non-empty key
    # fixture -- so the fixture is a third possible cause and reporting only the
    # two TOOLS printed "missing: none" on the one host shape where the message
    # mattered most. GOOGLE_KEY_CACHE is not assigned until later in this file,
    # so a caller that runs BEFORE that point (case f4) has no fixture clause to
    # report and correctly omits it; the :- keeps that from tripping `set -u`.
    if [ -n "${GOOGLE_KEY_CACHE:-}" ] && [ ! -s "${GOOGLE_KEY_CACHE:-}" ]; then
        m="${m:+${m} and }the key fixture"
    fi
    printf '%s' "${m:-none}"
}

# ── Case f: install_pinned_key REFUSES an unexpected key ───────
# The behavioural test for the trust anchor. install_pinned_key fetches the key
# with curl, so a curl stub on PATH makes both failure arms reachable with no
# network and no root — every rejection path returns before the first $SUDO.
#
# This is the case that fails if the fingerprint comparison is removed.
run_install_pinned_key() {
    local stub_body=$1
    # Own bin (bin-f), not the shared FIXTURE_DIR/bin -- TEST-002. This curl
    # stub is rewritten on every f0/f1/f2 call, so a shared dir would make each
    # call's curl silently depend on whatever the PREVIOUS f-case last wrote.
    mkdir -p "${FIXTURE_DIR}/bin-f"
    cat > "${FIXTURE_DIR}/bin-f/curl" <<EOF
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
    chmod +x "${FIXTURE_DIR}/bin-f/curl"
    # shellcheck disable=SC2030,SC2031  # subshell-local PATH/SUDO overrides are deliberate
    (
        PATH="${FIXTURE_DIR}/bin-f:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO="/bin/false"   # any privileged call would fail loudly, proving we never reach one
        ARCH="amd64"
        set +e
        # Own scratch dir (f-scratch), not the shared FIXTURE_DIR (TEST-006):
        # install_pinned_key derives its gpg homedir/keyring from "$1", and
        # case j below needs its OWN gpg keyring, untainted by whatever key
        # f0/f1/f2 last imported into one shared here.
        mkdir -p "${FIXTURE_DIR}/f-scratch"
        out=$(install_pinned_key "${FIXTURE_DIR}/f-scratch" 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

# f0: curl itself fails to fetch the key (network error, DNS failure, a
# downgrade redirect refused by --proto/--proto-redir). This is the FIRST and
# EARLIEST branch of install_pinned_key, and it was untested: f1/f2's stub
# below always exits 0, so a fetch failure never happened in this suite.
res_f0=$(run_install_pinned_key 'exit 22')
assert_eq "case f: a curl fetch failure is refused (rc 1)" "1" "$(echo "${res_f0}" | sed -n '1p')"
assert_contains "case f: the fetch failure is diagnosed, not blamed on the key" \
    "Could not fetch Google's signing key" "${res_f0}"
if printf '%s' "${res_f0}" | grep -q "matches pinned fingerprint"; then
    echo "FAIL: case f: a fetch failure did not stop before ever verifying a key"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case f: a fetch failure stops before any verification or \$SUDO call"
    pass_count=$((pass_count + 1))
fi

# Structural companion to f0: --proto/--proto-redir are what turn a downgrade
# REDIRECT into a hard failure rather than a silent cleartext fetch, and no
# behavioural test can see them -- a working curl fetches the key with or
# without them, so f0's stub (which ignores every flag but -o) cannot tell the
# difference either. Grepping the source is the only practical guard for a
# flag whose absence is silent, same spirit as case p's trap-line check below.
#
# TEST-003: scoped to install_pinned_key()'s body, and to the curl line within
# it, the same way f5 below scopes to main(). The previous version grepped the
# WHOLE file, which a comment mentioning the flags satisfies just as well as the
# call itself -- so deleting the flags from the fetch and leaving any prose
# behind kept this assertion GREEN while affirmatively reporting that a
# TLS-downgrade control was in place. An assertion that certifies an absent
# security control is worse than no assertion, because it is read as proof.
# `|| true` guards the extraction so an empty match FAILS the check below rather
# than aborting the suite under its own `set -euo pipefail`.
key_fn_body_f=$(fn_code install_pinned_key)
# TEST-002: EVERY curl in the function must be pinned, not merely one of them. The
# previous form piped all curl lines into a single `grep -qF`, which answers "does
# any line carry the flags" — so adding a second, unpinned fetch (a mirror fallback,
# a retry with different options) would have been accepted silently. Only one curl
# exists today, so nothing was mis-certified; this closes the semantics rather than
# a present-day hole. Counted rather than any-matched so the two numbers must agree.
#
# TEST-003: `curl` is matched as a command word ANYWHERE on the line, not only as
# the line's first word — the previous regex left an assignment-form fetch
# (`key_alt=$(curl ...)`) uncounted, so a second, unpinned fetch added that way
# left both the count and the pinned-count at 1 and this assertion still printed
# "all 1 curl fetch(es) ... pinned". One shared variable feeds the count, the
# pinned-count, AND the fidelity sentinel below, so widening the match can never
# leave the sentinel behind pattern-coupled to the old, narrower regex.
curl_word_re='(^|[[:space:]]|\$\(|\(|\||&&|;)curl[[:space:]]'
# ROUND-16: join line continuations FIRST, exactly as the f5b apt-get counter
# does (see script_body_f5_joined below). Without it the two counters disagree on
# what a "call" is: install_pinned_key's curl spans continuation lines and its
# --proto/--proto-redir pins sit on a LATER line than the `curl` word, so the
# pinned-count grep could only ever see them by accident of line splitting. The
# asymmetry was the defect -- one sibling counting logical lines and the other
# physical ones.
#
# KNOWN LIMITATION, stated rather than papered over: this counts `curl` in
# command position by prefix, so a prose mention inside a same-line string (e.g.
# log_info "... please curl the key ...") would also count. fn_code strips only
# whole-line comments. No such string exists in install_pinned_key today, and the
# fix -- parsing shell quoting -- is far more machinery than the risk warrants.
#
# ROUND-16 CORRECTION: joining alone was a COVERAGE REGRESSION, caught by
# mutation. `grep -c` counts LINES, so once continuations are joined a single
# line can hold BOTH an unpinned and a pinned curl and be counted once:
#
#   curl http://mirror/key.pub || \        unjoined: lines=2 pinned=1 -> FAIL (right)
#   curl --proto '=https' ... https://...    joined: lines=1 pinned=1 -> PASS (wrong)
#
# That reverts the guarantee TEST-002 established and neutralizes TEST-003's
# widening, since ||, && and ; are exactly the operators that precede a `\`.
# So: join continuations (flags stay with their command), THEN split on command
# separators (each command is counted on its own). Both properties hold at once.
# The same normalisation is applied to the f5b apt-get counter below, which had
# the identical latent bug.
normalize_commands() {
    awk '{ if (sub(/\\$/, "")) { printf "%s ", $0; next } else { print } }' \
        | sed 's/||/\n/g; s/&&/\n/g; s/;/\n/g; s/|/\n/g'
}
key_fn_body_f_joined=$(printf '%s\n' "${key_fn_body_f}" | normalize_commands)
f_curl_lines=$(printf '%s\n' "${key_fn_body_f_joined}" | grep -cE "$curl_word_re" || true)
f_curl_pinned=$(printf '%s\n' "${key_fn_body_f_joined}" | grep -E "$curl_word_re" \
    | grep -cF -- "--proto '=https' --proto-redir '=https'" || true)
if [ "${f_curl_lines}" -ge 1 ] && [ "${f_curl_lines}" -eq "${f_curl_pinned}" ]; then
    echo "PASS: case f: all ${f_curl_lines} curl fetch(es) in install_pinned_key pin --proto/--proto-redir to https (downgrade redirects refused)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case f: ${f_curl_pinned} of ${f_curl_lines} curl fetch(es) in install_pinned_key pin --proto/--proto-redir to https — an unpinned fetch accepts a downgrade redirect"
    fail_count=$((fail_count + 1))
fi
# Residual, stated honestly rather than implied fixed: a fetch smuggled into a
# helper install_pinned_key() CALLS (rather than performed inline) is still
# invisible here — fn_code is strictly single-function and non-recursive, and
# no extractor in this repo follows transitive callees.

# Fidelity sentinel for the scoping above: if install_pinned_key() is renamed or
# the fetch stops being a `curl` line, the awk/grep pair silently matches nothing
# and the assertion fails for the wrong reason. Pin that the extraction actually
# found the fetch, so a structural drift is reported as drift rather than as a
# missing flag.
if printf '%s' "${key_fn_body_f_joined}" | grep -qE "$curl_word_re"; then
    echo "PASS: case f: the scoped extraction still finds the key-fetch curl in install_pinned_key()"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case f: install_pinned_key() no longer contains a curl line — the --proto check above is now vacuous, fix the extraction rather than deleting it"
    fail_count=$((fail_count + 1))
fi

# f5 (TEST-012): the apt bound (SEC-BE-008/SEC-BE-010) is equally invisible to
# any behavioural stub -- a stubbed apt-get exits the same whether or not it
# is ever actually wrapped in `timeout`/`DPkg::Lock::Timeout`. Grepping the
# source is the same idiom as f0-f4 above, for the same reason: the flag's
# absence is silent.
#
# Scoped to main()'s own body (TEST-001), the same way case p scopes its trap
# greps: grepping the whole file let a commented-out or documentation
# occurrence of the same text satisfy the check without the call itself ever
# running inside main(). `|| true` guards the assignment for the same reason
# case p's does -- an empty match must FAIL the assertions below, not abort
# the suite under this file's own `set -euo pipefail`.
main_body_f5=$(fn_code main)
if printf '%s' "${main_body_f5}" | grep -qE '\$SUDO timeout -k 30 300 apt-get update -qq -o DPkg::Lock::Timeout=120' \
    && printf '%s' "${main_body_f5}" | grep -qE '\$SUDO timeout -k 30 900 apt-get install ' \
    && printf '%s' "${main_body_f5}" | grep -qF -- '-o DPkg::Lock::Timeout=120 google-chrome-stable'; then
    echo "PASS: case f: both apt-get calls are bounded by timeout -k 30 and DPkg::Lock::Timeout, with \$SUDO privileging the timeout itself (SEC-BE-010)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case f: an apt-get call in main() lost its timeout/-k/DPkg::Lock::Timeout bound, or \$SUDO no longer wraps timeout"
    fail_count=$((fail_count + 1))
fi

# f5b (TEST-002 / TEST-004): the three checks above are EXISTENCE-based -- they
# prove the two apt-get calls that exist today are bounded, but say nothing
# about a THIRD, unbounded one added alongside them. MUTATION-PROVEN: adding a
# third `$SUDO apt-get install -y --no-install-recommends some-extra-package`
# inside main() left this suite at 214 passed / 0 failed, exit 0 while f5 kept
# printing "both apt-get calls are bounded" — true of the two calls it already
# knew about, silent on the one it didn't. Counted the same way case f's
# curl-fetch check above counts curl lines against pinned-curl lines, so any
# THIRD (or further) apt-get call has to carry the bound too, not just the
# first two.
#
# TEST-004: scanned over the WHOLE SCRIPT, not fn_code main. Two further
# mutations were verified to defeat a main()-scoped version while the suite
# stayed green: a bare `apt-get install ...` with no `$SUDO` inside main()
# (on the root path $SUDO expands to empty, so it is behaviourally identical
# to the caught form at run time), and a `$SUDO apt-get install ...` as the
# first line of a helper main() calls (suppress_permanent_repo). fn_code is
# strictly single-function and non-recursive, and no extractor in this repo
# follows transitive callees, so this could not be fixed by improving the
# scoped extraction. Comments are stripped exactly as fn_code does (a comment
# satisfies a grep, which is what this suite exists to avoid), and `$SUDO` is
# de-anchored -- but `apt-get` must still be in COMMAND position: a free `.*`
# before it would also match require_tools()'s help string above ("Install
# them first: apt-get install -y ...") and turn this red on correct code.
#
# Line continuations are joined first: apt-get install's DPkg::Lock::Timeout
# bound sits on the CONTINUATION line, not the invocation line, so each call
# has to become exactly one logical line before it can be counted.
# Same join-then-split normalisation as case f above, and for the same reason:
# joining alone let two apt-get calls chained by `&&` across a continuation count
# as one line, so an unbounded call rode along with a bounded one. Verified: a
# two-call continuation counted 1 before this change and 2 after.
script_body_f5_joined=$(grep -vE '^[[:space:]]*#' "${INSTALL_SCRIPT}" | normalize_commands)
# SELF-4: the prefix set is a CHAIN of command words, not a fixed `$SUDO?timeout?`.
# The predecessor required the literal `$SUDO`, so three behaviourally identical
# forms evaded it and measured GREEN with an unbounded call present:
#   sudo apt-get install …          (literal sudo; identical on the unprivileged path)
#   cd /tmp && apt-get install …    (after a && separator)
#   env FOO=1 apt-get install …     (env-prefixed)
# Anchoring on "line start OR a command separator, then any chain of prefix words"
# is complete for command position in a way an enumeration of two prefixes is not.
#
# It must still refuse a match INSIDE a string: require_tools()'s help text
# (`log_info "Install them first: apt-get install -y …"`) contains the words but
# not in command position, and a free `.*` before apt-get would turn this red on
# correct code. Verified against the real script: exactly 2 matches, 0 of them the
# help string; and each of the three evasions above raises the count to 3.
aptget_call_re='(^|[;&|][[:space:]]*)[[:space:]]*(if[[:space:]]+!:?[[:space:]]+)?([[:space:]]*(\$SUDO|sudo|env|timeout|nice|ionice)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+|-[^[:space:]]+[[:space:]]+|[0-9]+[[:space:]]+)*)*apt-get[[:space:]]+(update|install)[[:space:]]'
f5_aptget_lines=$(printf '%s\n' "${script_body_f5_joined}" \
    | grep -cE "$aptget_call_re" || true)
f5_aptget_bounded=$(printf '%s\n' "${script_body_f5_joined}" \
    | grep -E "$aptget_call_re" \
    | grep -F -- 'timeout -k' \
    | grep -cF -- 'DPkg::Lock::Timeout=120' || true)
if [ "${f5_aptget_lines}" -ge 2 ] && [ "${f5_aptget_lines}" -eq "${f5_aptget_bounded}" ]; then
    echo "PASS: case f: all ${f5_aptget_lines} apt-get call(s) in the script carry the DPkg::Lock::Timeout=120 bound (no unbounded call slipped in alongside the two known ones, whether inside main() or a helper it calls)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case f: only ${f5_aptget_bounded} of ${f5_aptget_lines} apt-get call(s) in the script carry the DPkg::Lock::Timeout=120 bound — an unbounded apt-get call is reachable"
    fail_count=$((fail_count + 1))
fi
# Residual, stated honestly: a call smuggled through `eval` or `bash -c` is
# still not counted by a source-text scan.

# Fidelity sentinel for the join+count above, the same idea as case f's curl
# extraction sentinel: if the script's apt-get calls are ever restructured
# (renamed, no longer $SUDO-timeout-prefixed) the extraction would silently
# match nothing and the count-match check above would pass vacuously at 0-of-0.
if [ "${f5_aptget_lines}" -ge 1 ]; then
    echo "PASS: case f: the apt-get call extraction still finds at least one call in the script"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case f: the script no longer contains a \$SUDO timeout ... apt-get call — the bound-count check above is now vacuous, fix the extraction rather than deleting it"
    fail_count=$((fail_count + 1))
fi

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
if [ "${HAS_GPG}" = true ]; then
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
else
    skip "case f2: fingerprint-mismatch diagnosis for an unexpected real key (gpg not found on PATH)" 4
fi

# f2b (TEST-001): a near-miss primary key -- one whose fingerprint shares
# GOOGLE_KEY_FPR's TRAILING 16 HEX CHARS (a 64-bit short key ID) with a
# completely different key otherwise. No two real GPG keys are known to
# collide on a 16-hex-char suffix -- finding one would need on the order of
# 2^64 key generations -- so this drives install_pinned_key's fingerprint
# comparison with a STUBBED gpg (the same idiom case w uses for a stubbed
# apt-cache) instead of a committed fixture key, isolating the comparison
# LOGIC from real cryptography.
#
# Nothing in any of the four suites previously distinguished a full
# 40-hex-char fingerprint pin from a short-key-id (last-16-hex) pin: a
# regression that shortened GOOGLE_KEY_FPR to its last 16 chars, or loosened
# the `grep -qxF` membership check on line 406 to a suffix match, would
# silently accept this key -- and every other 40-char suffix collision along
# with it -- while f2 above (an UNRELATED foreign key with no suffix overlap)
# would still be correctly refused either way, so f2 alone cannot catch this.
near_miss_fpr="DEADBEEFCAFEBABE012345677721F63BD38B4796"  # ends in GOOGLE_KEY_FPR's trailing 16 hex chars
mkdir -p "${FIXTURE_DIR}/bin-f2b"
cat > "${FIXTURE_DIR}/bin-f2b/curl" <<'EOF'
#!/bin/bash
out=""
while [ $# -gt 0 ]; do
    [ "$1" = "-o" ] && { out="$2"; shift 2; continue; }
    shift
done
printf 'dummy key bytes\n' > "$out"
EOF
cat > "${FIXTURE_DIR}/bin-f2b/gpg" <<EOF
#!/bin/bash
case "\$*" in
    *--import*)
        exit 0
        ;;
    *--fingerprint*)
        printf 'pub:-:2048:1:AAAAAAAAAAAAAAAA:::-:::scESC:\n'
        printf 'fpr:::::::::%s:\n' "${near_miss_fpr}"
        exit 0
        ;;
    *--export*)
        printf 'dummy exported key bytes\n'
        exit 0
        ;;
esac
exit 0
EOF
chmod +x "${FIXTURE_DIR}/bin-f2b/curl" "${FIXTURE_DIR}/bin-f2b/gpg"
res_f2b=$(
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    PATH="${FIXTURE_DIR}/bin-f2b:${PATH}"
    SUDO="/bin/false"   # any privileged call would fail loudly, proving we never reach one
    ARCH="amd64"
    set +e
    mkdir -p "${FIXTURE_DIR}/f2b-scratch"
    out=$(install_pinned_key "${FIXTURE_DIR}/f2b-scratch" 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case f: a near-miss key (shares only GOOGLE_KEY_FPR's trailing 16 hex chars) does not succeed (rc 1)" \
    "1" "$(echo "${res_f2b}" | sed -n '1p')"
assert_contains "case f: the near-miss key is diagnosed as a fingerprint mismatch" \
    "fingerprint mismatch" "${res_f2b}"
if printf '%s' "${res_f2b}" | grep -q "matches pinned fingerprint"; then
    echo "FAIL: case f: a near-miss (short-key-id-colliding) key was ACCEPTED -- a truncated pin would be silently exploitable"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case f: a fingerprint that only shares the trailing 16 hex chars is never accepted as matching the pin"
    pass_count=$((pass_count + 1))
fi

# f4 (TEST-004: f3 is intentionally absent, not a removed case -- f0/f1/f2
# cover install_pinned_key's three rejection arms and this is the only other
# f-case, numbered to match its position rather than renumbered to f3):
# main() calls install_pinned_key BEFORE suppress_permanent_repo, so a run
# that never earns trust also never mutates /etc/default (install-chrome.sh's
# own stated ordering rationale). Drives this through main() itself, since that
# is the only call site where the ordering exists at all -- f0-f2 call
# install_pinned_key in isolation and say nothing about it. CHROME_CANDIDATES
# is emptied and a passthrough sudo is supplied so main() reaches the ordered
# pair unprivileged; the curl stub serves the wrong key so install_pinned_key
# fails and the run must stop there.
if [ "${HAS_GPG}" = true ] && [ "${HAS_TIMEOUT}" = true ]; then
    root_f4="${FIXTURE_DIR}/root-f4"
    bin_f4="${FIXTURE_DIR}/bin-f4"
    mkdir -p "${root_f4}" "${bin_f4}"
    printf '#!/bin/bash\nexec "$@"\n' > "${bin_f4}/sudo"
    cat > "${bin_f4}/dpkg" <<'EOF'
#!/bin/bash
[ "$1" = "--print-architecture" ] && { echo amd64; exit 0; }
exit 1
EOF
    cat > "${bin_f4}/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${SCRIPT_DIR}/fixtures/not-google-signing-key.asc' > "\$out"
EOF
    chmod +x "${bin_f4}/sudo" "${bin_f4}/dpkg" "${bin_f4}/curl"
    # NOT the usual `set +e` INSIDE the subshell before calling main(): the ordering
    # property being tested is main()'s reliance on `set -e` ITSELF to abort before
    # suppress_permanent_repo runs (install_pinned_key's failure is a bare
    # statement, not an explicit `if ! ...; then exit 1; fi` check). Disabling
    # errexit before the call -- the pattern every other main()-driving case in
    # this file uses -- would disable it for main()'s own internals too, and
    # install_pinned_key's failure would silently stop aborting the run, which is
    # exactly the ordering swap this case exists to catch. So `set +e` is applied
    # OUTSIDE, around the whole command substitution, the same way case r and case
    # t already do it for a script invocation.
    set +e
    res_f4=$(
        (
            VESPASIAN_TEST_ROOT="${root_f4}"
            export VESPASIAN_TEST_ROOT
            PATH="${bin_f4}:${PATH}"
            # shellcheck source=install-chrome.sh
            source "${INSTALL_SCRIPT}"
            CHROME_CANDIDATES=()
            main
        ) 2>&1
    )
    rc_f4=$?
    set -e
    assert_eq "case f: main() aborts on a fingerprint mismatch before any further mutation (rc 1)" \
        "1" "${rc_f4}"
    assert_contains "case f: the abort is the fingerprint mismatch, not something else" \
        "fingerprint mismatch" "${res_f4}"
    if [ -e "${root_f4}/etc/default/google-chrome" ]; then
        echo "FAIL: case f: /etc/default/google-chrome was written despite never earning trust (ordering swapped?)"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case f: a run that never earns trust never mutates /etc/default (install before suppress)"
        pass_count=$((pass_count + 1))
    fi
else
    skip "case f4: main() ordering guarantee on a fingerprint mismatch ($(main_deps_missing) not found on PATH)" 3
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
# Mode actually achieved on disk (SEC-BE-003) -- a literal `install -m 0644`
# in the source is not evidence of what lands; only stat proves it, same
# reasoning as case j's three keyring/list/pref mode assertions below.
assert_eq "case g: the rewritten defaults file is world-readable but not writable (0644)" \
    "644" "$(stat -c '%a' "${FIXTURE_DIR}/defaults-existing" 2>/dev/null)"

# g3: absent file is created opted-out.
res_g3=$(run_suppress "${FIXTURE_DIR}/defaults-new")
assert_eq "case g: an absent defaults file is created (rc 0)" "0" "$(echo "${res_g3}" | sed -n '1p')"
assert_eq "case g: the created file opts out of the repo" \
    "repo_add_once=false" "$(cat "${FIXTURE_DIR}/defaults-new")"
assert_eq "case g: the newly-created defaults file is world-readable but not writable (0644)" \
    "644" "$(stat -c '%a' "${FIXTURE_DIR}/defaults-new" 2>/dev/null)"

# g4: a hardlinked defaults file is refused (TEST-009). A hardlink is neither
# a symlink nor caught by the [ -L ] guard above, and it defeats that guard
# from the READ side rather than the write side: the `$SUDO grep` inside
# suppress_permanent_repo reads "$f" as root and the unprivileged caller's own
# shell redirects that output into $staged, so a hardlink planted at "$f"
# turns this into an arbitrary root-readable-file read into a caller-owned
# file. This case was previously reachable by no test in either suite:
# deleting the whole nlink block left the suite green.
printf 'KEEP_ME=1\n' > "${FIXTURE_DIR}/defaults-hardlink-victim"
ln -f "${FIXTURE_DIR}/defaults-hardlink-victim" "${FIXTURE_DIR}/defaults-hardlink"
res_g4=$(run_suppress "${FIXTURE_DIR}/defaults-hardlink")
assert_eq "case g: a hardlinked defaults file is refused (rc 1)" \
    "1" "$(echo "${res_g4}" | sed -n '1p')"
assert_contains "case g: the hardlink refusal names the reason" \
    "has multiple hard links" "${res_g4}"
assert_eq "case g: the hardlink victim's content is untouched" \
    "KEEP_ME=1" "$(cat "${FIXTURE_DIR}/defaults-hardlink-victim")"

# g5/g6 (TEST-007): the in-`sh` TOCTOU re-check. g/g4 above drive the OUTER
# [ -L ]/nlink guards, which run once, well before the privileged read. The
# `$SUDO sh -c '...'` block inside suppress_permanent_repo re-checks BOTH
# conditions again, immediately before the read, specifically to close the
# window between those two points — and nothing in any of the four suites ever
# made that window matter: `[ -L "$f" ] && exit 3` and the hard-link re-check
# `&& exit 4` are reachable only if "$f" changes shape AFTER the outer guard
# passes, and no case swapped it there.
#
# This can't use real concurrency without flakiness, so it plants the swap
# deterministically at the one place a swap CAN happen without a race: the
# `$SUDO install -d -- "$(dirname -- "$f")"` call that runs between the outer
# guard and the privileged read. A stubbed `install` performs the swap first,
# then execs the real `install` so the directory step still succeeds — this is
# exactly the race SEC-BE-002 defends against, sequenced rather than timed.
run_suppress_toctou() {
    local f="$1" victim="$2" attack="$3"
    local bin="${FIXTURE_DIR}/bin-toctou-${attack}"
    rm -rf "${bin}"; mkdir -p "${bin}"
    local real_install
    real_install="$(command -v install)"
    case "${attack}" in
        symlink)  printf '#!/bin/bash\nln -sf "%s" "%s"\nexec "%s" "$@"\n' \
                       "${victim}" "${f}" "${real_install}" > "${bin}/install" ;;
        hardlink) printf '#!/bin/bash\nln -f "%s" "%s"\nexec "%s" "$@"\n' \
                       "${victim}" "${f}" "${real_install}" > "${bin}/install" ;;
    esac
    chmod +x "${bin}/install"
    # shellcheck disable=SC2030,SC2031  # subshell-local overrides are deliberate
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        CHROME_DEFAULTS_FILE="${f}"
        SCRATCH_DIR="${FIXTURE_DIR}/scratch"
        mkdir -p "${SCRATCH_DIR}"
        PATH="${bin}:${PATH}"
        set +e
        out=$(suppress_permanent_repo 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

printf 'repo_add_once=true\n' > "${FIXTURE_DIR}/defaults-toctou-symlink"
printf 'root secret content\n' > "${FIXTURE_DIR}/toctou-symlink-victim"
res_g5=$(run_suppress_toctou "${FIXTURE_DIR}/defaults-toctou-symlink" \
    "${FIXTURE_DIR}/toctou-symlink-victim" symlink)
assert_eq "case g: a defaults file swapped to a symlink between the outer guard and the privileged read is refused (rc 1)" \
    "1" "$(echo "${res_g5}" | sed -n '1p')"
assert_contains "case g: the in-sh re-check names the symlink race, not a generic read failure" \
    "became a symlink between the guard and the read" "${res_g5}"
assert_eq "case g: the symlink race's victim content is untouched" \
    "root secret content" "$(cat "${FIXTURE_DIR}/toctou-symlink-victim")"

printf 'repo_add_once=true\n' > "${FIXTURE_DIR}/defaults-toctou-hardlink"
printf 'root secret hardlink content\n' > "${FIXTURE_DIR}/toctou-hardlink-victim"
res_g6=$(run_suppress_toctou "${FIXTURE_DIR}/defaults-toctou-hardlink" \
    "${FIXTURE_DIR}/toctou-hardlink-victim" hardlink)
assert_eq "case g: a defaults file swapped to a hardlink between the outer guard and the privileged read is refused (rc 1)" \
    "1" "$(echo "${res_g6}" | sed -n '1p')"
assert_contains "case g: the in-sh re-check names the hardlink race, not a generic read failure" \
    "gained a hard link between the guard and the read" "${res_g6}"
assert_eq "case g: the hardlink race's victim content is untouched" \
    "root secret hardlink content" "$(cat "${FIXTURE_DIR}/toctou-hardlink-victim")"

# ── Case h: container detection gates the apt-cache wipe ───────
# Wiping /var/lib/apt/lists is safe in a throwaway image and destructive on a
# developer's own machine, so both arms are pinned.
# $1 is a VESPASIAN_TEST_ROOT under which /.dockerenv and/or run/.containerenv
# may or may not exist. $2 is the value to export as REMOTE_CONTAINERS (empty
# means unset), $3 is the value to export as $container (empty means unset).
#
# TEST-010: only two of in_container()'s four probes were ever the deciding
# term in any assertion here — /run/.containerenv and $container were
# reachable from no case at all, so deleting either probe left the whole
# suite green. TEST-006: every probe NOT under test in a given call is
# explicitly cleared (not just left alone), so an ambient REMOTE_CONTAINERS or
# $container (this devcontainer sets the former; some CI runners' own
# containerized job sets the latter) cannot silently satisfy in_container()
# and make an assertion pass for the wrong reason.
run_in_container() {
    # shellcheck disable=SC2030,SC2031  # subshell-local env overrides are deliberate
    (
        VESPASIAN_TEST_ROOT="$1"
        export VESPASIAN_TEST_ROOT
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        if [ -n "$2" ]; then REMOTE_CONTAINERS="$2"; else unset REMOTE_CONTAINERS; fi
        if [ -n "$3" ]; then container="$3"; else unset container; fi
        set +e
        in_container
        printf '%s\n' "$?"
    )
}
mkdir -p "${FIXTURE_DIR}/root-container" "${FIXTURE_DIR}/root-host" \
    "${FIXTURE_DIR}/root-containerenv/run"
touch "${FIXTURE_DIR}/root-container/.dockerenv"
touch "${FIXTURE_DIR}/root-containerenv/run/.containerenv"
assert_eq "case h: /.dockerenv present means container" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-container" "" "")"
assert_eq "case h: /run/.containerenv present means container (TEST-010)" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-containerenv" "" "")"
assert_eq "case h: REMOTE_CONTAINERS set means container" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-host" "true" "")"
assert_eq "case h: \$container set means container (TEST-010)" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-host" "" "podman")"
# TEST-004: every name in the allowlist, not just one. Pinning `podman` alone left
# the other twelve untested — mutation-proven: reducing the case arm to
# `docker | podman)` deleted eleven runtime names and the suite stayed at 201/0,
# exit 0. That matters because SEC-BE-004's own rationale names buildah, kaniko,
# containerd and crio as the reason the allowlist exists, so losing them silently
# is losing the fix. Derived from the source rather than hardcoded here: a
# hand-copied list in the test drifts from the one in the script, which is the
# failure mode this assertion is meant to prevent.
h_names=$(fn_code in_container \
    | sed -n '/case "\${container:-}" in/,/esac/p' \
    | grep -oE '[a-z][a-z0-9-]+' \
    | grep -vE '^(case|container|esac|return|in)$' | sort -u)
if [ -z "${h_names}" ]; then
    echo "FAIL: case h: could not extract in_container's runtime-name allowlist — the per-name assertions below are vacuous"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case h: in_container's runtime-name allowlist extracted from the source"
    pass_count=$((pass_count + 1))
    h_unmatched=""
    for h_name in ${h_names}; do
        [ "$(run_in_container "${FIXTURE_DIR}/root-host" "" "${h_name}")" = "0" ] \
            || h_unmatched="${h_unmatched} ${h_name}"
    done
    if [ -n "${h_unmatched}" ]; then
        echo "FAIL: case h: \$container value(s) in the allowlist NOT treated as a container:${h_unmatched}"
        fail_count=$((fail_count + 1))
    else
        h_count=$(printf '%s\n' ${h_names} | grep -c .)
        echo "PASS: case h: all ${h_count} allowlisted \$container runtime names are treated as a container"
        pass_count=$((pass_count + 1))
    fi
    # And the converse: the allowlist must not have shrunk. Pinned by count so a
    # deletion is caught even though the names themselves are source-derived —
    # without this, dropping eleven names shrinks BOTH the expectation and the
    # evidence, and the loop above passes vacuously on the survivors.
    if [ "$(printf '%s\n' ${h_names} | grep -c .)" -ge 13 ]; then
        echo "PASS: case h: the runtime-name allowlist still carries at least 13 names"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case h: in_container's runtime-name allowlist shrank to $(printf '%s\n' ${h_names} | grep -c .) names (expected >= 13) — SEC-BE-004's buildah/kaniko/containerd/crio coverage may be gone"
        fail_count=$((fail_count + 1))
    fi
fi
# SEC-BE-003: REMOTE_CONTAINERS is now validated the same way $container is,
# instead of accepting any non-empty value. "false" is the case that mattered: a
# tool (or a developer) setting it explicitly to false previously WON the
# destructive branch — remove_phone_home plus the apt-lists wipe — on a machine
# that is not a container at all, because only emptiness was tested.
assert_eq "case h: REMOTE_CONTAINERS=false is NOT treated as a container (SEC-BE-003)" \
    "1" "$(run_in_container "${FIXTURE_DIR}/root-host" "false" "")"
assert_eq "case h: an unrecognized REMOTE_CONTAINERS value is NOT treated as a container" \
    "1" "$(run_in_container "${FIXTURE_DIR}/root-host" "some-unrelated-value" "")"
assert_eq "case h: REMOTE_CONTAINERS=1 IS treated as a container (truthy spelling)" \
    "0" "$(run_in_container "${FIXTURE_DIR}/root-host" "1" "")"

# SEC-BE-004: an unrelated tool exporting a same-named, non-empty $container
# (a Makefile variable, a CI shim) must NOT win the destructive branch on a
# developer's own machine -- only a recognized runtime name may.
assert_eq "case h: an unrecognized \$container value is NOT treated as a container" \
    "1" "$(run_in_container "${FIXTURE_DIR}/root-host" "" "some-unrelated-value")"
assert_eq "case h: neither signal means NOT a container (cache is left alone)" \
    "1" "$(run_in_container "${FIXTURE_DIR}/root-host" "" "")"

# ── Case i: the unsupported-arch diagnostic reaches the operator ─
# Case d proves resolve_arch REJECTS an unsupported arch; it says nothing about
# whether the operator ever learns why. That gap was real: log_fail wrote to
# stdout and main()'s `ARCH="$(resolve_arch)"` captured it, so the script died
# with an empty terminal. Run the SCRIPT (not the function) so the call site is
# in scope, and assert the reason appears in the combined output.
#
# CHROME_CANDIDATES is emptied rather than relying on PATH isolation: the array
# holds ABSOLUTE paths (/usr/bin/google-chrome …), which `command -v` resolves
# regardless of PATH, so a host with a real Chrome would take the idempotency
# exit and never reach resolve_arch. Overriding the array is what makes this case
# give the same answer on a browserless CI runner and on a dev box with Chrome.
mkdir -p "${FIXTURE_DIR}/root-arch"
# main() reaches resolve_arch only after resolve_sudo, require_apt and
# require_tools. Those are stubbed here for FIDELITY, not for portability.
#
# Measured, because the obvious story is wrong: without these stubs the case
# still passes on a PATH with no apt-get at all. It passes because the harness
# runs `set +e` before calling main(), which disables errexit, so require_apt's
# `return 1` is DISCARDED and execution walks on to resolve_arch anyway. That
# makes the case green by way of a control flow production can never take —
# under the script's own `set -euo pipefail`, that same failure aborts.
# Satisfying the prerequisites for real means the case reaches resolve_arch the
# way a real run would.
# The stubs go in a directory of their OWN, not the shared FIXTURE_DIR/bin.
# Writing them into the shared bin poisoned every LATER case: case j needs the
# REAL gpg to verify the pinned key, and a `gpg` that exits 0 made its four
# trust-anchor assertions fail. Scoping them to this case is the difference
# between fixing an isolation problem and moving it downstream.
#
# dpkg's stub lives in THIS SAME directory now too (TEST-002), rather than in
# the shared FIXTURE_DIR/bin used by case d's run_resolve_arch: a `dpkg` last
# written by case d for a DIFFERENT arch, resolved here only because it
# happened to still be on PATH, is exactly the undeclared cross-case ordering
# dependency this suite already fixed once for apt-get/curl/gpg/sudo above.
ARCH_STUBS="${FIXTURE_DIR}/bin-arch"
mkdir -p "${ARCH_STUBS}"
make_dpkg_stub riscv64 "${ARCH_STUBS}"
# sudo must actually chain through to its argument; the rest need only exist
# and succeed, because this case is about what happens AFTER them.
printf '#!/bin/bash\nexec "$@"\n' > "${ARCH_STUBS}/sudo"
for _t in apt-get curl gpg; do
    printf '#!/bin/bash\nexit 0\n' > "${ARCH_STUBS}/${_t}"
done
chmod +x "${ARCH_STUBS}"/*
unset _t
arch_result=$(
    VESPASIAN_TEST_ROOT="${FIXTURE_DIR}/root-arch"
    export VESPASIAN_TEST_ROOT
    # bin-arch first (this case's own stubs, dpkg included), then the host (for
    # coreutils). Prefixed rather than replaced: replacing PATH outright broke
    # the script at `dirname` before main() ran.
    PATH="${ARCH_STUBS}:${PATH}"
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
# TEST-005: this suite's header claims it needs no network, but says nothing
# about gpg -- and the very next line calls it unconditionally. An absent gpg
# used to abort the whole script here under `set -euo pipefail` (a bare
# command-not-found inside a pipeline feeding a command substitution), killing
# the run mid-suite with no summary and no indication that everything from
# here on -- the trust anchor, the phone-home chain, containment, cleanup_all
# -- never executed. Checked explicitly so the gap becomes a diagnosable skip
# (and, per the policy below, a hard FAIL) instead of a silent abort.
if command -v gpg >/dev/null 2>&1; then
    have_gpg=1
else
    have_gpg=0
fi
if [ "${have_gpg}" -eq 1 ] && [ -s "${GOOGLE_KEY_CACHE}" ]; then
    have_real_key=1
else
    have_real_key=0
fi

# Guard the fixture itself: if it ever stops containing the pinned primary key,
# cases j/j2 would be testing nothing. Assert that before relying on it.
if [ "${have_real_key}" -eq 1 ]; then
    # `|| true` (TEST-007): a bare `var=$(pipeline)` assignment takes the
    # pipeline's own exit status under this file's `set -euo pipefail`, so a
    # gpg failure here would abort the WHOLE SUITE at this line rather than
    # let the assertion below report it as a FAIL — the same load-bearing
    # pattern case p's comment documents for its own extraction.
    fixture_fprs=$(gpg --homedir "${GNUPG_ASSERT_HOME}" --show-keys --with-colons \
        --with-fingerprint "${GOOGLE_KEY_CACHE}" 2>/dev/null \
        | awk -F: '$1=="pub"{w=1} $1=="fpr"&&w{print $10; w=0}') || true
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
    mkdir -p "${root_j}/etc/apt/sources.list.d" "${root_j}/usr/share/keyrings" \
             "${root_j}/etc/apt/preferences.d"
    # bin-j, not the shared FIXTURE_DIR/bin (TEST-002): j2's curl below serves a
    # DIFFERENT bundle, and a shared dir would make whichever ran last leak into
    # any case added after them.
    res_j=$(
        VESPASIAN_TEST_ROOT="${root_j}"
        export VESPASIAN_TEST_ROOT
        mkdir -p "${FIXTURE_DIR}/bin-j"
        PATH="${FIXTURE_DIR}/bin-j:${PATH}"
        cat > "${FIXTURE_DIR}/bin-j/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${GOOGLE_KEY_CACHE}' > "\$out"
EOF
        chmod +x "${FIXTURE_DIR}/bin-j/curl"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        ARCH="amd64"
        set +e
        # Own scratch dir (j-scratch), not the shared FIXTURE_DIR (TEST-006):
        # cases f0/f1/f2 above pass install_pinned_key that same shared dir,
        # and it accumulates a gpg keyring across calls (gpg --import is
        # additive, nothing here deletes between cases). f2 imports a valid
        # but NON-Google key there, so case j — unscoped — was silently
        # verifying its fingerprint check against a keyring that already held
        # a second, unrelated key, not the single-key input its own comments
        # assume. Scoped, this case's gpg homedir starts empty every run,
        # mirroring round 5's fix for the same hazard in the PATH stub bins.
        mkdir -p "${FIXTURE_DIR}/j-scratch"
        out=$(install_pinned_key "${FIXTURE_DIR}/j-scratch" 2>&1)
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
    # Modes actually achieved on disk -- a literal `install -m 0644` in the
    # source is not evidence of what lands; only stat proves it. All three of
    # install_pinned_key's `install -m 0644` writes are checked, not just the
    # keyring: TMP_LIST and TMP_PREF get the same treatment and had no assertion.
    assert_eq "case j: the installed keyring is world-readable but not writable (0644)" \
        "644" "$(stat -c '%a' "${root_j}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" 2>/dev/null)"
    assert_eq "case j: the installed apt source list is world-readable but not writable (0644)" \
        "644" "$(stat -c '%a' "${root_j}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" 2>/dev/null)"
    assert_eq "case j: the installed origin pin is world-readable but not writable (0644)" \
        "644" "$(stat -c '%a' "${root_j}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref" 2>/dev/null)"
    # The pin's CONTENT, not just its mode (TEST-007). Asserting 0644 alone left
    # the file's actual policy untested: rewriting it to `Pin: origin
    # evil.example.com` / `Pin-Priority: 1` keeps the mode at 0644 and stays
    # green, while the constraint that makes `apt-get install` resolve the
    # package NAME from the origin this script vouched for is gone. That pin is
    # one of the two layers of the "the package came from where we verified"
    # guarantee, so it needs its own assertion rather than a mode proxy.
    # `|| true` (TEST-007): when install_pinned_key legitimately FAILS (e.g. a
    # fingerprint mismatch), none of these files exist, `cat` exits non-zero,
    # and this bare assignment would otherwise abort the WHOLE SUITE right
    # here under `set -euo pipefail` — MUTATION-VERIFIED: without this guard,
    # a wrong GOOGLE_KEY_FPR ran only 52 of 180 assertions before the suite
    # died mid-case, with no summary line.
    pref_j=$(cat "${root_j}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref" 2>/dev/null) || true
    assert_contains "case j: the origin pin names the package it constrains" \
        "Package: google-chrome-stable" "${pref_j}"
    assert_contains "case j: the origin pin constrains the package to dl.google.com" \
        "Pin: origin dl.google.com" "${pref_j}"
    assert_contains "case j: the origin pin outranks an already-installed version (1001)" \
        "Pin-Priority: 1001" "${pref_j}"
    # Only the pinned key may end up in the keyring: exporting the whole fetched
    # bundle would hand apt every key the endpoint chose to return.
    # `|| true` (TEST-007): same reasoning as pref_j above — a missing keyring
    # (install_pinned_key failed) must not abort the suite here.
    exported_fprs=$(gpg --homedir "${GNUPG_ASSERT_HOME}" --show-keys --with-colons --with-fingerprint \
        "${root_j}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" 2>/dev/null \
        | awk -F: '$1=="pub"{want=1} $1=="fpr" && want{print $10; want=0}') || true
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
        mkdir -p "${FIXTURE_DIR}/bin-j2"
        PATH="${FIXTURE_DIR}/bin-j2:${PATH}"
        cat > "${FIXTURE_DIR}/bin-j2/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${FIXTURE_DIR}/two-key-bundle.asc' > "\$out"
EOF
        chmod +x "${FIXTURE_DIR}/bin-j2/curl"
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
    # `|| true` (TEST-007): same reasoning as pref_j/exported_fprs above.
    j2_fprs=$(gpg --homedir "${GNUPG_ASSERT_HOME}" --show-keys --with-colons --with-fingerprint \
        "${root_j2}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" 2>/dev/null \
        | awk -F: '$1=="pub"{want=1} $1=="fpr" && want{print $10; want=0}') || true
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
    if [ "${have_gpg}" -eq 1 ]; then
        skip "case j/j2: trust-anchor success path (fixture test/fixtures/google-linux-signing-key.asc missing or empty)" 14
    else
        skip "case j/j2: trust-anchor success path (gpg not found on PATH)" 14
    fi
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
assert_eq "case k: the appended-to defaults file is world-readable but not writable (0644)" \
    "644" "$(stat -c '%a' "${FIXTURE_DIR}/defaults-no-key" 2>/dev/null)"

# ── Case l: resolve_sudo and require_apt refusals ───────────────
# Both are pure precondition paths that return before any mutation, and neither
# had a test. The selftest header claims every rejection path is reachable
# unprivileged — these make that true rather than aspirational.
run_resolve_sudo() {
    # $2 (optional): a file to capture resolve_sudo's own diagnostic in. It is
    # NOT captured via `out=$(resolve_sudo ...)` -- a command substitution
    # always forks ITS OWN subshell, so any SUDO=... assignment resolve_sudo
    # makes would be lost the instant that substitution returns, and every
    # caller downstream would see "unset" regardless of which branch actually
    # ran. Redirecting straight to a file keeps resolve_sudo in THIS subshell,
    # so its SUDO assignment survives to the printf below.
    local msgfile="${2:-/dev/null}"
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        PATH="$1"
        set +e
        resolve_sudo >"${msgfile}" 2>&1
        printf '%s\n%s\n' "$?" "${SUDO-unset}"
    )
}
mkdir -p "${FIXTURE_DIR}/empty-bin"
# The refusal path needs `id -u` to resolve to the REAL uid so the root check
# inside resolve_sudo evaluates as DESIGNED. With a bare empty PATH, `id` is
# unresolvable: `$(id -u)` returns empty, `[ "" -eq 0 ]` errors "integer
# expression expected" and returns non-zero -- which happens to still take the
# "not root" branch, so the case passed, but by a degenerate route that never
# actually asked whether we are root. Stubbing `id` (not adding real coreutils
# to PATH, which would risk making a real `sudo` resolvable too) fixes that
# while keeping sudo itself genuinely absent.
real_uid=$(id -u)
cat > "${FIXTURE_DIR}/empty-bin/id" <<EOF
#!/bin/bash
[ "\$1" = "-u" ] && { echo "${real_uid}"; exit 0; }
exit 1
EOF
chmod +x "${FIXTURE_DIR}/empty-bin/id"

# A PATH with neither sudo nor anything else: non-root + no sudo must refuse.
# Both output lines are asserted, not just rc: the previous version discarded
# resolve_sudo's own diagnostic entirely (`>/dev/null 2>&1`), so the message
# was unverified, and nothing ever read the SUDO line the harness captured.
if [ "$(id -u)" -ne 0 ]; then
    msgfile_l="${FIXTURE_DIR}/resolve_sudo_l.msg"
    res_l=$(run_resolve_sudo "${FIXTURE_DIR}/empty-bin" "${msgfile_l}")
    assert_eq "case l: non-root without sudo refuses (rc 1)" \
        "1" "$(echo "${res_l}" | sed -n '1p')"
    assert_eq "case l: SUDO is left unset on the refusal path" \
        "unset" "$(echo "${res_l}" | sed -n '2p')"
    assert_contains "case l: the refusal names the reason" \
        "Not running as root and sudo is unavailable" "$(cat "${msgfile_l}" 2>/dev/null)"
else
    skip "case l: non-root sudo refusal (running as root)" 3
fi

# The two SUCCESS paths had no coverage at all -- neither is hypothetical, both
# feed every privileged command in the script. sudo-present: SUDO must become
# exactly the string "sudo", not merely rc 0 (rc 0 alone is also what a broken
# resolve_sudo that always "succeeds" would produce).
mkdir -p "${FIXTURE_DIR}/sudo-bin"
cp "${FIXTURE_DIR}/empty-bin/id" "${FIXTURE_DIR}/sudo-bin/id"
printf '#!/bin/bash\nexec "$@"\n' > "${FIXTURE_DIR}/sudo-bin/sudo"
chmod +x "${FIXTURE_DIR}/sudo-bin/sudo"
res_l3=$(run_resolve_sudo "${FIXTURE_DIR}/sudo-bin")
assert_eq "case l: non-root with sudo available succeeds (rc 0)" \
    "0" "$(echo "${res_l3}" | sed -n '1p')"
assert_eq "case l: SUDO is set to the sudo prefix" \
    "sudo" "$(echo "${res_l3}" | sed -n '2p')"

# Root branch: `id -u` stubbed to report 0 (fakeroot-style), which resolve_sudo
# must accept WITHOUT ever calling sudo -- no sudo binary is on this PATH at
# all, so a resolve_sudo that skipped the root check would fail here instead.
mkdir -p "${FIXTURE_DIR}/root-bin"
cat > "${FIXTURE_DIR}/root-bin/id" <<'EOF'
#!/bin/bash
[ "$1" = "-u" ] && { echo 0; exit 0; }
exit 1
EOF
chmod +x "${FIXTURE_DIR}/root-bin/id"
res_l4=$(run_resolve_sudo "${FIXTURE_DIR}/root-bin")
assert_eq "case l: a root uid short-circuits before sudo is even checked (rc 0)" \
    "0" "$(echo "${res_l4}" | sed -n '1p')"
assert_eq "case l: SUDO is the empty prefix when already root" \
    "" "$(echo "${res_l4}" | sed -n '2p')"

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
             "${root_n}/usr/share/keyrings" "${root_n}/etc/apt/preferences.d"
    # Both the legacy .list and the deb822 .sources the current package writes.
    # TMP_PREF (the origin pin) is planted alongside TMP_LIST/TMP_KEYRING since
    # cleanup_apt_wiring and verify_install's temp-artifact loop now cover all
    # three.
    touch "${root_n}/etc/apt/sources.list.d/google-chrome.list" \
          "${root_n}/etc/apt/sources.list.d/google-chrome.sources" \
          "${root_n}/etc/cron.daily/google-chrome" \
          "${root_n}/usr/share/keyrings/google-chrome.gpg" \
          "${root_n}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" \
          "${root_n}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" \
          "${root_n}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref"
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
              usr/share/keyrings/google-chrome-vespasian-temp.gpg \
              etc/apt/preferences.d/google-chrome-vespasian-temp.pref; do
    if [ -e "${root_n}/${tmpart}" ]; then
        echo "FAIL: case n: cleanup_apt_wiring left ${tmpart} behind"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case n: cleanup_apt_wiring unlinked ${tmpart}"
        pass_count=$((pass_count + 1))
    fi
done

# n3a: verify_install must FAIL when a PHONE-HOME artifact survives, and that
# failure must be DISTINCT from the temporary-artifact failure below (TEST-007).
# The old case n3 planted BOTH sets of files via plant_phone_home, so
# verify_install always exited at the EARLIER temporary-artifact loop and the
# PHONE_HOME_PATHS loop this case exists to cover was never reached; the
# needle "still present" matched the earlier message too, so the case passed
# either way. This fixture plants ONLY the PHONE_HOME_PATHS entries -- no
# vespasian-temp files -- so the earlier loop passes clean and execution
# actually reaches the phone-home loop. in_container()'s audit is gated on
# in_container(), so the container arm is pinned explicitly, same as case o.
rm -rf "${root_n}"
mkdir -p "${root_n}/etc/apt/sources.list.d" "${root_n}/etc/cron.daily" \
         "${root_n}/usr/share/keyrings"
touch "${root_n}/etc/apt/sources.list.d/google-chrome.list" \
      "${root_n}/etc/apt/sources.list.d/google-chrome.sources" \
      "${root_n}/etc/cron.daily/google-chrome" \
      "${root_n}/usr/share/keyrings/google-chrome.gpg"
: > "${root_n}/.dockerenv"
res_n3a=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    unset container
    PATH="${FIXTURE_DIR}/fakebin:${PATH}"
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    SUDO=""
    set +e
    out=$(verify_install 2>&1)
    printf '%s\n%s\n' "$?" "${out}"
)
assert_eq "case n3a: verify_install fails when a phone-home artifact survives (rc 1)" \
    "1" "$(echo "${res_n3a}" | sed -n '1p')"
assert_contains "case n3a: verify_install names the phone-home artifact distinctly" \
    "Phone-home artifact still present" "${res_n3a}"

# n3b: verify_install must FAIL when its OWN temporary apt artifact survives --
# the OTHER half of the split, and the arm the old n3 was accidentally testing
# every time. Fixture plants ONLY TMP_LIST/TMP_KEYRING/TMP_PREF, no
# PHONE_HOME_PATHS, so this is reached regardless of in_container().
rm -rf "${root_n}"
mkdir -p "${root_n}/etc/apt/sources.list.d" "${root_n}/usr/share/keyrings" \
         "${root_n}/etc/apt/preferences.d"
touch "${root_n}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" \
      "${root_n}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" \
      "${root_n}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref"
res_n3b=$(
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
assert_eq "case n3b: verify_install fails when a temporary apt artifact survives (rc 1)" \
    "1" "$(echo "${res_n3b}" | sed -n '1p')"
assert_contains "case n3b: verify_install names the temporary artifact distinctly" \
    "Temporary apt artifact still present" "${res_n3b}"

# n4a/n4b: verify_install must PASS once the chain has actually cleaned up, on
# BOTH arms -- and each arm's success message must be asserted EXACTLY, not
# via the ambiguous needle "left behind" that matches both of verify_install's
# success messages (TEST-008). The old case n4 asserted only "left behind"
# without pinning which arm ran, so its result silently depended on whether
# the runner happened to export REMOTE_CONTAINERS (true in this devcontainer,
# unset on a bare GitHub runner) -- exercising different production code
# depending on who ran it, same divergence case o already had to fix.
plant_phone_home
: > "${root_n}/.dockerenv"
res_n4a=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    unset container
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
assert_eq "case n4a: verify_install passes on a clean tree, container arm (rc 0)" \
    "0" "$(echo "${res_n4a}" | sed -n '1p')"
assert_contains "case n4a: the container arm reports its exact success message" \
    "No Google apt source, keyring, or update pinger left behind" "${res_n4a}"

plant_phone_home
rm -f "${root_n}/.dockerenv"
res_n4b=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    unset container
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
assert_eq "case n4b: verify_install passes on a clean tree, non-container arm (rc 0)" \
    "0" "$(echo "${res_n4b}" | sed -n '1p')"
assert_contains "case n4b: the non-container arm reports its exact (different) success message" \
    "No temporary apt artifacts left behind" "${res_n4b}"
assert_contains "case n4b: the non-container arm explains why package artifacts are unaudited" \
    "not audited (not a container)" "${res_n4b}"

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
#
# Own dir (bin-o), not the shared FIXTURE_DIR/bin (TEST-002): case o2 below
# installs its OWN sudo shim rather than inheriting this one, so the two cases
# do not silently depend on which order they run in.
mkdir -p "${FIXTURE_DIR}/bin-o"
cat > "${FIXTURE_DIR}/bin-o/sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF
chmod +x "${FIXTURE_DIR}/bin-o/sudo"

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
    unset container
    PATH="${FIXTURE_DIR}/bin-o:${PATH}"
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

# ── Case o2: the NON-container early exit leaves the host alone ─
# The mirror of case o, and the arm that regressed. On a machine that is not a
# throwaway image the early exit must NOT delete the package's apt source or
# updater (they are not ours), must NOT exit 1 for finding them, and must say so.
# An earlier version of this fix gated the removal on in_container() but left
# verify_install checking those same paths unconditionally, so a developer's
# machine with a normally-installed Chrome got a hard failure. Only the pair of
# cases o + o2 pins both arms.
#
# TEST-002: this installs its OWN sudo shim (bin-o2) rather than inheriting
# case o's (bin-o). The two cases sharing one bin was an undeclared ordering
# dependency -- reordering or deleting case o would have silently changed what
# case o2 executes as, without any assertion here noticing.
mkdir -p "${FIXTURE_DIR}/bin-o2"
cat > "${FIXTURE_DIR}/bin-o2/sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF
chmod +x "${FIXTURE_DIR}/bin-o2/sudo"

plant_phone_home
rm -f "${root_n}/.dockerenv"
res_o2=$(
    VESPASIAN_TEST_ROOT="${root_n}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    unset container
    PATH="${FIXTURE_DIR}/bin-o2:${PATH}"
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
#
# TEST-009: the extraction used to grep the WHOLE FILE, so a trap statement
# sitting in a function main() never calls (e.g. a helper the traps were moved
# into but never wired up) satisfied every assertion below just as well as the
# real ones inside main(). Anchoring the extraction to main()'s own body closes
# that: a trap outside the range main() actually executes can no longer count.
#
# `|| true` is load-bearing, not decoration: if a mutation removes every trap
# from main()'s body, grep finds zero matches and exits 1, and under this
# file's own `set -euo pipefail` that pipeline failure would silently ABORT
# THE WHOLE SUITE right here -- no summary, no FAIL line, the exact anti-
# pattern TEST-005 exists to prevent, just relocated to this assignment.
# Falling back to an empty trap_setup instead lets every assertion below
# evaluate against "no traps found" and FAIL individually, which is what
# should happen when main() no longer installs its signal handlers.
trap_setup=$(awk '/^main\(\) \{/,/^\}/' "${INSTALL_SCRIPT}" | grep -E "^ *trap " || true)
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

# p2: a RUNTIME complement to the structural check above, closing the one gap
# that text-matching main()'s body cannot: a trap statement can sit textually
# inside main() (so it satisfies the awk-scoped grep above) and still never
# execute, e.g. wrapped in a branch main() never takes. Driving a real SIGINT/
# SIGTERM is out (see the note above -- it hung the suite twice); this
# doesn't drive a signal at all. It overrides detect_chrome_binary AFTER
# sourcing the script -- bash resolves function calls by name at call time, so
# main() invokes THIS version -- to snapshot the shell's ACTUAL trap table
# (`trap -p`) the instant main() reaches its first call to it, which is
# immediately after main()'s own `trap ... EXIT/INT/TERM` statements and
# before anything needing curl/gpg/apt-get. The override also reports a
# browser present, so main() takes the harmless early exit right after.
# VERIFIED to catch what the structural check above cannot: wrapping the three
# `trap` statements in `if false; then ... fi` (still textually inside
# main()) leaves the grep-based check green but this probe's output empty.
run_trap_probe() {
    (
        # This SELFTEST script sets its own EXIT/INT/TERM traps at file scope
        # (near the top, for its own FIXTURE_DIR cleanup), and subshells
        # INHERIT signal traps from their parent unless cleared. install-
        # chrome.sh's INT/TERM bodies (`exit 130` / `exit 143`) are byte-
        # identical to this harness's own, so without this reset the probe
        # below would "see" the HARNESS's ambient traps and pass even when
        # main() never installs its own -- measured: it did, on first draft,
        # for exactly the INT/TERM assertions (the EXIT trap bodies differ
        # between the two scripts, so that one was never masked). Clearing
        # first makes every trap this probe reports attributable to main().
        trap - EXIT INT TERM
        VESPASIAN_TEST_ROOT="$1"
        export VESPASIAN_TEST_ROOT
        PATH="${FIXTURE_DIR}/bin-p:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        # shellcheck disable=SC2317  # invoked indirectly, by main() calling this name dynamically
        detect_chrome_binary() {
            trap -p
            printf '/bin/true\n'
            return 0
        }
        set +e
        main 2>&1
    )
}
mkdir -p "${FIXTURE_DIR}/root-p-trap" "${FIXTURE_DIR}/bin-p"
printf '#!/bin/bash\nexec "$@"\n' > "${FIXTURE_DIR}/bin-p/sudo"
chmod +x "${FIXTURE_DIR}/bin-p/sudo"
trap_probe=$(run_trap_probe "${FIXTURE_DIR}/root-p-trap")
assert_contains "case p2 (runtime): cleanup_all is actually installed on EXIT" \
    "trap -- 'cleanup_all' EXIT" "${trap_probe}"
assert_contains "case p2 (runtime): SIGINT is actually wired to exit 130" \
    "trap -- 'exit 130' SIGINT" "${trap_probe}"
assert_contains "case p2 (runtime): SIGTERM is actually wired to exit 143" \
    "trap -- 'exit 143' SIGTERM" "${trap_probe}"

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
    unset container
    VESPASIAN_TEST_ROOT="${root_r}" \
    bash "${SCRIPT_DIR}/install-chrome.sh" 2>&1
)
rc_r=$?
set -e
assert_eq "case r: browser present + no gpg/curl on PATH still exits 0" "0" "${rc_r}"
assert_contains "case r: it reports the existing browser rather than a missing tool" \
    "already present" "${out_r}"

# ── Case s: log helpers must not interpret escapes in DATA ─────
# log_* render externally-derived strings (gpg stderr, browser paths, apt
# errors). They were `echo -e`, which interprets \e/\n INSIDE the message, so a
# hostile or merely odd string could forge log lines or drive the terminal.
# They are printf '%b[TAG]%b %s' now — colour via %b, message via %s. Without
# this case, reverting to `echo -e` leaves every other assertion green.
# TEST-011: round 4 hardened log_header too ("was still `echo -e`-ing its
# argument while its four siblings were hardened to printf %s"), but no
# assertion was added for it, and this probe only ever drove log_info/log_fail
# -- log_header, log_ok and log_warn stayed unproven. log_ok and log_warn are
# not cosmetic gaps either: report_browser_prerequisite renders a filesystem
# path through exactly one of them (`log_ok "Browser: $chrome_bin"` or the
# not-runnable branch), so those are the two that render externally-derived
# data most often in this script.
log_probe=$(
    # shellcheck source=common.sh
    source "${SCRIPT_DIR}/common.sh"
    log_info 'literal\e[31m and \n stay literal'
    log_fail 'second\tline'
    log_header 'header\e[31m stays literal'
    log_ok 'ok\e[31m stays literal'
    log_warn 'warn\e[31m stays literal'
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
if printf '%s' "${log_probe}" | grep -qF 'header\e[31m stays literal'; then
    echo "PASS: case s: log_header prints backslash escapes in the message literally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case s: log_header interpreted escapes in the message (echo -e regression?)"
    fail_count=$((fail_count + 1))
fi
if printf '%s' "${log_probe}" | grep -qF 'ok\e[31m stays literal'; then
    echo "PASS: case s: log_ok prints backslash escapes in the message literally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case s: log_ok interpreted escapes in the message (echo -e regression?)"
    fail_count=$((fail_count + 1))
fi
if printf '%s' "${log_probe}" | grep -qF 'warn\e[31m stays literal'; then
    echo "PASS: case s: log_warn prints backslash escapes in the message literally"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case s: log_warn interpreted escapes in the message (echo -e regression?)"
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

# SEC-BE-006: this trap-fired removal is now ALSO gated on in_container(), so
# the container arm has to be pinned deterministically rather than relying on
# whatever REMOTE_CONTAINERS happens to be exported as on the machine running
# this suite (set in this devcontainer, unset on a bare GitHub runner).
: > "${root_u}/.dockerenv"

plant_u
(
    VESPASIAN_TEST_ROOT="${root_u}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    unset container
    # shellcheck source=install-chrome.sh disable=SC1091
    source "${INSTALL_SCRIPT}"
    SUDO=""
    # This case drives cleanup_all() directly, bypassing main()'s own lock
    # acquisition, so LOCK_HELD has to be pinned by hand to simulate the
    # normal case under test here: a run that legitimately held the lock
    # (SEC-BE-008). The lock-not-held arms are covered separately.
    LOCK_HELD=1
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
assert_eq "case u: a failed install (INSTALL_ATTEMPTED=1) in a container has its phone-home artifacts cleaned" \
    "0" "${left_u}"

# The NON-container arm of the same guard (SEC-BE-006): a failed install must
# NOT strip a working Chrome's update channel outside a container — dpkg's
# postinst plants these artifacts DURING apt-get, so `apt-get install`
# succeeding followed by an abort (verify_apt_origin returning non-zero is one
# such abort, and it is exactly this reachable) must leave them in place on a
# developer's own machine. No case in this suite (root_u has no .dockerenv
# from here on, and the two ambient signals are unset) covered this before.
rm -f "${root_u}/.dockerenv"
plant_u
(
    VESPASIAN_TEST_ROOT="${root_u}"
    export VESPASIAN_TEST_ROOT
    unset REMOTE_CONTAINERS
    unset container
    # shellcheck source=install-chrome.sh disable=SC1091
    source "${INSTALL_SCRIPT}"
    SUDO=""
    LOCK_HELD=1
    SCRATCH_DIR="${FIXTURE_DIR}/scratch-u4"; mkdir -p "$SCRATCH_DIR"
    INSTALL_ATTEMPTED=1
    cleanup_all
) >/dev/null 2>&1
kept_u4=1
for f in "${root_u}/etc/apt/sources.list.d/google-chrome.list" \
         "${root_u}/etc/apt/sources.list.d/google-chrome.sources" \
         "${root_u}/etc/cron.daily/google-chrome" \
         "${root_u}/usr/share/keyrings/google-chrome.gpg"; do
    [ -e "$f" ] || kept_u4=0
done
assert_eq "case u: a failed install (INSTALL_ATTEMPTED=1) outside a container leaves phone-home artifacts alone" \
    "1" "${kept_u4}"

plant_u
(
    VESPASIAN_TEST_ROOT="${root_u}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh disable=SC1091
    source "${INSTALL_SCRIPT}"
    SUDO=""
    LOCK_HELD=1
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

# The trap's OTHER guard. INSTALL_SUCCEEDED=1 means "main() already made the
# container-aware AC4 decision", so the trap must defer to it and leave the
# package's artifacts exactly as main() chose to. Without this arm, a trap that
# ignored the flag would silently delete the update channel of the Chrome it had
# just successfully installed on a developer's machine — undoing case v's gate
# from the failure side.
plant_u
(
    VESPASIAN_TEST_ROOT="${root_u}"
    export VESPASIAN_TEST_ROOT
    # shellcheck source=install-chrome.sh disable=SC1091
    source "${INSTALL_SCRIPT}"
    SUDO=""
    LOCK_HELD=1
    SCRATCH_DIR="${FIXTURE_DIR}/scratch-u3"; mkdir -p "$SCRATCH_DIR"
    INSTALL_ATTEMPTED=1
    INSTALL_SUCCEEDED=1
    cleanup_all
) >/dev/null 2>&1
kept_u3=1
for f in "${root_u}/etc/apt/sources.list.d/google-chrome.list" \
         "${root_u}/etc/cron.daily/google-chrome"; do
    [ -e "$f" ] || kept_u3=0
done
assert_eq "case u: a SUCCESSFUL install (INSTALL_SUCCEEDED=1) leaves main()'s decision alone" \
    "1" "${kept_u3}"

# Ordering guard, and the reason this case exists at all. INSTALL_SUCCEEDED must
# be set AFTER main()'s container-aware removal, not next to `apt-get install`.
# dpkg's postinst plants the phone-home artifacts DURING apt-get, so an early
# exit between the two points (verify_apt_origin's `exit 1` is one today, and
# any future check added there is another) fires the trap with the flag already
# set — the trap then defers to a decision main() never reached, and a
# permanently trusted Google apt source plus the root-run daily pinger survive a
# FAILED run. That regression shipped once and is invisible behaviourally: every
# other assertion in this file stays green with the assignment in the wrong
# place, because no case drives that exact window. Hence a structural check.
#
# The anchor has to be the INSTALL-PATH removal specifically. main() contains a
# SECOND bare `remove_phone_home` earlier, on the idempotent early-exit branch,
# and anchoring on the first match silently compares against that one instead:
# the buggy position (right after `apt-get install`) still sorts after the
# early-exit removal, so the guard passed while reproducing the exact regression
# it exists to catch. Verified by mutation — this comment is the record of that.
# Anchoring on `apt-get install` first, then the NEXT removal after it, pins the
# window that actually matters: apt-get < install-path removal < flag.
# `|| true` on every extraction below is load-bearing, exactly as in case p: a
# mutation that removes one of these statements makes its grep match nothing and
# exit 1, and under this file's `set -euo pipefail` that pipeline failure aborts
# THE WHOLE SUITE at this assignment — no summary, no FAIL line. Falling back to
# an empty string instead lets the sentinel below report the breakage as a
# failure, which is the entire point of having a sentinel.
main_body_u=$(fn_code main)
# Not anchored to line-start any more (the apt bound wraps the call in
# `if ! $SUDO timeout N apt-get install ...; then`, ordered $SUDO-first per
# SEC-BE-010 so `timeout` itself runs privileged and can actually signal what
# it bounds), but still requires the literal "$SUDO timeout" ... "apt-get
# install" substring, which the log_fail message a few lines below it
# ("apt-get install failed or timed out.") does not carry -- so the anchor
# still lands on the real call, not that diagnostic.
# The `-k <n>` slot is optional in this anchor because SEC-BE-006 added it
# (`timeout -k 30 900 …`, so a process ignoring the first signal still dies).
# Without the optional group this sentinel fired — correctly and loudly, which
# is the point of having it — the moment that flag landed.
apt_at=$(printf '%s\n' "${main_body_u}" | grep -nE '^[[:space:]]*(if ! )?\$SUDO timeout (-k [0-9]+ )?[0-9]+ apt-get install ' | head -1 | cut -d: -f1 || true)
succ_at=$(printf '%s\n' "${main_body_u}" | grep -n '^[[:space:]]*INSTALL_SUCCEEDED=1[[:space:]]*$' | head -1 | cut -d: -f1 || true)
rm_at=""
if [ -n "${apt_at}" ]; then
    rm_at=$(printf '%s\n' "${main_body_u}" | awk -v start="${apt_at}" \
        'NR > start && /^[[:space:]]*remove_phone_home[[:space:]]*$/ { print NR; exit }')
fi
# Fidelity sentinel first: a broken extraction (main() renamed, any of the three
# statements reworded) must FAIL loudly rather than let the comparison below pass
# vacuously on empty strings.
if [ -n "${succ_at}" ] && [ -n "${rm_at}" ] && [ -n "${apt_at}" ]; then
    echo "PASS: case u: apt-get install, the install-path removal, and INSTALL_SUCCEEDED=1 all located in main()"
    pass_count=$((pass_count + 1))
    if [ "${succ_at}" -gt "${rm_at}" ]; then
        echo "PASS: case u: INSTALL_SUCCEEDED is set after main()'s container-aware removal"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case u: INSTALL_SUCCEEDED=1 precedes remove_phone_home — a failed run between apt-get and the removal would strand the Google apt source and pinger"
        fail_count=$((fail_count + 1))
    fi
else
    echo "FAIL: case u: could not locate apt-get install, the install-path remove_phone_home, and/or INSTALL_SUCCEEDED=1 in main() — ordering guard is vacuous"
    fail_count=$((fail_count + 1))
fi

# ── Case v: in_container() gates removal on the MAIN install path too ───
# Cases o/o2 pin the in_container() gate on the IDEMPOTENT early exit only.
# main() has a SECOND, independent in_container() call further down -- reached
# only after `apt-get install` has actually "succeeded" -- and nothing
# exercised it: every other case in this suite stops before the first $SUDO.
# This is the security-relevant behaviour change of the whole wave (remove_
# phone_home on the main path used to run unconditionally; it is now gated the
# same way the early exit already was) and it had zero coverage.
#
# Reaching it unprivileged needs every step of the install path stubbed
# through, INCLUDING the postinst side effect the whole audit exists to catch:
# a real `apt-get install` is what actually plants the phone-home artifacts, so
# the apt-get stub plants them itself (and drops a runnable fake browser)
# exactly when it is invoked with "install", mirroring what dpkg's postinst
# really does. Depends on the same committed key fixture as cases j/j2 (install_
# pinned_key has to genuinely succeed to reach this code); skips distinctly
# from trust_anchor_skips if that fixture or gpg is unavailable, since this
# case is not testing the trust anchor itself, only relying on it.
run_main_install_path() {
    # $2 is named "mode", not "container": install-chrome.sh's in_container()
    # now also checks the ambient `container` env var (SEC-BE-005), and a local
    # variable of that exact name here would shadow it for every function this
    # subshell sources and calls -- silently making in_container() see "host"/
    # "container" as a non-empty value and answer true unconditionally. Verified
    # by the collision itself: this is what happened before this var was renamed.
    local root="$1" mode="$2" bin_v
    bin_v="${FIXTURE_DIR}/bin-v-${mode}"
    rm -rf "${root}" "${bin_v}"
    mkdir -p "${root}" "${bin_v}"

    # A marker under /var/lib/apt/lists (TEST-012): the in_container() gate on
    # main()'s cache wipe had no fixture tree to actually wipe, so a mutation
    # that deleted the gate entirely was invisible to this suite. Planted here
    # so both the container and host runs below can pin their own arm of it.
    mkdir -p "${root}/var/lib/apt/lists"
    : > "${root}/var/lib/apt/lists/marker"

    printf '#!/bin/bash\nexec "$@"\n' > "${bin_v}/sudo"
    cat > "${bin_v}/dpkg" <<'EOF'
#!/bin/bash
[ "$1" = "--print-architecture" ] && { echo amd64; exit 0; }
exit 1
EOF
    cat > "${bin_v}/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${GOOGLE_KEY_CACHE}' > "\$out"
EOF
    # SEC-BE-002: no `***` marker here — this stub answers BOTH the pre- and
    # post-install verify_apt_origin calls in main() (it is a static script, it
    # cannot distinguish which call it is answering), and `Installed: (none)`
    # with a `***` version-table line is a combination real apt cannot
    # produce. verify_apt_origin now resolves the origin from `Candidate:`,
    # which this shape still exercises correctly on both calls.
    cat > "${bin_v}/apt-cache" <<'POLICY_STUB'
#!/bin/bash
cat <<'POLICY'
google-chrome-stable:
  Installed: (none)
  Candidate: 999.0.0.0-1
  Version table:
     999.0.0.0-1 500
        500 https://dl.google.com/linux/chrome/deb stable/main amd64 Packages
POLICY
POLICY_STUB
    # Simulates dpkg's postinst: the actual moment the phone-home artifacts and
    # a runnable browser binary appear on a real host. Only "install" plants
    # them, so `apt-get update` (and anything else) stays a no-op.
    cat > "${bin_v}/apt-get" <<EOF
#!/bin/bash
case "\$*" in
    *install*google-chrome-stable*)
        mkdir -p '${root}/etc/apt/sources.list.d' '${root}/etc/cron.daily' '${root}/usr/share/keyrings'
        touch '${root}/etc/apt/sources.list.d/google-chrome.list' \\
              '${root}/etc/apt/sources.list.d/google-chrome.sources' \\
              '${root}/etc/cron.daily/google-chrome' \\
              '${root}/usr/share/keyrings/google-chrome.gpg'
        printf '#!/bin/bash\necho "Google Chrome 999.0.0.0"\n' > '${bin_v}/google-chrome'
        chmod +x '${bin_v}/google-chrome'
        ;;
esac
exit 0
EOF
    chmod +x "${bin_v}/sudo" "${bin_v}/dpkg" "${bin_v}/curl" "${bin_v}/apt-cache" "${bin_v}/apt-get"

    (
        # umask 0 (SEC-BE-003): a Dockerfile RUN commonly runs with one, and
        # it is the adverse case that actually distinguishes `install -d`
        # (fixed 0755 regardless of umask) from a `mkdir -p` regression
        # (0777 under this umask) -- under the suite's own ambient umask
        # (022 in this devcontainer and on GitHub-hosted runners) the two
        # produce the SAME mode, so the parent-directory assertion below
        # would not bite without this. Forcing it here is what gives that
        # assertion teeth on every host this suite runs on.
        umask 0
        VESPASIAN_TEST_ROOT="${root}"
        export VESPASIAN_TEST_ROOT
        if [ "${mode}" = "container" ]; then
            : > "${root}/.dockerenv"
        fi
        unset REMOTE_CONTAINERS
        # Unset too, not just avoided by renaming the local above: an ambient
        # `container` (set by some CI runners' own containerized job) must not
        # silently flip this run onto the container arm regardless of $mode.
        unset container
        PATH="${bin_v}:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        # An ABSOLUTE path, not the bare name "google-chrome": command -v on a
        # bare name resolves it anywhere on PATH, including a REAL Chrome the
        # host already has (this devcontainer does). That silently took the
        # idempotent EARLY exit instead of the main install path this case
        # exists to drive through -- same trap case i's comment documents --
        # and made both assertions below pass for the wrong reason (nothing
        # was ever planted, so nothing needed to be removed). Pinning to the
        # exact path the apt-get stub will create is what forces the real path.
        CHROME_CANDIDATES=("${bin_v}/google-chrome")
        set +e
        out=$(main 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

if [ "${have_real_key}" -eq 1 ] && [ "${HAS_TIMEOUT}" = true ]; then
    root_v1="${FIXTURE_DIR}/root-v1"
    res_v1=$(run_main_install_path "${root_v1}" "container")
    assert_eq "case v: in_container()=true main-install-path run succeeds end to end (rc 0)" \
        "0" "$(echo "${res_v1}" | sed -n '1p')"
    if [ -e "${root_v1}/etc/apt/sources.list.d/google-chrome.list" ] || \
       [ -e "${root_v1}/etc/cron.daily/google-chrome" ]; then
        echo "FAIL: case v: in_container()=true still left the package's phone-home artifacts on the main install path"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case v: in_container()=true removes the package's phone-home artifacts on the main install path"
        pass_count=$((pass_count + 1))
    fi
    # TEST-012: the in_container() gate on the /var/lib/apt/lists wipe had no
    # fixture to actually destroy, so this arm is what proves it still fires.
    if [ -e "${root_v1}/var/lib/apt/lists/marker" ]; then
        echo "FAIL: case v: in_container()=true left /var/lib/apt/lists intact (the cache wipe did not run)"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case v: in_container()=true wipes /var/lib/apt/lists"
        pass_count=$((pass_count + 1))
    fi
    # TEST-013 / SEC-BE-003: the version record's success path had no positive
    # assertion anywhere in this per-PR suite (only its ABSENCE on a no-install
    # run, in case o2) -- only the mode was previously stat-checked for the
    # keyring/list/pref trio, not for this write or its parent directory.
    assert_contains "case v: an install writes the chrome-version record" \
        "999.0.0.0" "$(cat "${root_v1}/usr/share/vespasian/chrome-version" 2>/dev/null)"
    assert_eq "case v: the chrome-version record is world-readable but not writable (0644)" \
        "644" "$(stat -c '%a' "${root_v1}/usr/share/vespasian/chrome-version" 2>/dev/null)"
    assert_eq "case v: the chrome-version record's parent directory is 0755" \
        "755" "$(stat -c '%a' "${root_v1}/usr/share/vespasian" 2>/dev/null)"
    # SEC-BE-005/TEST-005: the lock file is the only privileged write in the
    # whole script with no stat -c %a assertion anywhere in this suite before
    # this line. run_main_install_path runs main() under `umask 0` (see the
    # comment on that `umask 0` line above), which is exactly the adverse case
    # `install -m 0644` exists to defend against -- a bare `> "$LOCK_FILE"` or
    # `touch` would land the lock at 0666 under this umask instead. Measured:
    # swapping `$SUDO install -m 0644 -- /dev/null "$LOCK_FILE"` for
    # `$SUDO rm -f -- "$LOCK_FILE"; $SUDO touch "$LOCK_FILE"; $SUDO chmod 0666
    # "$LOCK_FILE"` on a scratch copy left the whole suite green before this
    # assertion existed.
    assert_eq "case v: the install lock is created 0644 even under umask 0" \
        "644" "$(stat -c '%a' "${root_v1}/tmp/vespasian-install-chrome.lock" 2>/dev/null)"

    root_v2="${FIXTURE_DIR}/root-v2"
    res_v2=$(run_main_install_path "${root_v2}" "host")
    assert_eq "case v: in_container()=false main-install-path run succeeds end to end (rc 0)" \
        "0" "$(echo "${res_v2}" | sed -n '1p')"
    if [ -e "${root_v2}/etc/apt/sources.list.d/google-chrome.list" ] && \
       [ -e "${root_v2}/etc/cron.daily/google-chrome" ]; then
        echo "PASS: case v: in_container()=false leaves the package's phone-home artifacts alone on the main install path"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case v: in_container()=false removed artifacts it does not own on the main install path"
        fail_count=$((fail_count + 1))
    fi
    # TEST-012, the host arm: /var/lib/apt/lists is not this script's to wipe
    # outside a container.
    if [ -e "${root_v2}/var/lib/apt/lists/marker" ]; then
        echo "PASS: case v: in_container()=false leaves /var/lib/apt/lists intact"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case v: in_container()=false wiped /var/lib/apt/lists, which it does not own"
        fail_count=$((fail_count + 1))
    fi
    # TEST-013: the record is written on the install path regardless of
    # in_container() -- that predicate governs the PACKAGE's own artifacts,
    # not this script's own audit record.
    assert_contains "case v: an install writes the chrome-version record outside a container too" \
        "999.0.0.0" "$(cat "${root_v2}/usr/share/vespasian/chrome-version" 2>/dev/null)"
    # SEC-BE-009: the non-container message must say what actually happened
    # (no update channel, because suppress_permanent_repo already ran
    # unconditionally before apt-get install) rather than "leaving ... alone"
    # -- there is nothing left to leave alone, since the postinst never
    # created the permanent source or pinger in the first place.
    assert_contains "case v: the non-container message names the actual state (no update channel), not a false 'left alone'" \
        "no apt update channel" "${res_v2}"
else
    skip "case v: main-install-path in_container() gating (needs the same key fixture/gpg as j/j2, plus timeout(1) for require_tools; missing: $(main_deps_missing))" 12
fi

# ── Case v4: record_chrome_version's write-failure arm is non-fatal, not
# silent (TEST-005) ──────────────────────────────────────────────────────────
# record_chrome_version has two branches: the staged-write chain succeeds and
# it logs "Recorded build in ...", or any step fails and it logs "Could not
# write the version record to ..." and returns success anyway (deliberately
# non-fatal -- the browser install already succeeded, and the record is an
# audit convenience, not a correctness requirement). Only the success arm was
# exercised anywhere (case v above, via the full install path); `grep -rn
# 'Could not write the version record' test/` returns only install-chrome.sh
# itself. Replacing the else body with `exit 1`, or with a silent `:`, left
# all four suites green — and each changes real behaviour.
#
# rc alone is explicitly insufficient — install-chrome-selftest.sh's own case q
# region records that being mutation-defeated once, because a later gate
# produced the same rc — so both the rc AND the arm's distinctive message are
# asserted. SCRATCH_DIR="" breaks the first `&&` clause at
# install-chrome.sh:1199 (the same lever already used for cleanup_all's
# failure arms above), with SUDO="" so nothing privileged is attempted.
res_v4=$(
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        SUDO=""
        SCRATCH_DIR=""
        set +e
        out=$(record_chrome_version "999.0.0.0" 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
)
assert_eq "case v4: record_chrome_version's write-failure arm still returns 0 (the documented non-fatal contract)" \
    "0" "$(echo "${res_v4}" | sed -n '1p')"
assert_contains "case v4: record_chrome_version's write-failure arm logs that it could not write the record" \
    "Could not write the version record" "${res_v4}"

# ── Case v3: main()'s AC4 and origin-recheck call sites, by POSITION ────────
#
# TEST-005 / TEST-007. Case v above drives the real install path, but its only
# assertion for the non-container arm is `assert_contains ... "no apt update
# channel"` -- the LOG LINE that claims suppression happened, not the call that
# makes it true. Deleting `suppress_permanent_repo` from main() left the entire
# suite green at 191/0: main() deliberately skips remove_phone_home on that path
# and verify_install deliberately skips the artifact audit, both justified by
# "suppression already ran", so with the call gone nothing removes the Google
# apt source and root cron pinger on a developer's machine and nothing notices.
# That call is the ONLY AC4 control on the non-container path.
#
# TEST-007 is the same shape one function over: verify_apt_origin is called
# twice, before AND after `apt-get install` (the postinst runs DURING apt-get,
# which is exactly when the origin can change), and case y pins only the first.
#
# Both are position claims, not presence claims, so both are checked by
# comparing line numbers inside main()'s own awk-extracted body -- the technique
# case u already uses for INSTALL_SUCCEEDED. A bare presence grep would pass with
# the statements in the wrong order, which for suppression-before-install is the
# whole property that matters.
main_body_v3=$(fn_code main)
sup_at=$(printf '%s\n' "${main_body_v3}" | grep -nE '^[[:space:]]*suppress_permanent_repo[[:space:]]*$' | head -1 | cut -d: -f1 || true)
aptinst_at=$(printf '%s\n' "${main_body_v3}" | grep -nE '^[[:space:]]*(if ! )?\$SUDO timeout (-k [0-9]+ )?[0-9]+ apt-get install ' | head -1 | cut -d: -f1 || true)
origin_lines=$(printf '%s\n' "${main_body_v3}" | grep -nE '^[[:space:]]*if ! verify_apt_origin; then$' | cut -d: -f1 || true)
origin_count=$(printf '%s' "${origin_lines}" | grep -c . || true)
origin_post_at=""
if [ -n "${aptinst_at}" ]; then
    origin_post_at=$(printf '%s\n' "${origin_lines}" | awk -v start="${aptinst_at}" '$1 > start { print $1; exit }')
fi

# Fidelity sentinel first, for the same reason case u has one: a renamed main()
# or a reworded statement makes every comparison below compare empty strings,
# which would pass vacuously. Drift must be reported as drift.
if [ -n "${sup_at}" ] && [ -n "${aptinst_at}" ] && [ "${origin_count}" -ge 1 ]; then
    echo "PASS: case v3: main()'s suppression call, apt-get install, and origin check all located"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case v3: could not locate main()'s suppression call, apt-get install, or origin check — the ordering assertions below are vacuous, fix the extraction rather than deleting it"
    fail_count=$((fail_count + 1))
fi

assert_eq "case v3: main() actually CALLS suppress_permanent_repo (AC4's only control on the non-container path)" \
    "called" "$([ -n "${sup_at}" ] && echo "called" || echo "MISSING — the 'no apt update channel' log line is now a false claim")"

assert_eq "case v3: suppression runs BEFORE apt-get install, so the postinst never creates the repo or pinger" \
    "before" "$( { [ -n "${sup_at}" ] && [ -n "${aptinst_at}" ] && [ "${sup_at}" -lt "${aptinst_at}" ]; } && echo "before" || echo "NOT before apt-get install — the postinst plants the phone-home artifacts first")"

assert_eq "case v3: verify_apt_origin is called twice, not once" \
    "2" "${origin_count}"

assert_eq "case v3: one verify_apt_origin call sits AFTER apt-get install (the postinst can change the origin mid-install)" \
    "after" "$([ -n "${origin_post_at}" ] && echo "after" || echo "MISSING — only the pre-install gate is present")"

# ── Case w: verify_apt_origin, both arms (TEST-010 / SEC-BE-002) ─
#
# This function was reachable from no case at all — it appeared in the suite
# only inside a comment — so BOTH arms were untested and replacing its whole
# body with `return 0` left the suite green. It is one of the two layers of the
# "the package came from the origin we vouched for" guarantee (the apt
# preference pin is the other), so an unexercised accept-anything arm is a
# silent loss of that guarantee.
#
# Driven with a stubbed apt-cache so no real apt state is needed: the function
# only parses `apt-cache policy` output, which makes it cheap to pin exactly.
#
# SEC-BE-002: the fixtures below build a FULL, shape-accurate `apt-cache
# policy` block (Installed:/Candidate:/Version table:) rather than just the
# version-table lines. Earlier fixtures paired `Installed: (none)` with a
# `***` version-table line — a combination real apt cannot produce, since
# `***` marks only the INSTALLED version — which is exactly what let a parser
# anchored on `***` alone look correct while refusing every pre-install host.
run_verify_apt_origin() {
    local installed="$1" candidate="$2" version_table="$3" tag="$4"
    local stub_bin="${FIXTURE_DIR}/bin-w-${tag}"
    rm -rf "${stub_bin}"; mkdir -p "${stub_bin}"
    {
        printf '#!/bin/bash\n'
        printf 'cat <<'"'"'POLICY'"'"'\n'
        printf 'google-chrome-stable:\n'
        printf '  Installed: %s\n' "${installed}"
        printf '  Candidate: %s\n' "${candidate}"
        printf '  Version table:\n'
        printf '%s\n' "${version_table}"
        printf 'POLICY\n'
    } > "${stub_bin}/apt-cache"
    chmod +x "${stub_bin}/apt-cache"
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        PATH="${stub_bin}:${PATH}"
        set +e
        out=$(verify_apt_origin 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

# A raw variant for the one fixture that must NOT go through the realistic
# wrapper above: an apt-cache that produces no parseable output at all.
run_verify_apt_origin_raw() {
    local policy_out="$1" stub_bin="${FIXTURE_DIR}/bin-w-$2"
    rm -rf "${stub_bin}"; mkdir -p "${stub_bin}"
    {
        printf '#!/bin/bash\n'
        printf 'cat <<'"'"'POLICY'"'"'\n%s\nPOLICY\n' "${policy_out}"
    } > "${stub_bin}/apt-cache"
    chmod +x "${stub_bin}/apt-cache"
    (
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        PATH="${stub_bin}:${PATH}"
        set +e
        out=$(verify_apt_origin 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

# The accepting arm, PRE-install: the package is not installed yet (the exact
# state main()'s pre-install gate at :806 is always reached in), and the
# candidate resolves from Google's own host. `Installed: (none)` with NO `***`
# line is the only shape real apt produces for this state — the pre-install
# accept arm every prior round's fixtures modelled with none at all (SEC-BE-002).
res_w0=$(run_verify_apt_origin '(none)' '150.0.7871.186-1' \
    '     150.0.7871.186-1 500
        500 https://dl.google.com/linux/chrome/deb stable/main amd64 Packages' \
    preinstall_accept)
assert_eq "case w: a not-yet-installed candidate from dl.google.com is accepted (rc 0)" \
    "0" "$(echo "${res_w0}" | sed -n '1p')"

# The accepting arm, POST-install: the candidate IS the installed version, so
# its version-table line carries the `***` marker — the only state that marker
# actually exists to flag.
res_w1=$(run_verify_apt_origin '150.0.7871.186-1' '150.0.7871.186-1' \
    ' *** 150.0.7871.186-1 500
        500 https://dl.google.com/linux/chrome/deb stable/main amd64 Packages' \
    accept)
assert_eq "case w: an already-installed candidate from dl.google.com is accepted (rc 0)" \
    "0" "$(echo "${res_w1}" | sed -n '1p')"

# The rejecting arm: a completely different host, pre-install (this is the
# shape main()'s pre-install gate actually sees on a hostile host — case y
# below drives the same shape through main() end to end).
res_w2=$(run_verify_apt_origin '(none)' '1.0.0-1' \
    '     1.0.0-1 500
        500 https://mirror.evil.example/linux/chrome/deb stable/main amd64 Packages' \
    reject)
assert_eq "case w: a foreign origin is refused (rc 1)" \
    "1" "$(echo "${res_w2}" | sed -n '1p')"
assert_contains "case w: the refusal names the origin it saw" \
    "mirror.evil.example" "${res_w2}"

# The substring trap this check used to fall into: `grep -qF 'dl.google.com'`
# matched any URL merely CONTAINING that text, so a lookalike host satisfied it.
# Both of these are rejected only because the check now anchors on the URL's
# host component (SEC-BE-001).
#
# TEST-003: `rc == 1` alone does not prove the HOST-anchoring gate is what
# refused either fixture — a LATER gate (the GOOGLE_APT_URL prefix check) also
# refuses both, since neither origin starts with GOOGLE_APT_URL, so a broken
# host gate that let either origin through would still land on rc 1 via that
# later gate. MUTATION-PROVEN: reverting the host-anchoring block (the two
# extraction lines plus the exact-match `[ "$host" != "dl.google.com" ]`) to the
# OLD substring form the comment above describes — `grep -qF 'dl.google.com'`
# against the WHOLE origin, not the extracted host — left this suite at
# 214 passed / 0 failed, exit 0: both origins still contain "dl.google.com" as a
# substring (the lookalike as a host PREFIX, the pathmatch inside the path), so
# the broken gate let both through, and both were then caught instead by the
# GOOGLE_APT_URL prefix gate ("not the source this run pinned"), preserving
# rc 1 for both while the check the case NAMES was silently defeated. Asserting
# on the host gate's OWN distinctive message — which embeds the exact origin it
# saw — closes that: a mutation that routes the refusal through a different
# gate now shows up as a message mismatch instead of a matching rc.
res_w3=$(run_verify_apt_origin '(none)' '1.0.0-1' \
    '     1.0.0-1 500
        500 https://dl.google.com.attacker.example/linux/chrome/deb stable/main amd64 Packages' \
    lookalike)
assert_eq "case w: a lookalike host (dl.google.com.attacker.example) is refused" \
    "1" "$(echo "${res_w3}" | sed -n '1p')"
assert_contains "case w: the lookalike is refused by the HOST-anchoring gate specifically" \
    "unexpected origin: https://dl.google.com.attacker.example/linux/chrome/deb (expected dl.google.com)" "${res_w3}"
res_w4=$(run_verify_apt_origin '(none)' '1.0.0-1' \
    '     1.0.0-1 500
        500 https://mirror.example/dl.google.com/deb stable/main amd64 Packages' \
    pathmatch)
assert_eq "case w: dl.google.com appearing in the PATH is refused" \
    "1" "$(echo "${res_w4}" | sed -n '1p')"
assert_contains "case w: the path-only match is refused by the HOST-anchoring gate specifically" \
    "unexpected origin: https://mirror.example/dl.google.com/deb (expected dl.google.com)" "${res_w4}"

# w4b (SEC-BE-001): a bare-integer version collides with a PRIORITY column,
# not just a URL lookalike. `500` is a syntactically valid Debian version, and
# a naive `$1 == ver` row selector cannot tell that version row apart from a
# SOURCE row whose priority happens to equal it. This fixture's first source
# line ("500 https://.../dl.google.com/...") sits at the SAME priority as an
# unrelated earlier version row, purely to give the buggy selector a
# priority-column match to latch onto before it ever reaches the real
# candidate row below. The REAL match for candidate "500" is the LAST version
# row ("500 100"), whose source is evil.example. Before SEC-BE-001's fix this
# fixture made verify_apt_origin match the source row's priority column,
# print the FOLLOWING line's dl.google.com URL, and ACCEPT — while the
# version apt actually resolves comes from evil.example. Confirmed by
# reverting the `$NF ~ /^[0-9]+$/` guard on a scratch copy: this exact
# fixture then returns rc 0 instead of rc 1.
res_w4b=$(run_verify_apt_origin '(none)' '500' \
    '     999.0.0-1 500
        500 https://mirror.example/linux/chrome/deb stable/main amd64 Packages
        500 https://dl.google.com/linux/chrome/deb stable/main amd64 Packages
     500 100
        100 https://evil.example/linux/chrome/deb stable/main amd64 Packages' \
    priority_collision)
assert_eq "case w: a bare-integer version cannot be satisfied by a priority-column collision (rc 1)" \
    "1" "$(echo "${res_w4b}" | sed -n '1p')"
assert_contains "case w: the priority-collision fixture is refused as evil.example, not accepted as dl.google.com" \
    "evil.example" "${res_w4b}"

# An apt-cache that produces nothing (held dpkg lock, corrupted cache) must be
# refused with a diagnostic rather than aborting the script under errexit — the
# `|| policy=""` guard exists for exactly this, and without a case the guard's
# absence would surface as a silent abort rather than a failure (QUAL-006).
res_w5=$(run_verify_apt_origin_raw '' emptypolicy)
assert_eq "case w: an unreadable apt policy is refused, not silently accepted" \
    "1" "$(echo "${res_w5}" | sed -n '1p')"
assert_contains "case w: the empty-policy refusal is diagnosed as unknown" \
    "unknown" "${res_w5}"

# w6 (SEC-BE-002): the RIGHT HOST over the WRONG TRANSPORT. The host comparison
# alone accepted `http://dl.google.com/...` — a plaintext apt transport for the
# correct host. The package signature is verified either way, but the metadata and
# therefore the version apt selects become attacker-influenceable in transit, and
# this script pins an https source precisely so that cannot happen. The case v
# fixture used to encode the permissive behaviour (its stub emitted http://), which
# is how this went unnoticed.
res_w6=$(run_verify_apt_origin '(none)' '999.0.0.0-1' \
    '     999.0.0.0-1 500
        500 http://dl.google.com/linux/chrome/deb stable/main amd64 Packages' \
    http_downgrade)
assert_eq "case w: the right host over http:// is refused (rc 1)" \
    "1" "$(echo "${res_w6}" | sed -n '1p')"
assert_contains "case w: the http refusal names the transport, not just the host" \
    "non-https transport" "${res_w6}"

# w7 (SEC-BE-002): the right host AND https, but a DIFFERENT repo PATH than the one
# this run pinned (`/linux/OTHER/deb` rather than `/linux/chrome/deb`) — an unrelated
# third-party repo offering the same package name under the right host and scheme.
# The prefix comparison against GOOGLE_APT_URL rejects it because the PATH differs;
# it does not (and cannot) distinguish an IDENTICAL URI verified by a different
# keyring, which `apt-cache policy` never reports and which requires root to plant.
res_w7=$(run_verify_apt_origin '(none)' '999.0.0.0-1' \
    '     999.0.0.0-1 500
        500 https://dl.google.com/linux/OTHER/deb stable/main amd64 Packages' \
    foreign_google_source)
assert_eq "case w: an https dl.google.com source that is NOT the pinned one is refused (rc 1)" \
    "1" "$(echo "${res_w7}" | sed -n '1p')"
assert_contains "case w: the wrong-source refusal names the source this run pinned" \
    "not the source this run pinned" "${res_w7}"

# w8 (TEST-006): a MALFORMED origin row — the shape guard's fail-closed arm. Case
# w4b covers a priority-column collision, but nothing fed the parser a row whose
# `$2` is not a `scheme://...` URL at all, so the guard that requires that shape was
# never exercised in the direction where it must refuse.
res_w8=$(run_verify_apt_origin '(none)' '999.0.0.0-1' \
    '     999.0.0.0-1 500
        500 not-a-url-at-all stable/main amd64 Packages' \
    malformed_origin_row)
assert_eq "case w: a malformed (non-URL) origin row is refused, not parsed as an origin (rc 1)" \
    "1" "$(echo "${res_w8}" | sed -n '1p')"

# ── Case x: cleanup_all's step ORDER and errexit tolerance (TEST-011) ──
#
# Cases p/p2 assert the trap is REGISTERED (`trap 'cleanup_all' EXIT`); nothing
# asserted what the handler does once it fires. Reverting it to its pre-round-5
# shape — cleanup_apt_wiring first, no `|| true` — left the suite green, so the
# fix for "one failing step aborts the handler under errexit and strands a
# permanently trusted Google apt source plus a root cron pinger" was unprotected.
#
# Driven by replacing the two steps with recorders, so the assertions are about
# cleanup_all's own control flow rather than about what the steps do. That is
# the property under test: ORDER (security-relevant removal first) and
# TOLERANCE (an earlier failure must not skip a later step).
mkdir -p "${FIXTURE_DIR}/root-x"
: > "${FIXTURE_DIR}/root-x/.dockerenv"

run_cleanup_all() {
    local order_log="$1" fail_step="$2" rc=0
    # The subshell is the errexit boundary. `cleanup_all` is invoked as a PLAIN
    # command inside it, so the script's own `set -euo pipefail` applies to the
    # handler's steps: without `|| true`, a failing step aborts the subshell and
    # the order log is left short. Capturing rc with `|| rc=$?` on the SUBSHELL
    # (not on cleanup_all) is what keeps errexit live where it matters — putting
    # `||` directly on cleanup_all suspends errexit for the whole handler and
    # makes this case pass whether or not the tolerance is there. Verified: with
    # `||` on cleanup_all, deleting every `|| true` from the handler kept the
    # suite green.
    (
        # cleanup_all now calls in_container() before its first step
        # (SEC-BE-006), so this case's own subject — ORDER and TOLERANCE of
        # cleanup_all's steps — needs a deterministic container answer,
        # independent of whether the host running this suite happens to
        # export REMOTE_CONTAINERS. root-x/.dockerenv pins it to "container",
        # which is the arm that actually calls remove_phone_home; case u
        # covers the non-container arm.
        VESPASIAN_TEST_ROOT="${FIXTURE_DIR}/root-x"
        export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS
        unset container
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        # A failed install: this is the arm that must remove the phone-home
        # artifacts, and the arm a mid-install abort actually takes.
        INSTALL_ATTEMPTED=1
        INSTALL_SUCCEEDED=0
        # This case's subject is cleanup_all's OWN order/tolerance, not the
        # lock — pin LOCK_HELD=1 to simulate the normal case (this run held
        # the lock), the same way case u does (SEC-BE-008).
        LOCK_HELD=1
        SCRATCH_DIR=""
        remove_phone_home() {
            echo "remove_phone_home" >> "${order_log}"
            [ "${fail_step}" = "remove_phone_home" ] && return 1
            return 0
        }
        cleanup_apt_wiring() {
            echo "cleanup_apt_wiring" >> "${order_log}"
            [ "${fail_step}" = "cleanup_apt_wiring" ] && return 1
            return 0
        }
        # Re-arm errexit EXPLICITLY inside the subshell. Bash disables `set -e`
        # for a compound command that is an operand of `||`, and that disabling
        # reaches inside the subshell too — so without this line the handler runs
        # errexit-off and the tolerance assertions below pass whether or not
        # `|| true` is present. Measured: deleting every `|| true` from
        # cleanup_all kept the suite green until this `set -e` was added.
        set -e
        cleanup_all >/dev/null 2>&1
    ) || rc=$?
    printf '%s\n' "${rc}"
}

# Order: the security-relevant removal must run BEFORE the wiring cleanup.
log_x1="${FIXTURE_DIR}/cleanup-order-1"; : > "${log_x1}"
rc_x1=$(run_cleanup_all "${log_x1}" none)
assert_eq "case x: cleanup_all succeeds when both steps succeed (rc 0)" "0" "${rc_x1}"
assert_eq "case x: remove_phone_home runs BEFORE cleanup_apt_wiring" \
    "remove_phone_home cleanup_apt_wiring" "$(tr '\n' ' ' < "${log_x1}" | sed 's/ $//')"

# Tolerance, asserted from the SOURCE rather than at runtime.
#
# A runtime attempt was written first and deliberately discarded: bash disables
# `set -e` for a compound command that is an operand of `||`, and that reaches
# inside the subshell, so every arrangement of `( ... ) || rc=$?` ran the handler
# errexit-OFF. Measured against a copy with every `|| true` deleted from
# cleanup_all: the suite stayed green (151/0). An assertion that cannot fail is
# not coverage, so the runtime rc checks were removed rather than left in place
# looking like protection.
#
# What DOES bite is asserting the tolerance is present in the handler's text.
# The property is a syntactic one — each step is `||`-guarded by something
# that itself always succeeds (`true`, or `log_warn`'s printf, per SEC-BE-005:
# a bare `|| true` swallowed a removal failure with no diagnostic at all) — so
# a source-level check is the honest form, and it is the same derive-from-
# source idiom the CI-wiring guards in test-runner-args.sh already use.
cleanup_all_src=$(sed -n '/^cleanup_all() {/,/^}/p' "${INSTALL_SCRIPT}")
for guarded_step in remove_phone_home cleanup_apt_wiring; do
    if printf '%s' "${cleanup_all_src}" \
        | grep -qE "^[[:space:]]*${guarded_step}[[:space:]]*\|\|[[:space:]]*(true|log_warn)"; then
        echo "PASS: case x: cleanup_all still tolerates a failing ${guarded_step} (|| true / || log_warn)"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: case x: cleanup_all no longer guards ${guarded_step} with '|| true' or '|| log_warn' — one failing step will abort the handler under errexit and strand the phone-home artifacts"
        fail_count=$((fail_count + 1))
    fi
done

# x2 (SEC-BE-005): the structural check above accepts EITHER `|| true` or
# `|| log_warn` — tolerance alone is not what SEC-BE-005 asked for. This
# behavioural case is what actually distinguishes them: a failing removal
# must be REPORTED, not just survived. Same harness as run_cleanup_all, but
# with output captured instead of discarded.
res_x2=$(
    (
        VESPASIAN_TEST_ROOT="${FIXTURE_DIR}/root-x"
        export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS
        unset container
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        INSTALL_ATTEMPTED=1
        INSTALL_SUCCEEDED=0
        LOCK_HELD=1
        SCRATCH_DIR=""
        remove_phone_home() { return 1; }
        cleanup_apt_wiring() { return 0; }
        set -e
        cleanup_all
    )
)
assert_contains "case x: a failing remove_phone_home is reported, not silently swallowed (SEC-BE-005)" \
    "Could not remove" "${res_x2}"

# ── Case y: the pre-install origin gate refuses BEFORE apt-get install runs ──
# (SEC-BE-009). verify_apt_origin now runs twice: once right after `apt-get
# update`, before `apt-get install` ever executes, and again afterward as a
# second check. This pins the FIRST call specifically -- apt-cache policy
# reports a non-Google origin for the candidate, so the install must never
# run at all, and no maintainer script from the wrong origin ever executes as
# root. Depends on the same committed key fixture as cases j/j2/v (install_
# pinned_key has to genuinely succeed to reach the gate), so it skips the
# same way those do when that fixture or gpg is unavailable.
if [ "${have_real_key}" -eq 1 ] && [ "${HAS_TIMEOUT}" = true ]; then
    root_y="${FIXTURE_DIR}/root-y"
    bin_y="${FIXTURE_DIR}/bin-y"
    rm -rf "${root_y}" "${bin_y}"
    mkdir -p "${root_y}" "${bin_y}"
    printf '#!/bin/bash\nexec "$@"\n' > "${bin_y}/sudo"
    cat > "${bin_y}/dpkg" <<'EOF'
#!/bin/bash
[ "$1" = "--print-architecture" ] && { echo amd64; exit 0; }
exit 1
EOF
    cat > "${bin_y}/curl" <<EOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }
    shift
done
cat '${GOOGLE_KEY_CACHE}' > "\$out"
EOF
    # A HOSTILE apt-cache policy: the candidate resolves from a third-party
    # mirror, not dl.google.com -- exactly the scenario TMP_PREF exists to
    # prevent, reached here via a stale/unrelated source rather than a failed
    # fetch of the pinned one (apt-get update itself still reports success).
    # No `***` marker (SEC-BE-002): this call happens BEFORE `apt-get install`
    # ever runs, so the package is genuinely not installed yet, and
    # `Installed: (none)` paired with a `***` version-table line is a shape
    # real apt cannot produce. verify_apt_origin resolves the origin from
    # `Candidate:`, which does not depend on the package being installed.
    cat > "${bin_y}/apt-cache" <<'POLICY_STUB'
#!/bin/bash
cat <<'POLICY'
google-chrome-stable:
  Installed: (none)
  Candidate: 1.0.0-1
  Version table:
     1.0.0-1 500
        500 https://mirror.evil.example/linux/chrome/deb stable/main amd64 Packages
POLICY
POLICY_STUB
    # apt-get install must NEVER be invoked; a marker file proves it, since a
    # gated run and a run that reached install-and-failed would both exit
    # non-zero and look identical from rc alone.
    cat > "${bin_y}/apt-get" <<EOF
#!/bin/bash
case "\$*" in
    *install*google-chrome-stable*)
        touch '${bin_y}/apt-get-install-ran'
        ;;
esac
exit 0
EOF
    chmod +x "${bin_y}"/sudo "${bin_y}"/dpkg "${bin_y}"/curl "${bin_y}"/apt-cache "${bin_y}"/apt-get
    res_y=$(
        VESPASIAN_TEST_ROOT="${root_y}"
        export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS
        unset container
        PATH="${bin_y}:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        CHROME_CANDIDATES=()
        set +e
        out=$(main 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
    assert_eq "case y: main() aborts before apt-get install when the candidate's origin is wrong (rc 1)" \
        "1" "$(echo "${res_y}" | sed -n '1p')"
    assert_contains "case y: the abort names the unexpected origin" \
        "unexpected origin" "${res_y}"
    if [ -e "${bin_y}/apt-get-install-ran" ]; then
        echo "FAIL: case y: apt-get install ran despite the pre-install origin gate"
        fail_count=$((fail_count + 1))
    else
        echo "PASS: case y: apt-get install never ran — the origin gate fired before it"
        pass_count=$((pass_count + 1))
    fi
else
    skip "case y: pre-install origin gate (needs the same key fixture/gpg as j/j2, plus timeout(1) for require_tools; missing: $(main_deps_missing))" 3
fi

# ── Case bp: _bounded_probe (TEST-008 / SEC-BE-005) ─────────────
# `grep -c _bounded_probe` returns 0 in all four suites: verify_install's
# `--version` probe (SEC-BE-005 — a browser that hangs on `--version` must not
# wedge the tail of a provisioning run) had no case anywhere. Driven directly,
# the same way case n/o drive other small helpers in isolation, rather than
# through the full install path this suite deliberately does not cover.
bp_dir="${FIXTURE_DIR}/bounded-probe"; mkdir -p "${bp_dir}"

# bp1: a normal, fast binary's --version output is returned unchanged, proving
# the timeout wrapper does not itself swallow or mangle a well-behaved probe.
cat > "${bp_dir}/chrome-fast" <<'EOF'
#!/bin/bash
[ "$1" = "--version" ] && { printf 'Google Chrome 999.0.0.0\n'; exit 0; }
exit 1
EOF
chmod +x "${bp_dir}/chrome-fast"
res_bp1=$(
    # shellcheck source=install-chrome.sh
    source "${INSTALL_SCRIPT}"
    CHROME_PROBE_TIMEOUT=2
    _bounded_probe "${bp_dir}/chrome-fast"
)
assert_eq "case bp: _bounded_probe returns a runnable binary's --version output" \
    "Google Chrome 999.0.0.0" "${res_bp1}"

# bp2 (SEC-BE-005): a binary that hangs on --version must not hang
# _bounded_probe itself -- that is the entire point of wrapping the call in
# timeout/gtimeout. `_bounded_probe`'s own bound is set very short
# (CHROME_PROBE_TIMEOUT=1) and the whole thing is wrapped in a much longer
# OUTER `timeout`, the same safety-net pattern case z3 uses for its FIFO: if
# the inner bound is ever removed, the hanging binary's 30s sleep is instead
# caught by the outer bound, so the suite fails loudly on a slow assertion
# rather than wedging forever.
#
# rc alone cannot distinguish "bounded correctly" from "bounded only by the
# outer safety net": both `timeout`s report 124 when they kill their child,
# so a correct 1s inner bound and a broken 15s outer bound are the SAME exit
# code. ELAPSED TIME is the only signal that actually separates them -- pass
# means this returns in low single-digit seconds; drop means it takes ~15s
# (the outer safety net's own bound) instead.
cat > "${bp_dir}/chrome-hang" <<'EOF'
#!/bin/bash
[ "$1" = "--version" ] && { sleep 30; printf 'should never print\n'; exit 0; }
exit 1
EOF
chmod +x "${bp_dir}/chrome-hang"
bp_tmo=""
for c in timeout gtimeout; do
    command -v "$c" >/dev/null 2>&1 && { bp_tmo="$c"; break; }
done
if [ -n "${bp_tmo}" ]; then
    bp_start=$(date +%s)
    # `|| true` (same load-bearing reason as case j's fixture-fpr assignment):
    # a bare `var=$(pipeline)` assignment takes the pipeline's own exit status
    # under this file's `set -euo pipefail`, and BOTH the pass and fail paths
    # here exit non-zero (the probe legitimately returns non-zero on a binary
    # it never got a version out of), so without this the PASSING case would
    # abort the whole suite before the assertions below ever run.
    out_bp2=$("${bp_tmo}" 15 bash -c '
        # shellcheck source=install-chrome.sh
        source "$1"
        CHROME_PROBE_TIMEOUT=1
        _bounded_probe "$2"
    ' _ "${INSTALL_SCRIPT}" "${bp_dir}/chrome-hang" 2>/dev/null) || true
    bp_elapsed=$(( $(date +%s) - bp_start ))
else
    # No timeout(1)/gtimeout(1) on this host at all: same degrade path
    # chrome_runnable documents for stock macOS. Nothing to bound the outer
    # call with either, so this arm cannot be driven here without risking a
    # genuinely wedged suite.
    # Credit 4: bp2's own pair (elapsed-under-bound, no-output) plus bp3's pair
    # below (CHROME_PROBE_TIMEOUT=0 rejected, CHROME_PROBE_TIMEOUT=--help
    # rejected) — bp3 is driven inside this same guard, so it skips too.
    skip "case bp: _bounded_probe timeout enforcement (no timeout/gtimeout on PATH)" 4
    out_bp2=""
    bp_elapsed=""
fi
if [ -n "${bp_tmo}" ]; then
    assert_eq "case bp: _bounded_probe cuts off a hanging --version near its own 1s bound, not the outer 15s safety net" \
        "under-outer-bound" "$([ "${bp_elapsed}" -lt 10 ] && echo "under-outer-bound" || echo "HUNG ${bp_elapsed}s — SEC-BE-005 bound is gone")"
    assert_eq "case bp: _bounded_probe on a hanging binary produces no output (the hang was cut off, not raced)" \
        "" "${out_bp2}"

    # bp3 (SEC-BE-002): _bounded_probe used to read CHROME_PROBE_TIMEOUT straight
    # into timeout(1)'s duration/option position with no validation, unlike
    # chrome_runnable, the sibling probe it says it reuses. Two values named by
    # the finding: CHROME_PROBE_TIMEOUT=0 (GNU timeout reads 0 as "no timeout",
    # which would let a hanging browser wedge the tail of a root provisioning
    # run forever) and CHROME_PROBE_TIMEOUT=--help (an unvalidated value would
    # reach timeout's OPTION position, landing usage text in the version
    # record instead of failing loudly). Both are driven inside this same
    # outer-safety-net guard as bp2 — same rationale: rc alone cannot
    # distinguish a correctly-rejected value from the 15s outer net, so elapsed
    # time is the assertion for the hang case.
    bp3_start=$(date +%s)
    # stdout is discarded rather than captured: the assertion for the hang case is
    # ELAPSED TIME (see above), so binding the output to a variable only produced an
    # unused one. rc is likewise not the assertion here.
    "${bp_tmo}" 15 bash -c '
        # shellcheck source=install-chrome.sh
        source "$1"
        CHROME_PROBE_TIMEOUT=0
        _bounded_probe "$2"
    ' _ "${INSTALL_SCRIPT}" "${bp_dir}/chrome-hang" >/dev/null 2>&1 || true
    bp3_elapsed=$(( $(date +%s) - bp3_start ))
    assert_eq "case bp: CHROME_PROBE_TIMEOUT=0 is rejected — a hanging --version is still cut off near the validated 2s default rather than left unbounded (SEC-BE-002)" \
        "under-outer-bound" "$([ "${bp3_elapsed}" -lt 10 ] && echo "under-outer-bound" || echo "HUNG ${bp3_elapsed}s — SEC-BE-002 validation is gone")"

    out_bp3_help=$(
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        CHROME_PROBE_TIMEOUT=--help
        _bounded_probe "${bp_dir}/chrome-fast"
    )
    assert_eq "case bp: CHROME_PROBE_TIMEOUT=--help is rejected — _bounded_probe returns the browser's version string, not timeout(1)'s usage text (SEC-BE-002)" \
        "Google Chrome 999.0.0.0" "${out_bp3_help}"
fi

# ── Case z: the install lock (SEC-BE-006 / SEC-BE-008 / TEST-011 / TEST-012) ──
#
# The flock block in main() had no assertion of any kind anywhere in this
# suite before this case: no coverage of the symlink/hardlink guard on the
# fixed LOCK_FILE path, and no coverage of what happens when the lock cannot
# be acquired. Driven through main() itself (not a helper) since the guard,
# the acquisition, and LOCK_HELD are all local to main()'s body.
run_lock_plant() {
    local root="$1" attack="$2" bin="${FIXTURE_DIR}/bin-lockplant-$2"
    rm -rf "${root}" "${bin}"; mkdir -p "${root}" "${bin}" "${root}/tmp"
    printf '#!/bin/bash\nexec "$@"\n' > "${bin}/sudo"
    chmod +x "${bin}/sudo"
    printf 'do not touch me\n' > "${root}/victim"
    case "${attack}" in
        symlink)  ln -s "${root}/victim" "${root}/tmp/vespasian-install-chrome.lock" ;;
        hardlink) ln "${root}/victim" "${root}/tmp/vespasian-install-chrome.lock" ;;
        # SEC-BE-004: a FIFO passes both guards above -- it is not a symlink and
        # has one hard link -- and `[ ! -e ]` then declines to replace it, so
        # `exec {LOCK_FD}<` blocks in open(2) forever waiting for a writer. The
        # deliberate `flock -w 300` bound is never reached because the hang is
        # in the OPEN, not the lock. That is why this helper is timeout-bounded:
        # without the bound this case wedges the whole suite instead of failing.
        fifo)     mkfifo "${root}/tmp/vespasian-install-chrome.lock" ;;
    esac
    # A run that hangs must FAIL LOUDLY, not hang the suite. rc 124 from
    # timeout(1) is the signal, and the assertions below treat it as a failure
    # distinct from a clean refusal.
    local tmo=""
    for c in timeout gtimeout; do
        command -v "$c" >/dev/null 2>&1 && { tmo="$c"; break; }
    done
    (
        VESPASIAN_TEST_ROOT="${root}"
        export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS
        unset container
        PATH="${bin}:${PATH}"
        set +e
        local out rc
        # ONE arm, not two. The `bash -c` is load-bearing: sourcing
        # install-chrome.sh directly here would pull its own `set -euo pipefail`
        # into this subshell, and the following bare assignment would then abort
        # the whole `(` block when main fails -- which every lock-planted case
        # here deliberately makes it do -- losing every case from z onward AND
        # the accounting pin, with no FAIL printed. A fresh bash process contains
        # that errexit; only its exit code escapes.
        #
        # Kept as a single arm because the else branch ran ONLY on a host with
        # neither timeout nor gtimeout -- no CI job -- so a revert to a direct
        # `source` stayed fully green everywhere and was measured to lose 24
        # assertions on a timeout-less host. One arm makes the form execute, and
        # therefore be exercised, on every host.
        local -a invoke=(bash -c 'source "$1"; main' _ "${INSTALL_SCRIPT}")
        [ -n "${tmo}" ] && invoke=("${tmo}" 15 "${invoke[@]}")
        out=$("${invoke[@]}" 2>&1)
        rc=$?
        printf '%s\n%s\n' "${rc}" "${out}"
    )
}

res_z1=$(run_lock_plant "${FIXTURE_DIR}/root-z1" symlink)
assert_eq "case z: a symlink at the lock path is refused (rc 1)" \
    "1" "$(echo "${res_z1}" | sed -n '1p')"
assert_contains "case z: the symlink refusal names the lock file" \
    "is a symlink" "${res_z1}"
assert_eq "case z: the symlink attack's target is untouched" \
    "do not touch me" "$(cat "${FIXTURE_DIR}/root-z1/victim" 2>/dev/null)"

res_z2=$(run_lock_plant "${FIXTURE_DIR}/root-z2" hardlink)
assert_eq "case z: a hardlink at the lock path is refused (rc 1)" \
    "1" "$(echo "${res_z2}" | sed -n '1p')"
assert_contains "case z: the hardlink refusal names the multiple hard links" \
    "multiple hard links" "${res_z2}"
assert_eq "case z: the hardlink attack's target is untouched" \
    "do not touch me" "$(cat "${FIXTURE_DIR}/root-z2/victim" 2>/dev/null)"

# case z2b (TEST-004 / TEST-005): a lock file owned by a THIRD uid — neither
# root nor the invoking user — is the fourth SEC-BE-004 guard, and it had no
# case anywhere in this suite: `grep -c 'owned by uid'` returns 1 in
# install-chrome.sh and 0 across all four suites, for both the reject arm and
# the `stat` failure arm ahead of it.
#
# It cannot be driven with a real chown: this suite runs unprivileged, and
# chowning a file to a uid this process does not own is exactly the privilege
# the guard exists to distrust. Instead a STUBBED `stat` — the same idiom case
# w uses for `apt-cache` — reports a fabricated owner for ONLY the planted lock
# file's `-c '%u'` query and defers to the REAL `stat` for every other query
# (including this same file's `-c '%h'` query), so the hard-link guard ahead of
# the owner check still sees a real, single-link file and does not itself
# refuse first.
#
# TEST-005: case z4's guard-PRESENCE check further below can only see that the
# `lock_owner=$(stat -c '%u' ...)` ASSIGNMENT still exists in main() — it says
# nothing about what the code DOES with the value, so turning the comparison
# unsatisfiable (`[ "$lock_owner" -eq -999 ]`, round 11's mutation) left that
# check green with the needle untouched. A stubbed `flock` that always fails
# stands in here for "whatever happens after the guards": if the owner guard
# does NOT refuse a hostile owner, execution falls through to the real
# acquisition and fails there instead, with a DIFFERENT, distinguishable
# message ("Could not acquire the install lock") — so this case's message
# assertion, not just its rc, is what a broken owner comparison actually trips.
run_lock_owner() {
    local root="$1" attack="$2" bin="${FIXTURE_DIR}/bin-lockowner-$2"
    rm -rf "${root}" "${bin}"; mkdir -p "${root}/tmp" "${bin}"
    printf '#!/bin/bash\nexec "$@"\n' > "${bin}/sudo"; chmod +x "${bin}/sudo"
    printf '#!/bin/bash\nexit 1\n' > "${bin}/flock"
    chmod +x "${bin}/sudo" "${bin}/flock"
    local lock_path="${root}/tmp/vespasian-install-chrome.lock"
    printf 'planted lock\n' > "${lock_path}"
    # A uid guaranteed to differ from both root (0) and this test's own uid,
    # without needing an actual "nobody"-class account to exist on the host.
    local fake_uid=$(($(id -u) + 1))
    local real_stat
    real_stat="$(command -v stat)"
    {
        printf '#!/bin/bash\n'
        printf 'if [ "$1" = "-c" ] && [ "$2" = "%%u" ] && [ "$4" = "%s" ]; then\n' "${lock_path}"
        case "${attack}" in
            reject)   printf '    echo %s\n' "${fake_uid}" ;;
            statfail) printf '    exit 1\n' ;;
        esac
        printf 'else\n'
        printf '    exec "%s" "$@"\n' "${real_stat}"
        printf 'fi\n'
    } > "${bin}/stat"
    chmod +x "${bin}/stat"
    (
        VESPASIAN_TEST_ROOT="${root}"
        export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS
        unset container
        PATH="${bin}:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        set +e
        out=$(main 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

res_zown1=$(run_lock_owner "${FIXTURE_DIR}/root-zown1" reject)
assert_eq "case z: a lock file owned by a third uid is refused (rc 1)" \
    "1" "$(echo "${res_zown1}" | sed -n '1p')"
assert_contains "case z: the third-uid refusal names the owner check, not a flock timeout" \
    "neither root nor" "${res_zown1}"

res_zown2=$(run_lock_owner "${FIXTURE_DIR}/root-zown2" statfail)
assert_eq "case z: a lock file whose owner cannot be determined fails closed (rc 1)" \
    "1" "$(echo "${res_zown2}" | sed -n '1p')"
assert_contains "case z: the stat-failure refusal names the owner check, not a flock timeout" \
    "Could not determine the owner" "${res_zown2}"

# case z3 (SEC-BE-004): the lock path is a fixed name in a sticky world-writable
# directory, so an unprivileged local user can plant ANY file type there before a
# root run. The symlink and hardlink guards above are the only two type checks,
# and a FIFO defeats both. Asserting rc 1 alone is not enough here: rc 124 means
# the run HUNG, which is the actual defect and a strictly worse outcome than a
# refusal, so it gets its own assertion rather than being folded into "not 1".
res_z3=$(run_lock_plant "${FIXTURE_DIR}/root-z3" fifo)
rc_z3=$(echo "${res_z3}" | sed -n '1p')
assert_eq "case z3: a FIFO at the lock path does not hang the run (rc is not 124)" \
    "no-timeout" "$([ "${rc_z3}" = "124" ] && echo "HUNG in open(2) — flock -w never applies" || echo "no-timeout")"
assert_eq "case z3: a FIFO at the lock path is refused (rc 1)" \
    "1" "${rc_z3}"
assert_contains "case z3: the refusal names the file type rather than a lock timeout" \
    "not a regular file" "${res_z3}"

# The acquisition itself, and what happens when it fails (TEST-011/TEST-012).
# A stubbed `flock` that always times out stands in for a genuinely contended
# lock without this case actually waiting out the real 300s bound. Fixed-path
# apt wiring is pre-planted to stand in for a CONCURRENT run's live state
# (SEC-BE-008): this run must never hold the lock, so its own EXIT trap must
# not touch it.
run_lock_contention() {
    local root="$1" bin="${FIXTURE_DIR}/bin-lockcontend"
    rm -rf "${root}" "${bin}"; mkdir -p "${root}" "${bin}"
    printf '#!/bin/bash\nexec "$@"\n' > "${bin}/sudo"
    printf '#!/bin/bash\nexit 1\n' > "${bin}/flock"
    chmod +x "${bin}/sudo" "${bin}/flock"
    mkdir -p "${root}/etc/apt/sources.list.d" "${root}/etc/apt/preferences.d" \
        "${root}/usr/share/keyrings"
    printf 'peer wiring\n' > "${root}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list"
    printf 'peer keyring\n' > "${root}/usr/share/keyrings/google-chrome-vespasian-temp.gpg"
    printf 'peer pin\n' > "${root}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref"
    (
        VESPASIAN_TEST_ROOT="${root}"
        export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS
        unset container
        PATH="${bin}:${PATH}"
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        set +e
        out=$(main 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}

root_z3="${FIXTURE_DIR}/root-z3"
res_z3=$(run_lock_contention "${root_z3}")
assert_eq "case z: a lock that cannot be acquired aborts main() (rc 1)" \
    "1" "$(echo "${res_z3}" | sed -n '1p')"
assert_contains "case z: the abort names the install lock" \
    "Could not acquire the install lock" "${res_z3}"
if [ -e "${root_z3}/etc/apt/sources.list.d/google-chrome-vespasian-temp.list" ] && \
   [ -e "${root_z3}/usr/share/keyrings/google-chrome-vespasian-temp.gpg" ] && \
   [ -e "${root_z3}/etc/apt/preferences.d/google-chrome-vespasian-temp.pref" ]; then
    echo "PASS: case z: a run that never held the lock does not strip a peer's apt wiring on exit"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case z: a run that never held the lock removed apt wiring it does not own — the exact race the lock exists to prevent"
    fail_count=$((fail_count + 1))
fi

# z4: the lock ACTUALLY EXCLUDES two concurrent runs (TEST-002).
#
# Every flock assertion above this point drives a STUBBED flock that always
# exits 1, which proves what happens when acquisition fails but says nothing
# about whether acquisition succeeding means anything. It did not: the previous
# implementation ran `install -m 0644 -- /dev/null "$LOCK_FILE"` unconditionally,
# and install(1) unlinks its destination before creating it, so each run locked
# a FRESH INODE and two runs proceeded in parallel. The whole suite stayed green
# through that, because no case ever held the lock in one process and tried to
# take it in another.
#
# This drives the real flock against the script's real acquisition sequence,
# extracted from the source so it cannot drift from what main() does. Holder
# takes the lock and sleeps; contender uses a 1s timeout and must FAIL.
# TEST-007: scoped to main()'s COMMENT-STRIPPED body, not the whole installer.
# Two defects, both mutation-proven:
#
#   1. The greps ran over the raw file, so a comment satisfied them. Rewriting the
#      real acquisition to `[ ! -f ]` + an `<>` read-write open and leaving the old
#      literals on one added comment line kept this printing "the acquisition
#      sequence still matches the one exercised below" at 201/0, exit 0 — while the
#      fixture below was mirroring a sequence main() no longer used. Detecting drift
#      is this sentinel's ONLY job, so a comment-satisfiable sentinel is inert.
#
#   2. It pinned two lines of an acquisition that now carries five guards ahead of
#      them (symlink, regular-file, hard-link count, owner, and the [ -e ] branch),
#      all added by SEC-BE-004, and then claimed the sequences "match". Deleting any
#      guard left the claim standing. The mirrored fixture deliberately does NOT
#      reproduce the guards — it exercises mutual exclusion, and the guards have
#      their own cases (z, z3) — so the honest contract is: pin the three lines the
#      fixture DOES mirror, pin that the guards still exist, and say which is which.
lock_main_code=$(fn_code main)
lock_seq_ok=1
grep -q 'if \[ ! -e "\$LOCK_FILE" \]; then' <<<"${lock_main_code}" || lock_seq_ok=0
grep -q 'exec {LOCK_FD}<"\$LOCK_FILE"' <<<"${lock_main_code}" || lock_seq_ok=0
grep -qE 'flock -w [0-9]+ "\$LOCK_FD"' <<<"${lock_main_code}" || lock_seq_ok=0
if [ "${lock_seq_ok}" -ne 1 ]; then
    echo "FAIL: case z4: the three lines the fixture below mirrors (create-when-absent, read-only open, bounded flock) are no longer main()'s — fix the fixture rather than deleting this case"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case z4: the create/open/flock lines the fixture mirrors are still main()'s"
    pass_count=$((pass_count + 1))
fi
# The four SEC-BE-004 guards the fixture does not mirror. Cases z and z3 DO drive
# them behaviourally -- they source install-chrome.sh and run the real main() with
# only $SUDO stubbed, so deleting `[ -L ]` really does fail case z. What those
# cases cannot see is POSITION: run_lock_plant pre-plants the hostile file before
# invoking main(), so the path always exists when the guards run, and the guards
# fire identically whether they sit before or after the create. That is what the
# ordering assertions below cover, and it is not hypothetical -- see their comment.
lock_guards_missing=""
while IFS='|' read -r needle label; do
    [ -n "$needle" ] || continue
    grep -qE -- "$needle" <<<"${lock_main_code}" || lock_guards_missing="${lock_guards_missing} ${label}"
done <<'GUARDS'
if \[ -L "\$LOCK_FILE" \]; then|symlink-refusal
if \[ ! -f "\$LOCK_FILE" \]; then|regular-file-refusal
lock_nlink=\$\(stat -c '%h'|hardlink-count
lock_owner=\$\(stat -c '%u'|owner-check
GUARDS
if [ -n "${lock_guards_missing}" ]; then
    echo "FAIL: case z4: main()'s lock guards are gone:${lock_guards_missing} — a hostile plant at the fixed /tmp path is admitted again (SEC-BE-004)"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case z4: main() still carries all four SEC-BE-004 lock guards"
    pass_count=$((pass_count + 1))
fi

# TEST-001: the guards' POSITION, not merely their presence. The four needles above
# match wherever the guards sit, and the old PASS text claimed "ahead of the open" --
# a position it never measured. That mattered: SEC-BE-001's whole fix was positional.
# The guards used to sit ABOVE the create with three of them inside `if [ -e ]`, so
# on a host where the lock path was absent every guard was skipped and a plant
# arriving before the conditional create was opened unchecked. MEASURED: restoring
# that layout left this suite at 239 passed, 0 failed -- the security fix could be
# reverted in full and nothing noticed.
#
# Same idiom as cases u and v3: locate each statement inside main()'s extracted body
# and compare offsets, with a fidelity sentinel FIRST so a rename or a reword is
# reported as drift instead of silently making every comparison compare empty
# strings. `-e` deliberately has its own needle: its return is what re-admits the
# skip-every-guard shape, so it is pinned absent rather than merely ordered.
#
# ALL FOUR guards are compared, not three. The first version of this block omitted
# the hard-link guard while its sentinel still said "all four" and both assertions
# were titled "every lock guard". MEASURED both directions: relocating ONLY that
# guard above the create left the suite at 244 passed, 0 failed, and moving it
# below the open did too -- every assertion here satisfied while that guard sat
# exactly where the failure text says a guard must never sit. Above the create it
# also goes vacuous: `stat` fails on an absent path, lock_nlink becomes empty, and
# `[ -n "$lock_nlink" ]` skips the comparison.
#
# nlink is the guard least substitutable by its neighbours, so omitting it was the
# worst of the four to omit: a hard link SHARES its target's inode, so `[ -L ]`
# does not see it, `[ -f ]` passes it, and `stat -c '%u'` reports the TARGET's
# owner -- a hard link to any root-owned file reads back uid 0 and clears the
# owner check as well.
lk_create_at=$(printf '%s\n' "${lock_main_code}" | grep -nE '^[[:space:]]*if \[ ! -e "\$LOCK_FILE" \]; then$' | head -1 | cut -d: -f1 || true)
lk_symlink_at=$(printf '%s\n' "${lock_main_code}" | grep -nE '^[[:space:]]*if \[ -L "\$LOCK_FILE" \]; then$' | head -1 | cut -d: -f1 || true)
lk_regular_at=$(printf '%s\n' "${lock_main_code}" | grep -nE '^[[:space:]]*if \[ ! -f "\$LOCK_FILE" \]; then$' | head -1 | cut -d: -f1 || true)
lk_nlink_at=$(printf '%s\n' "${lock_main_code}" | grep -nE '^[[:space:]]*lock_nlink=\$\(stat -c' | head -1 | cut -d: -f1 || true)
lk_owner_at=$(printf '%s\n' "${lock_main_code}" | grep -nE '^[[:space:]]*lock_owner=\$\(stat -c' | head -1 | cut -d: -f1 || true)
lk_open_at=$(printf '%s\n' "${lock_main_code}" | grep -nE '^[[:space:]]*exec \{LOCK_FD\}<"\$LOCK_FILE"$' | head -1 | cut -d: -f1 || true)
lk_ewrap_n=$(printf '%s\n' "${lock_main_code}" | grep -cE '^[[:space:]]*if \[ -e "\$LOCK_FILE" \]; then$' || true)

if [ -n "${lk_create_at}" ] && [ -n "${lk_symlink_at}" ] && [ -n "${lk_regular_at}" ] \
   && [ -n "${lk_nlink_at}" ] && [ -n "${lk_owner_at}" ] && [ -n "${lk_open_at}" ]; then
    echo "PASS: case z4: main()'s create, all four lock guards and the open were all located"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case z4: could not locate main()'s create, a lock guard, or the open — the ordering assertions below would be vacuous; fix the extraction rather than deleting it"
    fail_count=$((fail_count + 1))
fi

assert_eq "case z4: every lock guard runs AFTER the create, so it inspects the inode exec will open" \
    "after" "$( { [ -n "${lk_create_at}" ] && [ -n "${lk_symlink_at}" ] && [ -n "${lk_regular_at}" ] \
                  && [ -n "${lk_nlink_at}" ] && [ -n "${lk_owner_at}" ] \
                  && [ "${lk_symlink_at}" -gt "${lk_create_at}" ] \
                  && [ "${lk_regular_at}" -gt "${lk_create_at}" ] \
                  && [ "${lk_nlink_at}" -gt "${lk_create_at}" ] \
                  && [ "${lk_owner_at}" -gt "${lk_create_at}" ]; } && echo "after" \
                || echo "NOT after the create — on a host where the lock path is absent the guards are skipped and a plant before the conditional create is opened unchecked (SEC-BE-001)")"

assert_eq "case z4: every lock guard runs BEFORE the open" \
    "before" "$( { [ -n "${lk_open_at}" ] && [ -n "${lk_symlink_at}" ] && [ -n "${lk_regular_at}" ] \
                   && [ -n "${lk_nlink_at}" ] && [ -n "${lk_owner_at}" ] \
                   && [ "${lk_symlink_at}" -lt "${lk_open_at}" ] \
                   && [ "${lk_regular_at}" -lt "${lk_open_at}" ] \
                   && [ "${lk_nlink_at}" -lt "${lk_open_at}" ] \
                   && [ "${lk_owner_at}" -lt "${lk_open_at}" ]; } && echo "before" \
                || echo "NOT before exec {LOCK_FD}< — a guard after the open cannot stop the open it exists to gate")"

assert_eq "case z4: no \`if [ -e ]\` wrapper around the guards (that shape skips them all when the path is absent)" \
    "0" "${lk_ewrap_n}"

# TEST-004: the SOURCE-level assertions above need nothing ambient -- they read
# install-chrome.sh's text. The three below run two real processes contending for
# a real lock, so they need flock(1), the one ambient dependency in this case that
# had no credited skip while every other in this file does. This arm makes z4
# report the missing tool instead of three failures blaming mutual exclusion.
#
# Scope, stated rather than implied: this does NOT make a flock-less host green,
# and no claim here should be read that way. MEASURED at HEAD before this arm
# existed, a PATH with no flock produced 11 failures across cases f, i, j and
# others and terminated before the summary -- install-chrome.sh's require_tools
# refuses such a host outright (case z5 pins that refusal), so every case that
# drives main() fails for the same upstream reason. That shape is pre-existing,
# unrelated to z4, and out of this round's scope. The credit keeps z4's own
# accounting honest on it; it does not repair the shape.
if ! command -v flock >/dev/null 2>&1; then
    skip "case z4: concurrent lock acquisition (flock not found on PATH)" 3
else
# This branch's body is deliberately NOT indented. It contains a `<<'Z4EOF'`
# here-doc, and `<<` (not `<<-`) requires its terminator at column 0; indenting
# the body indents the delimiter and the here-doc swallows the rest of the file.
# MEASURED: indenting the 47 lines below produced "here-document delimited by
# end-of-file" and a syntax error. `<<-` is not an alternative either, since it
# strips only TABS and this file is space-indented throughout.
z4_dir="${FIXTURE_DIR}/lock-z4"; mkdir -p "${z4_dir}"
z4_lock="${z4_dir}/vespasian-install-chrome.lock"
cat > "${z4_dir}/acquire.sh" <<'Z4EOF'
#!/usr/bin/env bash
# Mirrors main()'s acquisition: create ONLY when absent, open read-only, flock.
# TEST-008: $4, when given, is a readiness file this script touches AFTER the lock is
# held, so the contender can wait for the real event instead of guessing at a delay.
LOCK_FILE="$1"; hold="$2"; wait_s="$3"; ready_file="${4:-}"
if [ ! -e "$LOCK_FILE" ]; then install -m 0644 -- /dev/null "$LOCK_FILE"; fi
exec {LOCK_FD}<"$LOCK_FILE"
if flock -w "$wait_s" "$LOCK_FD"; then
    echo "ACQUIRED"
    [ -n "$ready_file" ] && : > "$ready_file"
    sleep "$hold"
else
    echo "BLOCKED"
fi
Z4EOF
chmod +x "${z4_dir}/acquire.sh"
# TEST-008: readiness signal, not a fixed sleep. `sleep 0.5` was the only
# wall-clock-timed assertion in the four suites, and it was timed in the fragile
# direction: if a throttled runner had not let the holder take the lock within 0.5s,
# the contender ACQUIRED and this case failed on correct code. Waiting for the
# holder's own signal removes the race; the bounded loop means a genuine failure to
# acquire still fails (with a named diagnostic) rather than hanging the suite.
z4_ready="${z4_dir}/holder.ready"
rm -f "${z4_ready}"
"${z4_dir}/acquire.sh" "${z4_lock}" 3 1 "${z4_ready}" > "${z4_dir}/holder.out" 2>&1 &
z4_holder=$!
z4_waited=0
while [ ! -e "${z4_ready}" ] && [ "${z4_waited}" -lt 100 ]; do
    sleep 0.05
    z4_waited=$((z4_waited + 1))
done
if [ -e "${z4_ready}" ]; then
    echo "PASS: case z4: the holder signalled it holds the lock (readiness, not a fixed delay)"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case z4: the holder never signalled it acquired the lock within 5s — the mutual-exclusion assertions below cannot be trusted"
    fail_count=$((fail_count + 1))
fi
z4_contender=$("${z4_dir}/acquire.sh" "${z4_lock}" 0 1 2>&1)
wait "${z4_holder}" 2>/dev/null || true
assert_eq "case z4: the first run acquires the install lock" \
    "ACQUIRED" "$(cat "${z4_dir}/holder.out")"
assert_eq "case z4: a CONCURRENT second run is blocked by it (mutual exclusion is real)" \
    "BLOCKED" "${z4_contender}"
fi

# z5: flock is required, not optional (SEC-BE-003).
#
# main() used to warn and continue when flock was missing. On that path
# LOCK_HELD stayed 0 while the run still wrote the apt wiring and still ran
# apt-get install, so cleanup_all — gated on LOCK_HELD — did nothing, and a
# failed install stranded a permanently trusted Google apt source plus the
# package's root cron pinger. The degrade is gone; this pins that it stays gone.
run_no_flock() {
    local root="$1" bin="${FIXTURE_DIR}/bin-noflock"
    rm -rf "${root}" "${bin}"; mkdir -p "${root}" "${bin}"
    printf '#!/bin/bash\nexec "$@"\n' > "${bin}/sudo"; chmod +x "${bin}/sudo"
    # Build the tool farm BEFORE narrowing PATH — populating it from inside a
    # shell that has already lost `mkdir` does not work, which is how the first
    # version of this case failed.
    local core="${FIXTURE_DIR}/bin-noflock-core"
    rm -rf "${core}"; mkdir -p "${core}"
    local t p
    for t in bash sh env cat rm mkdir rmdir stat install grep sed awk id dirname basename ln chmod date sleep tr sort head tail wc mktemp; do
        p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "${core}/$t"
    done
    # Sanity: the farm must NOT contain flock, or this case proves nothing.
    if [ -e "${core}/flock" ]; then
        echo "FAIL: case z5: the no-flock tool farm contains flock — the case would be vacuous"
        return 99
    fi
    (
        VESPASIAN_TEST_ROOT="${root}"; export VESPASIAN_TEST_ROOT
        unset REMOTE_CONTAINERS; unset container
        PATH="${bin}:${core}"; export PATH
        # shellcheck source=install-chrome.sh
        source "${INSTALL_SCRIPT}"
        set +e
        out=$(main 2>&1)
        printf '%s\n%s\n' "$?" "${out}"
    )
}
res_z5=$(run_no_flock "${FIXTURE_DIR}/root-z5")
assert_eq "case z5: main() refuses to run when flock is absent (rc 1)" \
    "1" "$(echo "${res_z5}" | sed -n '1p')"
# Match the REFUSAL's distinctive wording, not the bare token "flock not found".
# Measured: the old degrade logged "flock not found — concurrent installs are
# not mutually exclusive", so an assertion on that token passed identically
# whether the script refused or warned-and-continued, and a mutation restoring
# the degrade left this case green. "refusing to run" appears only on the
# refusal path.
assert_contains "case z5: the refusal names flock rather than degrading silently" \
    "refusing to run without mutual exclusion" "${res_z5}"
# And prove it aborted BEFORE doing any work: a degrade would fall through to
# the idempotency check and the install path, both of which announce themselves.
if printf '%s' "${res_z5}" | grep -q 'Runnable browser already present\|Installing google-chrome-stable'; then
    echo "FAIL: case z5: the run continued past the missing-flock check — the degrade path is back"
    fail_count=$((fail_count + 1))
else
    echo "PASS: case z5: the run stopped at the flock check rather than continuing into the install path"
    pass_count=$((pass_count + 1))
fi

# ── Case cr: the CREDIT REGISTER is derived from the call sites, not believed ──
# TEST-001. The register above says it "can be checked against the source rather
# than believed" -- but nothing checked it, which is the same shape of unbacked
# claim this suite exists to catch. This case makes the sentence true.
#
# PER-SITE, not just a total (TEST-002). The first version of this case compared
# only the scalar maximum, and that is defeatable by an offsetting pair: cases v
# and y carry byte-identical gate conditions, so re-crediting v 12->13 and y 3->2
# leaves the maximum at 44, leaves pass+fail+skip_credit at its pin on the equipped
# host, and leaves it correct on all three degraded shapes too, because v and y
# always co-fire. Both arms would then mis-credit their blocks. The sibling suite
# recorded exactly this defeat as MUTATION-PROVEN and moved to a per-site register;
# this is the same idiom, keyed by each site's own message.
#
# Sites are compared verbatim, credits included, so a re-credit, a re-wording, an
# added arm, a removed arm, or a credit dropped entirely all show up as drift.
EXPECTED_SKIP_REGISTER='case a2: committed-mode check (not a git checkout)=1
case f2: fingerprint-mismatch diagnosis for an unexpected real key (gpg not found on PATH)=4
case f4: main() ordering guarantee on a fingerprint mismatch ($(main_deps_missing) not found on PATH)=3
case j/j2: trust-anchor success path (fixture test/fixtures/google-linux-signing-key.asc missing or empty)=14
case j/j2: trust-anchor success path (gpg not found on PATH)=14
case l: non-root sudo refusal (running as root)=3
case v: main-install-path in_container() gating (needs the same key fixture/gpg as j/j2, plus timeout(1) for require_tools; missing: $(main_deps_missing))=12
case y: pre-install origin gate (needs the same key fixture/gpg as j/j2, plus timeout(1) for require_tools; missing: $(main_deps_missing))=3
case bp: _bounded_probe timeout enforcement (no timeout/gtimeout on PATH)=4
case z4: concurrent lock acquisition (flock not found on PATH)=3'
cr_actual=$(grep -oE '^[[:space:]]*skip "[^"]*" [0-9]+' "${BASH_SOURCE[0]}" \
    | sed -E 's/^[[:space:]]*skip "([^"]*)" ([0-9]+)$/\1=\2/')
# Sites WITHOUT an explicit credit default to 0 and would silently not appear
# above, so they are counted separately rather than being invisible.
cr_sites=$(grep -cE '^[[:space:]]*skip "' "${BASH_SOURCE[0]}")
cr_expected_sites=$(printf '%s\n' "${EXPECTED_SKIP_REGISTER}" | wc -l)
if [ "${cr_actual}" = "${EXPECTED_SKIP_REGISTER}" ] && [ "${cr_sites}" -eq "${cr_expected_sites}" ]; then
    echo "PASS: case cr: skip-credit register is current — ${cr_sites} sites, each credit matching its recorded value"
    pass_count=$((pass_count + 1))
else
    echo "FAIL: case cr: skip-credit register drifted — a skip was added, removed, re-credited, re-worded, or written with no explicit credit. Expected:
${EXPECTED_SKIP_REGISTER}
Found (${cr_sites} total sites, credited ones listed):
${cr_actual}
Per-site credits are pinned, not just their sum: an offsetting swap between two arms that always co-fire (v and y) leaves the total right while both mis-credit their blocks."
    fail_count=$((fail_count + 1))
fi

# And the DECLARED maximum in the register comment, evaluated -- the left-hand side
# of the arithmetic, not the "= 44" written after it, so a register whose own sum
# has gone stale is caught. Max per label, not sum: j/j2 declares the same credit
# on two mutually-exclusive arms, which is why the maximum is 47 and not the 61 the
# ten literals add to.
cr_derived=$(
    awk '
        match($0, /skip "case [a-z0-9\/]+:/) {
            label = substr($0, RSTART + 11, RLENGTH - 12)
            if (match($0, /" [0-9]+$/)) {
                credit = substr($0, RSTART + 2, RLENGTH - 2) + 0
                if (credit > max[label]) max[label] = credit
            }
        }
        END { t = 0; for (l in max) t += max[l]; print t }
    ' "${BASH_SOURCE[0]}"
)
cr_declared=$(
    expr_str=$(grep -oE '^# Maximum skip_credit on a maximally-degraded host: [0-9+]+' "${BASH_SOURCE[0]}" \
               | grep -oE '[0-9+]+$' || true)
    if [ -n "${expr_str}" ]; then echo $((expr_str)); else echo "UNPARSED"; fi
)
assert_eq "case cr: the credit register's declared maximum matches the skip() call sites" \
    "${cr_derived}" "${cr_declared}"

# ── Summary ─────────────────────────────────────────────────────
SUITE_COMPLETED=1
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
if [ "${skip_count}" -ne 0 ]; then
    echo "install-chrome-selftest: NOTE — ${skip_count} case(s) skipped: ${skipped_labels}"
    echo "  Each SKIP line above states its own cause; the credit register near the top"
    echo "  of this file lists what each contributes. Skipped is not covered."
fi
# The accounting pin runs FIRST, before the trust-anchor guard's exit. Ordered
# the other way, a gpg-less host exited at the trust-anchor check and the pin
# never evaluated — so on exactly the degraded configuration the skip credits
# exist for, a wrong credit was invisible. Measured: with EXPECTED_ASSERTIONS
# deliberately falsified on such a host, the old order printed no drift line at
# all. The pin now reports it. (The two guards still exit independently: a
# drift exits here, so the trust-anchor message below is not also printed --
# both are CI failures either way, and reporting the accounting error first is
# the point, since a wrong credit is what makes every other count untrustworthy.)
if [ "$((pass_count + fail_count + skip_credit))" -ne "${EXPECTED_ASSERTIONS}" ]; then
    echo "install-chrome-selftest: FAIL — assertion accounting drift: expected ${EXPECTED_ASSERTIONS} assertions (pass+fail+skip_credit), saw $((pass_count + fail_count + skip_credit))."
    echo "  A case was added or removed without updating EXPECTED_ASSERTIONS."
    exit 1
fi
if [ "${trust_anchor_skips}" -ne 0 ]; then
    echo "install-chrome-selftest: FAIL — the trust-anchor success path (j/j2) was skipped; that is a coverage hole."
    echo "  (cases j/j2 read test/fixtures/google-linux-signing-key.asc; if that fixture is"
    echo "   missing or empty the trust anchor's success path is untested — fix it, do not skip.)"
    exit 1
fi
[ "${fail_count}" -eq 0 ]
