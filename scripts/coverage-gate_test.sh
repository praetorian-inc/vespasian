#!/usr/bin/env bash
#
# Regression test for the `coverage-gate` awk program in the Makefile.
#
# WHY THIS EXISTS
#
# `make coverage-gate` enforces a coverage threshold with a dense one-line awk
# program that has four failure modes a coverage gate MUST get right: a
# non-numeric threshold exits 2, a threshold above 100 exits 2, coverage below
# the threshold exits 1, and a missing `total:` line fails closed at exit 2. That
# logic already shipped one real false-green bug -- `threshold + 0` silently
# coerced a non-numeric value to 0, so ANY coverage passed a gate that still
# printed a reassuring PASS -- and it was an external reviewer, not a test, that
# caught it. Nothing re-runs that reasoning on edit, so a future tweak to the
# one-liner could reintroduce a fail-open pass and look identical to a correct
# one: both print and exit 0.
#
# It is also, like scripts/check-unreachability-claims_test.sh next to it, an
# awk program authored on macOS that first runs for real on the ubuntu CI runner.
# `awk -v` tolerates embedded newlines on GNU and not on BSD, so a local green
# says nothing about the runner. Wiring this test into the coverage-gate CI job
# (mirroring that sibling's "Self-test the claims checker" step) is what actually
# closes that gap; a green run here is evidence about this machine only.
#
# HOW IT WORKS -- TWO LAYERS
#
# 1. Fragment cases (assert_gate). The program under test is not copied here --
#    it is EXTRACTED from the live recipe via `make -n coverage-gate-check`, so
#    the test exercises exactly what CI runs and cannot drift from it. The
#    threshold is supplied through the environment (the recipe reads it from
#    `ENVIRON["COVERAGE_THRESHOLD"]`, not `awk -v`, so an untrusted value cannot
#    inject a second awk program argument). Each case feeds a fixture
#    `go tool cover -func` block on stdin and asserts an EXACT awk exit code, so
#    an awk that cannot start (exit 2 where 0 or 1 was expected) fails loudly
#    rather than passing vacuously.
#
# 2. Real-target cases (assert_make). The fragment cases test the awk program in
#    isolation; they cannot see the recipe around it. So a second layer runs the
#    real `coverage-gate-check` target -- through the COVERAGE_FUNC seam so a
#    fixture stands in for `go tool cover` and no Go build is needed -- and
#    asserts make's OWN exit code. This catches three regressions layer 1 is
#    blind to: a `-` recipe prefix that would make `make` swallow a FAIL and exit
#    0; a dropped `+ 0` that turns the numeric compare lexicographic (a 9.5%
#    coverage then passes an 85% gate); and a zeroed default COVERAGE_THRESHOLD
#    (a case that omits the threshold exercises the Makefile default). Note make
#    collapses the awk program's exit 1 and exit 2 into its own exit 2 on any
#    recipe failure, so these cases assert exit 2 for a failed gate and 0 for a
#    passing one, and lean on the printed FAIL/PASS text to name the reason.
#
# A final guard asserts the total case count, so silently deleting a case (which
# would otherwise leave the suite green) is itself a failure -- the same
# convention as EXPECTED_ASSERTIONS in test/setup-live-targets_test.sh.
#
# No Go build, no network: ~1s.

set -uo pipefail

# Every case increments this; the suite fails if the final total is not exactly
# EXPECTED_CASES, so a deleted case cannot pass unnoticed. Update it deliberately
# when adding or removing a case.
EXPECTED_CASES=15

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Extract the awk program from the real recipe. `make -n` needs the Makefile, so
# run it from the repo root. `coverage-gate-check` is the profile-only target, so
# `make -n` prints just its one awk line (no `go test` prerequisite).
gate_line="$(cd "$REPO_ROOT" && make -n coverage-gate-check 2>/dev/null | grep 'go tool cover -func=coverage.out | awk')"
if [ -z "$gate_line" ]; then
  echo "FATAL: could not find the coverage-gate awk command in 'make -n coverage-gate-check' output" >&2
  exit 2
fi

# The awk program starts at `BEGIN {` and runs to the closing single quote at end
# of line. Anchor on 'BEGIN so anything before it (the pipe, `go tool cover`) is
# irrelevant. The program itself contains no single quotes.
q="'"
AWK_PROG="BEGIN${gate_line#*${q}BEGIN}"
AWK_PROG="${AWK_PROG%${q}}"
if [ "${AWK_PROG#BEGIN}" = "$AWK_PROG" ]; then
  echo "FATAL: failed to isolate the awk program from: $gate_line" >&2
  exit 2
fi

failures=0
cases=0

# assert_gate NAME THRESHOLD FIXTURE WANT_EXIT WANT_SUBSTRING [WANT_ABSENT]
# Runs the extracted awk program with THRESHOLD (supplied via the environment, as
# the recipe reads it) over FIXTURE on stdin and checks the exit code, an expected
# substring (if non-empty), and -- if WANT_ABSENT is given -- that the output does
# NOT contain it. WANT_ABSENT pins branches that share an exit code with another:
# a BEGIN threshold-validation error and a missing `total:` line both exit 2, so
# asserting the "no total:" message is ABSENT is what proves the BEGIN error was
# not overwritten by the END `bad` guard (`if (bad) exit bad`) -- the only
# otherwise-untested branch.
assert_gate() {
  local name="$1" threshold="$2" fixture="$3" want_exit="$4" want_sub="$5" want_absent="${6:-}"
  cases=$((cases + 1))

  local out rc
  out="$(printf '%s\n' "$fixture" | COVERAGE_THRESHOLD="$threshold" awk "$AWK_PROG" 2>&1)"
  rc=$?

  local ok=1
  if [ "$rc" -ne "$want_exit" ]; then
    ok=0
    printf 'FAIL %s\n  exit = %d, want %d\n' "$name" "$rc" "$want_exit"
  fi
  if [ -n "$want_sub" ] && ! printf '%s' "$out" | grep -qF -- "$want_sub"; then
    ok=0
    printf 'FAIL %s\n  output lacks %q\n' "$name" "$want_sub"
  fi
  if [ -n "$want_absent" ] && printf '%s' "$out" | grep -qF -- "$want_absent"; then
    ok=0
    printf 'FAIL %s\n  output contains %q and must not\n' "$name" "$want_absent"
  fi

  if [ "$ok" -eq 1 ]; then
    printf 'ok   %s\n' "$name"
  else
    failures=$((failures + 1))
    printf '  --- awk output ---\n%s\n  ------------------\n' "$out"
  fi
}

# assert_make NAME THRESHOLD FIXTURE WANT_EXIT WANT_SUBSTRING
# Drives the REAL `coverage-gate-check` target with COVERAGE_FUNC standing in for
# `go tool cover` (so no Go build) and asserts make's OWN exit code. An empty
# THRESHOLD exercises the Makefile's default COVERAGE_THRESHOLD. make exits 2 on
# any recipe failure (collapsing the gate's exit 1 and 2), so WANT_EXIT is 2 for a
# failed gate and 0 for a passing one; the substring names the reason.
assert_make() {
  local name="$1" threshold="$2" fixture="$3" want_exit="$4" want_sub="$5"
  cases=$((cases + 1))

  local tmp out rc
  tmp="$(mktemp)"
  printf '%s\n' "$fixture" > "$tmp"

  if [ -n "$threshold" ]; then
    out="$(cd "$REPO_ROOT" && make coverage-gate-check COVERAGE_THRESHOLD="$threshold" COVERAGE_FUNC="cat $tmp" 2>&1)"
  else
    out="$(cd "$REPO_ROOT" && make coverage-gate-check COVERAGE_FUNC="cat $tmp" 2>&1)"
  fi
  rc=$?
  rm -f "$tmp"

  local ok=1
  if [ "$rc" -ne "$want_exit" ]; then
    ok=0
    printf 'FAIL %s\n  make exit = %d, want %d\n' "$name" "$rc" "$want_exit"
  fi
  if [ -n "$want_sub" ] && ! printf '%s' "$out" | grep -qF -- "$want_sub"; then
    ok=0
    printf 'FAIL %s\n  output lacks %q\n' "$name" "$want_sub"
  fi

  if [ "$ok" -eq 1 ]; then
    printf 'ok   %s\n' "$name"
  else
    failures=$((failures + 1))
    printf '  --- make output ---\n%s\n  -------------------\n' "$out"
  fi
}

# A minimal but realistic `go tool cover -func` block: the gate only reads the
# `total:` line's last field, but a preceding per-func line keeps the fixture
# honest about the real input shape.
PASS_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		100.0%
total:							(statements)	86.4%'
LOW_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		80.0%
total:							(statements)	80.0%'
AT_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		85.0%
total:							(statements)	85.0%'
# Single-leading-digit total: numerically below 85, but lexicographically ABOVE
# "85" ('9' > '8'). A correct gate FAILs it; a gate that dropped `+ 0` would
# string-compare and let it PASS. This is the fixture the earlier cases lacked.
NINE_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		9.5%
total:							(statements)	9.5%'
NO_TOTAL_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		100.0%'
FULL_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		100.0%
total:							(statements)	100.0%'

# --- Layer 1: the awk program in isolation (assert_gate) ---

# 1. Coverage below the threshold fails the build (exit 1). The core gate.
assert_gate "below threshold fails" 85 "$LOW_FIXTURE" 1 "FAIL"

# 2. Coverage above the threshold passes (exit 0).
assert_gate "above threshold passes" 85 "$PASS_FIXTURE" 0 "PASS"

# 3. Coverage exactly at the threshold passes: the comparison is `pct < threshold`,
#    so equality is not a failure. Pins the boundary.
assert_gate "coverage exactly at threshold passes" 85 "$AT_FIXTURE" 0 "PASS"

# 4. A non-numeric threshold exits 2 rather than coercing to 0 and printing PASS.
#    This is the exact false-green this gate was fixed to remove.
assert_gate "non-numeric threshold fails closed" "abc" "$PASS_FIXTURE" 2 "not a number" "no total: line"

# 5. An empty threshold is likewise rejected (empty string fails the numeric regex).
assert_gate "empty threshold fails closed" "" "$PASS_FIXTURE" 2 "not a number" "no total: line"

# 6. A threshold above 100 is out of range and exits 2 -- otherwise no coverage
#    could ever pass, a silent mis-set knob rather than an error.
assert_gate "threshold over 100 fails closed" 150 "$PASS_FIXTURE" 2 "outside 0..100" "no total: line"

# 7. No `total:` line means `go tool cover` produced nothing usable; the gate must
#    fail closed (exit 2) rather than pass because it found no failure.
assert_gate "missing total line fails closed" 85 "$NO_TOTAL_FIXTURE" 2 "no total: line"

# 8. A decimal threshold is valid and, above coverage, passes -- the regex admits
#    an optional decimal part.
assert_gate "decimal threshold above coverage passes" 85.5 "$PASS_FIXTURE" 0 "PASS"

# 9. A decimal threshold below coverage still fails, so the decimal path shares the
#    real comparison rather than being merely accepted.
assert_gate "decimal threshold below coverage fails" 85.5 "$AT_FIXTURE" 1 "FAIL"

# 10. A negative threshold is rejected: the regex admits only digits with an optional
#     decimal part, so a leading '-' fails it (exit 2). Guards against a regex loosened
#     to '^-?[0-9]+...' that would let COVERAGE_THRESHOLD=-5 pass every `pct < threshold`
#     comparison and print PASS. Also asserts "no total: line" is absent, so the BEGIN
#     error is not masked by the END guard.
assert_gate "negative threshold fails closed" -5 "$PASS_FIXTURE" 2 "not a number" "no total: line"

# 11. A threshold of exactly 100 is IN range -- the check rejects >100, not ==100 --
#     and over 100% coverage it passes (exit 0). Pins the upper boundary as accepted,
#     so a regression tightening the bound to `>= 100` would be caught.
assert_gate "threshold exactly 100 is accepted" 100 "$FULL_FIXTURE" 0 "PASS"

# 12. Single-digit coverage below an 85 gate fails (exit 1). Guards the `+ 0`
#     numeric coercion directly: without it the compare is lexicographic and "9.5"
#     sorts above "85", so this case would flip to PASS.
assert_gate "single-digit coverage below threshold fails (guards + 0)" 85 "$NINE_FIXTURE" 1 "FAIL"

# --- Layer 2: the real coverage-gate-check target (assert_make) ---

# 13. Real target, below the DEFAULT threshold, fails. The case omits the threshold,
#     so it runs the Makefile's default (85): 80% < 85% must fail. Catches a zeroed
#     default (COVERAGE_THRESHOLD ?= 0 would make 80% pass) and a `-` recipe prefix
#     (make would exit 0 while printing FAIL).
assert_make "real make: below default threshold fails" "" "$LOW_FIXTURE" 2 "FAIL"

# 14. Real target, single-digit coverage against an 85 gate, fails. Catches the same
#     `-` prefix and the `+ 0` drop end-to-end through make, not just in the fragment.
assert_make "real make: single-digit coverage fails an 85 gate" 85 "$NINE_FIXTURE" 2 "FAIL"

# 15. Real target, coverage above the threshold, passes (make exit 0). Proves the
#     whole recipe -- pipe, ENVIRON read, awk -- works end to end, not only its failure
#     paths, so an always-failing recipe can't masquerade as a working gate.
assert_make "real make: above threshold passes" 85 "$PASS_FIXTURE" 0 "PASS"

echo
if [ "$cases" -ne "$EXPECTED_CASES" ]; then
  printf 'case-count guard: ran %d cases, expected %d -- a case was added or removed without updating EXPECTED_CASES\n' "$cases" "$EXPECTED_CASES"
  exit 1
fi
if [ "$failures" -ne 0 ]; then
  printf '%d of %d cases FAILED\n' "$failures" "$cases"
  exit 1
fi
printf 'all %d cases passed\n' "$cases"
