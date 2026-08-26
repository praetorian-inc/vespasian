#!/usr/bin/env bash
#
# Regression test for the `coverage-gate` awk program in the Makefile.
#
# WHY THIS EXISTS
#
# `make coverage-gate` embeds a dense one-line awk program with four failure
# modes that a coverage gate MUST get right: a non-numeric threshold exits 2, a
# threshold above 100 exits 2, coverage below the threshold exits 1, and a
# missing `total:` line fails closed at exit 2. That logic already shipped one
# real false-green bug -- `threshold + 0` silently coerced a non-numeric value to
# 0, so ANY coverage passed a gate that still printed a reassuring PASS -- and it
# was an external reviewer, not a test, that caught it. Nothing re-runs that
# reasoning on edit, so a future tweak to the one-liner could reintroduce a
# fail-open pass and look identical to a correct one: both print and exit 0.
#
# It is also, like scripts/check-unreachability-claims_test.sh next to it, an
# awk program authored on macOS that first runs for real on the ubuntu CI runner.
# `awk -v` tolerates embedded newlines on GNU and not on BSD, so a local green
# says nothing about the runner. Wiring this test into the coverage-gate CI job
# (mirroring that sibling's "Self-test the claims checker" step) is what actually
# closes that gap; a green run here is evidence about this machine only.
#
# HOW IT WORKS
#
# The program under test is not copied here -- it is EXTRACTED from the live
# recipe via `make -n coverage-gate`, so the test exercises exactly what CI runs
# and cannot drift from it. `make -n` prints the command with make's `$$` already
# reduced to `$`, i.e. the real awk program. The recipe's own `-v threshold=...`
# is dropped and each case supplies its own threshold, which is how the
# threshold-validation modes get exercised. The awk program contains no single
# quotes and begins with `BEGIN {`, so it is isolated by anchoring on that.
#
# Each case feeds a fixture `go tool cover -func` block on stdin and asserts an
# EXACT exit code, so an awk that cannot start (exit 2 where 0 or 1 was expected)
# fails loudly rather than passing vacuously. No Go build, no network: ~1s.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Extract the awk program from the real recipe. `make -n` needs the Makefile, so
# run it from the repo root.
gate_line="$(cd "$REPO_ROOT" && make -n coverage-gate 2>/dev/null | grep 'go tool cover -func=coverage.out | awk')"
if [ -z "$gate_line" ]; then
  echo "FATAL: could not find the coverage-gate awk command in 'make -n coverage-gate' output" >&2
  exit 2
fi

# The awk program starts at `BEGIN {` and runs to the closing single quote at end
# of line. Anchor on 'BEGIN so the (possibly quoted) `-v threshold=...` before it
# is irrelevant.
q="'"
AWK_PROG="BEGIN${gate_line#*${q}BEGIN}"
AWK_PROG="${AWK_PROG%${q}}"
if [ "${AWK_PROG#BEGIN}" = "$AWK_PROG" ]; then
  echo "FATAL: failed to isolate the awk program from: $gate_line" >&2
  exit 2
fi

failures=0
cases=0

# assert_gate NAME THRESHOLD FIXTURE WANT_EXIT WANT_SUBSTRING
# Runs the extracted awk program with THRESHOLD over FIXTURE on stdin and checks
# the exit code and (if non-empty) an expected substring of the output.
assert_gate() {
  local name="$1" threshold="$2" fixture="$3" want_exit="$4" want_sub="$5"
  cases=$((cases + 1))

  local out rc
  out="$(printf '%s\n' "$fixture" | awk -v threshold="$threshold" "$AWK_PROG" 2>&1)"
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

  if [ "$ok" -eq 1 ]; then
    printf 'ok   %s\n' "$name"
  else
    failures=$((failures + 1))
    printf '  --- awk output ---\n%s\n  ------------------\n' "$out"
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
NO_TOTAL_FIXTURE='github.com/praetorian-inc/vespasian/cmd/vespasian/main.go:20:	run		100.0%'

# 1. Coverage below the threshold fails the build (exit 1). The core gate.
assert_gate "below threshold fails" 85 "$LOW_FIXTURE" 1 "FAIL"

# 2. Coverage above the threshold passes (exit 0).
assert_gate "above threshold passes" 85 "$PASS_FIXTURE" 0 "PASS"

# 3. Coverage exactly at the threshold passes: the comparison is `pct < threshold`,
#    so equality is not a failure. Pins the boundary.
assert_gate "coverage exactly at threshold passes" 85 "$AT_FIXTURE" 0 "PASS"

# 4. A non-numeric threshold exits 2 rather than coercing to 0 and printing PASS.
#    This is the exact false-green this gate was fixed to remove.
assert_gate "non-numeric threshold fails closed" "abc" "$PASS_FIXTURE" 2 "not a number"

# 5. An empty threshold is likewise rejected (empty string fails the numeric regex).
assert_gate "empty threshold fails closed" "" "$PASS_FIXTURE" 2 "not a number"

# 6. A threshold above 100 is out of range and exits 2 -- otherwise no coverage
#    could ever pass, a silent mis-set knob rather than an error.
assert_gate "threshold over 100 fails closed" 150 "$PASS_FIXTURE" 2 "outside 0..100"

# 7. No `total:` line means `go tool cover` produced nothing usable; the gate must
#    fail closed (exit 2) rather than pass because it found no failure.
assert_gate "missing total line fails closed" 85 "$NO_TOTAL_FIXTURE" 2 "no total: line"

# 8. A decimal threshold is valid and, above coverage, passes -- the regex admits
#    an optional decimal part.
assert_gate "decimal threshold above coverage passes" 85.5 "$PASS_FIXTURE" 0 "PASS"

# 9. A decimal threshold below coverage still fails, so the decimal path shares the
#    real comparison rather than being merely accepted.
assert_gate "decimal threshold below coverage fails" 85.5 "$AT_FIXTURE" 1 "FAIL"

echo
if [ "$failures" -ne 0 ]; then
  printf '%d of %d cases FAILED\n' "$failures" "$cases"
  exit 1
fi
printf 'all %d cases passed\n' "$cases"
