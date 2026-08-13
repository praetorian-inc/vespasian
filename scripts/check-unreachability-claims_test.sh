#!/usr/bin/env bash
#
# Regression test for check-unreachability-claims.sh.
#
# WHY THIS EXISTS
#
# The checker shipped without a test, and two things followed from that.
#
# 1. Its behavior rested on controls run by hand. When the citation-resolution
#    logic was rewritten, nothing re-ran them, so a rewrite that silently stopped
#    rejecting phantom citations would have looked identical to one that worked:
#    both print nothing and exit 0.
#
# 2. It was only ever exercised on the author's macOS box before CI ran it for
#    real. `mktemp -t NAME` is a filename PREFIX on BSD and a TEMPLATE on GNU
#    (which needs three or more X's), so the checker passed locally and aborted in
#    CI with "too few X's in template".
#
#    Every case below asserts an EXACT exit code, so a checker that cannot start
#    (returning 2 where 0 or 1 was expected) fails all of them. Verified by
#    injecting an early `exit 2`: 9 of 9 cases failed.
#
#    Read the limit precisely: this catches a portability fault only on the
#    platform where that fault is fatal. Re-adding `mktemp -t NAME` and running
#    this test on macOS still passes 9 of 9, because BSD mktemp accepts it — the
#    very asymmetry that hid the bug. What closes the gap is the CI job running
#    this on ubuntu, not the test's existence. A green run here is evidence about
#    this machine only.
#
# It needs no Go build, no network, and no browser; it runs in about a second, so
# it belongs in the same fast job as the checker itself.
#
# HOW IT WORKS
#
# Each case builds a throwaway git repo, drops the checker into scripts/, writes
# fixture .go files, `git add`s them (the checker reads `git ls-files`, which lists
# the index, so no commit is needed) and runs the checker in --all mode. A fresh
# repo per case keeps one case's exit code from masking another's.
#
# mktemp is called as a bare `mktemp -d` with no template, which is the one form
# both BSD and GNU accept — the bug above is not repeated here.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKER="$SCRIPT_DIR/check-unreachability-claims.sh"

if [ ! -x "$CHECKER" ]; then
  echo "FATAL: $CHECKER is missing or not executable" >&2
  exit 2
fi

failures=0
cases=0

# new_fixture_repo echoes the path to a fresh repo with the checker installed.
new_fixture_repo() {
  local dir
  dir="$(mktemp -d)" || return 1
  git -C "$dir" init -q .
  mkdir -p "$dir/scripts"
  cp "$CHECKER" "$dir/scripts/"
  echo "$dir"
}

# assert_case NAME EXPECTED_EXIT EXPECTED_SUBSTRING REPO
# EXPECTED_SUBSTRING may be empty, meaning "output is not checked".
# A leading "!" on the substring inverts it to "must NOT contain".
assert_case() {
  local name="$1" want_exit="$2" want_sub="$3" repo="$4"
  cases=$((cases + 1))

  local out rc
  out="$("$repo/scripts/check-unreachability-claims.sh" --all 2>&1)"
  rc=$?

  local ok=1
  if [ "$rc" -ne "$want_exit" ]; then
    ok=0
    printf 'FAIL %s\n  exit = %d, want %d\n' "$name" "$rc" "$want_exit"
  fi
  if [ -n "$want_sub" ]; then
    case "$want_sub" in
    '!'*)
      if printf '%s' "$out" | grep -qF -- "${want_sub#!}"; then
        ok=0
        printf 'FAIL %s\n  output contains %q and must not\n' "$name" "${want_sub#!}"
      fi
      ;;
    *)
      if ! printf '%s' "$out" | grep -qF -- "$want_sub"; then
        ok=0
        printf 'FAIL %s\n  output lacks %q\n' "$name" "$want_sub"
      fi
      ;;
    esac
  fi

  if [ "$ok" -eq 1 ]; then
    printf 'ok   %s\n' "$name"
  else
    failures=$((failures + 1))
    printf '  --- checker output ---\n%s\n  ----------------------\n' "$out"
  fi
  rm -rf "$repo"
}

# real_tests writes a *_test.go carrying the test functions citations resolve
# against. Kept in its own package to prove the lookup is module-wide: a claim in
# pkg/a may legitimately cite a test in pkg/b.
real_tests() {
  local repo="$1"
  mkdir -p "$repo/pkg/b"
  cat >"$repo/pkg/b/b_test.go" <<'EOF'
package b

import "testing"

func TestRealThing(t *testing.T)         {}
func TestFamily_Alpha(t *testing.T)      {}
func TestFamily_Beta(t *testing.T)       {}
func TestInAnotherPackage(t *testing.T)  {}
EOF
  git -C "$repo" add -A
}

# claim_file writes pkg/a/a.go with BODY as the comment block above a func.
claim_file() {
  local repo="$1" body="$2"
  mkdir -p "$repo/pkg/a"
  {
    echo "package a"
    echo
    printf '%s\n' "$body"
    echo "func Thing() {}"
  } >"$repo/pkg/a/a.go"
  git -C "$repo" add -A
}

# ---------------------------------------------------------------------------
# 1. A claim with no citation is flagged.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. A second call can never happen.'
assert_case "claim with no citation is flagged" 1 "unreachability claim with no test cited" "$repo"

# ---------------------------------------------------------------------------
# 2. A claim whose only citation is a phantom is flagged, and the phantom is
#    NAMED. This is the case the shape-only regex used to pass: the identifier
#    looked like a test, so the block was accepted.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. A second call can never happen.
// TestNoSuchTestAnywhere pins it.'
assert_case "phantom citation is flagged and named" 1 "cites a test that does not exist: TestNoSuchTestAnywhere" "$repo"

# ---------------------------------------------------------------------------
# 3. A claim citing a real test passes, and the test lives in ANOTHER package,
#    so this also pins the module-wide lookup.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. A second call can never happen.
// TestInAnotherPackage pins it.'
assert_case "cross-package resolving citation passes" 0 "" "$repo"

# ---------------------------------------------------------------------------
# 4. A family citation (a prefix of real tests) passes, so pointing at a group
#    stays legal.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. A second call can never happen.
// Covered by TestFamily_* in the integration suite.'
assert_case "family prefix citation passes" 0 "" "$repo"

# ---------------------------------------------------------------------------
# 5. Past-tense narrative about a fixed defect is not a present guarantee, so
#    the EXCLUDE list must keep it unflagged even with no citation.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. Gating on Properties alone made the
// recursion unreachable, which is why the caller guard moved.'
assert_case "past-tense defect narrative is not flagged" 0 "" "$repo"

# ---------------------------------------------------------------------------
# 6. Hedged prose is not a guarantee and must not be flagged, or the check stops
#    being signal.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. We do not expect a second call, and
// today no caller makes one.'
assert_case "hedged prose is not flagged" 0 "" "$repo"

# ---------------------------------------------------------------------------
# 7. A claim inside a _test.go file is out of scope.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
mkdir -p "$repo/pkg/a"
cat >"$repo/pkg/a/a_test.go" <<'EOF'
package a

// A second call can never happen.
func helper() {}
EOF
git -C "$repo" add -A
assert_case "claims in _test.go files are skipped" 0 "" "$repo"

# ---------------------------------------------------------------------------
# 8. With no test functions at all the checker must refuse rather than pass
#    vacuously: every citation would be unresolvable, so a silent 0 would be the
#    worst possible answer.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
claim_file "$repo" '// Thing does a thing. A second call can never happen.
// TestRealThing pins it.'
assert_case "empty test set refuses to pass vacuously" 2 "refusing to pass vacuously" "$repo"

# ---------------------------------------------------------------------------
# 9. A block carrying BOTH a phantom and a resolving citation passes. Recorded
#    because two hand-run controls were wasted on exactly this: a phantom was
#    injected into a block that already had a real citation, nothing was flagged,
#    and the checker looked broken when it was correct.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. A second call can never happen.
// TestNoSuchTestAnywhere and TestRealThing pin it.'
assert_case "one resolving citation is enough alongside a phantom" 0 "!does not exist" "$repo"

# ---------------------------------------------------------------------------
echo
if [ "$failures" -ne 0 ]; then
  printf '%d of %d cases FAILED\n' "$failures" "$cases"
  exit 1
fi
printf 'all %d cases passed\n' "$cases"
