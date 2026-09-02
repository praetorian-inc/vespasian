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
#    injecting an early `exit 2`: every case failed.
#
#    Read the limit precisely: this catches a portability fault only on the
#    platform where that fault is fatal. Re-adding `mktemp -t NAME` and running
#    this test on macOS still passes everything, because BSD mktemp accepts it —
#    the very asymmetry that hid the bug. What closes the gap is the CI job running
#    this on ubuntu, not the test's existence. A green run here is evidence about
#    this machine only.
#
# It needs no Go build, no network, and no browser; it runs in about a second, so
# it belongs in the same fast job as the checker itself.
#
# HOW IT WORKS
#
# Each case builds a throwaway git repo, drops the checker into scripts/, writes
# fixture .go files, and `git add`s them (the checker reads `git ls-files`, which
# lists the index). A fresh repo per case keeps one case's exit code from masking
# another's.
#
# Cases 1-12 run --all, where every comment block is in scope, and need no commit.
# Cases 13-15 run --changed against a base ref and therefore do commit, because
# that mode's whole point is which lines moved.
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
  # Identity set ON THE FIXTURE REPO, because the --changed cases commit and a CI
  # runner has none: this test failed there with "fatal: empty ident name" while
  # passing locally off the author's global config. It is not overriding a resolved
  # value — nothing resolves inside a throwaway repo — and it touches neither the real
  # repo nor global config.
  #
  # The runner's condition cannot be faithfully reproduced on macOS, and the two
  # obvious attempts both mislead:
  #
  #   - Clearing global/system config is not enough. macOS git then derives an
  #     identity from the OS (verified: commits land as the login user at the
  #     hostname), so they succeed and the gap stays invisible. The runner had a
  #     derivable email but an EMPTY name, which is the case that errors.
  #   - GIT_AUTHOR_NAME=/GIT_COMMITTER_NAME= does force the error, but env beats
  #     repo config in git's precedence, so it also defeats the two lines above and
  #     "fails" no matter how correct the fix is. It tests nothing.
  #
  # What was verified instead: with no global or system config, a repo carrying these
  # two settings commits as `fixture <fixture@invalid>`, so repo-local config is what
  # git uses and CI's missing global identity is covered.
  git -C "$dir" config user.email fixture@invalid
  git -C "$dir" config user.name fixture
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
# 10. A claim is matched case-INSENSITIVELY, so one opening a sentence is caught.
#
#     CLAIM and EXCLUDE are lowercase alternations and awk's ~ is case-sensitive, so
#     a claim written as its own sentence ("Never reaches this branch...") had a
#     capital leading word, matched nothing, and the block was silently treated as
#     carrying no claim at all. That is the most natural phrasing for the assertion
#     this gate exists to catch (LAB-4678 review, QUAL-003).
#
#     Both rows are the SAME sentence differing only in the leading capital, so a
#     failure here can only be about case.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. Never reaches the fallback below.'
assert_case "sentence-initial capitalized claim is flagged" 1 "unreachability claim with no test cited" "$repo"

repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. never reaches the fallback below.'
assert_case "lowercase mid-sentence claim is still flagged" 1 "unreachability claim with no test cited" "$repo"

# ---------------------------------------------------------------------------
# 11. Case-folding must apply to EXCLUDE too, or lowercasing the input would start
#     flagging capitalized past-tense narrative that the lowercase exclusions used
#     to miss for the same reason.
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. Was unreachable until the guard below was added.'
assert_case "capitalized past-tense narrative stays excluded" 0 "!unreachability claim" "$repo"

# ---------------------------------------------------------------------------
# 12. A capitalized claim WITH a resolving citation still passes: case-folding the
#     claim test must not have folded the citation test, whose entire
#     discriminating power is the capital T in Test[A-Z].
# ---------------------------------------------------------------------------
repo="$(new_fixture_repo)" || exit 2
real_tests "$repo"
claim_file "$repo" '// Thing does a thing. Never reaches the fallback below.
// TestRealThing pins it.'
assert_case "capitalized claim with a real citation passes" 0 "!unreachability claim" "$repo"


# ---------------------------------------------------------------------------
# --changed mode: the RATCHET. Needs commits and a base ref, unlike the cases
# above, so it gets its own fixture builder.
#
# Whole-file selection would flag a pre-existing claim the moment anyone edits an
# unrelated function in the same file, which contradicts this checker's own header
# and the Makefile's ("pre-existing claims are not a merge blocker"). It happened
# for real: merging main into a branch pulled seven other authors' claims into
# scope and failed the build.
# ---------------------------------------------------------------------------

# assert_changed NAME EXPECTED_EXIT EXPECTED_SUBSTRING REPO
# Same contract as assert_case but runs --changed against the fixture's base-ref.
assert_changed() {
  local name="$1" want_exit="$2" want_sub="$3" repo="$4"
  cases=$((cases + 1))

  local out rc
  out="$(cd "$repo" && BASE_REF=base-ref ./scripts/check-unreachability-claims.sh --changed 2>&1)"
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

# new_ratchet_repo builds a repo whose base-ref commit already contains an UNCITED
# claim, so anything the caller does next is an edit on top of a pre-existing one.
# Commits use the ambient git identity deliberately: overriding it is what the
# no-override rule exists to prevent, and a throwaway repo needs no special author.
new_ratchet_repo() {
  local dir
  dir="$(new_fixture_repo)" || return 1
  mkdir -p "$dir/pkg"
  cat >"$dir/pkg/a.go" <<'GOEOF'
package a

// Old is old. A second call can never happen.
func Old() {}

// Untouched is untouched.
func Untouched() {}
GOEOF
  printf 'package a\n\nimport "testing"\n\nfunc TestRealThing(t *testing.T) {}\n' >"$dir/pkg/a_test.go"
  git -C "$dir" add -A
  git -C "$dir" commit -qm base
  git -C "$dir" branch -q base-ref
  echo "$dir"
}

# 13. An unrelated edit in a file holding a pre-existing uncited claim must NOT
#     flag it. This is the ratchet.
repo="$(new_ratchet_repo)" || exit 2
perl -pi -e 's{// Untouched is untouched\.}{// Untouched now does more.}' "$repo/pkg/a.go"
git -C "$repo" add -A && git -C "$repo" commit -qm edit-elsewhere
assert_changed "unrelated edit does not pull in a pre-existing claim" 0 "!can never happen" "$repo"

# 14. Editing the claim itself DOES bring it into scope — you are asserting it
#     afresh, so it must carry a citation.
repo="$(new_ratchet_repo)" || exit 2
perl -pi -e 's{A second call can never happen\.}{A second call can never happen, truly.}' "$repo/pkg/a.go"
git -C "$repo" add -A && git -C "$repo" commit -qm touch-the-claim
assert_changed "editing a claim brings it into scope" 1 "unreachability claim with no test cited" "$repo"

# 15. Every claim in a NEW file is in scope, since every line is added.
repo="$(new_ratchet_repo)" || exit 2
printf 'package a\n\n// New is new. This can never happen.\nfunc New() {}\n' >"$repo/pkg/b.go"
git -C "$repo" add -A && git -C "$repo" commit -qm new-file
assert_changed "a new file's claims are all in scope" 1 "pkg/b.go" "$repo"

# 16. A selection of zero Go files announces itself instead of passing silently.
# This is the ordinary case for a docs/CI/devcontainer PR: --changed selects only
# *.go, so the run examines nothing and exits 0 — indistinguishable from a clean
# run unless it says so. The notice is not a failure; a Go-free PR legitimately
# has nothing for this check to do.
repo="$(new_ratchet_repo)" || exit 2
printf 'hello\n' >"$repo/README.md"
git -C "$repo" add -A && git -C "$repo" commit -qm docs-only
assert_changed "a Go-free change announces that nothing was checked" 0 "no Go files in scope; nothing checked" "$repo"

# 17. ...and the notice must NOT fire when Go files ARE in scope, or it would be
# noise on every real run rather than a signal.
repo="$(new_ratchet_repo)" || exit 2
printf 'package a\n\nfunc Added() {}\n' >"$repo/pkg/b.go"
git -C "$repo" add -A && git -C "$repo" commit -qm go-change
assert_changed "the vacuity notice stays quiet when Go files are in scope" 0 "!nothing checked" "$repo"

# ---------------------------------------------------------------------------
echo
if [ "$failures" -ne 0 ]; then
  printf '%d of %d cases FAILED\n' "$failures" "$cases"
  exit 1
fi
printf 'all %d cases passed\n' "$cases"
