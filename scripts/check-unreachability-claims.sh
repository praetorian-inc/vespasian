#!/usr/bin/env bash
#
# Fails when a Go comment asserts that something is impossible, unreachable, or can
# never happen WITHOUT naming the test that pins it.
#
# WHY THIS EXISTS
#
# The LAB-4678 review found five defects. Three were cases where a comment asserted
# the exact property the code did not have, and argued for it at length:
#
#   - apitype.go argued that exclusive assignment made a lone text/xml response
#     impossible as a WSDL vote. It scored WSDL 0.85 against REST 0.80, so it was a
#     WSDL vote, and one XML response typed a whole capture as SOAP.
#   - rest.go, nextroute.go, jsstatic/doc.go, README.md and CLAUDE.md all asserted a
#     recovered Next.js route "can never become a spec operation". --confidence is an
#     operator flag; at 0.1 it did, with an invented verb.
#   - openapi.go stated two source-tag bugs were unreachable "only because Next.js
#     routes score below the classification threshold". The threshold is a flag.
#
# Each survived four rounds of human review. A confident paragraph reads as evidence
# and is not one. A test name is a claim someone can run.
#
# WHAT IT ASKS FOR
#
# Not fewer comments, and not weaker ones. If a comment says a state cannot occur, it
# must name the test that would fail if it did — that is the difference between
# documenting an invariant and asserting one. If no such test exists, either write it
# or soften the claim to what is actually known.
#
# SCOPE
#
# Deliberately narrow, so it stays signal. It matches only strong impossibility
# phrasing in the PRESENT tense, and is satisfied by any Test<Name> identifier in the
# same comment block. Prose like "this would be wrong" or "we do not expect" is not
# matched, because those do not read as guarantees. Narrative about a past defect
# ("gating on Properties alone MADE the recursion unreachable") is excluded too: that
# describes something that already happened rather than promising anything about now.
#
# By default it checks only files changed against a base ref, so it ratchets — new and
# modified code must comply, and pre-existing claims are not a merge blocker. Pass
# --all to sweep the whole tree.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

BASE="${BASE_REF:-origin/main}"
MODE="changed"
case "${1:-}" in
  --all) MODE="all" ;;
  --changed | "") MODE="changed" ;;
  *)
    echo "usage: $0 [--all|--changed]   (BASE_REF overrides the base, default origin/main)" >&2
    exit 2
    ;;
esac

# Strong, present-tense impossibility claims. Each asserts a guarantee a reader relies on.
CLAIM='cannot happen|can never|can not happen|never happens|never reaches|never occurs|is unreachable|are unreachable|stays unreachable|remains unreachable|is impossible|are impossible|stays impossible|must stay impossible|must be impossible|is not reachable'

# Past-tense narrative about a defect that HAS happened is not a guarantee about the
# present, and excluding it is what keeps this from flagging the comments that explain
# a fix. Same for "unreachable" in its network sense.
EXCLUDE='was unreachable|were unreachable|made .* unreachable|making .* unreachable|left .* unreachable|became unreachable|unreachable target|unreachable host|unreachable network|would have been unreachable|had been unreachable'

# Any Go test identifier satisfies the citation requirement.
CITATION='Test[A-Z][A-Za-z0-9_]*'

status=0

list_files() {
  if [ "$MODE" = all ]; then
    git ls-files '*.go'
  elif git rev-parse --verify --quiet "$BASE" >/dev/null; then
    git diff --name-only --diff-filter=d "$BASE"...HEAD -- '*.go'
  else
    # A missing base ref (shallow clone, detached CI checkout) degrades to the full
    # sweep rather than silently checking nothing. A check that quietly passes is
    # worse than one that is noisy.
    echo "warning: base ref $BASE not found; sweeping all files" >&2
    git ls-files '*.go'
  fi
}

while IFS= read -r file; do
  [ -n "$file" ] || continue
  case "$file" in
  *_test.go) continue ;;
  esac
  [ -f "$file" ] || continue

  # Walk each file's comment BLOCKS (runs of consecutive // lines), so a citation
  # anywhere in a block covers a claim anywhere in it.
  awk -v file="$file" -v claim="$CLAIM" -v exclude="$EXCLUDE" -v cite="$CITATION" '
    function claim_line(b,   n, lines, i) {
      n = split(b, lines, "\n")
      for (i = 1; i <= n; i++) {
        if (lines[i] ~ claim && lines[i] !~ exclude) return i
      }
      return 0
    }
    function flush(   idx, lines) {
      if (block != "") {
        idx = claim_line(block)
        if (idx && block !~ cite) {
          printf "%s:%d: unreachability claim with no test cited\n", file, start
          split(block, lines, "\n")
          gsub(/^[ \t]*\/\/[ \t]?/, "", lines[idx])
          printf "        %s\n", lines[idx]
          found++
        }
      }
      block = ""
    }
    {
      if ($0 ~ /^[ \t]*\/\//) {
        if (block == "") start = NR
        block = block "\n" $0
      } else {
        flush()
      }
    }
    END { flush(); exit (found > 0 ? 1 : 0) }
  ' "$file" || status=1
done < <(list_files)

if [ "$status" -ne 0 ]; then
  cat <<'MSG'

Each comment above guarantees a state cannot occur, without naming a test that
would fail if it did.

Fix by one of:
  1. Name the test in the comment (any Test<Name> identifier satisfies this).
  2. Write that test, then name it. Preferred when the claim is load-bearing.
  3. Soften the claim to what is actually known ("today no caller does X"),
     if the guarantee is not one the code enforces.

Do not delete the explanation to silence this. The comments are not the problem;
unbacked guarantees are.
MSG
fi

exit "$status"
