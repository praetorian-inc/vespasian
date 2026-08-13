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

# A Go test identifier satisfies the citation requirement only if it RESOLVES to a
# test that exists (see existing_tests below). Matching the identifier shape alone
# turned "name the test" into "type a plausible test name": the PR that added this
# script shipped three claims citing TestFriendlySourceTag_TotalOverJSStaticSources,
# TestDetectAPIType_LoneGenericXMLStaysREST and TestRodEngine_Interact_SkipsDestructive,
# none of which existed. A citation nobody can run is worse than none, because it
# reads as evidence that someone already checked.
CITATION='Test[A-Z][A-Za-z0-9_]*'

# Every test function name in the module, one newline-separated list. Module-wide on
# purpose, and independent of --changed/--all: a claim in pkg/classify legitimately
# cites a test in internal/pipeline, so per-package scoping would reject valid
# citations.
#
# Handed to awk through the ENVIRONMENT (ENVIRON[...] below), which is the only one
# of the three obvious channels that is portable both ways:
#
#   - -v VAR=value: BSD awk (macOS) rejects a newline inside a -v value
#     ("awk: newline in string"), so the whole check aborts locally.
#   - a temp file read as awk's first argument: needs mktemp, and `mktemp -t NAME`
#     is a BSD prefix but a GNU template, so GNU rejects it with "too few X's in
#     template". This script shipped that bug and it failed in CI while passing on
#     macOS — the exact mirror of the -v problem.
#   - ENVIRON: POSIX, and neither awk parses escapes in it.
#
# Size is bounded by the module's test count (~1700 names, ~70 KB), far inside
# ARG_MAX on both platforms.
existing_tests="$(git ls-files '*_test.go' | tr '\n' '\0' |
  xargs -0 grep -ho '^func Test[A-Za-z0-9_]*' 2>/dev/null |
  sed 's/^func //' | sort -u)"

if [ -z "$existing_tests" ]; then
  echo "error: found no test functions to resolve citations against; refusing to pass vacuously" >&2
  exit 2
fi

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
  VESPASIAN_TEST_NAMES="$existing_tests" \
    awk -v file="$file" -v claim="$CLAIM" -v exclude="$EXCLUDE" -v cite="$CITATION" '
    BEGIN {
      n = split(ENVIRON["VESPASIAN_TEST_NAMES"], names, "\n")
      for (i = 1; i <= n; i++) if (names[i] != "") test_names[names[i]] = 1
    }
    function claim_line(b,   n, lines, i) {
      n = split(b, lines, "\n")
      for (i = 1; i <= n; i++) {
        if (lines[i] ~ claim && lines[i] !~ exclude) return i
      }
      return 0
    }
    # A citation counts only when it names a test that exists. A trailing-underscore
    # or otherwise partial identifier (e.g. "TestRodEngine_Interact_*" citing a
    # family) resolves against any test it PREFIXES, so pointing at a group of tests
    # stays valid while a typo or a renamed test does not.
    function resolves(id,   t) {
      if (id in test_names) return 1
      for (t in test_names) if (index(t, id) == 1) return 1
      return 0
    }
    # Returns the first cited identifier that resolves, or "" when none do. Sets
    # cited_any so the caller can tell "no citation" from "citation that is a phantom".
    function resolved_citation(b,   rest, id, m) {
      cited_any = 0
      rest = b
      while (match(rest, cite)) {
        id = substr(rest, RSTART, RLENGTH)
        cited_any = 1
        if (resolves(id)) return id
        first_bad = (first_bad == "" ? id : first_bad)
        rest = substr(rest, RSTART + RLENGTH)
      }
      return ""
    }
    function flush(   idx, lines) {
      if (block != "") {
        idx = claim_line(block)
        if (idx) {
          first_bad = ""
          if (resolved_citation(block) == "") {
            split(block, lines, "\n")
            gsub(/^[ \t]*\/\/[ \t]?/, "", lines[idx])
            if (cited_any) {
              printf "%s:%d: unreachability claim cites a test that does not exist: %s\n", file, start, first_bad
            } else {
              printf "%s:%d: unreachability claim with no test cited\n", file, start
            }
            printf "        %s\n", lines[idx]
            found++
          }
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
  1. Name a test that EXISTS (the name must resolve to a real Test func, or be a
     prefix of one — a citation nobody can run is worse than none).
  2. Write that test, then name it. Preferred when the claim is load-bearing.
  3. Soften the claim to what is actually known ("today no caller does X"),
     if the guarantee is not one the code enforces.

Do not delete the explanation to silence this. The comments are not the problem;
unbacked guarantees are.
MSG
fi

exit "$status"
