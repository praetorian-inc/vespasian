#!/usr/bin/env bash
# AC3 RUNTIME PROOF (LAB-6015).
#
# The policy pin in test/test-runner-args.sh verifies that live-tests.yml SAYS
# `egress-policy: block`; it cannot verify that block ENFORCES. A harden-runner that
# stopped enforcing — or failed open after a runner-image change — leaves the YAML
# byte-identical and every static assertion green. This script is the only thing in
# the repo that reads the runtime behaviour rather than the file.
#
# WHY THIS IS A COMMITTED SCRIPT AND NOT AN INLINE `run:` BLOCK. It began as inline
# shell, and five review rounds of trying to pin that shell from
# test/test-runner-args.sh failed in the same way each time: a text pin over free-form
# shell cannot be exhaustive. Measured bypasses that each kept the whole suite green
# AND left this check exiting 0 — a bare `exit 0`, an `if false` wrapper, an
# argument-less `exit`, two exits on one line, `&& false` appended to the probe, a `#`
# inside a string ahead of `; exit 0`, and a trailing `# exit 1` comment. Each new
# pinned field (`exits`, `allexits`, `firstop`, `neutered`) closed the measured case
# and left an adjacent one, because shell has unbounded ways to express the same
# subversion. As a committed file the pin collapses to one exact invocation string with
# nothing to pattern-match, and the body gets the same treatment as the repo's other
# four guard suites: `bash -n` in the un-gated syntax-check step, and review of a real
# file rather than of a YAML scalar. AGENTS.md records that reasoning for
# test/assert-chrome-install.sh, which exists for exactly this reason.
#
# RESIDUAL, stated rather than implied: nothing pins this file's CONTENTS, so editing
# it to a no-op still passes. That is deliberate and consistent — test-runner-args.sh
# pins that preflight-selftest INVOKES its four guard suites, never what they contain.
# Content-pinning a script would fail on every legitimate edit.
#
# BOTH VERDICTS ARE LOAD-BEARING:
#   * The unlisted host is deliberately absent from preflight-selftest's allowlist, so
#     it must be unreachable. Under `audit` the same request SUCCEEDS, which is what
#     makes this discriminating rather than vacuous — verified: with no policy in play
#     this script fails.
#   * The control host IS allowlisted and must succeed, which rules out a runner with
#     no egress at all satisfying the first verdict for the wrong reason.
#   * NOT established: that the first refusal was a POLICY refusal rather than an
#     outage of that specific host. harden-runner blocks at the DNS layer, so a blocked
#     domain and an unresolvable one both surface as curl exit 6 and cannot be told
#     apart from inside the job. The mitigation is that both hostnames are pinned in
#     test/test-runner-args.sh, so a rename or typo fails the build rather than quietly
#     making this a no-op.
set -euo pipefail

# Pinned in test/test-runner-args.sh. proxy.golang.org must stay OFF
# preflight-selftest's allowlist (the endpoints pin enforces that) and must stay a
# real, resolvable host; github.com must stay the allowlisted control.
UNLISTED_URL="https://proxy.golang.org/"
CONTROL_URL="https://github.com/"

if curl -sS --max-time 15 -o /dev/null "$UNLISTED_URL" 2>/dev/null; then
    echo "FAIL: reached ${UNLISTED_URL}, which is absent from this job's allowlist — the egress policy is not enforcing"
    exit 1
fi
echo "ok: unlisted host unreachable"

if ! curl -sS --max-time 15 -o /dev/null "$CONTROL_URL"; then
    echo "FAIL: cannot reach ${CONTROL_URL}, which IS allowlisted — this runner has no egress at all, so the refusal above proves nothing"
    exit 1
fi
echo "ok: allowlisted host reachable — so the refusal above is not a blanket loss of egress"
