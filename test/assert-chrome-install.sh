#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Post-install assertion for install-chrome.sh: the install must have produced a
# browser that detect_chrome_binary resolves and that actually renders a page.
# Run by live-tests.yml's install-chrome-e2e job, after install-chrome.sh.
#
# A committed script rather than an inline `run:` block: the install-chrome-e2e
# job is opt-in (workflow_dispatch, plus push to main), so a syntax error in an
# inline block would first surface on main. As a file it joins the un-gated
# preflight-selftest job's `bash -n` list, which runs on every PR.
#
# Usage: bash test/assert-chrome-install.sh   (from anywhere; paths are script-relative)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"

# Check the exit status explicitly, don't just take stdout.
# On failure detect_chrome_binary returns non-zero with an EMPTY stdout.
# The `|| { … }` is what makes that failure actionable: without it the
# next line ran `"" --headless …`, whose "command not found" is a far
# worse diagnostic than the real one. (A bare `bin=$(...)` would in fact
# trip errexit here — a plain assignment takes the substitution's exit
# status; it is a `local`/`declare`/`export` DECLARATION that swallows
# it — but aborting with no message is still the wrong outcome, which is
# why the explicit handler stays.)
bin=$(detect_chrome_binary) || {
    echo "detect_chrome_binary found no runnable browser after install" >&2
    exit 1
}
[ -n "${bin}" ] || { echo "detect_chrome_binary returned an empty path" >&2; exit 1; }
echo "detected: ${bin}"
# Bounded, for the reason install-chrome.sh:1335 gives for the same operation:
# "detect_chrome_binary only reached this point by running the binary under a
# timeout; re-running it unbounded here reintroduces the hang that bound guards
# against, at the very end of a root provisioning run and with no diagnostic."
# --dump-dom renders a page, so it is materially more hang-prone than the
# --version that comment was written about. Same idiom as common.sh's
# chrome_runnable: use timeout(1) when it exists, probe directly when it does
# not, rather than refusing to run. 30s, not CHROME_PROBE_BUDGET's 2s default,
# because that budget bounds a --version call and this one paints a document.
#
# `-k 5` for the reason install-chrome.sh gives for its own apt bounds: a process
# can defer the first SIGTERM, so without a kill-after a wedged browser outlives
# the bound. The pin in test-runner-args.sh reads the resolved kill-after and
# duration from a stub and requires both positive, so deleting either reds CI.
#
# This paragraph used to survey which other bounded calls in the tree carry a
# kill-after and which do not. That inventory was wrong in four consecutive
# reviews — a miscount, a mislabel, an unproven absolute, and a missing entry —
# because it was hand-counted prose with nothing checking it, describing six call
# sites this file does not own. It is gone rather than corrected a fifth time. If
# you need to know what the tree does, `grep -rnE '(timeout|\}") -k' test/*.sh`
# answers it in one command and cannot go stale. Note the second alternative: this
# file and common.sh invoke timeout through a variable, so a search for the
# literal `timeout -k` alone misses them — which is also why the deleted
# hand-count kept missing entries.
#
# --no-sandbox is unconditional. Both callers need it and neither can use the
# sandbox: install-chrome-e2e runs as root in a container, and devcontainer-image
# runs this through `devcontainer exec` as the `vscode` user inside a container
# whose devcontainer.json sets VESPASIAN_NO_SANDBOX for the same reason. Chrome's
# sandbox cannot initialise in either. The Go path makes the same choice behind
# VESPASIAN_NO_SANDBOX (browser.go's vespasianEnablesNoSandbox); it is spelled out
# here rather than gated because every caller is containerised and always needs
# it. If a non-container caller is ever added, gate it rather than extending this
# list — the invariant is "containerised", not "these two jobs".
render_timeout=$(timeout_cmd)
if [ -n "${render_timeout}" ]; then
    "${render_timeout}" -k 5 30 "${bin}" --headless --no-sandbox --dump-dom about:blank >/dev/null
else
    "${bin}" --headless --no-sandbox --dump-dom about:blank >/dev/null
fi
