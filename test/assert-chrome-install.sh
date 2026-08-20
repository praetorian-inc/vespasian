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
# `-k 5` for the reason install-chrome.sh gives for its own apt bounds: a
# process can defer the first SIGTERM, so without a kill-after a wedged browser
# outlives the bound. That matches the three PRIVILEGED apt invocations, which
# all carry one (`-k 5 30`, `-k 30 300`, `-k 30 900`). It deliberately does NOT
# match the tree's three unprivileged probes — common.sh's chrome_runnable,
# install-chrome.sh's _bounded_probe, and setup-live-targets.sh's wait_for_grpc
# — which pass a bare duration. Those bound a `--version` call or a TCP connect
# that either answers at once or is already wedged, so a kill-after buys nothing;
# this one renders a document inside a root provisioning run, which is the shape
# the apt bounds are written for.
#
# --no-sandbox is unconditional: this script's only caller is the
# install-chrome-e2e job, which runs as root in a container where Chrome's
# sandbox cannot initialise. The Go path makes the same choice behind
# VESPASIAN_NO_SANDBOX (browser.go's vespasianEnablesNoSandbox); it is spelled out
# here rather than gated because there is exactly one caller and it always
# needs it.
render_timeout=$(timeout_cmd)
if [ -n "${render_timeout}" ]; then
    "${render_timeout}" -k 5 30 "${bin}" --headless --no-sandbox --dump-dom about:blank >/dev/null
else
    "${bin}" --headless --no-sandbox --dump-dom about:blank >/dev/null
fi
