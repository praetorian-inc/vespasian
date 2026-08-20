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

# QUAL-001: check the exit status explicitly, don't just take stdout.
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
"${bin}" --headless --no-sandbox --dump-dom about:blank >/dev/null
