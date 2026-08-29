#!/usr/bin/env bash
#
# Asserts that the devcontainer image ships a browser the Go side can both
# RESOLVE and DRIVE. Runs INSIDE the container, via `devcontainer exec` from the
# devcontainer-image job in .github/workflows/live-tests.yml.
#
# This is a committed file rather than an inline `run:` block, and that is
# load-bearing rather than tidiness. An inline block is not a file, so `bash -n`
# cannot see it and no guard suite can read it; the job is opt-in, so a syntax
# error in one first surfaces on main. That is not hypothetical here — run
# 32388761616, the first execution of install-chrome-e2e in its life, lost two
# steps to exactly that, which is why test/assert-chrome-install.sh was extracted
# for the same reason (see its header). As a file this joins the un-gated
# preflight-selftest job's `bash -n` list, which runs on every PR.
#
# Usage: bash test/assert-devcontainer-lookpath.sh   (from the repo root)
set -euo pipefail

# The four BrowserManager tests are what LAB-5064 AC1 / LAB-5766 actually name:
# "the pkg/crawl //go:build integration launch/kill/close tests run (not skip)".
# TestConfigureLauncher_PinsSystemBrowser is kept alongside them, not instead of
# them: it is the only one that asserts go-rod's LookPath resolves a pinned .Bin
# (LAB-4999), and it is the one that runs even where Chrome cannot launch.
# Filtering to it alone — as this step originally did — asserted resolution and
# called it launch coverage.
REQUIRED_TESTS=(
    TestBrowserManager_LaunchAndKill
    TestBrowserManager_KillIdempotent
    TestBrowserManager_Close
    TestBrowserManager_CloseIdempotent
    TestConfigureLauncher_PinsSystemBrowser
)

run_re="$(IFS='|'; printf '%s' "${REQUIRED_TESTS[*]}")"

# VESPASIAN_REQUIRE_CHROME turns skipIfNoChrome's skip into a failure, the same
# way the integration-tests job sets it: this image is SUPPOSED to have a
# browser, so an unavailable Chrome is a failure here rather than a skip.
#
# It does not make the per-test PASS assertions below redundant.
# TestConfigureLauncher_PinsSystemBrowser guards itself with its own
# `t.Skip` on launcher.LookPath rather than through skipIfNoChrome, and
# `go test` exits 0 on a skip — so the exit code alone can still be green with
# the one assertion AC1 is worded around never having run.
out=""
rc=0
out="$(VESPASIAN_REQUIRE_CHROME=1 go test -tags integration -run "${run_re}" -v ./pkg/crawl 2>&1)" || rc=$?
printf '%s\n' "$out"

if [ "$rc" -ne 0 ]; then
    # Deliberately environment-neutral. This arm fires on ANY non-zero exit —
    # a module download failure against proxy.golang.org, a toolchain mismatch
    # under GOTOOLCHAIN=local, a compile error — not only on browser
    # resolution, so naming LookPath here would misattribute most of them.
    echo "assert-devcontainer-lookpath: go test exited ${rc}; see the output above for the actual cause" >&2
    exit 1
fi

# Anchored on the trailing " (" that go test -v always emits before the elapsed
# time, so a longer sibling name cannot satisfy a shorter one's assertion:
# without it, "--- PASS: TestConfigureLauncher_PinsSystemBrowserExtra" contains
# and therefore satisfies a plain substring search for
# "--- PASS: TestConfigureLauncher_PinsSystemBrowser".
missing=()
for t in "${REQUIRED_TESTS[@]}"; do
    if ! printf '%s\n' "$out" | grep -qE -- "^[[:space:]]*--- PASS: ${t} \("; then
        missing+=("$t")
    fi
done

if [ "${#missing[@]}" -ne 0 ]; then
    echo "assert-devcontainer-lookpath: these tests did not report --- PASS (skipped, or never ran): ${missing[*]}" >&2
    echo "  A skip here means the image shipped no browser go-rod can resolve or launch." >&2
    exit 1
fi

echo "assert-devcontainer-lookpath: all ${#REQUIRED_TESTS[@]} integration tests reported PASS in the devcontainer image"
