# Development image for vespasian. Its headline job is to close LAB-5064's AC1:
# ship a runnable, non-snap Chrome so `launcher.LookPath()`
# resolves a browser that can actually start, and the pkg/crawl
# `//go:build integration` launch/kill/close tests and the rod-backed live
# targets run instead of failing or skipping.
#
# Digest-pinned like the repo's release Dockerfile and the install-chrome-e2e
# job's container: a mutable tag means the thing this image installs into can
# change under us between builds. Refresh deliberately.
#
# Why this base rather than a bare golang image: it already carries the pieces
# install-chrome.sh requires and a devcontainer expects — ca-certificates,
# curl/gnupg, the non-root `vscode` user with sudo and git. Its Go is NOT one of
# those pieces: the tag ships 1.25.12 and the layer below replaces it, because
# GOTOOLCHAIN=local means Go will not fetch a newer toolchain and go.mod on main
# already asks for 1.27.0. It does NOT carry a usable Node: its metadata label lists the
# node feature, but nvm's versions/ directory is empty, so node and npm are
# installed below. Their npm deps come from devcontainer.json's onCreateCommand,
# which cannot be a layer because the workspace is bind-mounted over it. It
# builds as root, so install-chrome.sh resolves
# SUDO="" and takes its privileged branches directly, exactly as the
# install-chrome-e2e job does. Multi-arch: the index carries linux/amd64 and
# linux/arm64, and Google publishes google-chrome-stable for both
# (dists/stable/Release advertises `Architectures: amd64 arm64`), so an Apple
# Silicon build is not a dead end.
FROM mcr.microsoft.com/devcontainers/go:1.25-bookworm@sha256:30cbde1de62f190904446d8b81dcfd0befcfd60889419edb8872d598be9632cc

# python3 and yq are the two hard prerequisites the base image lacks. Its
# baked-in devcontainer features are common-utils, git, go and node only —
# confirmed from the image's own `devcontainer.metadata` label, not assumed.
#
# python3 is not optional: setup-live-targets.sh's preflight fails outright
# without it, and test/validate.sh and `make check-docs` both shell to it.
#
# yq is not optional either, and it is the one this image previously missed:
# test/test-runner-args.sh answers structural questions about live-tests.yml
# through it and routes to fail() — not skip() — when it is absent, so a
# fresh devcontainer without it fails one of the four guard suites the repo
# tells contributors to run. Deliberately no pass/fail counts here: the first
# version of this comment quoted the numbers measured at the time, and they went
# stale TWICE inside this one PR as the suite grew (135 -> 151 -> 153 assertions),
# which is the same stale-figure defect the comment was warning about. The
# invariant is what matters and it does not move: the guard routes to fail(), so
# the failures are COUNTED, so `PASS + FAIL + SKIP_CREDIT` still equals
# EXPECTED_ASSERTIONS and the accounting pin does not fire. The suite reports an
# honest failure rather than a misleading accounting-drift message.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

# The base image's Go is too old and cannot fix itself. `mcr.microsoft.com/devcontainers/go`
# publishes no 1.27 tag yet (newest is 1.26), and GOTOOLCHAIN=local — which this
# image keeps deliberately, so no build silently downloads a compiler — means Go
# will NOT fetch the toolchain go.mod asks for. It errors instead:
#
#   go: go.mod requires go >= 1.27.0 (running go 1.25.12; GOTOOLCHAIN=local)
#
# MEASURED, not hypothesised: that is verbatim what the devcontainer-image job
# printed when `go test ./pkg/crawl` ran in this image against main's go.mod.
# Every Go step in the container fails that way, which takes AC2 of LAB-5766
# with it, and the message names GOTOOLCHAIN rather than the image, so it reads
# as a toolchain setting to relax rather than a base image to bump.
#
# So install the toolchain go.mod actually requires, over the base image's, at
# /usr/local/go — the path the base image already puts on PATH. SHA-256 pinned
# per architecture exactly like the yq layer below; refresh version and BOTH
# digests together, deliberately.
#
# This pin will go stale when go.mod's `go` directive moves again. That is not
# left to a reader noticing: the devcontainer-image job's conformance step
# compares this toolchain against go.mod at runtime and fails naming both
# versions, so the next bump reports the mismatch rather than reproducing the
# opaque GOTOOLCHAIN error above.
RUN set -eu; \
    ver=1.27.0; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sha=675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685 ;; \
      arm64) sha=51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda ;; \
      *) echo "unsupported architecture for the Go pin: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${ver}.linux-${arch}.tar.gz" -o /tmp/go.tgz; \
    printf '%s  %s\n' "$sha" /tmp/go.tgz | sha256sum -c -; \
    rm -rf /usr/local/go; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm -f /tmp/go.tgz; \
    /usr/local/go/bin/go version

# Debian's `yq` package is a DIFFERENT tool (a Python wrapper around jq) whose
# CLI does not accept the `-o=json -I=0` form the guard suite uses, so this is
# the upstream Go binary rather than an apt install. Pinned by SHA-256 for both
# architectures the base image index carries, and the architecture is resolved
# at build time so an arm64 build gets the arm64 binary. Same posture as the
# Chrome installer's fingerprint pin: a binary fetched over TLS alone is not
# verified. Refresh version and BOTH digests together, deliberately.
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sha=0fb28c6680193c41b364193d0c0fc4a03177aecde51cfc04d506b1517158c2fb ;; \
      arm64) sha=b7f7c991abe262b0c6f96bbcb362f8b35429cefd59c8b4c2daa4811f1e9df599 ;; \
      *) echo "unsupported architecture for the yq pin: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/mikefarah/yq/releases/download/v4.47.1/yq_linux_${arch}" \
      -o /usr/local/bin/yq; \
    printf '%s  %s\n' "$sha" /usr/local/bin/yq | sha256sum -c -; \
    chmod 0755 /usr/local/bin/yq; \
    yq --version

# Node is NOT present in the base image, despite its devcontainer.metadata label
# listing ghcr.io/devcontainers/features/node:1. MEASURED, from the build log of
# the first run that got this far: /usr/local/share/nvm holds nvm's own source
# checkout and its versions/ directory is EMPTY — there is no versions/node at
# all. The feature set up nvm, PATH=$NVM_DIR/current/bin and
# NVM_SYMLINK_CURRENT=true, but never installed a version, so `current` dangles
# and nothing resolves node or npm at any point.
#
# That is why two earlier attempts failed: onCreateCommand died with
# `/bin/sh: 1: npm: not found`, and resolving nvm inside the script hit the same
# wall. The problem was never PATH or profile loading — the binary was absent.
#
# Install it here, pinned to the same major the CI jobs use (actions/setup-node
# node-version: 20 at live-tests.yml:121 and :845), so the container and CI agree
# on the Node that parses specs. bash, not /bin/sh: nvm requires bash and
# Debian's sh is dash. The binaries are then symlinked into /usr/local/bin, which
# is on every PATH, because onCreateCommand and every `devcontainer exec` run
# under `/bin/sh -c` and load no profile.
#
# Unpinned, unlike the yq and Go layers on either side, and that asymmetry is
# deliberate rather than an oversight: `nvm install 20` floats within a major.
# Those two layers pin because their binaries are fetched over plain TLS from a
# release host, so a digest is the only thing distinguishing the intended
# artifact from a substituted one. nvm resolves through its own index and this
# Node only has to parse JSON and YAML specs for the validators; no artifact
# under test is built by it, and no assertion depends on its patch level. Pin it
# the day one does.
RUN bash -c 'set -euo pipefail; \
    export NVM_DIR="${NVM_DIR:-/usr/local/share/nvm}"; \
    [ -s "$NVM_DIR/nvm.sh" ] || { echo "FATAL: nvm not found at $NVM_DIR; the FROM changed" >&2; exit 1; }; \
    . "$NVM_DIR/nvm.sh"; \
    nvm install 20; \
    nvm alias default 20; \
    nvm use default; \
    for b in node npm npx; do \
        p="$(command -v "$b" || true)"; \
        [ -n "$p" ] && [ -x "$p" ] || { echo "FATAL: $b missing after nvm install" >&2; exit 1; }; \
        ln -sfn "$p" "/usr/local/bin/$b"; \
    done; \
    /usr/local/bin/node --version; \
    /usr/local/bin/npm --version'

# Both files into the SAME directory, and that is not stylistic: install-chrome.sh
# derives SCRIPT_DIR from its own dirname and sources common.sh from there, so
# copying the installer alone fails at `source` with "No such file or directory".
# Reaching `test/` at all requires the build context to be the repo root rather
# than this directory — see "context" in devcontainer.json.
COPY test/install-chrome.sh test/common.sh /tmp/vespasian-chrome/

# container=docker is REQUIRED here, not decoration. install-chrome.sh always
# pre-seeds the google-chrome package's own opt-out so the permanent apt source
# and the daily update pinger are never created, but the belt-and-braces half —
# removing and then VERIFYING absent whatever the package planted anyway — is
# gated behind in_container(). That gate reads /.dockerenv, /run/.containerenv,
# REMOTE_CONTAINERS, or $container naming a known runtime, and none of those is a
# dependable build-time signal: /.dockerenv is a marker the daemon places for
# `docker run`, and REMOTE_CONTAINERS is a VS Code runtime variable. Rather than
# depend on which builder a developer happens to have, name the runtime
# outright. It is a truthful value — an image build is exactly the throwaway
# image that branch was written for — and it is what makes "no new background
# egress from the image" a verified property rather than an assumed one.
#
# Scoped to this RUN rather than set as ENV so it does not leak into the running
# container and perturb unrelated tooling that reads $container. At runtime the
# devcontainer sets REMOTE_CONTAINERS=true itself, so in_container() is already
# true there without help.
#
# Note what idempotency does and does not buy here. A cache HIT skips this layer
# entirely, and a cache MISS is a genuine reinstall into a fresh layer that has
# no browser yet — so the early exit never fires during a build. What it buys is
# that a developer (or a postCreateCommand, if one is ever added) can run the
# script inside the finished container without it trying to install twice.
RUN container=docker /tmp/vespasian-chrome/install-chrome.sh \
    && rm -rf /tmp/vespasian-chrome
