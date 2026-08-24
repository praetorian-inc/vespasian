# Development image for vespasian. Its one job beyond the stock Go toolchain is
# to close LAB-5064's AC1: ship a runnable, non-snap Chrome so `launcher.LookPath()`
# resolves a browser that can actually start, and the pkg/crawl
# `//go:build integration` launch/kill/close tests and the rod-backed live
# targets run instead of failing or skipping.
#
# Digest-pinned like the repo's release Dockerfile and the install-chrome-e2e
# job's container: a mutable tag means the thing this image installs into can
# change under us between builds. Refresh deliberately.
#
# Why this base rather than a bare golang image: it already carries the pieces
# install-chrome.sh requires and a devcontainer expects — Go 1.25.12 (>= go.mod's
# 1.25.8, which matters because GOTOOLCHAIN=local means Go will NOT fetch a
# newer toolchain), ca-certificates/curl/gnupg, the non-root `vscode` user with
# sudo, git, and Node (needed by the graphql-server target and
# test/spec-validators; their npm deps are installed by devcontainer.json's
# onCreateCommand, not here — see the note there). It builds as root, so
# install-chrome.sh resolves
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
