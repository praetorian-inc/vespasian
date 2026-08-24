#!/usr/bin/env bash
#
# devcontainer.json's onCreateCommand. Installs the Node dependencies the live
# and generator targets parse specs with — @apidevtools/swagger-parser and
# graphql — which cannot be baked into an image layer because the workspace is
# bind-mounted over the image's copy of it.
#
# A committed script rather than an inline JSON string, for the reason
# test/assert-chrome-install.sh and test/assert-devcontainer-lookpath.sh are
# files: an inline string is invisible to `bash -n`, and onCreateCommand runs
# only when a container is created, so a mistake in one surfaces late and to a
# developer rather than to CI.
#
# Why the nvm dance. The base image ships Node through nvm
# (NVM_DIR=/usr/local/share/nvm, with PATH pointing at $NVM_DIR/current/bin),
# and the devcontainer CLI runs onCreateCommand under `/bin/sh -c`, which is
# neither a login nor an interactive shell and so does not load the profile that
# puts nvm's bin on PATH. MEASURED: the first CI run of this job that got as far
# as container creation failed here with
#   /bin/sh: 1: npm: not found
#   onCreateCommand from devcontainer.json failed with exit code 127
# so resolving npm explicitly is the fix, not a precaution.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v npm >/dev/null 2>&1; then
    # Prefer the version nvm has marked current; fall back to sourcing nvm.
    if [ -n "${NVM_DIR:-}" ] && [ -x "${NVM_DIR}/current/bin/npm" ]; then
        PATH="${NVM_DIR}/current/bin:${PATH}"
        export PATH
    elif [ -n "${NVM_DIR:-}" ] && [ -s "${NVM_DIR}/nvm.sh" ]; then
        # shellcheck disable=SC1091
        . "${NVM_DIR}/nvm.sh"
    fi
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "on-create: npm not found. The base image is expected to ship Node via nvm" >&2
    echo "  (NVM_DIR=${NVM_DIR:-<unset>}); check the FROM in .devcontainer/Dockerfile." >&2
    exit 1
fi

echo "on-create: using $(command -v npm) ($(npm --version))"
cd test/spec-validators
# --ignore-scripts matches every other npm call site in this repo, blocking
# package lifecycle scripts from executing.
npm ci --ignore-scripts
echo "on-create: spec-validator dependencies installed"
