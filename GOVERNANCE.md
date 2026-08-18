# Governance

This document describes who maintains Vespasian, how decisions get made, and what to do when the process stalls. It exists so contributors don't have to guess who can accept a change.

Vespasian is sponsored by [Praetorian](https://www.praetorian.com/), which funds its development and provides the security contact used for vulnerability and conduct reports.

## Table of contents

- [Maintainers](#maintainers)
- [Decision making](#decision-making)
- [Changes to the maintainer team](#changes-to-the-maintainer-team)
- [Releases](#releases)
- [Escalation](#escalation)
- [Code of conduct](#code-of-conduct)

## Maintainers

Maintainers review and merge pull requests, cut releases, and set technical direction.

| GitHub |
|--------|
| [@santiago-praetorian](https://github.com/santiago-praetorian) |
| [@eli-wald](https://github.com/eli-wald) |
| [@logan-bayless](https://github.com/logan-bayless) |

This roster and [`CODEOWNERS`](CODEOWNERS) are kept in sync — `CODEOWNERS` is what actually drives review assignment on a pull request, so a change to one is a change to the other. If you find them disagreeing, that's a bug; please open an issue.

## Decision making

Most changes are routine and need no ceremony:

- **Pull requests** require at least one approving review before merge; a branch ruleset enforces that. The approval is expected to come from a maintainer other than the author, and `CODEOWNERS` requests that review automatically, but code-owner approval is convention here rather than an enforced gate.
- **Maintainers do not self-merge** without another maintainer's approval, including for their own changes.
- **Routine changes** — bug fixes, tests, documentation, dependency bumps — proceed on a single approval.
- **Substantial changes** — a new API type, a breaking change to the `capture.json` format, a new runtime dependency, or anything that changes CLI behavior users rely on — should start as an issue so the discussion happens before the implementation. This is about saving contributors wasted work, not about gatekeeping.

Where maintainers disagree, the expectation is that they resolve it in the open on the pull request or issue. If a disagreement can't be settled that way, it is escalated to the Praetorian team that sponsors the project.

## Changes to the maintainer team

- A new maintainer is proposed by an existing maintainer and confirmed by consensus of the current maintainers.
- A maintainer may step down at any time by opening a pull request removing themselves.
- Maintainers who have been inactive for an extended period may be moved off the roster by consensus of the remaining maintainers.

Any change to the team updates both this file and [`CODEOWNERS`](CODEOWNERS) in the same pull request.

## Releases

Releases are triggered by pushing a `v*` tag; [`.github/workflows/release.yml`](.github/workflows/release.yml) then runs GoReleaser, which builds the binaries and publishes the GitHub release. There is no manual publishing step.

Creating the tag is the gated part. An organization-level ruleset restricts creation of `refs/tags/v*`, so being on the roster above does not by itself let you cut a release. A maintainer without that permission asks a Praetorian organization administrator to create the tag.

## Escalation

If a pull request or issue stalls:

1. Comment on the thread — maintainers may simply have missed it.
2. If there's still no response after roughly a week, `@`-mention the maintainers listed above.
3. If a review is disputed, ask for a second maintainer to weigh in rather than relitigating with the first.

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to security@praetorian.com, as described there.

Security vulnerabilities follow a separate process — see [`SECURITY.md`](SECURITY.md). Do not report them in a public issue.
