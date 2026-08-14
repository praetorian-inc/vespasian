# Support

Thanks for using Vespasian. This page explains where to ask, what to include, and what to expect back.

## Where to ask

Questions, bug reports, and feature requests go through [GitHub Issues](https://github.com/praetorian-inc/vespasian/issues):

| You want to | Template | And |
|---|---|---|
| Ask how to do something, or check whether behavior is expected | **Question** | include the context below |
| Report something that doesn't work | **Bug report** | describe expected versus actual, with the context below |
| Suggest a capability or improvement | **Feature request** | describe the use case it unblocks |
| Report a security vulnerability | none — **don't** | see [`SECURITY.md`](SECURITY.md) |

Start at [new issue](https://github.com/praetorian-inc/vespasian/issues/new/choose) and pick the matching template; each one asks for the context below as form fields. Before filing, the [README](README.md) covers installation, the CLI reference, which API types are supported, and an [FAQ](README.md#frequently-asked-questions) — a fair number of questions are answered there.

If you're unsure whether something is a bug or a misunderstanding, say so and file it as a question. Working that out is our job, not yours.

## What to include

Vespasian's behavior depends heavily on what it was pointed at and how the traffic was captured, so a question without that context usually costs a round trip. Include:

- **Version** — output of `vespasian version`
- **OS and architecture**, and whether you're running in a container or devcontainer
- **Go version** (`go version`) if you built from source
- **The command you ran**, with flags
- **Where the traffic came from** — headless crawl, Burp Suite XML, HAR, or mitmproxy import
- **What you expected** versus what happened
- **A relevant excerpt** of `capture.json` or the generated spec

**Redact before posting.** Captures and generated specs routinely contain hostnames, tokens, cookies, and request bodies from real targets. Issues are public and are not the place for any of that. Strip it, or replace it with representative dummy values.

## What to expect

Vespasian is maintained by [Praetorian](https://www.praetorian.com/) alongside other work. Issues are answered on a **best-effort basis — there is no response-time commitment or SLA.**

In practice:

- Questions and bug reports with the context above get answered fastest, because there's nothing to ask for first.
- Reproducible bugs are prioritized over ones we can't reproduce.
- A quiet issue hasn't been rejected. If a thread stays quiet, follow the escalation steps in [`GOVERNANCE.md`](GOVERNANCE.md).

## Security

**Never report a security vulnerability in a public issue.** Follow [`SECURITY.md`](SECURITY.md) — email security@praetorian.com. The same applies to anything sensitive you find in a capture of a third party's system.
