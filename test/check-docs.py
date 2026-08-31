#!/usr/bin/env python3
"""Assert the repository's community-health docs are present, linked, and self-consistent.

Four checks, each independently reportable:

1. presence        — the community-health set exists at the repository root. LAB-5870 landed
                     after GOVERNANCE.md and SUPPORT.md were absent from `main` for a week
                     because two stacked PRs merged into feature branches that nothing merges
                     from again. Nothing in CI noticed.
2. links           — every relative markdown link and heading anchor resolves. A cross-link
                     added alongside a new document is the other half of that failure: the
                     document can be present and the link to it still dead.
3. reference-links — reference-style link definitions and their usages correspond. CHANGELOG.md
                     is Keep a Changelog format, where each `## [x.y.z]` heading is a shortcut
                     reference resolved by a `[x.y.z]: <url>` definition at the foot of the file.
                     The inline-link check sees neither half, so a deleted definition (the
                     heading renders as literal brackets) or an orphaned one would pass silently.
4. roster          — the `*` owner line in CODEOWNERS matches the maintainer table in
                     GOVERNANCE.md. Both files assert they are kept in sync and each points at
                     the other, but CODEOWNERS is what actually drives review assignment, so a
                     one-sided edit misroutes reviews while both documents still read as
                     authoritative.

Written in Python rather than shell deliberately: the link and slug logic needs real
parsing, and the surrounding scripts are developed on macOS and run on Linux, where the
`sed`/`grep`/`stat` flag sets diverge in both directions.

Exit status is 0 when every check passes, 1 otherwise. Run with --verbose to list what
was checked rather than only what failed.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Community-health files that must exist at the repository root. GitHub surfaces each of
# these in its own UI slot, so an absent one degrades silently rather than erroring.
REQUIRED_ROOT_FILES = [
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "LICENSE",
    "CODEOWNERS",
]

# Directories whose markdown is not ours to validate.
SKIP_DIR_PARTS = {"node_modules", ".worktrees", "vendor", "dist", "bin"}

# Inline markdown links and images: [text](target) / ![alt](target), optional "title".
# Reference-style usages ([label], [text][label], [label][]) are matched separately
# by BRACKET_RE for the reference-links check, not here.
LINK_RE = re.compile(r"!?\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<text>.+?)\s*$", re.MULTILINE)
FENCE_RE = re.compile(r"^([ \t]*)(```|~~~)", re.MULTILINE)

# Reference-style link plumbing (Keep a Changelog leans on it: a "## [1.0.0]"
# heading is a shortcut reference that resolves through a "[1.0.0]: <url>"
# definition at the foot of the file). LINK_RE sees neither half, so without a
# dedicated check a deleted definition (heading renders as literal brackets) or
# an orphaned definition passes silently.
REF_DEF_RE = re.compile(r"^ {0,3}\[(?P<label>[^\]\n]+)\]:\s+\S", re.MULTILINE)
# A bracket group. Labels do not nest. Reference-style images (`![label]`,
# `![label][]`, `![text][label]`) resolve through the same definitions as
# reference links, so they are counted as usages too; inline links/images
# (`[text](url)`, `![alt](url)`) are excluded downstream by the following "(".
BRACKET_RE = re.compile(r"\[(?P<inner>[^\[\]]*)\]")
# A GitHub task-list checkbox at a list-item start: "- [ ]", "* [x]", "+ [X]".
# The bracket prefix is the bullet up to the checkbox.
TASK_ITEM_RE = re.compile(r"^\s*[-*+]\s+$")
# Inline code spans, so bracketed tokens inside them (`[role=button]`,
# `map[string][]string`) are not read as reference links. The disjoint
# `[\s\S]` (not `.|\n`) keeps the lazy repetition single-path, not ReDoS-shaped.
INLINE_CODE_RE = re.compile(r"(?P<ticks>`+)[\s\S]*?(?P=ticks)")


def repo_root():
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(out.stdout.strip())


def tracked_markdown(root):
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.md", "*.markdown"],
        capture_output=True, text=True, check=True,
    )
    paths = []
    for line in out.stdout.splitlines():
        p = Path(line)
        if SKIP_DIR_PARTS & set(p.parts):
            continue
        paths.append(p)
    return sorted(paths)


def strip_fenced_blocks(text):
    """Blank out fenced code blocks so links inside samples are not validated.

    Lines are replaced rather than removed so reported line numbers stay accurate.
    """
    lines = text.split("\n")
    out, fence = [], None
    for line in lines:
        m = FENCE_RE.match(line)
        marker = m.group(2) if m else None
        if fence is None and marker:
            fence = marker
            out.append("")
            continue
        if fence is not None:
            # A closing fence is the same marker character run, nothing else on the line.
            if marker and line.strip().startswith(fence):
                fence = None
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def slugify(heading_text):
    """GitHub's heading-anchor algorithm, as applied to already-rendered heading text.

    Inline markdown is stripped first (backticks, emphasis, and link syntax reduced to
    its text) because the anchor derives from the rendered text, not the source.
    """
    t = LINK_RE.sub(lambda m: m.group("text"), heading_text)
    t = t.replace("`", "").replace("*", "").replace("_", "")
    t = t.lower()
    t = re.sub(r"[^a-z0-9 \-]", "", t)
    return t.strip().replace(" ", "-")


def anchors_for(path, cache):
    """Every anchor a markdown file exposes, including GitHub's -1/-2 duplicate suffixes."""
    if path in cache:
        return cache[path]
    try:
        text = strip_fenced_blocks(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        cache[path] = set()
        return cache[path]
    seen, anchors = {}, set()
    for m in HEADING_RE.finditer(text):
        base = slugify(m.group("text"))
        if not base:
            continue
        n = seen.get(base, 0)
        anchors.add(base if n == 0 else f"{base}-{n}")
        seen[base] = n + 1
    # Explicit HTML anchors authors may have placed by hand.
    for m in re.finditer(r"<a\s+[^>]*(?:name|id)=[\"']([^\"']+)[\"']", text):
        anchors.add(m.group(1))
    cache[path] = anchors
    return anchors


def check_presence(root, failures, verbose):
    for name in REQUIRED_ROOT_FILES:
        if (root / name).exists():
            if verbose:
                print(f"  present: {name}")
        else:
            failures.append(
                f"presence: required community-health file {name} is missing from the "
                f"repository root"
            )


def check_links(root, files, failures, verbose):
    cache = {}
    checked = 0
    for rel in files:
        path = root / rel
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            failures.append(f"links: cannot read {rel}: {e}")
            continue
        text = strip_fenced_blocks(raw)
        for m in LINK_RE.finditer(text):
            target = m.group("target")
            line_no = text.count("\n", 0, m.start()) + 1
            if target.startswith(("http://", "https://", "mailto:", "tel:")):
                continue
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            frag = ""
            if "#" in target:
                target, frag = target.split("#", 1)
            # Same-file anchor: [text](#section)
            if target == "":
                checked += 1
                if frag and frag not in anchors_for(path, cache):
                    failures.append(
                        f"links: {rel}:{line_no} anchor #{frag} does not match any "
                        f"heading in this file"
                    )
                continue
            # Resolve relative to the containing file, as a markdown renderer does.
            resolved = (path.parent / target.replace("%20", " ")).resolve()
            checked += 1
            if not resolved.exists():
                failures.append(f"links: {rel}:{line_no} target {target} does not exist")
                continue
            if frag and resolved.is_file() and resolved.suffix.lower() in (".md", ".markdown"):
                if frag not in anchors_for(resolved, cache):
                    failures.append(
                        f"links: {rel}:{line_no} anchor #{frag} does not match any "
                        f"heading in {target}"
                    )
    if verbose:
        print(f"  checked {checked} relative links/anchors across {len(files)} markdown files")


def codeowners_default_owners(root, failures):
    path = root / "CODEOWNERS"
    if not path.exists():
        return None
    owners = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts[0] == "*":
            if owners is not None:
                failures.append(
                    "roster: CODEOWNERS declares more than one '*' rule; the last one "
                    "wins on GitHub, which makes the roster ambiguous to read"
                )
            owners = {p.lstrip("@").lower() for p in parts[1:] if p.startswith("@")}
    if owners is None:
        failures.append("roster: CODEOWNERS has no '*' default-owner rule")
    return owners


def governance_maintainers(root, failures):
    path = root / "GOVERNANCE.md"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    m = re.search(r"^##+\s+Maintainers\s*$(.*?)(?=^##+\s|\Z)", text, re.MULTILINE | re.DOTALL)
    if not m:
        failures.append("roster: GOVERNANCE.md has no '## Maintainers' section")
        return None
    handles = {h.lower() for h in re.findall(r"@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)", m.group(1))}
    if not handles:
        failures.append("roster: GOVERNANCE.md's Maintainers section lists no @handles")
        return None
    return handles


def check_roster(root, failures, verbose):
    owners = codeowners_default_owners(root, failures)
    maintainers = governance_maintainers(root, failures)
    if owners is None or maintainers is None:
        return
    if owners == maintainers:
        if verbose:
            print(f"  roster matches ({len(owners)}): {', '.join('@' + o for o in sorted(owners))}")
        return
    only_co = sorted(owners - maintainers)
    only_gov = sorted(maintainers - owners)
    detail = []
    if only_co:
        detail.append("in CODEOWNERS but not GOVERNANCE.md: " + ", ".join("@" + o for o in only_co))
    if only_gov:
        detail.append("in GOVERNANCE.md but not CODEOWNERS: " + ", ".join("@" + o for o in only_gov))
    failures.append(
        "roster: CODEOWNERS '*' owners and the GOVERNANCE.md maintainer table disagree "
        "(" + "; ".join(detail) + "). CODEOWNERS drives review assignment, so the two "
        "must be changed together."
    )


def strip_inline_code(text):
    """Blank inline code spans, preserving newlines so line numbers stay accurate."""
    return INLINE_CODE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _norm_label(label):
    """CommonMark reference-label matching: case-insensitive, whitespace-collapsed."""
    return re.sub(r"\s+", " ", label).strip().lower()


def reference_defs_and_usages(text):
    """Return (defs, usages) of reference-link labels found in already-stripped text.

    Definitions are `[label]: target` lines. Usages are shortcut (`[label]`),
    collapsed (`[label][]`), and full (`[text][label]`) references, including
    their image forms (`![label]`, ...). Inline links/images (`[text](url)`,
    `![alt](url)`), definitions, empty brackets, GitHub task-list checkboxes
    (`- [ ]` / `- [x]`), and footnotes (`[^ref]`) are excluded.
    """
    defs = {_norm_label(m.group("label")) for m in REF_DEF_RE.finditer(text)}
    usages = set()
    for m in BRACKET_RE.finditer(text):
        nxt = text[m.end()] if m.end() < len(text) else ""
        if nxt in ("(", ":"):
            continue  # inline link/image, or reference definition
        inner = m.group("inner")
        if not inner.strip() or inner.startswith("^"):
            continue  # empty / unchecked task-list marker / footnote
        if inner in ("x", "X"):
            # Checked task-list item ("- [x]"): a checkbox, not a reference.
            line_start = text.rfind("\n", 0, m.start()) + 1
            if TASK_ITEM_RE.match(text[line_start:m.start()]):
                continue
        if nxt == "[":
            m2 = BRACKET_RE.match(text, m.end())
            if m2 is not None:
                usages.add(_norm_label(m2.group("inner").strip() or inner))
                continue
        usages.add(_norm_label(inner))
    return defs, usages


def check_reference_links(root, files, failures, verbose):
    """Reference-style link definitions and usages must correspond, per file.

    Scoped to files that actually define a reference link, so prose brackets in
    definition-free documents cannot false-positive.
    """
    checked = 0
    for rel in files:
        path = root / rel
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            failures.append(f"reference-links: cannot read {rel}: {e}")
            continue
        text = strip_inline_code(strip_fenced_blocks(raw))
        defs, usages = reference_defs_and_usages(text)
        if not defs:
            continue
        checked += 1
        for label in sorted(usages - defs):
            failures.append(
                f"reference-links: {rel} uses reference-style link [{label}] with no "
                f"matching [{label}]: definition"
            )
        for label in sorted(defs - usages):
            failures.append(
                f"reference-links: {rel} defines reference-style link [{label}]: but "
                f"nothing uses it"
            )
    if verbose:
        print(f"  checked reference-style links in {checked} markdown file(s)")


CHECKS = {
    "presence": check_presence,
    "links": check_links,
    "reference-links": check_reference_links,
    "roster": check_roster,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--verbose", "-v", action="store_true", help="list what was checked")
    ap.add_argument(
        "--only", choices=sorted(CHECKS), action="append",
        help="run only the named check (repeatable); default runs all four",
    )
    args = ap.parse_args()

    root = repo_root()
    files = tracked_markdown(root)
    selected = args.only or sorted(CHECKS)

    failures = []
    for name in selected:
        if args.verbose:
            print(f"{name}:")
        if name in ("links", "reference-links"):
            CHECKS[name](root, files, failures, args.verbose)
        else:
            CHECKS[name](root, failures, args.verbose)

    if failures:
        print(f"\ncheck-docs: {len(failures)} problem(s) found\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(file=sys.stderr)
        return 1
    print(f"check-docs: ok ({', '.join(selected)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
