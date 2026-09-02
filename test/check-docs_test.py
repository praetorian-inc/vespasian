#!/usr/bin/env python3
"""Unit tests for test/check-docs.py, focused on the reference-style link checker.

The module under test has a hyphen in its name, so it is loaded by path rather
than imported. Run directly with no third-party dependency:

    python3 test/check-docs_test.py            # or: python3 -m unittest, with -v

Covers the pure helpers (strip_fenced_blocks, strip_inline_code, _norm_label,
reference_defs_and_usages across shortcut/collapsed/full references, their image
forms, and the exclusions) and check_reference_links end-to-end against a temp
fixture tree, asserting the exact failure strings CI would surface.
"""

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "check_docs", Path(__file__).with_name("check-docs.py")
)
cd = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cd)


class NormLabelTest(unittest.TestCase):
    def test_case_insensitive_and_whitespace_collapsed(self):
        self.assertEqual(cd._norm_label("  Un   released "), "un released")
        self.assertEqual(cd._norm_label("1.0.0"), "1.0.0")


class StripTest(unittest.TestCase):
    def test_strip_fenced_blocks_blanks_lines_preserving_count(self):
        src = "a\n```\n[x]: bad\n```\nb\n"
        out = cd.strip_fenced_blocks(src)
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertNotIn("[x]: bad", out)

    def test_strip_inline_code_blanks_bracketed_tokens(self):
        # `[role=button]` and `map[string][]string` must not read as references.
        out = cd.strip_inline_code("use `[role=button]` and `map[string][]string`")
        self.assertNotIn("[role=button]", out)
        self.assertNotIn("[string]", out)

    def test_strip_inline_code_preserves_newlines(self):
        src = "a `code\nspan` b\n"
        self.assertEqual(cd.strip_inline_code(src).count("\n"), src.count("\n"))


class ReferenceDefsAndUsagesTest(unittest.TestCase):
    def defs_usages(self, text):
        return cd.reference_defs_and_usages(text)

    def test_definition_line(self):
        defs, usages = self.defs_usages("[unreleased]: https://example.test\n")
        self.assertEqual(defs, {"unreleased"})
        self.assertEqual(usages, set())

    def test_definition_requires_whitespace_and_following_target(self):
        # TEST-001: REF_DEF_RE needs "]:" then whitespace then a non-space target.
        # A colon-adjacent token ("[label]:no-space") or an empty target
        # ("[empty]:" at end of line) is NOT a reference definition.
        defs, _ = self.defs_usages("[label]:no-space\n[empty]:\n")
        self.assertEqual(defs, set())

    def test_checked_ordered_list_excluded(self):
        # TEST-002: an ordered-list checkbox ("1. [x]", "1) [X]") is a checkbox,
        # not a reference usage of label "x" — consistent with bullet lists.
        for text in ("1. [x] done\n", "1) [X] done\n"):
            _, usages = self.defs_usages(text)
            self.assertEqual(usages, set(), text)

    def test_shortcut_reference(self):
        _, usages = self.defs_usages("## [Unreleased]\n")
        self.assertEqual(usages, {"unreleased"})

    def test_collapsed_reference(self):
        _, usages = self.defs_usages("see [1.0.0][]\n")
        self.assertEqual(usages, {"1.0.0"})

    def test_full_reference_counts_label_not_text(self):
        _, usages = self.defs_usages("see [the release][1.0.0]\n")
        self.assertEqual(usages, {"1.0.0"})

    def test_inline_link_excluded(self):
        _, usages = self.defs_usages("see [text](https://example.test)\n")
        self.assertEqual(usages, set())

    def test_footnote_excluded(self):
        _, usages = self.defs_usages("text[^note] more\n")
        self.assertEqual(usages, set())

    def test_empty_and_unchecked_task_list_excluded(self):
        _, usages = self.defs_usages("- [ ] todo\nempty []\n")
        self.assertEqual(usages, set())

    def test_checked_task_list_excluded(self):
        # TEST-003: "- [x]" is a checkbox, not a reference usage.
        _, usages = self.defs_usages("- [x] done\n")
        self.assertEqual(usages, set())

    def test_real_x_shortcut_reference_still_counts(self):
        # A genuine [x] shortcut reference (not at a list-item start) is kept.
        _, usages = self.defs_usages("see [x] here\n")
        self.assertEqual(usages, {"x"})

    def test_reference_images_count_their_label(self):
        # TEST-002: shortcut/collapsed/full reference images all count the label,
        # so a definition used only by a reference image is not flagged orphaned.
        for text in ("![logo]\n", "![logo][]\n", "![alt][logo]\n"):
            _, usages = self.defs_usages(text)
            self.assertEqual(usages, {"logo"}, text)

    def test_inline_image_excluded(self):
        _, usages = self.defs_usages("![alt](https://example.test/l.png)\n")
        self.assertEqual(usages, set())


class CheckReferenceLinksTest(unittest.TestCase):
    def run_check(self, name_to_body):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            files = []
            for name, body in name_to_body.items():
                (root / name).write_text(body, encoding="utf-8")
                files.append(Path(name))
            failures = []
            cd.check_reference_links(root, files, failures, verbose=False)
            return failures

    def test_well_formed_passes(self):
        body = "## [Unreleased]\n\n[Unreleased]: https://example.test/compare\n"
        self.assertEqual(self.run_check({"CHANGELOG.md": body}), [])

    def test_missing_definition_reported(self):
        body = "## [1.0.0]\n\n[Unreleased]: https://example.test/c\n## [Unreleased]\n"
        failures = self.run_check({"CHANGELOG.md": body})
        self.assertEqual(
            failures,
            [
                "reference-links: CHANGELOG.md uses reference-style link [1.0.0] "
                "with no matching [1.0.0]: definition"
            ],
        )

    def test_orphaned_definition_reported(self):
        body = "## Unreleased\n\n[Unreleased]: https://example.test/compare\n"
        failures = self.run_check({"CHANGELOG.md": body})
        self.assertEqual(
            failures,
            [
                "reference-links: CHANGELOG.md defines reference-style link "
                "[unreleased]: but nothing uses it"
            ],
        )

    def test_file_without_definitions_is_skipped(self):
        # A doc that uses no reference definitions is not checked at all, so a
        # bare bracketed token in prose cannot false-positive.
        self.assertEqual(self.run_check({"README.md": "prose with [brackets] only\n"}), [])

    def test_definitions_inside_code_fence_are_not_seen(self):
        body = "## [Unreleased]\n\n```\n[stale]: https://example.test/old\n```\n" \
               "[Unreleased]: https://example.test/c\n"
        self.assertEqual(self.run_check({"CHANGELOG.md": body}), [])

    def test_unreadable_file_reported_and_others_continue(self):
        # TEST-003: a file that cannot be decoded is reported, and the check does
        # not abort — a later well-formed file is still processed.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "bad.md").write_bytes(b"\xff\xfe## [Unreleased]\n")
            (root / "CHANGELOG.md").write_text(
                "## [1.0.0]\n\n[1.0.0]: https://example.test/c\n## [Unreleased]\n",
                encoding="utf-8",
            )
            failures = []
            cd.check_reference_links(
                root, [Path("bad.md"), Path("CHANGELOG.md")], failures, verbose=False
            )
        self.assertEqual(len(failures), 2, failures)
        self.assertTrue(
            failures[0].startswith("reference-links: cannot read bad.md: "), failures
        )
        self.assertIn(
            "reference-links: CHANGELOG.md uses reference-style link [unreleased] "
            "with no matching [unreleased]: definition",
            failures,
        )


class MainDispatchTest(unittest.TestCase):
    """TEST-004: main()/CHECKS wiring for the reference-links check."""

    def test_reference_links_registered_in_default_selection(self):
        self.assertIn("reference-links", sorted(cd.CHECKS))

    def test_main_dispatches_reference_links_with_files(self):
        # Drive main() through the ("links", "reference-links") dispatch branch:
        # a seeded reference-link mismatch must surface on stderr and set a
        # non-zero exit code, proving check_reference_links is invoked with the
        # (root, files, ...) signature and the tracked file list is forwarded.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "CHANGELOG.md").write_text(
                "## [1.0.0]\n\n[unreleased]: https://example.test/c\n",
                encoding="utf-8",
            )
            orig_repo_root = cd.repo_root
            orig_tracked = cd.tracked_markdown
            orig_argv = sys.argv
            cd.repo_root = lambda: root
            cd.tracked_markdown = lambda _root: [Path("CHANGELOG.md")]
            sys.argv = ["check-docs.py", "--only", "reference-links"]
            try:
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = cd.main()
            finally:
                cd.repo_root = orig_repo_root
                cd.tracked_markdown = orig_tracked
                sys.argv = orig_argv
        self.assertEqual(rc, 1)
        self.assertIn(
            "reference-links: CHANGELOG.md uses reference-style link [1.0.0] "
            "with no matching [1.0.0]: definition",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
