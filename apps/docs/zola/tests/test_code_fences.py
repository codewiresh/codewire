#!/usr/bin/env python3
"""code_fence_faults on the shapes a page can get wrong, and on every page.

A closing fence with text after it on the same line does not close its block,
so everything below it renders as code. That hid a section of the live
application secrets page (#4698).
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_site", HERE / "verify_site.py")
verify_site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_site)

FENCE = "`" * 3


def page(*lines: str) -> str:
    return "\n".join(lines) + "\n"


class CodeFenceTests(unittest.TestCase):
    def faults(self, *lines: str) -> list[tuple[int, str]]:
        return verify_site.code_fence_faults(page(*lines))

    def test_well_formed_fences_pass(self) -> None:
        self.assertEqual(self.faults(
            "Text.", "", FENCE + "sh", "cw ls", FENCE, "",
            "1. A step:", "", "   " + FENCE + "text", "   output", "   " + FENCE, "",
            "~~~", "tilde", "~~~",
        ), [])

    def test_a_longer_fence_may_hold_a_shorter_one(self) -> None:
        self.assertEqual(self.faults(
            FENCE + "`" + "markdown", FENCE + "sh", "cw ls", FENCE, FENCE + "`",
        ), [])

    def test_text_after_a_closing_fence_is_a_fault(self) -> None:
        # The fault of #4698: the close and the next sentence share a line.
        self.assertEqual(self.faults(
            FENCE + "text", "KEY  SOURCE", FENCE + " In the dashboard, the page has", "more prose.",
            "", "## What the processes see",
        ), [(3, "text follows a closing code fence on its line")])

    def test_a_fence_that_never_closes_is_a_fault(self) -> None:
        self.assertEqual(self.faults("Text.", FENCE + "sh", "cw ls"),
                         [(2, "a code fence never closes")])

    def test_an_opening_fence_carries_only_a_language(self) -> None:
        self.assertEqual(self.faults(FENCE + " Some prose", "x", FENCE),
                         [(1, "an opening code fence carries more than a language")])
        self.assertEqual(self.faults(FENCE + "rust,linenos", "x", FENCE), [])

    def test_inline_code_is_not_a_fence(self) -> None:
        self.assertEqual(self.faults("Use `" + FENCE + "` to open a block.", "Run `cw ls`."), [])

    def test_every_page_is_well_formed(self) -> None:
        verify_site.verify_code_fences(HERE.parent)


if __name__ == "__main__":
    unittest.main()
