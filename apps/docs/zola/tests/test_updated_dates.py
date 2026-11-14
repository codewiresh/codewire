#!/usr/bin/env python3
"""verify_updated_dates against real Git histories with chosen commit dates.

A page's `updated:` date is checked against its last edit. A squash merge
(`scripts/dev/merge-pr.sh`, `Reviewed-on: #N`) carries only the merge's
dates, so a page merged the day after it was written must pass (#4632),
while an edit dated later than the page says still fails.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_site", HERE / "verify_site.py")
verify_site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_site)

PAGE = "content/page.md"
ROUTES = [{"source": PAGE}]


class Repository:
    """A throwaway Git repository whose commits carry the dates a case names."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q")

    def git(self, *args: str, when: str | None = None) -> None:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Synthetic",
            "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic",
            "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        }
        if when:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"{when}T12:00:00+00:00"
        subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=self.root,
                       env=env, check=True, capture_output=True)

    def write(self, updated: str, body: str) -> None:
        path = self.root / PAGE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"---\ntitle: Page\nupdated: {updated}\n---\n{body}\n", encoding="utf-8")

    def commit(self, when: str, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message, when=when)


class UpdatedDates(unittest.TestCase):
    def setUp(self) -> None:
        self.work = tempfile.TemporaryDirectory()
        self.root = Path(self.work.name)

    def tearDown(self) -> None:
        self.work.cleanup()

    def test_a_page_dated_the_day_of_its_edit_passes(self) -> None:
        repo = Repository(self.root)
        repo.write("2026-11-12", "first")
        repo.commit("2026-11-12", "docs: write the page")
        verify_site.verify_updated_dates(ROUTES, self.root)

    def test_a_page_merged_the_day_after_it_was_written_passes(self) -> None:
        # The author's branch: written and dated on the 12th.
        branch = self.root / "branch"
        repo = Repository(branch)
        repo.write("2026-11-12", "first")
        repo.commit("2026-11-11", "docs: start")
        repo.write("2026-11-12", "edited")
        repo.commit("2026-11-12", "docs: write the page")
        verify_site.verify_updated_dates(ROUTES, branch)
        # main after merge-pr.sh: one squash commit, dated the merge, the 13th.
        squashed = self.root / "main"
        main = Repository(squashed)
        main.write("2026-11-12", "edited")
        main.commit("2026-11-13", "docs: write the page (#1)\n\nReviewed-on: #1")
        verify_site.verify_updated_dates(ROUTES, squashed)

    def test_an_edit_later_than_the_stated_date_fails(self) -> None:
        repo = Repository(self.root)
        repo.write("2026-11-10", "first")
        repo.commit("2026-11-10", "docs: write the page (#1)\n\nReviewed-on: #1")
        # A later edit on a branch that leaves the date behind.
        repo.write("2026-11-10", "changed")
        repo.commit("2026-11-12", "docs: change the page")
        with self.assertRaisesRegex(RuntimeError, "says updated 2026-11-10 but last changed 2026-11-12"):
            verify_site.verify_updated_dates(ROUTES, self.root)

    def test_outside_a_checkout_there_is_no_history_to_compare(self) -> None:
        (self.root / "content").mkdir()
        (self.root / PAGE).write_text("---\ntitle: Page\nupdated: 2000-01-01\n---\nbody\n", encoding="utf-8")
        verify_site.verify_updated_dates(ROUTES, self.root)


if __name__ == "__main__":
    unittest.main()
