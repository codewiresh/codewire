#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def require(text: str, expected: str) -> None:
    if expected not in text:
        raise RuntimeError(f"OpenSSF report is missing {expected!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unavailable", type=Path, required=True)
    parser.add_argument("--populated", type=Path, required=True)
    args = parser.parse_args()

    unavailable = (args.unavailable / "reference/openssf/index.html").read_text(encoding="utf-8")
    require(unavailable, "Scorecard data is unavailable in this build")
    require(unavailable, "Best Practices badge: unavailable")
    require(unavailable, "https://scorecard.dev/viewer/?uri=github.com/codewiresh/codewire")
    if "<table>" in unavailable:
        raise RuntimeError("the unavailable OpenSSF state rendered a results table")

    populated = (args.populated / "reference/openssf/index.html").read_text(encoding="utf-8")
    for expected in (
        "Best Practices badge: Passing",
        "https://www.bestpractices.dev/projects/14393",
        "<strong>9.2</strong>",
        "21a00a2",
        "v5.5.0",
        "October 3, 2026 at 00:45 UTC",
        "Snapshot fetched <time datetime=\"2026-11-08T00:00:00Z\">2026-11-08T00:00:00Z</time>",
        "Branch-Protection",
        "branch protection is not maximal on development and all release branches",
        "required approving review count is 1",
        "https://scorecard.dev/viewer/?uri=github.com/codewiresh/codewire",
    ):
        require(populated, expected)

    markdown = (args.populated / "reference/openssf.md").read_text(encoding="utf-8")
    require(markdown, "OpenSSF data is rendered into the HTML page at build time")
    require(markdown, "https://scorecard.dev/viewer/?uri=github.com/codewiresh/codewire")
    if "{{" in markdown or "{%" in markdown:
        raise RuntimeError("the OpenSSF shortcode leaked into Markdown")
    print("OpenSSF populated and unavailable report states passed")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(f"verify_security_posture: {error}") from error
