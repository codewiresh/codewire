#!/usr/bin/env python3
"""The README recording renderer turns terminal output into valid SVG text:
escapes go, a hyperlink's text stays, and nothing XML 1.0 forbids remains."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.dom.minidom

ROOT = Path(__file__).resolve().parents[3]
RENDERER = ROOT / "scripts/docs/render-terminal-svg.py"
URL = "https://codewire.sh/device?user_code=ABCD-EFGH"


class Renderer(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="render-svg-"))
        self.addCleanup(shutil.rmtree, self.temporary)

    def render(self, *lines):
        transcript = self.temporary / "transcript.jsonl"
        events = [{"t": 1.0, "cmd": "cw login"}]
        events += [{"t": 1.5 + index, "out": line} for index, line in enumerate(lines)]
        transcript.write_text("".join(json.dumps(event) + "\n" for event in events))
        output = self.temporary / "out.svg"
        subprocess.run([sys.executable, "-I", str(RENDERER), str(transcript), str(output)], check=True)
        svg = output.read_text(encoding="utf-8")
        document = xml.dom.minidom.parseString(svg.encode())
        # Each recorded line is a <text class="l lN">; the title bar is not.
        lines = [text for text in document.getElementsByTagName("text") if text.getAttribute("class").startswith("l ")]
        shown = "\n".join(
            "".join(node.data for tspan in text.getElementsByTagName("tspan") for node in tspan.childNodes
                    if node.nodeType == node.TEXT_NODE)
            for text in lines
        )
        return svg, shown

    def test_an_osc_8_hyperlink_keeps_its_text_and_drops_its_url(self):
        for end in ("\x1b\\", "\x07"):
            svg, shown = self.render(f"Visit \x1b]8;;{URL}{end}the sign-in page\x1b]8;;{end} to approve")
            self.assertIn("Visit the sign-in page to approve", shown, repr(end))
            self.assertNotIn("]8;", svg)
            self.assertNotIn(URL, svg)

    def test_a_link_whose_text_is_its_url_shows_the_url_once(self):
        svg, shown = self.render(f"\x1b]8;;{URL}\x1b\\{URL}\x1b]8;;\x1b\\")
        self.assertEqual(shown.count(URL), 1)
        self.assertNotIn("]8;", svg)

    def test_a_hyperlink_split_across_lines_fails_the_render_and_leaks_nothing(self):
        transcript = self.temporary / "split.jsonl"
        events = [
            {"t": 1.0, "cmd": "cw login"},
            {"t": 1.5, "out": f"Visit \x1b]8;;{URL}"},
            {"t": 1.6, "out": "\x1b\\the sign-in page\x1b]8;;\x1b\\"},
        ]
        transcript.write_text("".join(json.dumps(event) + "\n" for event in events))
        output = self.temporary / "split.svg"
        result = subprocess.run([sys.executable, "-I", str(RENDERER), str(transcript), str(output)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("transcript line 2 has an escape sequence that does not end on its line", result.stderr)
        self.assertNotIn(URL, result.stdout + result.stderr)
        self.assertFalse(output.exists())

    def test_colours_and_forbidden_controls_go_and_a_tab_stays(self):
        svg, shown = self.render("\x1b[1;32m✓\x1b[0m Done\x07\tnext")
        self.assertIn("✓ Done\tnext", shown)
        self.assertNotIn("\x1b", svg)
        self.assertNotIn("\x07", svg)


if __name__ == "__main__":
    unittest.main()
