#!/usr/bin/env python3
"""Tests for scripts/ci/setup/cargo-timings-summary.py: the longest units and
the last to finish come from the report's unit data, and a missing or empty
report never fails a build."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCRIPT = os.path.join(ROOT, "scripts", "ci", "setup", "cargo-timings-summary.py")
PREFIX = "[build batch] codewire-orchestration timings:"


def run(*args):
    return subprocess.run([sys.executable, "-I", "-B", SCRIPT, *args], capture_output=True, text=True)


class Summary(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.report = os.path.join(self.dir.name, "cargo-timing.html")

    def write(self, units):
        with open(self.report, "w", encoding="utf-8") as f:
            f.write(f"<script>\nconst UNIT_DATA = {json.dumps(units)};\nconst CONCURRENCY_DATA = [];\n</script>\n")

    def test_the_longest_and_last_units_are_named(self):
        self.write([
            {"name": "codewire-orchestration", "target": ' "lib" (test)', "start": 65.4, "duration": 151.1},
            {"name": "codewire-cli", "target": ' "lib" (test)', "start": 24.4, "duration": 104.7},
            {"name": "serde", "target": "", "start": 0.0, "duration": 3.0},
        ])
        result = run(self.report, PREFIX)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], f"{PREFIX} 3 units, 216.5 s from the first to the last")
        self.assertEqual(lines[1], f'{PREFIX} longest  151.1 s at   65.4 s  codewire-orchestration "lib" (test)')
        self.assertEqual(lines[3], f"{PREFIX} longest    3.0 s at    0.0 s  serde")
        self.assertEqual(lines[4], f'{PREFIX} last    ends  216.5 s (151.1 s)  codewire-orchestration "lib" (test)')
        self.assertEqual(len(lines), 7)

    def test_a_missing_report_prints_nothing_and_passes(self):
        result = run(self.report, PREFIX)
        self.assertEqual((result.returncode, result.stdout), (0, ""))

    def test_a_report_with_no_unit_data_says_so_and_passes(self):
        with open(self.report, "w", encoding="utf-8") as f:
            f.write("<html></html>")
        result = run(self.report, PREFIX)
        self.assertEqual((result.returncode, result.stdout), (0, f"{PREFIX} no unit data in the report\n"))

    def test_a_wrong_call_is_refused(self):
        self.assertEqual(run(self.report).returncode, 2)


if __name__ == "__main__":
    unittest.main()
