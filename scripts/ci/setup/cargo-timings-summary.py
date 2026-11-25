#!/usr/bin/env python3
"""Print the units that ran longest and the last to finish in one Cargo
--timings report, from the data the report embeds (codewire#5311,
infra#1534).

Usage: cargo-timings-summary.py REPORT PREFIX

Each line starts with PREFIX, e.g. "[build-once] timings:". Measurement
only: a missing report prints nothing, and one with no unit data says so;
both exit 0, so a build never fails on its summary.
"""
import json
import os
import re
import sys


def main(argv):
    if len(argv) != 3:
        print("usage: cargo-timings-summary.py REPORT PREFIX", file=sys.stderr)
        return 2
    report, prefix = argv[1], argv[2]
    if not os.path.isfile(report):
        return 0
    html = open(report, encoding="utf-8", errors="replace").read()
    match = re.search(r"const UNIT_DATA = (\[.*?\]);\n", html, re.S)
    if not match:
        print(f"{prefix} no unit data in the report")
        return 0
    units = json.loads(match.group(1))

    def label(unit):
        return f"{unit['name']} {unit.get('target', '').strip()}".strip()

    end = max((u["start"] + u["duration"] for u in units), default=0)
    print(f"{prefix} {len(units)} units, {end:.1f} s from the first to the last")
    for unit in sorted(units, key=lambda u: -u["duration"])[:12]:
        print(f"{prefix} longest {unit['duration']:6.1f} s at {unit['start']:6.1f} s  {label(unit)}")
    for unit in sorted(units, key=lambda u: -(u["start"] + u["duration"]))[:8]:
        print(f"{prefix} last    ends {unit['start'] + unit['duration']:6.1f} s ({unit['duration']:5.1f} s)  {label(unit)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
