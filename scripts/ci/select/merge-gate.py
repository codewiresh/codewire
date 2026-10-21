#!/usr/bin/env python3
"""Read merge-gate.tsv: what local merge qualification requires before merge.

  merge-gate.py check                  validate the table
  merge-gate.py families               print every family, one per line
  merge-gate.py decide FAMILY          print "yes" or "no<TAB>reason"
  merge-gate.py dump                   print every row as family<TAB>yes|no<TAB>reason

A malformed table, or a family without exactly one row, fails closed (exit 2):
a gate that cannot say what it requires must not silently require nothing.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

TABLE = Path(__file__).resolve().with_name("merge-gate.tsv")
FAMILY_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class GateError(RuntimeError):
    pass


@dataclass(frozen=True)
class Row:
    family: str
    before_merge: bool
    reason: str


def load(path: Path = TABLE) -> dict[str, Row]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"{path.name} is unreadable: {exc}") from exc
    rows: dict[str, Row] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise GateError(f"{path.name}:{number}: expected family<TAB>before_merge<TAB>reason")
        family, before_merge, reason = fields
        if not FAMILY_RE.fullmatch(family):
            raise GateError(f"{path.name}:{number}: family {family!r} is malformed")
        if before_merge not in ("yes", "no"):
            raise GateError(f"{path.name}:{number}: before_merge must be yes or no")
        if not reason.strip():
            raise GateError(f"{path.name}:{number}: {family} has no reason")
        if family in rows:
            raise GateError(f"{path.name}:{number}: {family} has more than one row")
        rows[family] = Row(family, before_merge == "yes", reason.strip())
    if not rows:
        raise GateError(f"{path.name} has no rows")
    return rows


def decide(rows: dict[str, Row], family: str) -> Row:
    try:
        return rows[family]
    except KeyError:
        raise GateError(f"{family} has no row in {TABLE.name}; add one") from None


def main(argv: list[str]) -> int:
    try:
        rows = load()
        if argv == ["check"]:
            return 0
        if argv == ["families"]:
            print("\n".join(rows))
            return 0
        if argv == ["dump"]:
            for row in rows.values():
                print(f"{row.family}\t{'yes' if row.before_merge else 'no'}\t{row.reason}")
            return 0
        if len(argv) == 2 and argv[0] == "decide":
            row = decide(rows, argv[1])
            print("yes" if row.before_merge else f"no\t{row.reason}")
            return 0
    except GateError as exc:
        print(f"merge-gate: {exc}", file=sys.stderr)
        return 2
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
