#!/usr/bin/env python3
"""Choose the Kind dashboard browser specs a change affects (#2974).

Each Kind dashboard spec in apps/dashboard/e2e opens with `// covers:` lines
naming the crates/codewire-dashboard-web files (paths relative to the crate)
its tests exercise. `make kind-test` (scripts/dev/kind/test-selected.sh) runs
only the specs covering a changed dashboard file. The files most pages pass
through (SHARED) are covered by no spec on purpose, and any change a header
does not map runs the whole suite. A change only to the browser tests'
TypeScript runs what Playwright finds changed (`--only-changed`). The whole
suite still runs at merge and on main.

  dashboard-specs.py select --base REF   # all REASON | specs SPEC... | only-changed SHA
  dashboard-specs.py check               # every Kind spec is mapped to files that exist
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
E2E = "apps/dashboard/e2e"
CRATE = "crates/codewire-dashboard-web"
# Every signed-in page passes through these: a change runs the whole suite.
SHARED = (
    "src/account_sessions.rs",
    "src/environment_connect.rs",
    "src/environment_drafts.rs",
    "src/routes/dashboard.rs",
    "src/routes/organization_governance.rs",
    "src/routes/terminal.rs",
    "templates/sidebar.html",
)
# Browser-test TypeScript Playwright follows from the specs that import it.
TEST_SOURCES = re.compile(r"^(?:auth\.setup\.ts|helpers/(?!.*\.test\.ts$)[\w.-]+\.ts)$")
COVERS = re.compile(r"^// covers: (.+)$")


class SelectionError(Exception):
    pass


def design_fixture_specs(root: Path) -> set[str]:
    text = (root / E2E / "helpers/design-fixtures.ts").read_text(encoding="utf-8")
    block = text[text.index("export const designFixtureSpecs = ["):]
    block = block[:block.index("]")]
    return set(re.findall(r'"([^"]+\.ssr\.ts)"', block))


def spec_covers(root: Path) -> dict[str, set[str]]:
    """Each Kind dashboard spec and the crate files its header names."""
    fixtures = design_fixture_specs(root)
    covers: dict[str, set[str]] = {}
    for path in sorted((root / E2E).glob("ssr-dashboard.*.ssr.ts")):
        if path.name in fixtures:
            continue
        files: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            match = COVERS.match(line)
            if not match:
                break
            files.update(match.group(1).split())
        covers[path.name] = files
    return covers


def select(changed: list[str], covers: dict[str, set[str]], fixtures: set[str]) -> tuple[str, list[str]]:
    """("all", [reason]), ("specs", names) or ("only-changed", [])."""
    specs: set[str] = set()
    product = typescript = False
    for path in changed:
        if path.endswith(".md"):
            continue
        if path.startswith((f"{CRATE}/src/", f"{CRATE}/templates/")):
            relative = path[len(CRATE) + 1:]
            covering = {name for name, files in covers.items() if relative in files}
            if not covering:
                return "all", [f"{path} is shared or not mapped to a Kind dashboard spec"]
            specs |= covering
            product = True
        elif path.startswith(f"{E2E}/"):
            name = path[len(E2E) + 1:]
            if name in covers or TEST_SOURCES.match(name):
                typescript = True
            elif name in fixtures or name.endswith(".test.ts"):
                continue  # Design fixtures and helper unit tests never run in Kind.
            else:
                return "all", [f"{path} is not mapped to a Kind dashboard spec"]
        else:
            return "all", [f"{path} is not mapped to a Kind dashboard spec"]
    if typescript and product:
        return "all", ["browser tests and dashboard sources both changed"]
    if typescript:
        return "only-changed", []
    if not specs:
        return "all", ["no dashboard source changed"]
    return "specs", sorted(specs)


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, text=True,
                          capture_output=True).stdout


def changed_paths(root: Path, base: str) -> tuple[str, list[str]]:
    merge_base = git(root, "merge-base", base, "HEAD").strip()
    changed = set(git(root, "diff", "--name-only", merge_base).split("\n"))
    changed |= set(git(root, "ls-files", "--others", "--exclude-standard").split("\n"))
    return merge_base, sorted(path for path in changed if path)


def check(root: Path) -> list[str]:
    problems = []
    covers = spec_covers(root)
    if not covers:
        problems.append("no Kind dashboard specs found")
    for name, files in covers.items():
        if not files:
            problems.append(f"{name} has no `// covers:` lines")
        for relative in sorted(files):
            if not (root / CRATE / relative).is_file():
                problems.append(f"{name} covers {relative}, which does not exist")
            if relative in SHARED:
                problems.append(f"{name} covers the shared {relative}; a change to it runs every spec")
    for relative in SHARED:
        if not (root / CRATE / relative).is_file():
            problems.append(f"shared {relative} does not exist")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    choose = commands.add_parser("select")
    choose.add_argument("--base", required=True)
    commands.add_parser("check")
    arguments = parser.parse_args()
    if arguments.command == "check":
        problems = check(ROOT)
        for problem in problems:
            print(f"dashboard-specs: {problem}", file=sys.stderr)
        return 1 if problems else 0
    merge_base, changed = changed_paths(ROOT, arguments.base)
    kind, values = select(changed, spec_covers(ROOT), design_fixture_specs(ROOT))
    if kind == "only-changed":
        values = [merge_base]
    print(" ".join([kind, *values]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
