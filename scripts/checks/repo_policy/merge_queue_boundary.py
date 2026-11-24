"""The merge queue's boundary list stays whole (#6173).

The merge queue lands a pull request without a review unless it changes a
path in .forgejo/merge-queue-boundary. So a line that matches nothing, or no
longer covers what it was written for, silently drops a boundary. Each line
must match at least one tracked file, and keeps a real example in
.forgejo/merge-queue-boundary-examples: the example must still be tracked,
and must match a line under its own heading and the line it is the example
for. Narrowing or deleting a line fails here until its example is changed in
the same reviewed pull request. A line that guards a path the tree doesn't
have yet (`.cargo/**`, `CODEOWNERS`) has the example `absent` instead, and
must match no tracked file: the pull request that adds one names it.

The queue matches with Rust's globset (`*` within one component); this check
reads the same subset, `*` and `**` only, and refuses any other glob syntax
so the two can't disagree.
"""

from __future__ import annotations

import re

from .shared import *

LIST = ".forgejo/merge-queue-boundary"
EXAMPLES = ".forgejo/merge-queue-boundary-examples"
ABSENT = "absent"

HEADING = re.compile(r"\[([a-z-]+)\]")


def glob_regex(glob: str) -> re.Pattern[str]:
    """A regex matching what globset matches for `glob`, with `*` kept
    within one path component and `**/` lines matched in any case."""
    if re.search(r"[\[\]{}?\\!]", glob):
        raise ValueError("only * and ** are allowed")
    parts = glob.split("/")
    if any("**" in part and part != "**" for part in parts):
        raise ValueError("** must be a whole path component")
    out = []
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**":
            out.append(".*" if last else "(?:[^/]+/)*")
            continue
        out.append("[^/]*".join(re.escape(piece) for piece in part.split("*")) + ("" if last else "/"))
    pattern = "".join(out)
    # `x/**` matches everything under x, never x itself.
    if glob.endswith("/**"):
        pattern = pattern[: -len(".*")] + ".+"
    return re.compile(f"^{pattern}$", re.IGNORECASE if glob.startswith("**/") else 0)


def parse_list(text: str) -> tuple[list[tuple[str, str, re.Pattern[str]]], list[str]]:
    """The list's (heading, glob, regex) lines, and what is wrong with it."""
    lines, failures, heading = [], [], None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = HEADING.fullmatch(line)
        if match:
            heading = match.group(1)
            continue
        if line.startswith("["):
            failures.append(f"{LIST}:{number}: {line!r} is not a lowercase [heading]")
        elif heading is None:
            failures.append(f"{LIST}:{number}: {line!r} comes before any heading")
        else:
            try:
                lines.append((heading, line, glob_regex(line)))
            except ValueError as error:
                failures.append(f"{LIST}:{number}: {line!r}: {error}")
    if not lines and not failures:
        failures.append(f"{LIST} names no path")
    return lines, failures


def parse_examples(text: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """The (heading, glob, path) examples, one `HEADING GLOB PATH` per line;
    the path `absent` marks a line that guards a path not in the tree."""
    examples, failures = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3:
            failures.append(f"{EXAMPLES}:{number}: expected HEADING GLOB PATH, got {line!r}")
            continue
        examples.append((fields[0], fields[1], fields[2]))
    return examples, failures


def failures_for(list_text: str, examples_text: str, tracked: list[str]) -> list[str]:
    lines, failures = parse_list(list_text)
    examples, example_failures = parse_examples(examples_text)
    failures += example_failures
    tracked_set = set(tracked)
    guards = {(heading, glob) for heading, glob, path in examples if path == ABSENT}
    for heading, glob, regex in lines:
        if (heading, glob) not in guards and not any(regex.match(path) for path in tracked):
            failures.append(f"[{heading}] {glob} matches no tracked file")
    for heading, glob, regex in lines:
        if not any(e_heading == heading and e_glob == glob for e_heading, e_glob, _ in examples):
            failures.append(f"[{heading}] {glob} has no example in {EXAMPLES}")
    by_line = {(heading, glob): regex for heading, glob, regex in lines}
    for heading, glob, path in examples:
        if path == ABSENT:
            regex = by_line.get((heading, glob))
            if regex is None:
                failures.append(f"absent example names [{heading}] {glob}, which the list doesn't have")
            else:
                present = next((p for p in tracked if regex.match(p)), None)
                if present:
                    failures.append(f"[{heading}] {glob} is marked absent but matches {present}: name it")
            continue
        if path not in tracked_set:
            failures.append(f"example {path} for [{heading}] {glob} is not a tracked file")
        regex = by_line.get((heading, glob))
        if regex is None:
            failures.append(f"example {path} names [{heading}] {glob}, which the list doesn't have")
        elif not regex.match(path):
            failures.append(f"[{heading}] {glob} no longer matches its example {path}")
    return failures


def self_test() -> list[str]:
    tracked = [
        "crates/codewire-idp/src/lib.rs",
        "docs/dev/AUTH-POLICY.md",
        "crates/codewire-server-core/migrations/0001_x.sql",
        "crates/codewire-orchestration/src/api/terminal.rs",
        "crates/codewire-orchestration/src/api/terminal/desktop.rs",
        "libs/sdk-ts/src/core/settings.ts",
    ]
    good_list = (
        "# boundaries\n[auth]\ncrates/codewire-idp/**\n**/*auth*\n"
        "crates/codewire-orchestration/src/api/terminal*\nlibs/sdk-*/**/settings*\n"
        "[migrations]\ncrates/*/migrations/**\n"
    )
    good_examples = (
        "auth crates/codewire-idp/** crates/codewire-idp/src/lib.rs\n"
        "auth **/*auth* docs/dev/AUTH-POLICY.md\n"
        "auth crates/codewire-orchestration/src/api/terminal* crates/codewire-orchestration/src/api/terminal.rs\n"
        "auth libs/sdk-*/**/settings* libs/sdk-ts/src/core/settings.ts\n"
        "migrations crates/*/migrations/** crates/codewire-server-core/migrations/0001_x.sql\n"
    )
    cases = {
        "the whole list passes": (good_list, good_examples, 0),
        "a narrowed line loses its example": (
            good_list.replace("crates/codewire-idp/**", "crates/codewire-idp/src/main.rs"),
            good_examples.replace("crates/codewire-idp/** ", "crates/codewire-idp/src/main.rs "),
            2,
        ),
        "a deleted line leaves its example naming it": (
            good_list.replace("crates/*/migrations/**\n", ""), good_examples, 1,
        ),
        "a line with no example": (good_list + "crates/codewire-idp/src/**\n", good_examples, 1),
        "an example that is not tracked": (
            good_list, good_examples.replace("settings.ts\n", "settings.py\n"), 1,
        ),
        "a line that matches nothing": (
            good_list + "[ci-trust]\n.nothing/**\n", good_examples + "ci-trust .nothing/** .nothing/x\n", 2,
        ),
        "* stays in one component": (
            good_list,
            good_examples.replace(
                "api/terminal* crates/codewire-orchestration/src/api/terminal.rs",
                "api/terminal* crates/codewire-orchestration/src/api/terminal/desktop.rs",
            ),
            1,
        ),
        "a directory line keeps its case": (
            good_list.replace("crates/codewire-idp/**", "Crates/codewire-idp/**"),
            good_examples.replace("auth crates/codewire-idp/**", "auth Crates/codewire-idp/**"),
            2,
        ),
        "a guard for an absent path passes": (
            good_list + "[ci-trust]\n.cargo/**\n", good_examples + "ci-trust .cargo/** absent\n", 0,
        ),
        "a guard whose path arrived must name it": (
            good_list + "[ci-trust]\n**/*settings*\n", good_examples + "ci-trust **/*settings* absent\n", 1,
        ),
        "other glob syntax is refused": (good_list + "crates/{a,b}/**\n", good_examples, 1),
        "a glob before any heading is refused": ("crates/x/**\n" + good_list, good_examples, 1),
        "an empty list is refused": ("# nothing\n", "", 1),
    }
    failures = []
    for name, (list_text, examples_text, expected) in cases.items():
        got = failures_for(list_text, examples_text, tracked)
        if len(got) != expected:
            failures.append(f"self-test {name!r}: {len(got)} failures, expected {expected}: {got}")
    return failures


def check_merge_queue_boundary(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("merge queue boundary", self_test()):
            return 1
        print("merge queue boundary: OK (self-test)")
        return 0
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True, timeout=60,
    ).stdout.decode().split("\0")
    tracked = [path for path in tracked if path]
    list_text = (ROOT / LIST).read_text(encoding="utf-8")
    examples_text = (ROOT / EXAMPLES).read_text(encoding="utf-8")
    if report("merge queue boundary", failures_for(list_text, examples_text, tracked), error_annotation=True):
        return 1
    lines = len(parse_list(list_text)[0])
    guards = sum(1 for *_, path in parse_examples(examples_text)[0] if path == ABSENT)
    print(f"merge queue boundary: OK ({lines} lines, {guards} guarding paths not in the tree yet)")
    return 0
