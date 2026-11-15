"""Every repository path a journey file names exists.

docs/journeys/README.md requires that a command, script or spec named in a
journey exists in this repository, so that the next walker can run it. Nothing
held a journey to that: a script could be renamed or removed and the journey
would go on naming it (#4356). This reads every file in docs/journeys/ and
fails on a named path that is not in the tree, and on a relative link whose
target is missing.

A path is a word, in inline code or in a code block, made of path segments
whose first segment is a top-level directory of the repository. A word with a
placeholder or a glob in it (`<name>`, `*`, `$VAR`) is not checked.
"""

from __future__ import annotations

from .shared import *

JOURNEYS = "docs/journeys"
# The credential store's namespace, not the repository's apps/ directory.
NOT_REPOSITORY_PATHS = ("apps/codewire/",)

PATH_WORD = re.compile(r"[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)+/?")
CODE_BLOCK = re.compile(r"^[ \t]*```.*?^[ \t]*```[ \t]*$", re.S | re.M)
INLINE_CODE = re.compile(r"`([^`]+)`")
LINK = re.compile(r"\]\(([^)\s]+)\)")


def named_paths(text: str, top_level: set[str]) -> list[str]:
    """The repository paths `text` names in its code blocks and inline code."""
    blocks = CODE_BLOCK.findall(text)
    prose = CODE_BLOCK.sub("\n", text)
    paths = set()
    for chunk in blocks + INLINE_CODE.findall(prose):
        for word in chunk.split():
            word = word.strip("\"'(),;:")
            if not PATH_WORD.fullmatch(word) or word.startswith(NOT_REPOSITORY_PATHS):
                continue
            if word.split("/", 1)[0] in top_level:
                paths.add(word)
    return sorted(paths)


def relative_links(text: str) -> list[str]:
    """The targets of `text`'s links to other files, without their anchors."""
    targets = set()
    for target in LINK.findall(CODE_BLOCK.sub("\n", text)):
        if "://" in target or target.startswith(("#", "mailto:")):
            continue
        targets.add(target.split("#", 1)[0])
    return sorted(targets)


def self_test() -> list[str]:
    failures: list[str] = []
    top_level = {"scripts", "apps", "docs"}
    text = (
        "Run `scripts/a.sh --flag docs/b.md` and the wrapped `scripts/c.sh\n"
        "  -- COMMAND`. See [the index](README.md#rules), [docs](https://example.test/x)\n"
        "and [here](#top). Not paths: `cw create`, `/workspace/big.bin`,\n"
        "`env:/workspace/f`, `scripts/<name>.sh`, `scripts/*/seed.sql`,\n"
        "`apps/codewire/dev/ci-smoke`, `other/tree/file`, `scripts`.\n"
        "\n"
        "  ```sh\n"
        "  scripts/d.sh | tee out.log\n"
        "  cw cp big.bin env:/workspace/big.bin\n"
        "  ```\n"
        "A path in prose, scripts/e.sh, is not checked.\n"
    )
    wanted = ["docs/b.md", "scripts/a.sh", "scripts/c.sh", "scripts/d.sh"]
    if named_paths(text, top_level) != wanted:
        failures.append(f"journey paths self-test: expected {wanted}, got {named_paths(text, top_level)}")
    if relative_links(text) != ["README.md"]:
        failures.append(f"journey paths self-test: expected one relative link, got {relative_links(text)}")
    return failures


def check_journey_paths(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("journey paths", self_test()):
            return 1
        print("journey paths: OK (self-test)")
        return 0
    top_level = {path.name for path in ROOT.iterdir() if path.is_dir() and path.name != ".git"}
    journeys = sorted((ROOT / JOURNEYS).glob("*.md"))
    failures: list[str] = []
    checked = 0
    for journey in journeys:
        name = journey.relative_to(ROOT).as_posix()
        text = journey.read_text(encoding="utf-8")
        for path in named_paths(text, top_level):
            checked += 1
            if not (ROOT / path).exists():
                failures.append(
                    f"{name} names {path}, which is not in the repository: "
                    "fix the path, or write \"no command yet\" and the issue that adds it"
                )
        for target in relative_links(text):
            checked += 1
            if not (journey.parent / target).exists():
                failures.append(f"{name} links to {target}, which does not exist")
    if not journeys:
        failures.append(f"{JOURNEYS} holds no journey files")
    if report("journey paths", failures):
        return 1
    print(f"journey paths: OK ({len(journeys)} files, {checked} paths and links)")
    return 0
