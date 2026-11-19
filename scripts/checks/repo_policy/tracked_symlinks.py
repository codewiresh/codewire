"""No tracked symlink a checkout has to follow.

A tracked link to a directory broke two consumers at once (#5260): Flux's
source-controller (go-git) could not check out any commit older than the one
that added crates/codewire-proto/proto, because it removed the link by
following it into the repository's proto/; and the cw runtime source capsule,
which carries regular files only, had no proto root to build from. So a
tracked symlink may point only at a file inside the tree, and none may sit
under crates/, where every Rust build and package reads.
"""

from __future__ import annotations

import posixpath
import subprocess

from .shared import *


def link_failures(links: dict[str, str], directories: set[str]) -> list[str]:
    """Each refused link in `links` (path -> target), given the tree's directories."""
    failures = []
    for path, target in sorted(links.items()):
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
        if path == "crates" or path.startswith("crates/"):
            failures.append(f"{path} -> {target}: no symlink under crates/; build from the real path instead")
        elif posixpath.isabs(target) or resolved == ".." or resolved.startswith("../"):
            failures.append(f"{path} -> {target}: a symlink must stay inside the tree")
        elif resolved in directories or resolved == ".":
            failures.append(f"{path} -> {target}: a symlink to a directory breaks older checkouts")
    return failures


def tracked() -> tuple[dict[str, str], set[str]]:
    listing = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-s", "-z"], capture_output=True, check=True, timeout=60,
    ).stdout.decode()
    links: dict[str, str] = {}
    directories: set[str] = set()
    for entry in filter(None, listing.split("\0")):
        meta, path = entry.split("\t", 1)
        mode, oid, _stage = meta.split(" ")
        parent = posixpath.dirname(path)
        while parent:
            directories.add(parent)
            parent = posixpath.dirname(parent)
        if mode == "120000":
            links[path] = subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "blob", oid], capture_output=True, check=True, timeout=60,
            ).stdout.decode()
    return links, directories


def self_test() -> list[str]:
    directories = {"proto", "proto/codewire", "crates", "crates/codewire-proto", "docs"}
    cases = {
        "a link to a file passes": ({"CLAUDE.md": "AGENTS.md"}, 0),
        "a skill link to a file passes": ({".claude/skills/x/SKILL.md": "../../../docs/x.md"}, 0),
        "the #5260 link is refused": ({"crates/codewire-proto/proto": "../../proto"}, 1),
        "any link under crates/ is refused": ({"crates/codewire-proto/README.md": "../../README.md"}, 1),
        "a link to a directory is refused": ({"tools/proto": "../proto"}, 1),
        "a link to the root is refused": ({"docs/root": ".."}, 1),
        "a link out of the tree is refused": ({"docs/out": "../../etc"}, 1),
        "an absolute link is refused": ({"docs/abs": "/etc/passwd"}, 1),
    }
    failures = []
    for name, (links, refused) in cases.items():
        got = len(link_failures(links, directories))
        if got != refused:
            failures.append(f"self-test {name!r}: {got} refusals, expected {refused}")
    return failures


def check_tracked_symlinks(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("tracked symlinks", self_test()):
            return 1
        print("tracked symlinks: OK (self-test)")
        return 0
    links, directories = tracked()
    if report("tracked symlinks", link_failures(links, directories), error_annotation=True):
        return 1
    print(f"tracked symlinks: OK ({len(links)} links, each to a file inside the tree)")
    return 0
