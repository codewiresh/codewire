#!/usr/bin/env python3
"""The Rust packages queue-pr.sh compile-checks for a pull request.

Reads `cargo metadata --no-deps --format-version 1` on stdin and the paths the
pull request changes (relative to the workspace root) as arguments. Prints one
package name per line: every workspace package that owns a changed file, and
with --with-dependents also every workspace package that depends on one of
those by path. Prints nothing for a pull request that touches no package;
queue-pr.sh then checks nothing. queue-pr.sh checks touched packages only for
now: dependents cost a broad PR about ten minutes of build slot
(cw-orchestrator, 2026-11-20).
"""

import json
import os
import sys


def packages(metadata, changed, with_dependents=False):
    root = metadata["workspace_root"]
    members = set(metadata["workspace_members"])
    dirs = {}
    for package in metadata["packages"]:
        if package["id"] in members:
            dirs[package["name"]] = os.path.relpath(os.path.dirname(package["manifest_path"]), root)
    touched = set()
    for path in changed:
        owners = [name for name, d in dirs.items() if d != "." and (path == d or path.startswith(d + "/"))]
        if owners:
            touched.add(max(owners, key=lambda name: len(dirs[name])))
    if not with_dependents:
        return sorted(touched)
    by_dir = {d: name for name, d in dirs.items()}
    dependents = set()
    for package in metadata["packages"]:
        if package["id"] not in members or package["name"] in touched:
            continue
        for dep in package.get("dependencies", []):
            dep_dir = dep.get("path") and os.path.relpath(dep["path"], root)
            if dep_dir and by_dir.get(dep_dir) in touched:
                dependents.add(package["name"])
    return sorted(touched) + sorted(dependents)


if __name__ == "__main__":
    args = sys.argv[1:]
    with_dependents = "--with-dependents" in args
    paths = [a for a in args if a != "--with-dependents"]
    print("\n".join(packages(json.load(sys.stdin), paths, with_dependents)))
