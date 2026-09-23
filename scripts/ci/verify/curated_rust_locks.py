#!/usr/bin/env python3
"""Keep the curated image Rust workspaces derived from the root workspace.

sync-manifests ROOT_MANIFEST CURATED_MANIFEST...
    Give every curated [workspace.dependencies] entry the root's version
    requirement, keeping the curated features. An entry whose source kind
    differs from the root (a Git revision against a registry version) takes
    the root's whole entry. Path dependencies are workspace members and are
    left alone.

check-drift ROOT_LOCK CURATED_LOCK NAME
    Fail when the curated lock selects any registry or Git package (name,
    version and source) that the root lock does not already select.
"""

import re
import sys
import tomllib

ENTRY = re.compile(r"^(?P<key>[A-Za-z0-9_-]+)\s*=\s*(?P<value>.+?)\s*$")
VERSION = re.compile(r'(\bversion\s*=\s*)"[^"]*"')


def dependency_lines(text):
    """Yield (index, key, value) for single-line [workspace.dependencies] entries."""
    section = None
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped
            continue
        if section != "[workspace.dependencies]" or not stripped or stripped.startswith("#"):
            continue
        match = ENTRY.match(stripped)
        if match is None:
            raise SystemExit(f"unsupported multi-line dependency entry: {stripped}")
        yield index, match["key"], match["value"]


def parse_value(value):
    return tomllib.loads(f"value = {value}")["value"]


def source_kind(spec):
    if isinstance(spec, str):
        return "registry"
    if "path" in spec:
        return "path"
    if "git" in spec:
        return "git"
    return "registry"


def version_of(spec):
    return spec if isinstance(spec, str) else spec.get("version")


def sync_manifests(root_manifest, curated_manifests):
    with open(root_manifest, encoding="utf-8") as handle:
        root_text = handle.read()
    root_values = {key: value for _, key, value in dependency_lines(root_text)}
    for curated in curated_manifests:
        with open(curated, encoding="utf-8") as handle:
            text = handle.read()
        lines = text.splitlines()
        changed = []
        for index, key, value in dependency_lines(text):
            if key not in root_values:
                continue
            root_spec = parse_value(root_values[key])
            spec = parse_value(value)
            root_kind, kind = source_kind(root_spec), source_kind(spec)
            if "path" in (root_kind, kind):
                continue
            if root_kind != kind or root_kind == "git":
                if spec != root_spec:
                    lines[index] = f"{key} = {root_values[key]}"
                    changed.append(key)
                continue
            wanted = version_of(root_spec)
            if wanted is None or version_of(spec) == wanted:
                continue
            if isinstance(spec, str):
                lines[index] = f'{key} = "{wanted}"'
            else:
                lines[index] = VERSION.sub(lambda match: f'{match[1]}"{wanted}"', lines[index], count=1)
            changed.append(key)
        if changed:
            with open(curated, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        print(f"[curated-rust-locks] {curated}: {', '.join(changed) if changed else 'already synced'}")


def locked_packages(path):
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    return {
        (package["name"], package["version"], package["source"])
        for package in data.get("package", [])
        if "source" in package
    }


def check_drift(root_lock, curated_lock, name):
    drift = sorted(locked_packages(curated_lock) - locked_packages(root_lock))
    if not drift:
        print(f"[curated-rust-locks] {name}: matches the root lock")
        return
    for package, version, source in drift:
        print(f"  {package} {version} ({source}) is not in the root Cargo.lock", file=sys.stderr)
    print(
        f"curated Rust workspace {name} drifted from the root lock; "
        "run scripts/dev/sync-curated-rust-locks.sh",
        file=sys.stderr,
    )
    raise SystemExit(1)


def main(arguments):
    if len(arguments) >= 3 and arguments[0] == "sync-manifests":
        sync_manifests(arguments[1], arguments[2:])
    elif len(arguments) == 4 and arguments[0] == "check-drift":
        check_drift(arguments[1], arguments[2], arguments[3])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
