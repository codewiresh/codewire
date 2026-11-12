"""Every dependency in a Cargo lockfile names exactly one locked package.

Cargo writes a dependency as a bare name while only one version of that
package is locked, and adds the version (and source) once there are more.
Two branches can each produce a valid lockfile that a textual merge joins
into an invalid one: #4308 kept `"base64"` while main had since locked base64
0.22.1 and 0.23.1, so `cargo --locked` refused main's lockfile after the merge
(b34cf2bb). A pull request's CI checks its own head, so the merge itself has
to be checked: scripts/dev/merge-pr.sh runs this on the would-be merge with
--lock -, and Policy runs it on every tracked lockfile. It needs neither cargo
nor the network.
"""

from __future__ import annotations

from .shared import *

LOCKFILE = re.compile(r"(?:^|/)(?:[A-Za-z0-9_-]+\.)?Cargo\.lock$")


def lock_failures(path: str, text: str) -> list[str]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{path} is not a valid Cargo lockfile: {error}"]
    packages = lock.get("package", [])
    keys = [(p.get("name"), p.get("version"), p.get("source")) for p in packages]
    failures = [
        f"{path} locks {name} {version} more than once"
        for (name, version, _source), count in sorted(Counter(keys).items(), key=str)
        if count > 1
    ]
    for package in packages:
        for dependency in package.get("dependencies", []):
            name, _, rest = dependency.partition(" ")
            version, _, source = rest.partition(" ")
            matches = [
                key for key in keys
                if key[0] == name
                and (not version or key[1] == version)
                and (not source or f"({key[2]})" == source)
            ]
            if len(matches) == 1:
                continue
            owner = f"{package.get('name')} {package.get('version')}"
            if matches:
                versions = ", ".join(sorted({str(key[1]) for key in matches}))
                failures.append(f"{path}: {owner} depends on {dependency!r}, which matches "
                                f"{len(matches)} locked packages ({versions}); it must name one")
            else:
                failures.append(f"{path}: {owner} depends on {dependency!r}, which is not locked")
    return failures


def lock(*packages: tuple) -> str:
    """A version 4 lockfile from (name, version, dependencies[, source]) tuples."""
    entries = []
    for name, version, dependencies, *source in packages:
        entry = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if source:
            entry += f'source = "{source[0]}"\n'
        if dependencies:
            entry += "dependencies = [\n" + "".join(f' "{d}",\n' for d in dependencies) + "]\n"
        entries.append(entry)
    return "version = 4\n\n" + "\n".join(entries)


def self_test() -> list[str]:
    failures: list[str] = []
    admitted = {
        "one version, bare name": lock(("app", "0.1.0", ["base64"]), ("base64", "0.22.1", [])),
        "two versions, each named": lock(
            ("app", "0.1.0", ["base64 0.22.1", "base64 0.23.1"]),
            ("base64", "0.22.1", []), ("base64", "0.23.1", [])),
        "two sources, each named": lock(
            ("app", "0.1.0", ["dep 1.0.0 (registry+one)", "dep 1.0.0 (registry+two)"]),
            ("dep", "1.0.0", [], "registry+one"), ("dep", "1.0.0", [], "registry+two")),
    }
    for label, text in admitted.items():
        if got := lock_failures("fixture/Cargo.lock", text):
            failures.append(f"cargo lock integrity self-test: {label} was refused: {got!r}")
    refused = {
        # b34cf2bb: a bare name once a second version is locked.
        "ambiguous bare name": (lock(("app", "0.1.0", ["base64"]), ("base64", "0.22.1", []),
                                     ("base64", "0.23.1", [])), "matches 2 locked packages"),
        "dangling name": (lock(("app", "0.1.0", ["base64"])), "is not locked"),
        "dangling version": (lock(("app", "0.1.0", ["base64 0.21.7"]), ("base64", "0.22.1", [])),
                             "is not locked"),
        "two sources, one bare": (lock(("app", "0.1.0", ["dep 1.0.0"]),
                                       ("dep", "1.0.0", [], "registry+one"),
                                       ("dep", "1.0.0", [], "registry+two")),
                                  "matches 2 locked packages"),
        "duplicate package": (lock(("app", "0.1.0", []), ("base64", "0.22.1", []),
                                   ("base64", "0.22.1", [])), "more than once"),
        "malformed lockfile": ("[[package]\n", "is not a valid Cargo lockfile"),
    }
    for label, (text, reason) in refused.items():
        got = lock_failures("fixture/Cargo.lock", text)
        if not any(reason in failure for failure in got):
            failures.append(f"cargo lock integrity self-test: {label} gave {got!r}, not {reason!r}")
    return failures


def check_cargo_lock_integrity(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("cargo lock integrity", self_test()):
            return 1
        print("cargo lock integrity: OK (self-test)")
        return 0
    if args.lock:
        text = sys.stdin.read() if args.lock == "-" else Path(args.lock).read_text(encoding="utf-8")
        label = args.label or ("standard input" if args.lock == "-" else args.lock)
        if report("cargo lock integrity", lock_failures(label, text), error_annotation=True):
            return 1
        print(f"cargo lock integrity: OK ({label})")
        return 0
    paths = sorted(path for path in git_source_files() if LOCKFILE.search(path))
    failures = [failure for path in paths for failure in lock_failures(path, read_text(path))]
    if report("cargo lock integrity", failures, error_annotation=True):
        return 1
    print(f"cargo lock integrity: OK ({len(paths)} lockfiles)")
    return 0
