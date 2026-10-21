"""Every Rust lockfile keeps webpki-roots at the emSign fix.

RUSTSEC-2026-0381 affects every webpki-roots below 1.0.10, which drops the
distrusted emSign ECC Root CA - G3. .supplychain/source-policy.json excepts
that advisory for the webpki-roots package, because a supplychain exception
cannot name a version. The one release it has to admit is 0.26.11, the
semver-trick shim that bundles no roots and re-exports webpki-roots 1; sqlx
0.8, tokio-tungstenite and async-nats still require the 0.26 line. This check
is what narrows the exception to that shim: every webpki-roots in a tracked
Cargo lockfile must be exactly 0.26.11 or at least 1.0.10. It also covers the
curated image locks (deployments/docker/*.Cargo.lock), which supplychain does
not read.
"""

from __future__ import annotations

from .shared import *

PACKAGE = "webpki-roots"
SHIM = "0.26.11"
FLOOR = (1, 0, 10)
REQUIRED_LOCKS = ("Cargo.lock", "crates/codewire-desktop/Cargo.lock")
LOCKFILE = re.compile(r"(?:^|/)(?:[A-Za-z0-9_-]+\.)?Cargo\.lock$")
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def allowed(version: str) -> bool:
    """Exactly the 0.26.11 shim, or a release at or above 1.0.10."""
    if version == SHIM:
        return True
    match = SEMVER.match(version)
    if not match:
        return False
    core = tuple(int(part) for part in match.group(1, 2, 3))
    # A pre-release sorts below its release, so 1.0.10-rc.1 is still affected.
    return core > FLOOR or (core == FLOOR and match.group(4) is None)


def lock_failures(path: str, text: str) -> list[str]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{path} is not a valid Cargo lockfile: {error}"]
    return [
        f"{path} locks {PACKAGE} {package.get('version')!s}; only the {SHIM} shim or "
        f"{'.'.join(map(str, FLOOR))} and later may be locked (RUSTSEC-2026-0381, "
        "excepted in .supplychain/source-policy.json only for the shim)"
        for package in lock.get("package", [])
        if package.get("name") == PACKAGE and not allowed(str(package.get("version", "")))
    ]


def lock(*versions: str) -> str:
    entries = [
        f'[[package]]\nname = "{PACKAGE}"\nversion = "{version}"\n' for version in versions
    ]
    return 'version = 4\n\n[[package]]\nname = "rustls"\nversion = "0.23.46"\n\n' + "\n".join(entries)


def self_test() -> list[str]:
    failures: list[str] = []
    for version in (SHIM, "1.0.10", "1.0.11", "1.1.0", "2.0.0", "1.0.10+build.1"):
        if not allowed(version):
            failures.append(f"webpki-roots floor self-test: {version} was refused")
    for version in ("1.0.9", "1.0.7", "1.0.0", "0.26.10", "0.26.12", "0.25.4",
                    "1.0.10-rc.1", "1.0", "", "latest"):
        if allowed(version):
            failures.append(f"webpki-roots floor self-test: {version!r} was admitted")
    if lock_failures("fixture/Cargo.lock", lock(SHIM, "1.0.10")):
        failures.append("webpki-roots floor self-test: the shim with 1.0.10 was refused")
    refused = lock_failures("fixture/Cargo.lock", lock(SHIM, "1.0.7"))
    if len(refused) != 1 or "1.0.7" not in refused[0]:
        failures.append(f"webpki-roots floor self-test: 1.0.7 beside the shim gave {refused!r}")
    if not lock_failures("fixture/Cargo.lock", "[[package]\n"):
        failures.append("webpki-roots floor self-test: a malformed lockfile was admitted")
    for path in ("Cargo.lock", "crates/codewire-desktop/Cargo.lock", "deployments/docker/derp.Cargo.lock"):
        if not LOCKFILE.search(path):
            failures.append(f"webpki-roots floor self-test: {path} is not read as a lockfile")
    for path in ("Cargo.lock.orig", "docs/Cargo.lockfile", "Cargo.toml"):
        if LOCKFILE.search(path):
            failures.append(f"webpki-roots floor self-test: {path} is read as a lockfile")
    return failures


def check_webpki_roots_floor(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("webpki-roots floor", self_test()):
            return 1
        print("webpki-roots floor: OK (self-test)")
        return 0
    paths = sorted(path for path in git_source_files() if LOCKFILE.search(path))
    failures = [f"{path} is missing" for path in REQUIRED_LOCKS if path not in paths]
    for path in paths:
        failures.extend(lock_failures(path, read_text(path)))
    if report("webpki-roots floor", failures):
        return 1
    print(f"webpki-roots floor: OK ({len(paths)} lockfiles)")
    return 0
