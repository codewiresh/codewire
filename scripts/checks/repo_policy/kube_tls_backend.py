"""kube is built with rustls-tls only, never its openssl-tls connector.

RUSTSEC-2026-0600 (GHSA-hm5x-4x3m-4w8m) affects kube-client, and kube which
re-exports it, from 0.64.0 until 4.2.1 and 5.2.0: with a cluster CA
configured, the openssl-tls connector started from OpenSSL's default verify
paths and added the CA, so any root in the default store passed. rustls-tls
trusts only the configured CA. No 3.x release is patched, so
.supplychain/source-policy.json excepts the advisory for kube-client until the
move to kube 4.2.1 or later. This check is what narrows that exception to the
rustls build:

- no tracked Cargo.toml enables openssl-tls on kube or kube-client, in a
  dependency's features or in a [features] entry;
- no kube-client in a tracked Cargo lockfile depends on openssl, openssl-sys
  or hyper-openssl (the root lock, the desktop lock and the curated image
  locks, which supplychain does not read);
- no Rust source under crates/ calls the openssl connector methods, which
  reach the flaw even with rustls-tls on;
- the exception, while it exists, has not passed its expiry date.
"""

from __future__ import annotations

import datetime

from .shared import *

ADVISORY = "RUSTSEC-2026-0600"
POLICY = ".supplychain/source-policy.json"
PACKAGES = ("kube", "kube-client")
FEATURE = "openssl-tls"
OPENSSL_CRATES = ("openssl", "openssl-sys", "hyper-openssl")
OPENSSL_METHODS = re.compile(
    r"\b(openssl_https_connector_with_connector|openssl_https_connector|openssl_ssl_connector_builder)\b"
)
REQUIRED_LOCKS = ("Cargo.lock", "crates/codewire-desktop/Cargo.lock")
LOCKFILE = re.compile(r"(?:^|/)(?:[A-Za-z0-9_-]+\.)?Cargo\.lock$")
MANIFEST = re.compile(r"(?:^|/)Cargo\.toml$")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def dependency_tables(manifest: dict) -> list[tuple[str, dict]]:
    """Every dependency table of a manifest, with its name, targets and workspace included."""
    tables = [(name, manifest.get(name, {})) for name in DEPENDENCY_TABLES]
    tables.append(("workspace.dependencies", manifest.get("workspace", {}).get("dependencies", {})))
    for target, body in manifest.get("target", {}).items():
        tables.extend((f"target.{target}.{name}", body.get(name, {})) for name in DEPENDENCY_TABLES)
    return [(name, table) for name, table in tables if isinstance(table, dict)]


def manifest_failures(path: str, text: str) -> list[str]:
    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{path} is not a valid Cargo manifest: {error}"]
    failures = []
    # A dependency named kube, or renamed from it (package = "kube").
    kube_keys = set()
    for table_name, table in dependency_tables(manifest):
        for key, spec in table.items():
            package = spec.get("package", key) if isinstance(spec, dict) else key
            if package not in PACKAGES:
                continue
            kube_keys.add(key)
            features = spec.get("features", []) if isinstance(spec, dict) else []
            if FEATURE in features:
                failures.append(f"{path} [{table_name}] enables {FEATURE} on {package} ({ADVISORY})")
    for feature, enables in manifest.get("features", {}).items():
        for entry in enables if isinstance(enables, list) else []:
            dependency, _, enabled = str(entry).partition("/")
            if enabled == FEATURE and dependency.rstrip("?") in kube_keys | set(PACKAGES):
                failures.append(f"{path} feature {feature} enables {entry} ({ADVISORY})")
    return failures


def lock_failures(path: str, text: str) -> list[str]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{path} is not a valid Cargo lockfile: {error}"]
    failures = []
    for package in lock.get("package", []):
        if package.get("name") != "kube-client":
            continue
        # A dependency entry is "name" or "name version".
        openssl = sorted({d.split(" ")[0] for d in package.get("dependencies", [])} & set(OPENSSL_CRATES))
        if openssl:
            failures.append(
                f"{path} locks kube-client {package.get('version')!s} with {', '.join(openssl)}: "
                f"its openssl-tls connector is built ({ADVISORY})"
            )
    return failures


def source_failures(path: str, text: str) -> list[str]:
    return [
        f"{path}:{number} calls kube's {match.group(1)}, which reaches {ADVISORY} even with rustls-tls on"
        for number, line in enumerate(text.splitlines(), 1)
        for match in [OPENSSL_METHODS.search(line)]
        if match
    ]


def expiry_failures(policy: dict, today: datetime.date) -> list[str]:
    for exception in policy.get("exceptions", []):
        if exception.get("advisory_id") != ADVISORY:
            continue
        try:
            expires = datetime.date.fromisoformat(str(exception.get("expires", "")))
        except ValueError:
            return [f"{POLICY}: the {ADVISORY} exception has no valid expires date"]
        if today > expires:
            return [f"{POLICY}: the {ADVISORY} exception expired on {expires}; move kube to 4.2.1 or later"]
    return []


def self_test() -> list[str]:
    failures: list[str] = []

    def expect(label: str, got: list[str], count: int) -> None:
        if len(got) != count:
            failures.append(f"kube TLS backend self-test: {label} gave {got!r}")

    rustls = '[workspace.dependencies]\nkube = { version = "3", default-features = false, features = ["client", "rustls-tls", "ws"] }\n'
    expect("the rustls workspace entry", manifest_failures("Cargo.toml", rustls), 0)
    expect("openssl-tls on the workspace entry",
           manifest_failures("Cargo.toml", rustls.replace('"ws"]', '"ws", "openssl-tls"]')), 1)
    expect("openssl-tls on kube-client",
           manifest_failures("a/Cargo.toml", '[dependencies]\nkube-client = { version = "3", features = ["openssl-tls"] }\n'), 1)
    expect("a renamed kube with openssl-tls",
           manifest_failures("a/Cargo.toml", '[dependencies]\nk8s = { package = "kube", version = "3", features = ["openssl-tls"] }\n'), 1)
    expect("openssl-tls on a target's kube",
           manifest_failures("a/Cargo.toml", '[target.\'cfg(unix)\'.dependencies]\nkube = { version = "3", features = ["openssl-tls"] }\n'), 1)
    expect("a feature that enables kube/openssl-tls",
           manifest_failures("a/Cargo.toml", '[dependencies]\nkube = { workspace = true, optional = true }\n[features]\nk = ["kube?/openssl-tls"]\n'), 1)
    expect("a feature that enables another crate's openssl-tls",
           manifest_failures("a/Cargo.toml", '[dependencies]\nreqwest = "0.12"\n[features]\nk = ["reqwest/native-tls"]\n'), 0)
    expect("a malformed manifest", manifest_failures("a/Cargo.toml", "[dependencies\n"), 1)
    client = '[[package]]\nname = "kube-client"\nversion = "3.1.0"\ndependencies = [\n "hyper-rustls",\n "rustls",\n]\n'
    expect("a rustls kube-client", lock_failures("Cargo.lock", client), 0)
    expect("a kube-client with hyper-openssl",
           lock_failures("Cargo.lock", client.replace('"rustls",', '"rustls",\n "hyper-openssl",')), 1)
    expect("a kube-client with a versioned openssl",
           lock_failures("Cargo.lock", client.replace('"rustls",', '"rustls",\n "openssl 0.10.75",')), 1)
    expect("openssl beside kube-client but not under it",
           lock_failures("Cargo.lock", client + '\n[[package]]\nname = "openssl"\nversion = "0.10.75"\n'), 0)
    expect("a malformed lockfile", lock_failures("Cargo.lock", "[[package]\n"), 1)
    expect("a call to the openssl connector",
           source_failures("crates/a/src/k.rs", "let c = config.openssl_https_connector()?;\n"), 1)
    expect("a call to the openssl builder",
           source_failures("crates/a/src/k.rs", "config.openssl_ssl_connector_builder()\n"), 1)
    expect("rustls connector calls", source_failures("crates/a/src/k.rs", "config.rustls_https_connector()?;\n"), 0)
    policy = {"exceptions": [{"advisory_id": ADVISORY, "expires": "2026-12-15"}]}
    expect("the exception on its last day", expiry_failures(policy, datetime.date(2026, 12, 15)), 0)
    expect("the exception after its expiry", expiry_failures(policy, datetime.date(2026, 12, 16)), 1)
    expect("no exception", expiry_failures({"exceptions": []}, datetime.date(2027, 6, 1)), 0)
    for path in ("Cargo.lock", "crates/codewire-desktop/Cargo.lock", "deployments/docker/derp.Cargo.lock"):
        if not LOCKFILE.search(path):
            failures.append(f"kube TLS backend self-test: {path} is not read as a lockfile")
    return failures


def check_kube_tls_backend(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("kube TLS backend", self_test()):
            return 1
        print("kube TLS backend: OK (self-test)")
        return 0
    files = git_source_files()
    locks = sorted(path for path in files if LOCKFILE.search(path))
    manifests = sorted(path for path in files if MANIFEST.search(path))
    sources = sorted(path for path in files if path.startswith("crates/") and path.endswith(".rs"))
    failures = [f"{path} is missing" for path in REQUIRED_LOCKS if path not in locks]
    for path in manifests:
        failures.extend(manifest_failures(path, read_text(path)))
    for path in locks:
        failures.extend(lock_failures(path, read_text(path)))
    for path in sources:
        failures.extend(source_failures(path, read_text(path)))
    failures.extend(expiry_failures(read_json(POLICY), datetime.datetime.now(datetime.timezone.utc).date()))
    if report("kube TLS backend", failures):
        return 1
    print(f"kube TLS backend: OK ({len(manifests)} manifests, {len(locks)} lockfiles, {len(sources)} sources)")
    return 0
