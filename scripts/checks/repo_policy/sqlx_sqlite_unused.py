"""sqlx's SQLite driver stays unused, and replaced by a never-built stand-in.

Codewire uses sqlx only with PostgreSQL. Cargo still resolves sqlx's optional
`sqlx-sqlite` into the lockfile, and its `links = "sqlite3"` claim (through
`libsqlite3-sys` below 0.38) would hold `rusqlite` on a bundled SQLite affected
by RUSTSEC-2026-0459. The root manifest patches `sqlx-sqlite` with
`third_party/sqlx-sqlite-unused`, which fails to compile if built (#3980).

This check turns any attempt to use the driver into a plain policy error
rather than that compile error: no manifest may enable an sqlx `sqlite*`
feature or depend on `sqlx-sqlite`, the patch must stay, every lockfile that
resolves `sqlx-sqlite` must resolve the stand-in, and the stand-in must keep
no dependencies and its `compile_error!`.
"""

from __future__ import annotations

from .shared import *

STUB = "third_party/sqlx-sqlite-unused"
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
LOCKFILE = re.compile(r"(?:^|/)(?:[A-Za-z0-9_-]+\.)?Cargo\.lock$")
MANIFEST = re.compile(r"(?:^|/)Cargo\.toml$")


def dependency_tables(manifest: dict) -> list[tuple[str, dict]]:
    """Every dependency table, with a label, including target and workspace ones."""
    tables = [(name, manifest.get(name)) for name in DEPENDENCY_TABLES]
    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        tables.append(("workspace.dependencies", workspace.get("dependencies")))
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target, entry in targets.items():
            if isinstance(entry, dict):
                tables.extend((f"target.{target}.{name}", entry.get(name)) for name in DEPENDENCY_TABLES)
    return [(label, table) for label, table in tables if isinstance(table, dict)]


def manifest_failures(path: str, text: str) -> list[str]:
    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{path} is not a valid Cargo manifest: {error}"]
    failures = []
    for feature, enables in (manifest.get("features") or {}).items():
        for entry in enables if isinstance(enables, list) else []:
            if isinstance(entry, str) and (
                    re.match(r"sqlx\??/sqlite", entry) or entry.startswith(("dep:sqlx-sqlite", "sqlx-sqlite"))):
                failures.append(
                    f"{path} feature {feature!r} enables {entry!r}; sqlx's SQLite driver is replaced by "
                    f"the never-built {STUB} (#3980)")
    for label, table in dependency_tables(manifest):
        for name, spec in table.items():
            package = spec.get("package", name) if isinstance(spec, dict) else name
            if package == "sqlx-sqlite":
                failures.append(
                    f"{path} [{label}] depends on sqlx-sqlite; sqlx's SQLite driver is replaced by "
                    f"the never-built {STUB} (#3980)")
            if package == "sqlx" and isinstance(spec, dict):
                for feature in spec.get("features", []):
                    if isinstance(feature, str) and feature.startswith("sqlite"):
                        failures.append(
                            f"{path} [{label}] enables sqlx feature {feature!r}; sqlx's SQLite driver "
                            f"is replaced by the never-built {STUB} (#3980)")
    return failures


def root_failures(text: str) -> list[str]:
    patch = tomllib.loads(text).get("patch", {}).get("crates-io", {})
    entry = patch.get("sqlx-sqlite")
    if not isinstance(entry, dict) or entry.get("path") != STUB:
        return [f"Cargo.toml must patch sqlx-sqlite with path = \"{STUB}\" (#3980)"]
    return []


def lock_failures(path: str, text: str) -> list[str]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{path} is not a valid Cargo lockfile: {error}"]
    return [
        f"{path} resolves sqlx-sqlite {package.get('version')!s} from {package['source']}; "
        f"only the {STUB} stand-in may be resolved (#3980)"
        for package in lock.get("package", [])
        if package.get("name") == "sqlx-sqlite" and "source" in package
    ]


def stub_failures(manifest_text: str, library_text: str) -> list[str]:
    failures = []
    manifest = tomllib.loads(manifest_text)
    if manifest.get("package", {}).get("name") != "sqlx-sqlite":
        failures.append(f"{STUB} must be the sqlx-sqlite package")
    if any(manifest.get(name) for name in DEPENDENCY_TABLES):
        failures.append(f"{STUB} must have no dependencies")
    if "compile_error!(" not in library_text:
        failures.append(f"{STUB}/src/lib.rs must fail to compile if anything builds it")
    return failures


def self_test() -> list[str]:
    failures: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            failures.append(f"sqlx-sqlite unused self-test: {message}")

    postgres = '[dependencies]\nsqlx = { version = "0.8", features = ["postgres", "json"] }\n'
    expect(not manifest_failures("a/Cargo.toml", postgres), "a PostgreSQL-only sqlx was refused")
    for feature in ("sqlite", "sqlite-unbundled", "sqlite-preupdate-hook"):
        refused = manifest_failures(
            "a/Cargo.toml", f'[dependencies]\nsqlx = {{ workspace = true, features = ["{feature}"] }}\n')
        expect(len(refused) == 1 and feature in refused[0], f"feature {feature} gave {refused!r}")
    expect(manifest_failures(
        "Cargo.toml", '[workspace.dependencies]\nsqlx = { version = "0.8", features = ["sqlite"] }\n'),
        "a workspace sqlite feature was admitted")
    expect(manifest_failures(
        "a/Cargo.toml", '[target.\'cfg(unix)\'.dev-dependencies]\nsqlx = { version = "0.8", features = ["sqlite"] }\n'),
        "a target dev-dependency sqlite feature was admitted")
    for forwarded in ("sqlx/sqlite", "sqlx?/sqlite-unbundled", "dep:sqlx-sqlite", "sqlx-sqlite/bundled"):
        refused = manifest_failures("a/Cargo.toml", f'[features]\nlocal = ["{forwarded}"]\n')
        expect(len(refused) == 1 and forwarded in refused[0], f"forwarded {forwarded} gave {refused!r}")
    expect(not manifest_failures("a/Cargo.toml", '[features]\nlocal = ["sqlx/postgres", "dep:sqlx"]\n'),
           "PostgreSQL feature forwarding was refused")
    expect(manifest_failures("a/Cargo.toml", '[dependencies]\nsqlx-sqlite = "0.8"\n'),
           "a direct sqlx-sqlite dependency was admitted")
    expect(manifest_failures("a/Cargo.toml", '[dependencies]\ndriver = { package = "sqlx-sqlite", version = "0.8" }\n'),
           "a renamed sqlx-sqlite dependency was admitted")
    expect(not root_failures(f'[patch.crates-io]\nsqlx-sqlite = {{ path = "{STUB}" }}\n'),
           "the stand-in patch was refused")
    expect(root_failures('[workspace]\nmembers = []\n'), "a missing patch was admitted")
    expect(root_failures('[patch.crates-io]\nsqlx-sqlite = { path = "elsewhere" }\n'),
           "a patch to another path was admitted")
    stand_in = '[[package]]\nname = "sqlx-sqlite"\nversion = "0.8.6"\n'
    real = stand_in + 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    expect(not lock_failures("Cargo.lock", stand_in), "the stand-in lock entry was refused")
    expect(lock_failures("Cargo.lock", real), "the registry sqlx-sqlite was admitted")
    good_stub = '[package]\nname = "sqlx-sqlite"\nversion = "0.8.6"\n[features]\nsqlite = []\n'
    expect(not stub_failures(good_stub, 'compile_error!("unused");\n'), "the stand-in was refused")
    expect(stub_failures(good_stub + '[dependencies]\nlibsqlite3-sys = "0.30"\n', 'compile_error!("x");\n'),
           "a stand-in with dependencies was admitted")
    expect(stub_failures(good_stub, "pub fn driver() {}\n"), "a buildable stand-in was admitted")
    return failures


def check_sqlx_sqlite_unused(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("sqlx-sqlite unused", self_test()):
            return 1
        print("sqlx-sqlite unused: OK (self-test)")
        return 0
    paths = git_source_files()
    manifests = sorted(path for path in paths if MANIFEST.search(path) and not path.startswith(f"{STUB}/"))
    locks = sorted(path for path in paths if LOCKFILE.search(path))
    failures = root_failures(read_text("Cargo.toml"))
    for path in manifests:
        failures.extend(manifest_failures(path, read_text(path)))
    for path in locks:
        failures.extend(lock_failures(path, read_text(path)))
    failures.extend(stub_failures(read_text(f"{STUB}/Cargo.toml"), read_text(f"{STUB}/src/lib.rs")))
    if report("sqlx-sqlite unused", failures):
        return 1
    print(f"sqlx-sqlite unused: OK ({len(manifests)} manifests, {len(locks)} lockfiles)")
    return 0
