"""The CLI is one product on Linux and macOS (#3797).

Every place codewire-cli or codewire-cli-bin behaves differently on the two
is recorded, with its reason, in os-splits.toml beside this file. The check
fails when a file has a single-OS `target_os` split that is not recorded with
its exact count, when a recorded count or group is stale, and when a CLI crate
links a workspace crate on one OS only although that crate has no OS-specific
code of its own and no recorded reason. That last pattern is how the macOS
build came to look for separate Mesh and DERP programs (#3794).
"""

from __future__ import annotations

from .shared import *

REGISTRY = "scripts/checks/repo_policy/os-splits.toml"
CRATES = ("codewire-cli", "codewire-cli-bin")
OSES = ("linux", "macos")
TARGET = re.compile(r"^\[target\.'cfg\((.*)\)'\.(dependencies|dev-dependencies)\]\s*$")


def split_lines(text: str) -> int:
    """Lines whose `target_os` gate names Linux or macOS but not both."""
    count = 0
    for line in text.splitlines():
        if "target_os" not in line:
            continue
        linux, macos = '"linux"' in line, '"macos"' in line
        if linux != macos:
            count += 1
    return count


def single_os(predicate: str) -> str | None:
    """The one OS a Cargo target predicate selects, if it selects exactly one."""
    named = [os for os in OSES if f'target_os = "{os}"' in predicate]
    if len(named) != 1 or predicate.strip().startswith("not("):
        return None
    return named[0]


def gated_dependencies(manifest: str) -> list[tuple[str, str]]:
    """(dependency, OS) for each dependency listed under a single-OS table."""
    gated, os = [], None
    for line in manifest.splitlines():
        if line.startswith("["):
            match = TARGET.match(line)
            os = single_os(match.group(1)) if match else None
            continue
        name = line.split("=", 1)[0].strip()
        if os and name and not name.startswith("#") and "=" in line:
            gated.append((name, os))
    return gated


def registry_failures(registry: dict, sources: dict[str, str]) -> list[str]:
    failures: list[str] = []
    groups = registry.get("groups", {})
    for name, group in groups.items():
        if not str(group.get("reason", "")).strip():
            failures.append(f"group {name} has no reason")
    files = registry.get("files", {})
    for path, entry in files.items():
        if entry.get("group") not in groups:
            failures.append(f"{path} names unknown group {entry.get('group')!r}")
    for path in sorted(set(sources) | set(files)):
        actual = split_lines(sources[path]) if path in sources else 0
        entry = files.get(path)
        if actual and entry is None:
            failures.append(
                f"{path} has {actual} Linux-or-macOS-only lines and no reason in {REGISTRY}: "
                "share the code if both OSes can run it, or record its group and count"
            )
        elif entry is not None and entry.get("count") != actual:
            failures.append(
                f"{path} has {actual} Linux-or-macOS-only lines, but {REGISTRY} records "
                f"{entry.get('count')}: update the record with its reason"
            )
    return failures


def dependency_failures(
    registry: dict, manifests: dict[str, str], crate_os_code: dict[str, bool]
) -> list[str]:
    failures: list[str] = []
    recorded = registry.get("dependencies", {})
    seen = set()
    for crate, manifest in manifests.items():
        for dependency, os in gated_dependencies(manifest):
            if dependency not in crate_os_code:
                continue
            key = f"{crate}/{dependency}"
            if key in seen:
                continue
            seen.add(key)
            if crate_os_code[dependency]:
                continue
            entry = recorded.get(key)
            if entry is None or entry.get("os") != os:
                failures.append(
                    f"{crate} links {dependency} only on {os}, but {dependency} has no OS-specific "
                    f"code: link it on both, or record why in {REGISTRY} [dependencies]"
                )
    for key in sorted(set(recorded) - seen):
        failures.append(f"{REGISTRY} records {key}, which no CLI crate gates to one OS")
    return failures


def has_os_code(crate: str) -> bool:
    return any(
        "target_os" in read_text(path)
        for path in git_source_files()
        if path.startswith(f"crates/{crate}/") and path.endswith(".rs")
    )


def self_test() -> list[str]:
    failures: list[str] = []
    expect = lambda ok, what: None if ok else failures.append(f"os-splits self-test: {what}")
    shared = '#[cfg(any(target_os = "linux", target_os = "macos"))]\n'
    linux = '#[cfg(target_os = "linux")]\nfn a() {}\n#[cfg(not(target_os = "linux"))]\nfn a() {}\n'
    expect(split_lines(shared) == 0, "a shared Linux-and-macOS gate was counted")
    expect(split_lines(linux) == 2, "a Linux split and its twin were not both counted")
    expect(split_lines('if cfg!(target_os = "macos") {') == 1, "cfg! was not counted")
    registry = {
        "groups": {"real": {"reason": "a reason"}},
        "files": {"crates/codewire-cli/src/a.rs": {"group": "real", "count": 2}},
    }
    expect(not registry_failures(registry, {"crates/codewire-cli/src/a.rs": linux}),
           "a recorded split was refused")
    expect(registry_failures(registry, {"crates/codewire-cli/src/a.rs": linux + linux}),
           "a grown split was admitted")
    expect(registry_failures(registry, {"crates/codewire-cli/src/a.rs": shared}),
           "a stale record was admitted")
    expect(registry_failures(registry, {"crates/codewire-cli/src/a.rs": linux,
                                        "crates/codewire-cli/src/b.rs": linux}),
           "an unrecorded file was admitted")
    expect(registry_failures({"groups": {"real": {"reason": ""}}, "files": {}}, {}),
           "a group without a reason was admitted")
    expect(registry_failures({"groups": {}, "files": registry["files"]},
                             {"crates/codewire-cli/src/a.rs": linux}),
           "an unknown group was admitted")
    manifest = (
        "[dependencies]\nserde = \"1\"\n\n"
        "[target.'cfg(target_os = \"linux\")'.dependencies]\n"
        "codewire-mesh = { path = \"../codewire-mesh\" }\ncodewire-real = { workspace = true }\n\n"
        "[target.'cfg(any(target_os = \"linux\", target_os = \"macos\"))'.dependencies]\n"
        "codewire-shared = { workspace = true }\n"
    )
    code = {"codewire-mesh": False, "codewire-real": True, "codewire-shared": False}
    found = dependency_failures({}, {"codewire-cli-bin": manifest}, code)
    expect(len(found) == 1 and "codewire-mesh only on linux" in found[0],
           f"the Mesh pattern gave {found!r}")
    recorded = {"dependencies": {"codewire-cli-bin/codewire-mesh": {"os": "linux", "group": "x"}}}
    expect(not dependency_failures(recorded, {"codewire-cli-bin": manifest}, code),
           "a recorded single-OS dependency was refused")
    expect(dependency_failures(recorded, {"codewire-cli-bin": manifest.replace(
        "codewire-mesh = { path = \"../codewire-mesh\" }\n", "")}, code),
           "a stale dependency record was admitted")
    return failures


def check_os_splits(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("os-splits", self_test()):
            return 1
        print("os-splits: OK (self-test)")
        return 0
    registry = tomllib.loads(read_text(REGISTRY))
    sources = {
        path: read_text(path)
        for path in git_source_files()
        if path.endswith(".rs") and any(path.startswith(f"crates/{crate}/") for crate in CRATES)
    }
    manifests = {crate: read_text(f"crates/{crate}/Cargo.toml") for crate in CRATES}
    workspace = {
        path.split("/")[1]
        for path in git_source_files()
        if path.startswith("crates/") and path.endswith("/Cargo.toml") and path.count("/") == 2
    }
    crate_os_code = {crate: has_os_code(crate) for crate in sorted(workspace)}
    failures = registry_failures(registry, sources)
    failures.extend(dependency_failures(registry, manifests, crate_os_code))
    if report("os-splits", failures):
        return 1
    print(f"os-splits: OK ({len(registry.get('files', {}))} files recorded)")
    return 0
