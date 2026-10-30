#!/usr/bin/env python3
"""Recipe-keyed cache of the local VM runtime's slow parts (#2539).

The arm64 and x86_64 kernels, the macOS e2fsprogs and git builds and the
signed VZ helper change only when their recipe changes, so a release reuses
the bytes an earlier release published: the same digests, so users download
nothing new for them. A part's recipe is the SHA-256 of its exact inputs: the
producer files and trees, their pins in local-runtime-sources.json, a kernel's
architecture, a signed part's signing identity and, for Mac-native parts, the
host facts the build depends on. Its record,
cw/v1/runtime-parts/<recipe>.json, names each output file as a
content-addressed blob in cw/v1/blobs/sha256/, and may carry the provenance of
the run that built it.

Build jobs read records and blobs anonymously from the public release origin
and check every digest; a miss means the part is built. Only the publishing
job, which holds release credentials, writes records (If-None-Match, read
back), and only for parts built in that run. Records are never overwritten or
deleted, so every recipe a release used stays cached, and each release also
publishes the blobs its own runtime pins. These builds are not claimed to be
byte-reproducible: a cache miss may yield different bytes. A Developer ID
signature carries a timestamp, so the signed helper never is: signing it once
per recipe (#1905) is what keeps its digest, and its notarization, stable.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release as release  # noqa: E402
import cw_release_r2 as r2  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
PINS = ROOT / "scripts/ci/release/local-runtime-sources.json"
RECORD_SCHEMA = "codewire.cw.runtime-part/v1"
HOST_FACTS = {"macos", "sdk", "clang"}
KERNEL_FILES = ("scripts/ci/release/build-runtime-kernel.sh", "scripts/ci/release/runtime-container.sh",
                "scripts/ci/verify/build-linux-vmm-kernel.py",
                "scripts/ci/verify/linux-vmm-kernel/dax.patch",
                "scripts/ci/verify/linux-vmm-kernel/provenance.json")
KERNEL_PINS = (("kernel_builder",), ("kernel_bc",), ("sources", "linux"))
# Each part's producer files, the pins (paths into the pins file) it uses, the
# files it outputs and which of them are executables. A kernel part also names
# its architecture (build-linux-vmm-kernel.py --arch), part of its recipe.
PARTS = {
    "kernel-arm64": {
        "files": KERNEL_FILES + ("scripts/ci/verify/linux-vmm-kernel/arm64.config",),
        "pins": KERNEL_PINS,
        "arch": "arm64",
        "outputs": ("Image-6.18.48-codewire3", "linux-source.tar.xz"),
        "executables": (),
        "host": False,
    },
    "kernel-x86_64": {
        "files": KERNEL_FILES + ("scripts/ci/verify/linux-vmm-kernel/x86_64.config",),
        "pins": KERNEL_PINS,
        "arch": "x86_64",
        # The kernel's GPL source is the arm64 part's archive of the same
        # pinned commit, which every target lists; a record names only blobs
        # a release publishes.
        "outputs": ("vmlinuz-6.18.48-codewire3",),
        "executables": (),
        "host": False,
    },
    "e2fsprogs-macos": {
        "files": ("scripts/dev/macos-ext4-tool.py", "scripts/dev/macos-command-owner.py"),
        "pins": (("sources", "e2fsprogs"),),
        # Exactly the files the runtime lock pins, so a record names only
        # blobs a release has published.
        "outputs": ("mke2fs", "e2fsck", "resize2fs", "debugfs", "mke2fs.conf"),
        "executables": ("mke2fs", "e2fsck", "resize2fs", "debugfs"),
        "host": True,
    },
    "git-macos": {
        "files": ("scripts/dev/macos-git-tool.py",),
        "pins": (("sources", "git"),),
        "outputs": ("git", "git-remote-https"),
        "executables": ("git", "git-remote-https"),
        "host": True,
    },
    # The Virtualization.framework helper, Developer ID signed and notarized
    # (#1905): built on the Mac (build-local-runtime.sh helper), signed in the
    # release's sign-helper job (sign-macos-helper.sh) and packed against the
    # Developer ID requirement (macos-local-runtime.py). Its tests and README
    # are not inputs of the executable.
    "vz-runner-macos": {
        "files": ("crates/codewire-local-vmm/macos-vz-runner/Package.swift",
                  "crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist"),
        "trees": ("crates/codewire-local-vmm/macos-vz-runner/Sources/",),
        "pins": (),
        "signing": {"identifier": "sh.codewire.vz-runner", "team": "PXQZM3GLP5"},
        "outputs": ("codewire-vz-runner",),
        "executables": ("codewire-vz-runner",),
        "host": True,
    },
}
# The slow parts each side of build-local-runtime.sh takes from the cache.
SIDE_PARTS = {"linux": ("kernel-arm64", "kernel-x86_64"),
              "macos": ("e2fsprogs-macos", "git-macos", "vz-runner-macos")}
# What a record may say about the run that built its part: the release source
# and version, the run, and the runners that built and signed it, and Apple's
# notarization submission. Free text never reaches a record.
PROVENANCE_FIELDS = {"source_sha", "version", "run_id", "build_runner", "sign_runner", "notary_submission_id"}
# Every input of the runtime a release builds: the slow parts' producers, the
# guest root's probe, the VZ helper, the cw runtime producers and the scripts
# that assemble and check them. The four-target dry run builds the runtime
# when one changes, and otherwise only checks the slow parts are cached. A
# trailing / names a tree.
RUNTIME_INPUTS = (
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates/codewire-vmm-guest-probe/",
    "crates/codewire-local-vmm/macos-vz-runner/",
    "scripts/ci/verify/build-local-vmm-initramfs.sh",
    "scripts/ci/verify/build-linux-vmm-kernel.py",
    "scripts/ci/verify/linux-vmm-kernel/",
    "scripts/ci/release/",
    "scripts/ci/select/",
    "scripts/dev/macos-local-runtime.py",
    "scripts/dev/linux-local-runtime.py",
    "scripts/dev/build-native-managed-agent.py",
    "scripts/dev/cw-runtime-image.py",
    "scripts/dev/macos-ext4-tool.py",
    "scripts/dev/macos-command-owner.py",
    "scripts/dev/macos-git-tool.py",
    ".gitea/workflows/cli-release.yaml",
    ".gitea/workflows/cw-release-dry-run.yaml",
)


class PartsError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise PartsError(reason)


def part(name):
    require(name in PARTS, f"unknown runtime part {name!r}")
    return PARTS[name]


def recipe(name, root=ROOT, pins_path=None, host=None):
    """The SHA-256 of one part's exact inputs."""
    shape = part(name)
    require(shape["host"] == (host is not None), f"{name} {'needs' if shape['host'] else 'takes no'} host facts")
    if host is not None:
        require(isinstance(host, dict) and set(host) == HOST_FACTS
                and all(isinstance(value, str) and 0 < len(value) <= 200 for value in host.values()),
                "host facts are not exactly macos, sdk and clang")
    pins = json.loads(Path(pins_path or Path(root) / "scripts/ci/release/local-runtime-sources.json").read_bytes())
    selected = {}
    for path in shape["pins"]:
        value = pins
        for key in path:
            require(isinstance(value, dict) and key in value, f"pin {'.'.join(path)} is missing")
            value = value[key]
        selected[".".join(path)] = value
    files = {}
    for relative in shape["files"]:
        files[relative] = hashlib.sha256((Path(root) / relative).read_bytes()).hexdigest()
    for tree in shape.get("trees", ()):
        found = sorted(tree_files(Path(root), tree))
        require(found, f"{tree} holds no files")
        for relative in found:
            files[relative] = hashlib.sha256((Path(root) / relative).read_bytes()).hexdigest()
    inputs = {"part": name, "files": files, "pins": selected, "host": host}
    if "arch" in shape:
        inputs["arch"] = shape["arch"]
    if "signing" in shape:
        inputs["signing"] = shape["signing"]
    return release.sha256(release.canonical(inputs))


def tree_files(root, tree):
    """Every file under TREE, relative to ROOT; a link or special file is refused."""
    for path in (root / tree).rglob("*"):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()),
                f"{path.relative_to(root)} is not a regular file or directory")
        if path.is_file():
            yield path.relative_to(root).as_posix()


def record(name, recipe_sha256, directory, provenance=None):
    """The canonical record of one built part's output files."""
    shape = part(name)
    require(release.is_hex(recipe_sha256, 64), "recipe is not a SHA-256")
    files = {}
    for output in shape["outputs"]:
        data = release.read_regular(Path(directory) / output, r2.MAX_OBJECT)
        files[output] = {"sha256": release.sha256(data), "size": len(data)}
    value = {"schema": RECORD_SCHEMA, "part": name, "recipe_sha256": recipe_sha256, "files": files}
    if provenance is not None:
        value["provenance"] = check_provenance(provenance)
    data = release.canonical(value)
    require(len(data) <= release.MAX_JSON, "runtime part record exceeds its bound")
    return data


def check_provenance(value):
    """A record's provenance: known fields, each short printable ASCII."""
    require(isinstance(value, dict) and value and set(value) <= PROVENANCE_FIELDS,
            "runtime part provenance names unknown fields")
    for key, text in value.items():
        require(isinstance(text, str) and 0 < len(text) <= 200
                and all(c.isascii() and (c.isalnum() or c in "-_.:") for c in text),
                f"runtime part provenance {key} is invalid")
    for key in ("source_sha",):
        require(key not in value or release.is_hex(value[key], 40), f"runtime part provenance {key} is invalid")
    return value


def set_provenance(path, assignments):
    """Add KEY=VALUE fields to the provenance file at PATH (created if absent)."""
    path = Path(path)
    value = release.parse_canonical(release.read_regular(path, release.MAX_JSON)) if path.exists() else {}
    for assignment in assignments:
        key, separator, text = assignment.partition("=")
        require(separator == "=" and key not in value, f"provenance assignment {assignment!r} is invalid or repeated")
        value[key] = text
    data = release.canonical(check_provenance(value))
    path.write_bytes(data)


def record_key(recipe_sha256):
    require(release.is_hex(recipe_sha256, 64), "recipe is not a SHA-256")
    return f"{release.OBJECT_PREFIX}/runtime-parts/{recipe_sha256}.json"


def parse_record(data, name, recipe_sha256):
    value = release.parse_canonical(data)
    shape = part(name)
    require(isinstance(value, dict) and set(value) - {"provenance"} == {"schema", "part", "recipe_sha256", "files"}
            and value["schema"] == RECORD_SCHEMA and value["part"] == name
            and value["recipe_sha256"] == recipe_sha256, "runtime part record is not for this recipe")
    if "provenance" in value:
        check_provenance(value["provenance"])
    files = value["files"]
    require(isinstance(files, dict) and set(files) == set(shape["outputs"]), "runtime part record files differ")
    for ref in files.values():
        require(isinstance(ref, dict) and set(ref) == {"sha256", "size"} and release.is_hex(ref["sha256"], 64)
                and type(ref["size"]) is int and 0 < ref["size"] <= r2.MAX_OBJECT, "runtime part file is invalid")
    return files


def fetch(origin, name, recipe_sha256, output):
    """Write a cached part's files into `output`; False on a cache miss.

    Every byte is checked against the record's digests before it is written.
    """
    response = origin.get(record_key(recipe_sha256), release.MAX_JSON)
    if response.status == 404:
        return False
    require(response.status == 200, f"runtime part record returned status {response.status}")
    files = parse_record(response.body, name, recipe_sha256)
    blobs = {}
    for output_name, ref in files.items():
        blob = origin.get(release.blob_key(ref["sha256"]), r2.MAX_OBJECT)
        require(blob.status == 200 and release.sha256(blob.body) == ref["sha256"] and len(blob.body) == ref["size"],
                f"cached {output_name} is missing or differs from its record")
        blobs[output_name] = blob.body
    output = Path(output)
    output.mkdir(mode=0o700)
    for output_name, data in blobs.items():
        release.write_new(output / output_name, data,
                          0o755 if output_name in part(name)["executables"] else 0o644)
    return True


def present(origin, name, recipe_sha256):
    """Whether the cache records this recipe; its blobs are not read."""
    response = origin.get(record_key(recipe_sha256), release.MAX_JSON)
    if response.status == 404:
        return False
    require(response.status == 200, f"runtime part record returned status {response.status}")
    parse_record(response.body, name, recipe_sha256)
    return True


def runtime_mode(paths):
    """'full' when a changed path is a runtime input, otherwise 'parts'."""
    for path in paths:
        if any(path == entry or (entry.endswith("/") and path.startswith(entry)) for entry in RUNTIME_INPUTS):
            return "full"
    return "parts"


def publish(s3, dist, records):
    """Write the cache records of the parts this release built.

    It runs after the release's blobs are published. A record may name only
    blobs this release publishes. A recipe already recorded with other bytes,
    by a concurrent build, keeps its record: it is never overwritten.
    """
    local = release.load_local_runtime(dist)
    require(local is not None, "the delivery carries no local runtime")
    published = {digest for digest, _ in local[1]}
    written = []
    for path in sorted(Path(records).glob("*.json")):
        data = release.read_regular(path, release.MAX_JSON)
        value = release.parse_canonical(data)
        require(isinstance(value, dict), "runtime part record is malformed")
        name, recipe_sha256 = value.get("part"), value.get("recipe_sha256")
        files = parse_record(data, name, recipe_sha256)
        require(path.name == f"{recipe_sha256}.json", "runtime part record is not named by its recipe")
        require(all(ref["sha256"] in published for ref in files.values()),
                f"the {name} record names a blob this release does not publish")
        key = record_key(recipe_sha256)
        try:
            outcome = r2.put_immutable(s3, key, data, "application/json")
        except r2.Conflict:
            r2.log(f"runtime part {name} recipe={recipe_sha256} kept: already recorded with other bytes")
            continue
        written.append((key, data, "application/json"))
        r2.log(f"runtime part {name} recipe={recipe_sha256} {outcome}")
    r2.read_back(s3, written, "authenticated runtime part")
    return len(written)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    publisher = sub.add_parser("publish", help="write this release's built part records (publishing job only)")
    publisher.add_argument("--dist", type=Path, required=True)
    publisher.add_argument("--records", type=Path, required=True)
    publisher.add_argument("--credentials", type=Path, required=True)
    sub.add_parser("runtime-mode", help="read changed paths on stdin; print full or parts")
    provenance = sub.add_parser("provenance", help="add KEY=VALUE fields to a record's provenance file")
    provenance.add_argument("--file", type=Path, required=True)
    provenance.add_argument("--set", action="append", required=True, metavar="KEY=VALUE")
    for command in ("recipe", "fetch", "present", "record"):
        each = sub.add_parser(command)
        each.add_argument("--part", required=True, choices=sorted(PARTS))
        if command == "recipe":
            each.add_argument("--host-facts", type=Path, help="JSON object: macos, sdk, clang (Mac-native parts)")
        else:
            each.add_argument("--recipe", required=True)
            if command != "present":
                each.add_argument("--dir", type=Path, required=True)
            if command == "record":
                each.add_argument("--provenance", type=Path, help="the provenance file of the run that built it")
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            s3 = r2.S3(r2.HttpsTransport(), r2.load_credentials(args.credentials))
            print(f"runtime-part: published records={publish(s3, args.dist, args.records)}")
        elif args.command == "runtime-mode":
            print(runtime_mode(line for line in sys.stdin.read().splitlines() if line))
        elif args.command == "provenance":
            set_provenance(args.file, args.set)
        elif args.command == "present":
            hit = present(r2.PublicOrigin(r2.HttpsTransport()), args.part, args.recipe)
            print(f"runtime-part: {args.part} recipe={args.recipe} cache={'hit' if hit else 'miss'}")
            return 0 if hit else 3
        elif args.command == "recipe":
            host = json.loads(args.host_facts.read_bytes()) if args.host_facts else None
            print(recipe(args.part, host=host))
        elif args.command == "fetch":
            hit = fetch(r2.PublicOrigin(r2.HttpsTransport()), args.part, args.recipe, args.dir)
            print(f"runtime-part: {args.part} recipe={args.recipe} cache={'hit' if hit else 'miss'}")
            return 0 if hit else 3
        else:
            provenance = None
            if args.provenance is not None:
                provenance = release.parse_canonical(release.read_regular(args.provenance, release.MAX_JSON))
            sys.stdout.buffer.write(record(args.part, args.recipe, args.dir, provenance))
    except (PartsError, release.ReleaseError, r2.PublishError, r2.TransportError, OSError) as error:
        print(f"runtime-part: REJECT {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
