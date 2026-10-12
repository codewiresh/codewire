#!/usr/bin/env python3
"""Recipe-keyed cache of the local VM runtime's slow parts (#2539).

The arm64 kernel and the macOS e2fsprogs and git builds change only when their
recipe changes, so a release reuses the bytes an earlier release published:
the same digests, so users download nothing new for them. A part's recipe is
the SHA-256 of its exact inputs: the producer files, their pins in
local-runtime-sources.json and, for Mac-native parts, the host facts the build
depends on. Its record, cw/v1/runtime-parts/<recipe>.json, names each output
file as a content-addressed blob in cw/v1/blobs/sha256/.

Build jobs read records and blobs anonymously from the public release origin
and check every digest; a miss means the part is built. Only the publishing
job, which holds release credentials, writes records (If-None-Match, read
back), and only for parts built in that run. These builds are not claimed to
be byte-reproducible: a cache miss may yield different bytes.
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
# Each part's producer files, and the pins (paths into the pins file) it uses.
PARTS = {
    "kernel-arm64": {
        "files": ("scripts/ci/release/build-runtime-kernel.sh", "scripts/ci/verify/build-linux-vmm-kernel.py",
                  "scripts/ci/verify/linux-vmm-kernel/arm64.config",
                  "scripts/ci/verify/linux-vmm-kernel/dax.patch",
                  "scripts/ci/verify/linux-vmm-kernel/provenance.json"),
        "pins": (("kernel_builder",), ("kernel_bc",), ("sources", "linux")),
        "outputs": ("Image-6.18.48-codewire2", "linux-source.tar.xz"),
        "host": False,
    },
    "e2fsprogs-macos": {
        "files": ("scripts/dev/macos-ext4-tool.py", "scripts/dev/macos-cli.py"),
        "pins": (("sources", "e2fsprogs"),),
        "outputs": ("mke2fs", "e2fsck", "resize2fs", "debugfs", "mke2fs.conf", "NOTICE", "libuuid-COPYING"),
        "host": True,
    },
    "git-macos": {
        "files": ("scripts/dev/macos-git-tool.py",),
        "pins": (("sources", "git"),),
        "outputs": ("git", "git-remote-https"),
        "host": True,
    },
}


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
    return release.sha256(release.canonical({"part": name, "files": files, "pins": selected, "host": host}))


def record(name, recipe_sha256, directory):
    """The canonical record of one built part's output files."""
    shape = part(name)
    require(release.is_hex(recipe_sha256, 64), "recipe is not a SHA-256")
    files = {}
    for output in shape["outputs"]:
        data = release.read_regular(Path(directory) / output, r2.MAX_OBJECT)
        files[output] = {"sha256": release.sha256(data), "size": len(data)}
    data = release.canonical({"schema": RECORD_SCHEMA, "part": name, "recipe_sha256": recipe_sha256,
                              "files": files})
    require(len(data) <= release.MAX_JSON, "runtime part record exceeds its bound")
    return data


def record_key(recipe_sha256):
    require(release.is_hex(recipe_sha256, 64), "recipe is not a SHA-256")
    return f"{release.OBJECT_PREFIX}/runtime-parts/{recipe_sha256}.json"


def parse_record(data, name, recipe_sha256):
    value = release.parse_canonical(data)
    shape = part(name)
    require(isinstance(value, dict) and set(value) == {"schema", "part", "recipe_sha256", "files"}
            and value["schema"] == RECORD_SCHEMA and value["part"] == name
            and value["recipe_sha256"] == recipe_sha256, "runtime part record is not for this recipe")
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
        release.write_new(output / output_name, data, 0o755 if output_name in ("git", "git-remote-https", "mke2fs",
                                                                              "e2fsck", "resize2fs", "debugfs")
                          else 0o644)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("recipe", "fetch", "record"):
        each = sub.add_parser(command)
        each.add_argument("--part", required=True, choices=sorted(PARTS))
        if command == "recipe":
            each.add_argument("--host-facts", type=Path, help="JSON object: macos, sdk, clang (Mac-native parts)")
        else:
            each.add_argument("--recipe", required=True)
            each.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "recipe":
            host = json.loads(args.host_facts.read_bytes()) if args.host_facts else None
            print(recipe(args.part, host=host))
        elif args.command == "fetch":
            hit = fetch(r2.PublicOrigin(r2.HttpsTransport()), args.part, args.recipe, args.dir)
            print(f"runtime-part: {args.part} recipe={args.recipe} cache={'hit' if hit else 'miss'}")
            return 0 if hit else 3
        else:
            sys.stdout.buffer.write(record(args.part, args.recipe, args.dir))
    except (PartsError, release.ReleaseError, r2.PublishError, r2.TransportError, OSError) as error:
        print(f"runtime-part: REJECT {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
