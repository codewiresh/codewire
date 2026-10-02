#!/usr/bin/env python3
"""Produce and admit the small, static cw OCI image without publishing it.

The image has one uncompressed layer and no base image, build hooks or runtime
interpreter. Import reads only its two fixed payloads; it never extracts a
filesystem or executes image code. The independently supplied index digest is
the admission pin. The resulting boot provenance binds all image descriptors.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import signal
import sys
import tarfile

MAX_CW = 256 * 1024 * 1024
MAX_ARCHIVE = MAX_CW + 4 * 1024 * 1024
MAX_JSON = 16 * 1024
MAX_MEMBERS = 32
TARGET = "x86_64-unknown-linux-musl"
CW_PATH = "usr/local/bin/cw"
META_PATH = "usr/local/share/codewire/cw-runtime.json"
DIRECTORIES = ("usr", "usr/local", "usr/local/bin", "usr/local/share", "usr/local/share/codewire")
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hex_value(value, size=64):
    return isinstance(value, str) and len(value) == size and all(c in "0123456789abcdef" for c in value)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def decode(data):
    require(0 < len(data) <= MAX_JSON, "JSON exceeds the image metadata bound")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=pairs)
    require(isinstance(value, dict), "JSON object required")
    return value


def read_regular(path, limit, private=False):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                "input must be a bounded regular file with one link")
        if private:
            require(before.st_uid == os.geteuid() and not before.st_mode & 0o022, "input is not owner controlled")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                                  value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) and len(data) == before.st_size, "input changed while reading")
        return data


def static_elf(data):
    require(64 <= len(data) <= MAX_CW and data[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<HH", data, 16) in ((2, 62), (3, 62)), "cw must be a static x86_64 ELF")
    offset, = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    require(offset >= 64 and size == 56 and 0 < count <= 128 and offset + count * size <= len(data), "invalid ELF program headers")
    for position in range(offset, offset + size * count, size):
        kind, = struct.unpack_from("<I", data, position)
        require(kind != 3, "cw has a dynamic interpreter")
        if kind == 2:
            start, = struct.unpack_from("<Q", data, position + 8)
            length, = struct.unpack_from("<Q", data, position + 32)
            require(length % 16 == 0 and start + length <= len(data), "invalid ELF dynamic table")
            for entry in range(start, start + length, 16):
                tag, = struct.unpack_from("<q", data, entry)
                if tag == 0:
                    break
                require(tag != 1, "cw has a dynamic dependency")


def validate_payload(metadata, cw):
    require(set(metadata) == {"schema_version", "protocol_version", "target", "source_revision",
                              "source_tree_sha256", "rustc", "sha256", "size"}, "unknown cw provenance fields")
    require(type(metadata["schema_version"]) is int and metadata["schema_version"] == 1
            and type(metadata["protocol_version"]) is int and metadata["protocol_version"] == 1
            and metadata["target"] == TARGET
            and hex_value(metadata["source_revision"], 40)
            and hex_value(metadata["source_tree_sha256"])
            and isinstance(metadata["rustc"], str) and metadata["rustc"].startswith("rustc 1.93.0 ")
            and len(metadata["rustc"]) <= 128
            and metadata["sha256"] == sha(cw)
            and type(metadata["size"]) is int and metadata["size"] == len(cw), "invalid cw provenance")
    static_elf(cw)


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, mode, data in entries:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.uid = member.gid = member.mtime = 0
            if data is None:
                member.type = tarfile.DIRTYPE
            else:
                member.size = len(data)
            archive.addfile(member, None if data is None else io.BytesIO(data))
    return output.getvalue()


def read_tar(data, allowed, image_blobs=False):
    # USTAR only: inspecting raw headers before tarfile prevents PAX/GNU
    # extension records from silently changing an entry's name or identity.
    offset = 0
    names = set()
    result = {}
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == bytes(512):
            require(len(data) >= offset + 1024 and not any(data[offset:]), "invalid tar terminator/padding")
            return result
        require(len(names) < MAX_MEMBERS and header[156:157] in (b"0", b"\0", b"5")
                and header[257:263] == b"ustar\0" and not any(header[345:500]), "unsupported tar entry")
        with tarfile.open(fileobj=io.BytesIO(header + bytes(1024)), mode="r:") as parser:
            member = parser.next()
        require(member is not None, "missing archive member")
        raw_name = header[:100].split(b"\0", 1)[0]
        canonical_name = (member.name + ("/" if member.isdir() else "")).encode("ascii")
        require(raw_name == canonical_name and not any(header[len(raw_name):100]), "noncanonical archive name")
        if image_blobs and member.name not in allowed:
            require(member.name.startswith("blobs/sha256/") and hex_value(member.name[13:])
                    and len(allowed) < 5, "unexpected image blob")
            allowed[member.name] = (0o444, False)
        require(member.name not in names and member.name in allowed,
                "unexpected or duplicate archive path")
        names.add(member.name)
        require(member.uid == member.gid == 0 and not member.linkname and not member.pax_headers,
                "invalid archive ownership or link")
        expected_mode, directory = allowed[member.name]
        require(member.mode == expected_mode and member.isdir() == directory
                and (member.isdir() or member.isreg()) and 0 <= member.size <= MAX_ARCHIVE
                and (not directory or member.size == 0), "invalid archive type, mode or size")
        start = offset + 512
        end = start + member.size
        require(end <= len(data), "truncated archive member")
        result[member.name] = data[start:end]
        next_offset = start + ((member.size + 511) // 512) * 512
        require(not any(data[end:next_offset]), "nonzero member padding")
        offset = next_offset
    raise ValueError("missing tar terminator")


def descriptor(media_type, data):
    return {"mediaType": media_type, "digest": "sha256:" + sha(data), "size": len(data)}


def checked_descriptor(value, media_type):
    require(isinstance(value, dict) and set(value) == {"mediaType", "digest", "size"}
            and value["mediaType"] == media_type and isinstance(value["digest"], str)
            and value["digest"].startswith("sha256:") and hex_value(value["digest"][7:])
            and type(value["size"]) is int and 0 < value["size"] <= MAX_ARCHIVE, "invalid OCI descriptor")
    return value["digest"][7:]


def admit(image, index_sha256):
    require(hex_value(index_sha256), "index pin must be lowercase SHA256")
    require(0 < len(image) <= MAX_ARCHIVE, "image archive exceeds its bound")
    # The admitted outer shape is fixed and contains only three digest blobs.
    # Inspect names first without interpreting their contents or extracting.
    allowed = {"oci-layout": (0o444, False), "index.json": (0o444, False)}
    files = read_tar(image, allowed, image_blobs=True)
    require(decode(files["oci-layout"]) == {"imageLayoutVersion": "1.0.0"}, "unsupported OCI layout")
    index_raw = files["index.json"]
    require(sha(index_raw) == index_sha256, "image index pin mismatch")
    index = decode(index_raw)
    require(set(index) == {"schemaVersion", "manifests"} and type(index["schemaVersion"]) is int and index["schemaVersion"] == 2
            and isinstance(index["manifests"], list) and len(index["manifests"]) == 1, "one image manifest required")
    require(isinstance(index["manifests"][0], dict), "manifest descriptor must be an object")
    selection = dict(index["manifests"][0])
    require(selection.pop("platform", None) == {"os": "linux", "architecture": "amd64"}, "unsupported image platform")

    def blob(value, media_type):
        digest = checked_descriptor(value, media_type)
        raw = files["blobs/sha256/" + digest]
        require(len(raw) == value["size"] and sha(raw) == digest, "OCI blob identity mismatch")
        return raw

    manifest_raw = blob(selection, MANIFEST)
    manifest = decode(manifest_raw)
    require(set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
            and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2 and manifest["mediaType"] == MANIFEST
            and isinstance(manifest["layers"], list) and len(manifest["layers"]) == 1, "one uncompressed layer required")
    config_raw = blob(manifest["config"], CONFIG)
    config = decode(config_raw)
    require(set(config) == {"os", "architecture", "config", "rootfs"}
            and config["os"] == "linux" and config["architecture"] == "amd64"
            and config["config"] == {} and set(config["rootfs"]) == {"type", "diff_ids"}
            and config["rootfs"]["type"] == "layers", "unsupported image configuration")
    layer_raw = blob(manifest["layers"][0], LAYER)
    require(config["rootfs"]["diff_ids"] == ["sha256:" + sha(layer_raw)], "layer diff_id mismatch")
    used = {"oci-layout", "index.json", *("blobs/sha256/" + item["digest"][7:]
             for item in (selection, manifest["config"], manifest["layers"][0]))}
    require(set(files) == used and len(used) == 5, "unreferenced or repeated image blobs")
    payload_paths = {name: (0o555, True) for name in DIRECTORIES}
    payload_paths.update({CW_PATH: (0o555, False), META_PATH: (0o444, False)})
    payload_files = read_tar(layer_raw, payload_paths)
    require(set(payload_files) == set(payload_paths), "incomplete cw layer")
    metadata = decode(payload_files[META_PATH])
    cw = payload_files[CW_PATH]
    validate_payload(metadata, cw)

    def identity(item):
        return {"sha256": item["digest"][7:], "size": item["size"]}

    provenance = {"schema_version": 1, "image_index_sha256": index_sha256,
                  "image_manifest": identity(selection), "image_config": identity(manifest["config"]),
                  "image_layer": identity(manifest["layers"][0]), "layer_diff_id": sha(layer_raw),
                  "payload": metadata}
    return cw, encode(provenance)


def fresh_output(path):
    require(path.is_absolute() and not path.exists(), "output must be a fresh absolute directory")
    path.mkdir(mode=0o700)


def write(path, data, mode):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def build(artifact_path, output):
    artifact = decode(read_regular(artifact_path, MAX_JSON, private=True))
    require(set(artifact) == {"schema_version", "protocol_version", "target", "source_revision",
                             "source_tree_sha256", "rustc", "path", "sha256"}, "unknown build descriptor fields")
    cw_path = Path(artifact.pop("path"))
    require(cw_path.is_absolute(), "cw build input path must be absolute")
    cw = read_regular(cw_path, MAX_CW, private=True)
    artifact["size"] = len(cw)
    validate_payload(artifact, cw)
    layer = tar_bytes([(name, 0o555, None) for name in DIRECTORIES]
                      + [(CW_PATH, 0o555, cw), (META_PATH, 0o444, encode(artifact))])
    config = encode({"os": "linux", "architecture": "amd64", "config": {},
                     "rootfs": {"type": "layers", "diff_ids": ["sha256:" + sha(layer)]}})
    manifest = encode({"schemaVersion": 2, "mediaType": MANIFEST,
                       "config": descriptor(CONFIG, config), "layers": [descriptor(LAYER, layer)]})
    selection = descriptor(MANIFEST, manifest)
    selection["platform"] = {"os": "linux", "architecture": "amd64"}
    index = encode({"schemaVersion": 2, "manifests": [selection]})
    image = tar_bytes([("oci-layout", 0o444, encode({"imageLayoutVersion": "1.0.0"})),
                       ("index.json", 0o444, index)]
                      + [("blobs/sha256/" + sha(data), 0o444, data) for data in (manifest, config, layer)])
    # Exercise the same hostile-input admission that the VM packer consumes.
    admitted_cw, _ = admit(image, sha(index))
    require(admitted_cw == cw, "image roundtrip changed cw")
    fresh_output(output)
    write(output / "cw.oci.tar", image, 0o400)
    receipt = {"schema_version": 1, "index_sha256": sha(index), "manifest_sha256": sha(manifest),
               "archive_sha256": sha(image), "cw_sha256": sha(cw), "source_revision": artifact["source_revision"]}
    write(output / "image.json", encode(receipt), 0o400)
    print(json.dumps(receipt))


def main():
    def expired(_signum, _frame):
        raise TimeoutError("cw image preparation exceeded its 60 second bound")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(60)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    produce = sub.add_parser("build")
    produce.add_argument("--artifact", type=Path, required=True)
    produce.add_argument("--output", type=Path, required=True)
    consume = sub.add_parser("unpack")
    consume.add_argument("--image", type=Path, required=True)
    consume.add_argument("--index-sha256", required=True)
    consume.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        build(args.artifact, args.output)
    else:
        cw, provenance = admit(read_regular(args.image, MAX_ARCHIVE, private=True), args.index_sha256)
        fresh_output(args.output)
        write(args.output / "cw", cw, 0o500)
        write(args.output / "provenance.json", provenance, 0o400)
        print(json.dumps({"cw_sha256": sha(cw), "provenance_sha256": sha(provenance)}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"cw-runtime-image: {error}", file=sys.stderr)
        sys.exit(1)
