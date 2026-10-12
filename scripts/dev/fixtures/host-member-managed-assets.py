#!/usr/bin/env python3
"""Admit and stage real Linux agents for the owned member integration fixture.

This imports the existing protected Host fixture's payload/OS/broker admission.
It does not run an agent, create a service, or grant release provenance to the
reused component cw. The Rust fixture owns all service and process effects.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import stat
import sys


SOURCE = Path(__file__).resolve().parents[3]
HOST_FIXTURE_SHA = "b849e4e91175769f78d7a5e4f7a1a507b41825857e863823875fce47aec757ce"
MAX_JSON = 1024 * 1024


def host_fixture():
    path = SOURCE / "scripts/dev/test-cli-host-managed.py"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    def stamp(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
                metadata.st_mode, metadata.st_nlink, metadata.st_size,
                metadata.st_mtime_ns, metadata.st_ctime_ns)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and before.st_size <= MAX_JSON):
            raise ValueError("protected fixture is not its bounded owned regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_JSON + 1)
        if (len(raw) > MAX_JSON or stamp(before) != stamp(os.fstat(fd))
                or stamp(before) != stamp(path.lstat())
                or hashlib.sha256(raw).hexdigest() != HOST_FIXTURE_SHA):
            raise ValueError("protected Host fixture changed; re-admit its owning input")
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_file_location("member_managed_host_fixture", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def pinned_json(host, path, expected):
    host.require(host.hexdigest(expected), "invalid JSON pin")
    raw, _ = host.regular(path, MAX_JSON)
    host.require(hashlib.sha256(raw).hexdigest() == expected, "JSON pin changed")
    return host.json_value(raw)


def component(host, path, pin, manifest_path, manifest_pin):
    manifest = pinned_json(host, manifest_path, manifest_pin)
    host.require(manifest.get("schema") == "codewire.managed-member-source-freeze/v1",
                 "unsupported managed component manifest")
    rows = manifest.get("sources")
    inputs = manifest.get("inputs")
    host.require(isinstance(rows, list) and len(rows) == 26 and
                 isinstance(inputs, list) and len(inputs) == 16, "incomplete component inputs")
    seen = set()
    for row in [*rows, *inputs]:
        name = host.relative(row.get("path"))
        host.require(name not in seen, "duplicate component input")
        seen.add(name)
        digest, _, _ = host.scan_regular(SOURCE / name, 16 * 1024 * 1024)
        host.require(digest == row.get("sha256"), "compiled/library input changed")
    digest, metadata, _ = host.scan_regular(path, host.MAX_CW_FILE, executable=True)
    host.require(host.hexdigest(pin) and digest == pin, "component cw differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        host.require(host.stable(os.fstat(fd)) == host.stable(metadata), "component cw changed")
        header = os.read(fd, 64)
        host.require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01" and
                     struct.unpack_from("<H", header, 18)[0] == 62 and
                     host.stable(os.fstat(fd)) == host.stable(Path(path).lstat()) == host.stable(metadata),
                     "component cw is not its admitted Linux amd64 ELF")
    finally:
        os.close(fd)
    return {"path": str(Path(path).resolve()), "sha256": digest, "bytes": metadata.st_size,
            "source_manifest_sha256": manifest_pin, "original_head": manifest["base_head"],
            "original_tree": manifest["base_tree"], "proof": "compiled-component-reuse-only"}


def admit(args, host):
    cw = component(host, args.cw, args.cw_sha256, args.component_manifest, args.component_sha256)
    agents = host.admit_agents(args.agents_manifest, args.agents_sha256)
    producer = host.load_producer(SOURCE)
    broker = host.admit_broker(args.broker, args.broker_receipt, SOURCE, producer)
    system = host.system_inputs()
    return cw, agents, broker, system


def write_json(host, path, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    host.require(len(raw) <= MAX_JSON, "asset receipt exceeds bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        seen = getattr(namespace, "_seen", set())
        if self.dest in seen:
            parser.error("duplicate scalar input")
        seen.add(self.dest)
        namespace._seen = seen
        setattr(namespace, self.dest, values)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("mode", choices=["admit", "stage", "cleanup"])
    for name in ("cw", "component-manifest", "agents-manifest", "broker", "broker-receipt", "stage-root"):
        parser.add_argument("--" + name, type=Path, action=Once)
    for name in ("cw-sha256", "component-sha256", "agents-sha256", "root-device", "root-inode"):
        parser.add_argument("--" + name, action=Once)
    args = parser.parse_args()
    host = host_fixture()
    if args.mode == "cleanup":
        host.require(args.stage_root is not None and args.root_device and args.root_inode and
                     args._seen == {"stage_root", "root_device", "root_inode"}, "cleanup arguments differ")
        host.require(all(re.fullmatch(r"[0-9]{1,20}", x) for x in (args.root_device, args.root_inode)),
                     "invalid cleanup identity")
        host.remove_owned_tree(args.stage_root, (int(args.root_device), int(args.root_inode)))
        print(json.dumps({"cleanup": "identified-owned-tree-only"}))
        return
    required = {"cw", "cw_sha256", "component_manifest", "component_sha256", "agents_manifest",
                "agents_sha256", "broker", "broker_receipt"}
    if args.mode == "stage":
        required.add("stage_root")
    host.require(getattr(args, "_seen", set()) == required, "asset argument group is incomplete or conflicting")
    cw, agents, broker, system = admit(args, host)
    receipt = {"schema": "codewire.member-managed-assets/v1", "status": "admitted",
               "cw": cw, "agent_manifest_sha256": agents["sha256"],
               "agent_source": agents["manifest"]["source"], "agents": agents["manifest"]["agents"],
               "agent_files": agents["pins"], "elf": agents["elf"], "broker": broker,
               "ordinary_host_runtime": system, "protected_fixture_sha256": HOST_FIXTURE_SHA,
               "actual_agents_executed": False, "public_release_proof": False}
    if args.mode == "stage":
        root = host.admit_scratch(args.stage_root)
        copied = {}
        for label in ("target", "caller"):
            binary = root / (label + "-cw")
            digest, metadata, _ = host.scan_regular(binary, host.MAX_CW_FILE, executable=True)
            host.require(digest == cw["sha256"] and metadata.st_size == cw["bytes"],
                         "copied endpoint differs from admitted component")
            copied[label] = {"sha256": digest, "dev": metadata.st_dev, "inode": metadata.st_ino}
        dest = root / "managed-assets"
        dest.mkdir(mode=0o700)
        payload, bins = host.stage_agents(agents, dest)
        receipt.update(status="staged", payload=str(payload), agent_bin=str(bins),
                       broker_path=str(Path(args.broker).resolve()), endpoint_copies=copied)
        write_json(host, root / "managed-assets.json", receipt)
    # Keep stdout below a single pipe buffer. The complete staged receipt is
    # read from its bounded private file by the Rust fixture.
    print(json.dumps({"schema": receipt["schema"], "status": receipt["status"], "cw": cw,
                      "agent_manifest_sha256": agents["sha256"],
                      "broker_sha256": broker["executable_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print source values, argv, capabilities, or provider settings.
        print("member-managed asset admission refused: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
