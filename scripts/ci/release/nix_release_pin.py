#!/usr/bin/env python3
"""The Nix flake's release pin, nix/release.json (docs/dev/CLI-NIX-INSTALL.md).

The pin names one release and, for each Nix system, the target, SHA-256 and
size of its released executable. Every value is recomputed here from the
signed release on the public origin, read as cw upgrade reads it, with no
credential.

nix/SHA256SUMS and nix/SHA256SUMS.asc beside it are that release's signed
checksums, so the pin can be proved offline.

Subcommands:
  render  for the release the stable channel names under its signature, write
          the pin, the signed checksums and a report of the recomputation (the
          pull request body). A channel that already names a newer release
          writes nothing: that release proposes its own pin
  check   recompute the pin from the signed release the pin names and fail
          unless the pin and checksums are exactly that; --blobs also
          downloads each executable and compares its SHA-256 and size
  verify  offline, run from a trusted base checkout over a candidate tree as
          data: the candidate's checksums carry the base's release key's
          signature, every pinned hash is the signed one, the pin is not older
          than the base's, and the release key is the base's. A candidate whose
          nix/ and key equal the base's is not checked

Diagnostics go to standard error.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release as release  # noqa: E402
import cw_release_r2 as r2  # noqa: E402

PIN_SCHEMA = "codewire.cw.nix/v1"
# The release target each Nix system installs; flake.nix holds the same map.
SYSTEMS = {
    "aarch64-darwin": "aarch64-apple-darwin",
    "aarch64-linux": "aarch64-unknown-linux-gnu",
    "x86_64-darwin": "x86_64-apple-darwin",
    "x86_64-linux": "x86_64-unknown-linux-musl",
}
SUMS_LINE = re.compile(r"([0-9a-f]{64})  (cw-[0-9A-Za-z._+-]+)")


class PinError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise PinError(reason)


def log(message):
    print(f"nix-release-pin: {message}", file=sys.stderr, flush=True)


def checksums(sums):
    """SHA256SUMS as {asset name: SHA-256}; every line must parse once."""
    lines = sums.decode("ascii").splitlines()
    entries = {}
    for line in lines:
        match = SUMS_LINE.fullmatch(line)
        require(match is not None, f"SHA256SUMS line is malformed: {line!r}")
        require(match.group(2) not in entries, f"SHA256SUMS names {match.group(2)} twice")
        entries[match.group(2)] = match.group(1)
    return entries


def pin_from(manifest, sums):
    """The pin for a validated, signed manifest and its signed SHA256SUMS. Each
    executable's hash must be the one SHA256SUMS lists for its asset."""
    version = manifest["release_tag"]
    listed = checksums(sums)
    require(set(listed) == {release.asset_name(version, target) for target in SYSTEMS.values()},
            "SHA256SUMS does not list exactly the four release assets")
    entries = {entry["target"]: entry for entry in manifest["targets"]}
    targets = {}
    for system, target in sorted(SYSTEMS.items()):
        executable = entries[target]["executable"]
        require(listed[release.asset_name(version, target)] == executable["sha256"],
                f"{target}: the manifest's executable is not the one SHA256SUMS lists")
        targets[system] = {"target": target, "sha256": executable["sha256"], "size": executable["size"]}
    return {"schema": PIN_SCHEMA, "release_tag": version, "targets": targets}


def pin_bytes(pin):
    return (json.dumps(pin, indent=2) + "\n").encode()


def report(pin, sums):
    """The recomputation, as Markdown: for each system the signed hash and the
    hash written, which must be the same."""
    version = pin["release_tag"]
    listed = checksums(sums)
    rows = []
    for system, entry in pin["targets"].items():
        asset = release.asset_name(version, entry["target"])
        signed = listed[asset]
        require(signed == entry["sha256"], f"{system}: the pin is not the signed hash")
        rows.append(f"| `{system}` | `{asset}` | `{signed}` | `{entry['sha256']}` | exact match |")
    return "\n".join([
        f"The stable channel names `{version}` under the release key's signature. Each hash below was "
        "recomputed from its signed `SHA256SUMS` and compared with what `nix/release.json` now holds.",
        "",
        "| System | Asset | Signed `SHA256SUMS` | Written | Result |",
        "| --- | --- | --- | --- | --- |",
        *rows,
        "",
        "This pull request changes only `nix/release.json` and the signed `nix/SHA256SUMS` and "
        "`nix/SHA256SUMS.asc` that prove it; the Supply-chain scan checks them from protected base.",
        "",
    ])


def fetch(origin, key, limit):
    try:
        response = origin.get(key, limit)
    except r2.TransportError as error:
        raise PinError(f"the public read of {key} failed") from error
    require(response.status == 200, f"the public origin answered {key} with status {response.status}")
    return response.body


def signed_release(origin, version, trust):
    """VERSION's validated manifest and SHA256SUMS, each checked against its
    detached signature."""
    names = ("release.json", "release.json.asc", "SHA256SUMS", "SHA256SUMS.asc")
    limits = (release.MAX_JSON, release.MAX_SIGNATURE, release.MAX_JSON, release.MAX_SIGNATURE)
    manifest, manifest_sig, sums, sums_sig = (fetch(origin, release.release_key(version, name), limit)
                                              for name, limit in zip(names, limits))
    signed = release.check_signed_release(version, manifest, manifest_sig, sums, sums_sig, trust)
    return signed, sums, sums_sig, manifest


def stable_release(origin, trust):
    """The pointer the public stable channel names, under a valid signature."""
    return release.verify_channel(fetch(origin, release.channel_key("stable"), release.MAX_JSON), trust)


def render(origin, version, trust, output, report_path, sums_path, sums_sig_path, sleep=None):
    require(release.release_version(version), "release version is invalid")
    named = stable_release(origin, trust)["release_tag"]
    if release.version_key(named) > release.version_key(version):
        log(f"the stable channel names {named}, newer than {version}; its own release proposes the pin")
        return False
    pointer = r2.offered(origin, version, trust, **({"sleep": sleep} if sleep else {}))
    manifest, sums, sums_sig, manifest_bytes = signed_release(origin, version, trust)
    require(hashlib.sha256(manifest_bytes).hexdigest() == pointer["release"]["sha256"],
            "the signed release is not the one the stable channel names")
    pin = pin_from(manifest, sums)
    output.write_bytes(pin_bytes(pin))
    sums_path.write_bytes(sums)
    sums_sig_path.write_bytes(sums_sig)
    # The report reads the file back, so it is about the bytes written.
    report_path.write_text(report(json.loads(output.read_bytes()), sums))
    log(f"wrote {output} for {version}")
    return True


def check(origin, pin_path, trust, blobs=False, report_path=None):
    written = pin_path.read_bytes()
    sums_path, sums_sig_path = pin_path.parent / "SHA256SUMS", pin_path.parent / "SHA256SUMS.asc"
    pin = json.loads(written)
    require(isinstance(pin, dict) and pin.get("schema") == PIN_SCHEMA, f"{pin_path}: unknown schema")
    version = pin.get("release_tag")
    require(release.release_version(version), f"{pin_path}: release_tag is invalid")
    manifest, sums, sums_sig, _ = signed_release(origin, version, trust)
    require(sums_path.is_file() and sums_path.read_bytes() == sums
            and sums_sig_path.is_file() and sums_sig_path.read_bytes() == sums_sig,
            f"{pin_path.parent}: SHA256SUMS and its signature are not the signed release {version}'s")
    expected = pin_bytes(pin_from(manifest, sums))
    if written != expected:
        want = json.loads(expected)["targets"]
        for system in sorted(set(want) | set(pin.get("targets") or {})):
            have = (pin.get("targets") or {}).get(system)
            if have != want.get(system):
                log(f"{system}: pinned {have}, signed release has {want.get(system)}")
        raise PinError(f"{pin_path} is not the pin of the signed release {version}")
    if blobs:
        for system, entry in pin["targets"].items():
            data = fetch(origin, release.blob_key(entry["sha256"]), release.MAX_EXECUTABLE)
            actual = (hashlib.sha256(data).hexdigest(), len(data))
            require(actual == (entry["sha256"], entry["size"]),
                    f"{system}: the served executable is {actual[0]} ({actual[1]} bytes), "
                    f"not {entry['sha256']} ({entry['size']} bytes)")
            log(f"{system}: served executable matches {entry['sha256']}")
    if report_path:
        report_path.write_text(report(pin, sums))
    log(f"{pin_path} is exactly the pin of the signed release {version}")


# The files the offline proof reads, relative to a tree's root.
PIN_FILES = ("nix/release.json", "nix/SHA256SUMS", "nix/SHA256SUMS.asc")
KEY_FILE = "apps/cli/GPG_PUBLIC_KEY.asc"
FINGERPRINT_FILE = "scripts/ci/release/cw_release.py"
FINGERPRINT_LINE = re.compile(r'^PRODUCTION_FINGERPRINT = "([0-9A-F]{40})"$', re.M)


def tree_file(root, name, limit=release.MAX_JSON):
    """A regular file of a tree read as data, or None when absent."""
    path = root / name
    if not path.exists() and not path.is_symlink():
        return None
    require(path.is_file() and not path.is_symlink(), f"{name} is not a regular file")
    data = path.read_bytes()
    require(len(data) <= limit, f"{name} is too large")
    return data


def tree_fingerprint(root):
    text = tree_file(root, FINGERPRINT_FILE, 4 * 1024 * 1024)
    match = FINGERPRINT_LINE.search((text or b"").decode("utf-8", "replace"))
    require(match is not None, f"{FINGERPRINT_FILE} names no release fingerprint")
    return match.group(1)


def verify(base, candidate, trust):
    """Prove the candidate's pin offline with the base's trust. Returns False
    when there is nothing to prove: the candidate's pin and release key are
    the base's."""
    files = {name: (tree_file(base, name), tree_file(candidate, name)) for name in PIN_FILES}
    if all(ours == theirs for ours, theirs in files.values()):
        log("nix/ is the base's; nothing to prove")
        return False
    # A pull request that changes the pin may not also change what proves it.
    require(tree_file(candidate, KEY_FILE, release.MAX_JSON) == tree_file(base, KEY_FILE, release.MAX_JSON),
            f"a pull request that changes nix/ may not change {KEY_FILE}")
    require(tree_fingerprint(candidate) == tree_fingerprint(base) == trust.fingerprint,
            "a pull request that changes nix/ may not change the release fingerprint")
    pin_data, sums, sums_sig = (files[name][1] for name in PIN_FILES)
    require(None not in (pin_data, sums, sums_sig), "nix/ must hold release.json, SHA256SUMS and SHA256SUMS.asc")
    release.verify_detached(sums, sums_sig, trust)
    pin = json.loads(pin_data)
    require(isinstance(pin, dict) and set(pin) == {"schema", "release_tag", "targets"}
            and pin["schema"] == PIN_SCHEMA, "nix/release.json: unknown schema")
    version = pin["release_tag"]
    require(release.release_version(version), "nix/release.json: release_tag is invalid")
    targets = pin["targets"]
    require(isinstance(targets, dict) and list(targets) == sorted(SYSTEMS),
            "nix/release.json must pin exactly the four systems, in order")
    listed = checksums(sums)
    require(set(listed) == {release.asset_name(version, target) for target in SYSTEMS.values()},
            f"the signed SHA256SUMS is not release {version}'s four assets")
    for system, target in SYSTEMS.items():
        entry = targets[system]
        require(isinstance(entry, dict) and set(entry) == {"target", "sha256", "size"}
                and entry["target"] == target, f"{system}: must pin {target}")
        require(entry["sha256"] == listed[release.asset_name(version, target)],
                f"{system}: {entry['sha256']} is not the signed hash of {release.asset_name(version, target)}")
        require(type(entry["size"]) is int and 0 < entry["size"] <= release.MAX_EXECUTABLE,
                f"{system}: size is invalid")
    require(pin_data == pin_bytes(pin), "nix/release.json is not in the rendered layout")
    base_pin = files["nix/release.json"][0]
    if base_pin is not None:
        older = json.loads(base_pin).get("release_tag")
        require(release.version_key(version) >= release.version_key(older),
                f"nix/release.json may not move back from {older} to {version}")
    log(f"nix/ pins {version}, proved against its signed SHA256SUMS")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    render_parser = sub.add_parser("render")
    render_parser.add_argument("--version", required=True)
    render_parser.add_argument("--output", type=Path, required=True)
    render_parser.add_argument("--report", type=Path, required=True)
    render_parser.add_argument("--sums", type=Path, required=True)
    render_parser.add_argument("--sums-signature", type=Path, required=True)
    check_parser = sub.add_parser("check")
    check_parser.add_argument("--pin", type=Path, required=True)
    check_parser.add_argument("--blobs", action="store_true")
    check_parser.add_argument("--report", type=Path)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--base", type=Path, required=True)
    verify_parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    origin = r2.PublicOrigin(r2.HttpsTransport())
    try:
        if args.command == "verify":
            # The trust is this script's own: run from the protected base, it
            # is the base's key and fingerprint, never the candidate's.
            verify(args.base, args.candidate, release.PRODUCTION_TRUST)
        elif args.command == "render":
            render(origin, args.version, release.PRODUCTION_TRUST, args.output, args.report,
                   args.sums, args.sums_signature)
        else:
            check(origin, args.pin, release.PRODUCTION_TRUST, args.blobs, args.report)
    except (PinError, r2.PublishError, release.ReleaseError) as error:
        print(f"nix-release-pin: REJECT {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
