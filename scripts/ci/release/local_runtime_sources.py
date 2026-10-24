#!/usr/bin/env python3
"""Fetch the exact third-party sources the local VM runtime ships (#2539).

A release publishes, beside the runtime it pins, the source of every
third-party component in it: the license obligation for the GPL and LGPL
parts, and a record for the rest. local-runtime-sources.json pins each source
by URL and SHA-256; Alpine's BusyBox build files are pinned one by one and
assembled into a deterministic tar. The kernel's source is the exact archive
its build made (build-runtime-kernel.sh), not a download.

`fetch --side linux` writes the sources of the guest parts the Linux build
job makes for every target (BusyBox, its Alpine build files, runc and what it
links, and the kernel's archive); `--side linux-host` those of the Linux
target's host programs (Cloud Hypervisor, virtiofsd); `--side macos` those of
the Mac-native parts (e2fsprogs, git). Each writes components.json, which the
runtime packer turns into the document's components.
"""

import argparse
import hashlib
import io
import json
import sys
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release as release  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
PINS = ROOT / "scripts/ci/release/local-runtime-sources.json"
SCHEMA = "codewire.local-runtime-sources/v1"
SIDES = {
    "linux": ("busybox", "busybox-alpine-build", "runc", "libseccomp", "libpathrs", "linux"),
    "linux-host": ("cloud-hypervisor", "virtiofsd"),
    "macos": ("e2fsprogs", "git"),
}
PIN_SECTIONS = {"schema", "kernel_builder", "kernel_bc", "guest_root_builder", "initramfs_inputs",
                "linux_runtime", "cw_runtime_builder", "sources"}
# The guest root's static inputs for each Rust target it is built for.
GUEST_TARGETS = ("aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl")
# The Linux target's host programs: lock key -> the release artifact
# admission requires (crates/codewire-local-vmm/src/artifact.rs).
LINUX_RUNTIME = {"cloud_hypervisor": "v54.0", "virtiofsd": "v1.14.0"}
TIMEOUT = 120


class SourcesError(Exception):
    pass


class SourcesUnavailable(SourcesError):
    """A host did not answer with the bytes: the next mirror may. A wrong
    SHA-256 is a SourcesError, which no mirror overrides."""


def require(condition, reason):
    if not condition:
        raise SourcesError(reason)


def load_pins(path=PINS):
    pins = json.loads(Path(path).read_bytes())
    require(isinstance(pins, dict) and pins.get("schema") == SCHEMA and set(pins) == PIN_SECTIONS,
            "local runtime source pins are not the expected shape")
    inputs = pins["initramfs_inputs"]
    require(isinstance(inputs, dict) and set(inputs) == set(GUEST_TARGETS), "guest root inputs are not per target")
    for target, entry in inputs.items():
        require(isinstance(entry, dict) and set(entry) == {"busybox", "runc"}
                and https_pin(entry["busybox"]) and https_pin(entry["runc"])
                and isinstance(entry["busybox"].get("member"), str)
                and release.is_hex(entry["busybox"].get("member_sha256"), 64),
                f"guest root inputs for {target} must pin HTTPS URLs and SHA-256s")
    executables = pins["linux_runtime"]
    require(isinstance(executables, dict) and set(executables) == set(LINUX_RUNTIME),
            "Linux runtime executables are not the pinned set")
    for name, entry in executables.items():
        require(https_pin(entry) and entry.get("version") == LINUX_RUNTIME[name]
                and str(entry.get("release", "")).startswith("https://"), f"Linux runtime {name} pin is invalid")
        if "member" in entry:
            require(isinstance(entry["member"], str) and release.is_hex(entry.get("member_sha256"), 64)
                    and bounded(entry.get("member_size")), f"Linux runtime {name} archive member pin is invalid")
        else:
            require(bounded(entry.get("size")), f"Linux runtime {name} pin has no size")
    builder = pins["cw_runtime_builder"]
    require(isinstance(builder, dict) and https_pin(builder.get("zig", {}))
            and release._runtime_text(builder.get("cargo_zigbuild"), "."), "cw runtime builder pins are invalid")
    sources = pins["sources"]
    require(set(sources) == {name for names in SIDES.values() for name in names}, "pinned sources are not the set")
    for name, source in sources.items():
        require(release._runtime_text(name, "-_.") and release._runtime_text(source.get("version"), "-_.+")
                and release._runtime_text(source.get("license"), "-_.+ ()"), f"source {name} identity is invalid")
        if "url" in source:
            require(https_pin(source), f"source {name} must pin an HTTPS URL and its SHA-256")
        elif "aports" in source:
            aports = source["aports"]
            require(release.is_hex(aports.get("commit"), 40) and aports.get("files")
                    and all(release._runtime_text(file, "-_.") and release.is_hex(digest, 64)
                            for file, digest in aports["files"].items()), f"source {name} aports pins are invalid")
            bases = aports_bases(aports)
            require(all(isinstance(base, str) and base.startswith("https://") and not base.endswith("/")
                        for base in bases) and len(set(bases)) == len(bases),
                    f"source {name} aports hosts must be distinct HTTPS bases")
        else:
            require(source.get("from") == "kernel-build", f"source {name} has no origin")
    return pins


def https_pin(entry):
    return (isinstance(entry, dict) and str(entry.get("url", "")).startswith("https://")
            and release.is_hex(entry.get("sha256"), 64))


def bounded(size):
    return type(size) is int and 0 < size <= release.MAX_OBJECT


def file_name(name, source):
    if "url" in source:
        return urllib.parse.urlparse(source["url"]).path.rsplit("/", 1)[-1]
    if "aports" in source:
        return f"{name}-{source['version']}.tar"
    return "linux-source.tar.xz"


def download(url, digest, limit=release.MAX_OBJECT):
    """HTTPS bytes that must hash to `digest`; redirects are followed.

    The request carries urllib's own user agent: Alpine's GitLab serves a bot
    challenge to agents it does not recognize, a custom one included, and
    answers 418 when the challenge is not passed.
    """
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as response:
            require(response.geturl().startswith("https://"), f"{url} redirected off HTTPS")
            data = response.read(limit + 1)
    except OSError as error:
        raise SourcesUnavailable(f"{url}: {error}") from None
    require(len(data) <= limit, f"{url} exceeds its bound")
    require(hashlib.sha256(data).hexdigest() == digest, f"{url} differs from its pinned SHA-256")
    return data


def aports_bases(aports):
    """Alpine's aports host, then its mirrors, in the order they are tried."""
    return [aports.get("base"), *aports.get("mirrors", [])]


def aports_file(aports, file, fetch, down):
    """One pinned aports file from the first host that serves it.

    Only an unavailable host passes to the next one, and it joins `down`, so
    the rest of one tar never waits on it again: a dead host costs one
    timeout, not one per file. Bytes that differ from the pin are refused
    wherever they come from: the pinned SHA-256 alone admits a file,
    whichever host served it.
    """
    unavailable = []
    for base in aports_bases(aports):
        if base in down:
            continue
        url = f"{base}/{aports['commit']}/{aports['path']}/{urllib.parse.quote(file)}"
        try:
            return fetch(url, aports["files"][file])
        except SourcesUnavailable as error:
            down.add(base)
            unavailable.append(str(error))
    raise SourcesUnavailable(f"no aports host served {file}: {'; '.join(unavailable) or 'every host is down'}")


def aports_tar(name, source, fetch=download):
    """Alpine's pinned build files for a package as one deterministic tar."""
    aports = source["aports"]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        down = set()
        for file in sorted(aports["files"]):
            data = aports_file(aports, file, fetch, down)
            info = tarfile.TarInfo(f"{name}-{source['version']}/{file}")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def fetch_side(side, output, kernel=None, pins=None, fetch=download):
    """Write one side's sources and components.json into a fresh `output`."""
    pins = pins or load_pins()
    require(side in SIDES, "unknown side")
    output = Path(output)
    output.mkdir(mode=0o700)
    components = []
    for name in SIDES[side]:
        source = pins["sources"][name]
        target = file_name(name, source)
        if "url" in source:
            data = fetch(source["url"], source["sha256"])
        elif "aports" in source:
            data = aports_tar(name, source, fetch)
        else:
            require(kernel is not None, "the linux side needs --kernel, the kernel build's output")
            data = release.read_regular(Path(kernel) / target, release.MAX_OBJECT)
        require(0 < len(data) <= release.MAX_OBJECT, f"{name} source is out of bounds")
        release.write_new(output / target, data)
        components.append({"name": name, "version": source["version"], "license": source["license"],
                           "file": target})
    release.write_new(output / "components.json", release.canonical(components))
    return components


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--side", required=True, choices=sorted(SIDES))
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--kernel", type=Path, help="build-runtime-kernel.sh output (linux side)")
    sub.add_parser("check")
    args = parser.parse_args(argv)
    try:
        pins = load_pins()
        if args.command == "fetch":
            components = fetch_side(args.side, args.output, args.kernel, pins)
            for component in components:
                print(f"local-runtime-source: {component['name']} {component['version']} {component['file']}")
        else:
            print(f"local-runtime-sources: {len(pins['sources'])} sources pinned")
    except (SourcesError, release.ReleaseError, OSError, ValueError) as error:
        print(f"local-runtime-sources: REJECT {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
