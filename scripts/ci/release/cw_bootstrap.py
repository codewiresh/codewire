#!/usr/bin/env python3
"""Fixed public cw bootstrap; install only an admitted signed native payload."""

import argparse
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import cw_release as release

ORIGIN = "https://releases.codewire.sh/"
MAX_HEADER = 16 * 1024
REQUEST_SECONDS = 60


def production_key_bytes():
    return release.read_regular(Path(__file__).resolve().parents[3] / "apps/cli/GPG_PUBLIC_KEY.asc", 64 * 1024)


def setup():
    release.require(sys.version_info >= (3, 8), "Python3.8 or newer is required before installing cw")
    release.require(shutil.which("gpg") is not None,
                    "GnuPG is required; install gpg before running this installer")
    release.require(shutil.which("curl") is not None,
                    "curl is required; install curl before running this installer")


def target_for(system, machine):
    targets = {
        ("Linux", "x86_64"): "x86_64-unknown-linux-musl",
        ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
        ("Linux", "arm64"): "aarch64-unknown-linux-gnu",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Darwin", "aarch64"): "aarch64-apple-darwin",
    }
    release.require((system, machine) in targets, "unsupported operating system or architecture")
    return targets[system, machine]


def admitted_key(key):
    return (key == release.channel_key("stable")
            or re.fullmatch(r"cw/v1/blobs/sha256/[0-9a-f]{64}", key) is not None
            or re.fullmatch(r"cw/v1/releases/v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?/"
                            r"(?:release\.json(?:\.asc)?|SHA256SUMS(?:\.asc)?)", key) is not None)


def response_header(raw, cap, expected):
    lines = raw.decode("iso-8859-1").split("\r\n")
    release.require(re.fullmatch(r"HTTP/(?:1\.[01]|2|3) 200(?: .*)?", lines[0]) is not None,
                    "public release request did not return unredirected HTTP200")
    headers = {}
    for line in lines[1:]:
        release.require(":" in line and not line.startswith((" ", "\t")), "malformed response headers")
        name, value = line.split(":", 1)
        headers.setdefault(name.lower(), []).append(value.strip())
    release.require(all(value == "identity" for value in headers.get("content-encoding", [])),
                    "public release response must not be content-encoded")
    lengths = headers.get("content-length", [])
    release.require(len(lengths) <= 1, "public release response has ambiguous Content-Length")
    if lengths:
        release.require(re.fullmatch(r"[0-9]+", lengths[0]) is not None, "invalid response length")
        size = int(lengths[0])
        release.require(0 < size <= cap and (expected is None or size == expected["size"]),
                        "response length differs from its bound or signed size")


class FixedReader:
    """Own and reap one anonymous curl request; cap headers, body and elapsed time."""

    def read(self, key, cap, expected=None):
        release.require(admitted_key(key), "release object key is outside the closed public routes")
        curl = shutil.which("curl")
        release.require(curl is not None, "curl is required")
        command = [curl, "--disable", "--fail", "--silent", "--show-error", "--include",
                   "--proto", "=https", "--proxy", "", "--noproxy", "*",
                   "--connect-timeout", "5", "--max-time", str(REQUEST_SECONDS),
                   "--max-filesize", str(cap), "--header", "Accept-Encoding: identity", ORIGIN + key]
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL,
                                 env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"})
        deadline = time.monotonic() + REQUEST_SECONDS + 5
        header, data, ready = bytearray(), bytearray(), False
        try:
            os.set_blocking(child.stdout.fileno(), False)
            with selectors.DefaultSelector() as poll:
                poll.register(child.stdout, selectors.EVENT_READ)
                eof = False
                while not eof:
                    release.require(time.monotonic() < deadline, "public release request exceeded its deadline")
                    for _, _ in poll.select(min(0.05, max(0, deadline - time.monotonic()))):
                        chunk = os.read(child.stdout.fileno(), 64 * 1024)
                        if not chunk:
                            eof = True
                            break
                        if not ready:
                            header.extend(chunk)
                            end = header.find(b"\r\n\r\n")
                            if end < 0:
                                release.require(len(header) <= MAX_HEADER, "response headers exceed their bound")
                                continue
                            release.require(end <= MAX_HEADER, "response headers exceed their bound")
                            response_header(bytes(header[:end]), cap, expected)
                            chunk = bytes(header[end + 4:])
                            header.clear()
                            ready = True
                        release.require(len(chunk) <= cap - len(data), "public release object exceeds its bound")
                        data.extend(chunk)
            status = child.wait(timeout=max(0.01, deadline - time.monotonic()))
            release.require(status == 0 and ready and data, "public release transport failed")
            return bytes(data)
        finally:
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise release.ReleaseError("public release child cleanup is unknown") from None
            child.stdout.close()


def fetch(reader, key, cap, expected=None):
    if expected is not None:
        release.validate_ref(expected, key)
        release.require(expected["size"] <= cap, "signed object exceeds its metadata bound")
    data = reader.read(key, cap, expected)
    release.require(0 < len(data) <= cap, "public release object exceeds its bound")
    if expected is not None:
        release.require(release.object_ref(key, data) == expected, "public object differs from its signed reference")
    return data


def selected_payload(reader, trust, target, version=None):
    pointer = None
    if version is None:
        pointer = release.verify_channel(fetch(reader, release.channel_key("stable"), release.MAX_JSON), trust)
        version = pointer["release_tag"]
    release.require(release.valid_version(version) and release.release_version(version),
                    "version must be vMAJOR.MINOR.PATCH, optionally with a prerelease")
    manifest_bytes = fetch(reader, release.release_key(version, "release.json"), release.MAX_JSON,
                           pointer["release"] if pointer else None)
    manifest_sig = fetch(reader, release.release_key(version, "release.json.asc"), release.MAX_SIGNATURE,
                         pointer["release_signature"] if pointer else None)
    sums = fetch(reader, release.release_key(version, "SHA256SUMS"), release.MAX_JSON)
    sums_sig = fetch(reader, release.release_key(version, "SHA256SUMS.asc"), release.MAX_SIGNATURE)
    manifest = release.check_signed_release(version, manifest_bytes, manifest_sig, sums, sums_sig, trust)
    ordered = sorted(manifest["targets"], key=lambda entry: entry["asset_name"])
    expected_sums = "".join(f"{entry['identity']['sha256']}  {entry['asset_name']}\n" for entry in ordered).encode("ascii")
    release.require(sums == expected_sums, "SHA256SUMS does not list exactly the four manifest assets")
    entry = next(entry for entry in manifest["targets"] if entry["target"] == target)
    data = fetch(reader, entry["executable"]["key"], release.MAX_EXECUTABLE, entry["executable"])
    actual = release.make_identity(data, target, version, manifest["source_revision"],
                                   manifest["source_tree_sha256"], manifest["rustc"])
    release.require(actual == entry["identity"], "payload differs from its signed compiled identity")
    return data, actual


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_ok(info):
    return stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()) and info.st_mode & 0o022 == 0


def destination(fd):
    try:
        info = os.stat("cw", dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid in (0, os.geteuid()) and info.st_mode & 0o6022 == 0,
                    "existing cw is not an owner-controlled regular file")
    return stamp(info)


def atomic_install(data, install_dir):
    """Stage in the held destination directory; rename is the sole commit point."""
    install_dir = Path(os.path.abspath(install_dir))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    held, links, temporary, committed = [], [], None, False
    try:
        held.append(os.open("/", flags))
        release.require(directory_ok(os.fstat(held[-1])), "install directory root is not controlled")
        for part in install_dir.parts[1:]:
            parent = held[-1]
            try:
                os.mkdir(part, 0o755, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=parent)
            held.append(child)
            release.require(directory_ok(os.fstat(child)), "install directory is writable by another owner")
            links.append((parent, part, child))
        fd = held[-1]
        before = destination(fd)
        candidate = f".cw-install-{uuid.uuid4().hex}"
        stage = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=fd)
        temporary = candidate
        with os.fdopen(stage, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), 0o755)
            os.fsync(handle.fileno())
        for parent, name, child in links:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            current = os.fstat(child)
            release.require(directory_ok(named) and directory_ok(current)
                            and (named.st_dev, named.st_ino) == (current.st_dev, current.st_ino),
                            "install directory changed before replacement")
        release.require(destination(fd) == before, "existing cw changed before replacement")
        os.replace(temporary, "cw", src_dir_fd=fd, dst_dir_fd=fd)
        committed, temporary = True, None
        try:
            os.fsync(fd)
        except OSError:
            raise release.ReleaseError("cw was atomically replaced, but directory durability is unconfirmed") from None
    finally:
        if temporary is not None and held:
            os.unlink(temporary, dir_fd=held[-1])
        for fd in reversed(held):
            os.close(fd)
    return committed


def install(reader, trust, target, install_dir, version=None):
    data, identity = selected_payload(reader, trust, target, version)
    atomic_install(data, install_dir)
    return identity


def main(argv=None):
    parser = argparse.ArgumentParser(description="Install a signed native cw from releases.codewire.sh")
    parser.add_argument("--version", help="exact release tag; default: signed stable channel")
    parser.add_argument("--prefix", help="install to DIR/bin; default: /usr/local/bin or ~/.local/bin")
    parser.add_argument("--verbose", action="store_true", help="show admitted public release identity")
    args = parser.parse_args(argv)
    try:
        setup()
        target = target_for(platform.system(), platform.machine())
        if args.version is not None:
            release.require(release.valid_version(args.version) and release.release_version(args.version),
                            "version must be an exact release tag")
        install_dir = (Path(args.prefix) / "bin" if args.prefix is not None else
                       Path("/usr/local/bin") if os.access("/usr/local/bin", os.W_OK) else
                       Path.home() / ".local/bin")
        with tempfile.TemporaryDirectory(prefix="cw-install.") as home:
            os.chmod(home, 0o700)
            key = Path(home) / "GPG_PUBLIC_KEY.asc"
            release.write_new(key, production_key_bytes(), 0o600)
            trust = release.Trust(key, release.PRODUCTION_FINGERPRINT)
            identity = install(FixedReader(), trust, target, install_dir, args.version)
        print(f"==> Installed cw {identity['package_version']} to {install_dir / 'cw'}")
        if args.verbose:
            print(f"    target={identity['target']} sha256={identity['sha256']} size={identity['size']}")
        if str(install_dir) not in os.environ.get("PATH", "").split(os.pathsep):
            print(f"NOTE: add {install_dir} to your PATH")
        return 0
    except KeyboardInterrupt:
        print("cw install: interrupted", file=sys.stderr)
        return 130
    except (release.ReleaseError, OSError, subprocess.SubprocessError, ValueError, TypeError,
            KeyError, RecursionError, StopIteration, struct.error) as error:
        reason = str(error) if isinstance(error, release.ReleaseError) else type(error).__name__
        print(f"cw install: REJECT {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    raise SystemExit(main())
