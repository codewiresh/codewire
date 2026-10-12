"""Synthetic, credential-free fixtures for the cw release delivery tests.

Executables are header-correct byte strings carrying one closed build record,
and are never run. The OpenPGP key is generated per test run in a private home
and is never production trust. FakeR2 is an in-process S3 double with R2's
conditional-write semantics and injectable faults; nothing opens a network
connection.
"""

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/release"))
import cw_release as release  # noqa: E402

RUSTC = "rustc 1.93.0 (synthetic 2026-01-19)"
VERSION = "v0.4.2"
REVISION = "a" * 40
TREE = "b" * 64
ACCESS_KEY = "SYNTHETICACCESSKEY0123456789ABCD"
SECRET_KEY = "SYNTHETIC-SECRET-ACCESS-KEY-NEVER-LOGGED-0123456789abcdef"


def scratch(prefix):
    parent = ROOT / ".tmp"
    parent.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=parent))


def build_record(version=VERSION, target="x86_64-unknown-linux-musl", revision=REVISION, tree=TREE,
                 rustc=RUSTC):
    """The record crates/codewire-cli/build.rs embeds, framed identically."""
    body = release.canonical({"package_version": version, "rustc": rustc, "source_revision": revision,
                              "source_tree_sha256": tree, "target": target})
    return release.BUILD_RECORD_MAGIC + struct.pack("<I", len(body)) + body


def executable(target, version=VERSION, tag=b"", static=True, revision=REVISION, tree=TREE, rustc=RUSTC,
               record=None, embedded=b""):
    """Header-correct synthetic executable carrying one build record, and
    optionally the bytes of an embedded local runtime document."""
    body = bytearray(4096 + len(embedded))
    if "linux" in target:
        machine = 62 if target.startswith("x86_64") else 183
        body[:8] = b"\x7fELF\x02\x01\x01\x00"
        struct.pack_into("<HH", body, 16, 3, machine)
        struct.pack_into("<Q", body, 32, 64)            # e_phoff
        struct.pack_into("<HH", body, 54, 56, 1)       # e_phentsize, e_phnum
        struct.pack_into("<I", body, 64, 1 if static else 3)  # PT_LOAD or PT_INTERP
    else:
        cpu = 0x01000007 if target.startswith("x86_64") else 0x0100000C
        struct.pack_into("<IIII", body, 0, 0xFEEDFACF, cpu, 0, 2)
    if record is None:
        record = build_record(version, target, revision, tree, rustc)
    body[1024:1024 + len(record)] = record
    body[3072:3072 + len(tag)] = tag
    body[4096:] = embedded
    return bytes(body)


HELPER_LIBRARIES = ("/usr/lib/libSystem.B.dylib",
                    "/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization",
                    "/usr/lib/swift/libswiftCore.dylib")


def macos_helper(libraries=HELPER_LIBRARIES, runtime=True, entitlements=None, cpu=0x0100000C, signed=True,
                 rpaths=("@loader_path",)):
    """A minimal thin Mach-O executable shaped as the VZ helper: dylib load
    commands and an embedded code signature with a CodeDirectory and an
    entitlements blob. It is never run."""
    if entitlements is None:
        entitlements = release.HELPER_ENTITLEMENTS.read_bytes()
    commands = b""
    for name in libraries:
        path = name.encode() + b"\0"
        size = (24 + len(path) + 7) // 8 * 8
        commands += struct.pack("<IIIIII", 0xC, size, 24, 2, 0x10000, 0x10000) + path.ljust(size - 24, b"\0")
    for name in rpaths:
        path = name.encode() + b"\0"
        size = (12 + len(path) + 7) // 8 * 8
        commands += struct.pack("<III", 0x8000001C, size, 12) + path.ljust(size - 12, b"\0")
    directory = struct.pack(">IIIII", 0xFADE0C02, 20, 0x20500, 0x10002 if runtime else 0x2, 0)
    granted = struct.pack(">II", 0xFADE7171, 8 + len(entitlements)) + entitlements
    index = 12 + 16
    superblob = (struct.pack(">III", 0xFADE0CC0, index + len(directory) + len(granted), 2)
                 + struct.pack(">II", 0, index) + struct.pack(">II", 5, index + len(directory)) + directory + granted)
    ncmds = len(libraries) + len(rpaths) + (1 if signed else 0)
    sizeofcmds = len(commands) + (16 if signed else 0)
    dataoff = (32 + sizeofcmds + 15) // 16 * 16
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, 0, 2, ncmds, sizeofcmds, 0, 0)
    signature_command = struct.pack("<IIII", 0x1D, 16, dataoff, len(superblob)) if signed else b""
    body = header + commands + signature_command
    return body + b"\0" * (dataoff - len(body)) + (superblob if signed else b"")


def local_runtime(revision):
    """A synthetic macOS local runtime: its canonical document and blob bytes."""
    files = {}

    def ref(name):
        data = f"synthetic {name}\n".encode()
        files[digest(data)] = data
        return {"sha256": digest(data), "size": len(data)}

    def spec(path):
        return {"path": path, "architecture": "aarch64", **ref(path)}

    helper = macos_helper()
    files[digest(helper)] = helper
    lock = {"schema_version": 1,
            "vz_runner": {"path": "codewire-vz-runner", "architecture": "aarch64", "sha256": digest(helper),
                          "size": len(helper)},
            "kernel": spec("kernel"),
            "initramfs": spec("initramfs"),
            "e2fsprogs": {name: spec(path) for name, path in (
                ("mkfs_ext4", "mkfs.ext4"), ("e2fsck", "e2fsck"), ("resize2fs", "resize2fs"),
                ("debugfs", "debugfs"), ("mke2fs_conf", "mke2fs.conf"))},
            "git": {"git": spec("git"), "git_remote_https": spec("git-remote-https")}}
    components = [{"name": "e2fsprogs", "version": "1.47.4", "license": "GPL-2.0-only",
                   "source": ref("e2fsprogs-1.47.4.tar.gz")},
                  {"name": "git", "version": "2.56.0", "license": "GPL-2.0-only", "source": ref("git-2.56.0.tar.gz")}]
    document = release.canonical({"schema": release.LOCAL_RUNTIME_SCHEMA, "source_revision": revision,
                                  "targets": {"macos-aarch64": {"lock": lock, "components": components}}})
    return document, files


def write_local_runtime(dist, document, files):
    root, document_path, blobs = release.local_runtime_paths(dist)
    blobs.mkdir(parents=True)
    document_path.write_bytes(document)
    for name, data in files.items():
        (blobs / name).write_bytes(data)


def git(root, *args):
    # Fixed dates make identical trees commit to identical revisions.
    return subprocess.check_output(["git", "-C", str(root), *args], text=True,
                                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                                        "GIT_CONFIG_SYSTEM": "/dev/null",
                                        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                                        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}).strip()


def source_repo(base, lib="pub fn demo() {}\n"):
    """A tiny committed source tree with the digest's input kinds."""
    root = base / "source"
    (root / "crates/demo/src").mkdir(parents=True)
    (root / "scripts/dev").mkdir(parents=True)
    (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.93.0"\n')
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/demo"]\n')
    (root / "Cargo.lock").write_text("version = 4\n")
    (root / "crates/demo/src/lib.rs").write_text(lib)
    (root / "crates/demo/demo.proto").write_text('syntax = "proto3";\n')
    (root / "scripts/dev/build-native-managed-agent.py").write_text("# producer\n")
    (root / "scripts/dev/cw-runtime-image.py").write_text("# image\n")
    (root / "README.md").write_text("not a digest input\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
        "commit", "-q", "-m", "synthetic source")
    return root, git(root, "rev-parse", "HEAD")


class Signer:
    """A throwaway OpenPGP signing key in a private GNUPGHOME."""

    def __init__(self, base, name="Synthetic cw release"):
        self.home = base / f"gnupg-{name.split()[-1]}"
        self.home.mkdir(mode=0o700)
        self.env = {**os.environ, "GNUPGHOME": str(self.home), "LC_ALL": "C"}
        subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                        "--quick-gen-key", f"{name} <synthetic@example.invalid>", "ed25519", "sign", "never"],
                       env=self.env, check=True, capture_output=True)
        listing = subprocess.check_output(["gpg", "--batch", "--with-colons", "--list-secret-keys"],
                                          env=self.env, text=True, stderr=subprocess.DEVNULL)
        self.fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        self.public = base / f"{self.home.name}.asc"
        self.public.write_bytes(subprocess.check_output(
            ["gpg", "--batch", "--armor", "--export", self.fingerprint], env=self.env, stderr=subprocess.DEVNULL))
        self.trust = release.Trust(self.public, self.fingerprint)

    def sign(self, data, notation=None):
        """Detached signature; a signed `notation` makes distinct valid signature bytes."""
        extra = ["--sig-notation", f"retry@example.invalid={notation}"] if notation else []
        with tempfile.TemporaryDirectory(dir=self.home) as work:
            source, signature = Path(work) / "data", Path(work) / "data.asc"
            source.write_bytes(data)
            subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
                            *extra, "--armor", "--detach-sign", "--local-user", self.fingerprint,
                            "--output", str(signature), str(source)], env=self.env, check=True, capture_output=True)
            return signature.read_bytes()

    def secret_key(self):
        return subprocess.check_output(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                                        "--armor", "--export-secret-keys", self.fingerprint],
                                       env=self.env, stderr=subprocess.DEVNULL).decode()

    def close(self):
        subprocess.run(["gpgconf", "--homedir", str(self.home), "--kill", "all"],
                       env=self.env, capture_output=True)


def package(base, source, source_sha, version=VERSION, tag=b"", embedded=b""):
    """The package script's outputs: four raw assets plus SHA256SUMS. The
    macOS arm64 cw embeds `embedded`, as build.rs embeds a local runtime."""
    dist = base / "dist"
    dist.mkdir()
    tree = release.source_tree_sha256(source)
    executables = {target: executable(target, version, tag, revision=source_sha, tree=tree,
                                      embedded=embedded if target == release.LOCAL_RUNTIME_TARGET else b"")
                   for target in release.RELEASE_TARGETS}
    for target, data in executables.items():
        (dist / release.asset_name(version, target)).write_bytes(data)
    (dist / "SHA256SUMS").write_bytes(subprocess.check_output(
        "sha256sum cw-* | sort -k2", shell=True, cwd=dist))
    return dist, executables


def unsigned_delivery(base, version=VERSION, tag=b"", lib="pub fn demo() {}\n", runtime=False):
    """Package and prepare a delivery exactly as the CLI's prepare step does."""
    source, source_sha = source_repo(base, lib)
    digest = release.source_tree_sha256(source)
    document, files = local_runtime(source_sha) if runtime else (b"", {})
    dist, executables = package(base, source, source_sha, version, tag, document)
    entries, _, tree, rustc = release.prepare(dist, version, source, source_sha, source_sha, RUSTC,
                                              source_digest_before=digest)
    state = {"version": version, "tag_object_sha": source_sha, "source_sha": source_sha,
             "source_tree": tree, "rustc": rustc, "entries": entries}
    (dist / release.DELIVERY / "prepared.json").write_bytes(release.canonical(state))
    if runtime:
        write_local_runtime(dist, document, files)
    return dist, executables, source_sha


def signed_delivery(base, signer, version=VERSION, tag=b"", lib="pub fn demo() {}\n", runtime=False):
    """A complete signed delivery, built by the same functions the CLI runs."""
    source, source_sha = source_repo(base, lib)
    digest = release.source_tree_sha256(source)
    document, files = local_runtime(source_sha) if runtime else (b"", {})
    dist, executables = package(base, source, source_sha, version, tag, document)
    entries, _, tree, rustc = release.prepare(dist, version, source, source_sha, source_sha, RUSTC,
                                              source_digest_before=digest)
    state = {"version": version, "tag_object_sha": source_sha, "source_sha": source_sha,
             "source_tree": tree, "rustc": rustc, "entries": entries}
    (dist / release.DELIVERY / "prepared.json").write_bytes(release.canonical(state))
    if runtime:
        write_local_runtime(dist, document, files)
    sign_delivery(dist, signer, version, source_sha, tree, rustc, entries)
    return dist, executables, source_sha


def sign_delivery(dist, signer, version, source_sha, tree, rustc, entries):
    paths = release.delivery_paths(dist)
    paths["sums_sig"].write_bytes(signer.sign(paths["sums"].read_bytes()))
    manifest = release.finish_manifest(dist, version, source_sha, source_sha, tree, rustc, entries,
                                       signer.fingerprint)
    paths["manifest"].write_bytes(manifest)
    paths["manifest_sig"].write_bytes(signer.sign(manifest))
    sign_channel(dist, signer, version)


def sign_channel(dist, signer, version, notation=None):
    paths = release.delivery_paths(dist)
    pointer = release.channel_pointer("stable", paths["manifest"].read_bytes(),
                                      paths["manifest_sig"].read_bytes(), version)
    paths["pointer"].parent.mkdir(exist_ok=True)
    paths["pointer"].write_bytes(release.canonical(pointer))
    paths["channel"].write_bytes(release.channel_object(pointer, signer.sign(release.canonical(pointer), notation)))


def digest(data):
    return hashlib.sha256(data).hexdigest()


class FakeR2:
    """S3 double with R2 conditional writes, ETags and injectable faults."""

    def __init__(self):
        self.objects = {}
        self.generation = 0
        self.faults = []
        self.requests = []
        self.public_missing = set()
        self.before_put = None

    def _etag(self):
        self.generation += 1
        return f'"etag-{self.generation}"'

    def store(self, key, data):
        self.objects[key] = (data, self._etag())

    def dump(self, path):
        Path(path).write_text(json.dumps({
            "generation": self.generation,
            "objects": {key: [base64.b64encode(data).decode(), etag] for key, (data, etag) in self.objects.items()},
        }))

    @classmethod
    def load(cls, path):
        fake = cls()
        state = json.loads(Path(path).read_text())
        fake.generation = state["generation"]
        fake.objects = {key: (base64.b64decode(data), etag) for key, (data, etag) in state["objects"].items()}
        return fake

    def _fault(self, method, key):
        for index, (fault_method, fault_key, mode) in enumerate(self.faults):
            if fault_method == method and fault_key == key:
                del self.faults[index]
                return mode
        return None

    def request(self, method, host, path, headers, body=None, limit=None):
        import cw_release_r2 as r2
        self.requests.append((method, host, path, dict(headers)))
        if host == r2.PUBLIC_HOST:
            key = urllib.parse.unquote(path[1:])
            if key in self.public_missing or key not in self.objects:
                return r2.Response(404, {}, b"")
            return r2.Response(200, {}, self.objects[key][0])
        assert host == r2.S3_HOST and path.startswith(f"/{r2.BUCKET}/")
        assert headers["authorization"].startswith(f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/")
        assert headers["x-amz-content-sha256"] == digest(body or b"")
        key = urllib.parse.unquote(path[len(r2.BUCKET) + 2:])
        mode = self._fault(method, key)
        if mode == "lost":
            raise r2.TransportError("synthetic timeout")
        if method == "GET":
            if key not in self.objects:
                return r2.Response(404, {}, b"")
            data, etag = self.objects[key]
            if mode == "corrupt":
                data = data[:-1] + bytes([data[-1] ^ 1])
            return r2.Response(200, {"ETag": etag}, data)
        assert method == "PUT"
        if self.before_put:
            self.before_put(self, key)
        if mode == "500":
            return r2.Response(500, {}, b"")
        current = self.objects.get(key)
        if headers.get("if-none-match") == "*" and current is not None:
            status = 412
        elif "if-match" in headers and (current is None or current[1] != headers["if-match"]):
            status = 412
        else:
            assert "if-none-match" in headers or "if-match" in headers, "unconditional PUT"
            self.store(key, body)
            status = 200
        if mode == "applied-then-lost":
            raise r2.TransportError("synthetic timeout after write")
        return r2.Response(status, {"ETag": self.objects.get(key, (b"", ""))[1]}, b"")

    def puts(self, key=None):
        return [request for request in self.requests
                if request[0] == "PUT" and (key is None or request[2].endswith(key))]
