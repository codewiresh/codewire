#!/usr/bin/env python3
"""Publish one SDK version to npm or PyPI, once.

usage: publish-sdk.py npm DIST_DIR TOKEN_FILE
       publish-sdk.py pypi DIST_DIR TOKEN_FILE

DIST_DIR holds what package-sdk-ts.sh or package-sdk-python.sh wrote: one
codewire-sdk-VERSION.tgz, or one codewire-VERSION.tar.gz and one wheel.
TOKEN_FILE holds the registry token the OpenBao reader wrote; it is read into
memory and handed only to the upload, never printed or put in an argument.

A version that the registry already has is refused before any upload, since
neither registry lets a published version be replaced. After the upload the
registry is read back until it serves every file this run uploaded.
"""

from __future__ import annotations

import base64
import email.parser
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile

NPM_PACKAGE = "@codewire/sdk"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_PROJECT = "codewire"
PYPI_UPLOAD = "https://upload.pypi.org/legacy/"
PYPI_JSON = "https://pypi.org/pypi"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
READBACK_SECONDS = 300

# Core-metadata fields a distribution may repeat, with the name PyPI's upload
# form gives each; every other field is single and named by its header.
MULTI_FIELDS = {
    "classifier": "classifiers",
    "dynamic": "dynamic",
    "license-file": "license_files",
    "obsoletes-dist": "obsoletes_dist",
    "platform": "platform",
    "project-url": "project_urls",
    "provides-dist": "provides_dist",
    "provides-extra": "provides_extra",
    "requires-dist": "requires_dist",
    "requires-external": "requires_external",
    "supported-platform": "supported_platform",
}


def fail(message: str) -> None:
    raise SystemExit(f"[publish-sdk] ERROR: {message}")


def note(message: str) -> None:
    print(f"[publish-sdk] {message}", flush=True)


def read_token(path: pathlib.Path, pattern: str) -> str:
    token = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(pattern, token):
        fail(f"the token in {path.name} is not the expected registry token")
    return token


def http_status(url: str) -> int:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        with error:
            return error.code


def read_json(url: str) -> dict | None:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            if error.code == 404:
                return None
            raise


def wait_for(description: str, ready) -> None:
    deadline = time.monotonic() + READBACK_SECONDS
    while not ready():
        if time.monotonic() > deadline:
            fail(f"the registry did not serve {description} within {READBACK_SECONDS} s")
        time.sleep(10)
    note(f"the registry serves {description}")


def only(paths: list[pathlib.Path], what: str) -> pathlib.Path:
    if len(paths) != 1:
        fail(f"expected exactly one {what}, found {len(paths)}")
    return paths[0]


def publish_npm(dist: pathlib.Path, token_file: pathlib.Path) -> None:
    tarball = only(sorted(dist.glob("codewire-sdk-*.tgz")), "codewire-sdk-VERSION.tgz")
    version = tarball.name.removeprefix("codewire-sdk-").removesuffix(".tgz")
    if not VERSION.fullmatch(version):
        fail(f"{tarball.name} does not name a MAJOR.MINOR.PATCH version")
    with tarfile.open(tarball) as archive:
        manifest = json.load(archive.extractfile("package/package.json"))
    if manifest.get("name") != NPM_PACKAGE or manifest.get("version") != version:
        fail(f"{tarball.name} is not {NPM_PACKAGE}@{version}")

    package_url = f"{NPM_REGISTRY}/{NPM_PACKAGE.replace('/', '%2f')}"
    if http_status(f"{package_url}/{version}") == 200:
        fail(f"{NPM_PACKAGE}@{version} is already published; raise the version")

    token = read_token(token_file, r"npm_[A-Za-z0-9]{36}")
    with tempfile.TemporaryDirectory(prefix="codewire-npm-publish.") as work:
        userconfig = pathlib.Path(work) / "npmrc"
        # npm expands ${NPM_TOKEN} itself, so the token reaches only its environment.
        userconfig.write_text("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", encoding="ascii")
        userconfig.chmod(0o600)
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith(("NPM_CONFIG_", "npm_config_")) and name != "NPM_TOKEN"
        }
        environment |= {"NPM_TOKEN": token, "NPM_CONFIG_USERCONFIG": str(userconfig)}
        token = ""
        subprocess.run(
            ["npm", "publish", str(tarball), "--access", "public", "--registry", f"{NPM_REGISTRY}/"],
            check=True,
            env=environment,
        )
        environment.clear()
    wait_for(f"{NPM_PACKAGE}@{version}", lambda: http_status(f"{package_url}/{version}") == 200)


def distribution_metadata(path: pathlib.Path) -> tuple[email.message.Message, str, str]:
    """Return the archive's core metadata, its upload filetype and pyversion."""
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", name)]
            text = archive.read(only([pathlib.Path(name) for name in names], "wheel METADATA").as_posix())
        tag = path.name.removesuffix(".whl").split("-")[-3]
        return email.parser.BytesParser().parsebytes(text), "bdist_wheel", tag
    with tarfile.open(path) as archive:
        names = [name for name in archive.getnames() if re.fullmatch(r"[^/]+/PKG-INFO", name)]
        text = archive.extractfile(only([pathlib.Path(name) for name in names], "sdist PKG-INFO").as_posix()).read()
    return email.parser.BytesParser().parsebytes(text), "sdist", "source"


def upload_form(path: pathlib.Path) -> list[tuple[str, str]]:
    metadata, filetype, pyversion = distribution_metadata(path)
    content = path.read_bytes()
    fields = [
        (":action", "file_upload"),
        ("protocol_version", "1"),
        ("filetype", filetype),
        ("pyversion", pyversion),
        ("sha256_digest", hashlib.sha256(content).hexdigest()),
        ("blake2_256_digest", hashlib.blake2b(content, digest_size=32).hexdigest()),
    ]
    for header, value in metadata.items():
        key = header.lower()
        fields.append((MULTI_FIELDS.get(key, key.replace("-", "_")), str(value)))
    body = metadata.get_payload()
    if body and body.strip() and "Description" not in metadata:
        fields.append(("description", body))
    return fields


def post_upload(path: pathlib.Path, token: str) -> None:
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in upload_form(path):
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="content"; filename="{path.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n".encode()
        + path.read_bytes()
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    credential = base64.b64encode(f"__token__:{token}".encode()).decode()
    request = urllib.request.Request(
        PYPI_UPLOAD,
        data=b"".join(parts),
        method="POST",
        headers={
            "Authorization": f"Basic {credential}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "codewire-publish-sdk",
        },
    )
    credential = ""
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            note(f"PyPI accepted {path.name} ({response.status})")
    except urllib.error.HTTPError as error:
        # PyPI's reason names the refused field; it never echoes the token.
        fail(f"PyPI refused {path.name}: {error.code} {error.reason}")


def publish_pypi(dist: pathlib.Path, token_file: pathlib.Path) -> None:
    sdist = only(sorted(dist.glob(f"{PYPI_PROJECT}-*.tar.gz")), f"{PYPI_PROJECT}-VERSION.tar.gz")
    wheel = only(sorted(dist.glob(f"{PYPI_PROJECT}-*.whl")), f"{PYPI_PROJECT} wheel")
    version = sdist.name.removeprefix(f"{PYPI_PROJECT}-").removesuffix(".tar.gz")
    if not VERSION.fullmatch(version):
        fail(f"{sdist.name} does not name a MAJOR.MINOR.PATCH version")
    for path in (sdist, wheel):
        metadata, _, _ = distribution_metadata(path)
        if metadata["Name"] != PYPI_PROJECT or metadata["Version"] != version:
            fail(f"{path.name} is not {PYPI_PROJECT} {version}")

    if read_json(f"{PYPI_JSON}/{PYPI_PROJECT}/{version}/json") is not None:
        fail(f"{PYPI_PROJECT} {version} is already published; raise the version")

    token = read_token(token_file, r"pypi-[A-Za-z0-9_-]{50,500}")
    for path in (sdist, wheel):
        post_upload(path, token)
    token = ""

    def served() -> bool:
        release = read_json(f"{PYPI_JSON}/{PYPI_PROJECT}/{version}/json")
        names = {entry["filename"] for entry in (release or {}).get("urls", [])}
        return {sdist.name, wheel.name} <= names

    wait_for(f"{PYPI_PROJECT} {version}", served)


def main(argv: list[str]) -> None:
    if len(argv) != 3 or argv[0] not in {"npm", "pypi"}:
        raise SystemExit("usage: publish-sdk.py npm|pypi DIST_DIR TOKEN_FILE")
    registry, dist, token_file = argv[0], pathlib.Path(argv[1]), pathlib.Path(argv[2])
    if not dist.is_dir():
        fail(f"{dist} is not a directory")
    if not token_file.is_file() or token_file.stat().st_mode & 0o077:
        fail("the token file must exist and be private to its owner")
    (publish_npm if registry == "npm" else publish_pypi)(dist, token_file)


if __name__ == "__main__":
    main(sys.argv[1:])
