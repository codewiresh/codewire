#!/usr/bin/env python3
"""Synthetic proof for publish-sdk.py against local stand-ins for npm and PyPI."""

from __future__ import annotations

import base64
import contextlib
import email.parser
import email.policy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import unittest.mock
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("publish_sdk", ROOT / "scripts/ci/release/publish-sdk.py")
publish_sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish_sdk)

# Assembled at run time so no token-shaped literal is committed for scanners.
NPM_TOKEN = "npm_" + "A" * 36
PYPI_TOKEN = "pypi-" + "A" * 60
METADATA = """Metadata-Version: 2.4
Name: codewire
Version: 0.1.0
Summary: Codewire SDK
Project-URL: Homepage, https://codewire.example
Project-URL: Repository, https://git.example
License-Expression: MIT
License-File: LICENSE
Requires-Python: >=3.10
Requires-Dist: connectrpc==0.11.1
Requires-Dist: protobuf==7.35.1
Provides-Extra: test
Description-Content-Type: text/markdown

# codewire

The readme.
"""


class Registry:
    """npm's version document and PyPI's upload and JSON endpoints."""

    def __init__(self) -> None:
        self.npm_published: set[str] = set()
        self.pypi_files: list[str] = []
        self.uploads: list[tuple[str, dict[str, list[str]], bytes]] = []


def handler_for(registry: Registry):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

        def reply(self, status: int, body: dict | None = None) -> None:
            data = json.dumps(body or {}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path.startswith("/npm/@codewire%2fsdk/"):
                version = self.path.rsplit("/", 1)[-1]
                self.reply(200 if version in registry.npm_published else 404)
            elif self.path == "/pypi/codewire/0.1.0/json":
                if registry.pypi_files:
                    self.reply(200, {"urls": [{"filename": name} for name in registry.pypi_files]})
                else:
                    self.reply(404)
            else:
                self.reply(404)

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                f"Content-Type: {self.headers['Content-Type']}\r\n\r\n".encode() + body)
            fields: dict[str, list[str]] = {}
            content, filename = b"", ""
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if name == "content":
                    content, filename = part.get_payload(decode=True), part.get_filename()
                else:
                    fields.setdefault(name, []).append(part.get_payload(decode=True).decode())
            registry.uploads.append((self.headers["Authorization"], fields, content))
            registry.pypi_files.append(filename)
            self.reply(200)

    return Handler


def make_artifacts(dist: pathlib.Path, name: str = "codewire") -> None:
    package = json.dumps({"name": "@codewire/sdk", "version": "0.1.0"}).encode()
    with tarfile.open(dist / "codewire-sdk-0.1.0.tgz", "w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(package)
        archive.addfile(info, io.BytesIO(package))
    metadata = METADATA.replace("Name: codewire", f"Name: {name}").encode()
    with tarfile.open(dist / "codewire-0.1.0.tar.gz", "w:gz") as archive:
        info = tarfile.TarInfo("codewire-0.1.0/PKG-INFO")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
    with zipfile.ZipFile(dist / "codewire-0.1.0-py3-none-any.whl", "w") as archive:
        archive.writestr("codewire/__init__.py", "")
        archive.writestr("codewire-0.1.0.dist-info/METADATA", metadata)


class PublishSdkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="test-publish-sdk."))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.work)], check=True)
        self.registry = Registry()
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.registry))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        for name, value in {"NPM_REGISTRY": f"{base}/npm", "PYPI_UPLOAD": f"{base}/legacy/",
                            "PYPI_JSON": f"{base}/pypi", "READBACK_SECONDS": 5}.items():
            patcher = unittest.mock.patch.object(publish_sdk, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(publish_sdk.time, "sleep", lambda _: None)
        patcher.start()
        self.addCleanup(patcher.stop)

        # A stand-in npm that records its arguments, environment and config,
        # then makes the version appear in the local registry.
        self.npm_log = self.work / "npm.json"
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        fake_npm = bin_dir / "npm"
        fake_npm.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys, urllib.request\n"
            "config = pathlib.Path(os.environ['NPM_CONFIG_USERCONFIG']).read_text()\n"
            f"pathlib.Path({str(self.npm_log)!r}).write_text(json.dumps("
            "{'argv': sys.argv[1:], 'token': os.environ.get('NPM_TOKEN'), 'config': config}))\n"
            f"pathlib.Path({str(self.work / 'npm-published')!r}).touch()\n"
        )
        fake_npm.chmod(0o755)
        patcher = unittest.mock.patch.dict(os.environ, {"PATH": f"{bin_dir}:{os.environ['PATH']}"})
        patcher.start()
        self.addCleanup(patcher.stop)
        original_status = publish_sdk.http_status

        def status(url: str) -> int:
            if (self.work / "npm-published").exists():
                self.registry.npm_published.add("0.1.0")
            return original_status(url)

        patcher = unittest.mock.patch.object(publish_sdk, "http_status", status)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.dist = self.work / "dist"
        self.dist.mkdir()
        make_artifacts(self.dist)

    def token_file(self, token: str, mode: int = 0o600) -> pathlib.Path:
        path = self.work / "token"
        path.write_text(token)
        path.chmod(mode)
        return path

    def run_publish(self, registry: str, token: str, mode: int = 0o600) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            publish_sdk.main([registry, str(self.dist), str(self.token_file(token, mode))])
        return output.getvalue()

    def test_npm_publishes_once_with_the_token_only_in_npms_environment(self) -> None:
        output = self.run_publish("npm", NPM_TOKEN)
        record = json.loads(self.npm_log.read_text())
        self.assertEqual(record["argv"][0], "publish")
        self.assertTrue(record["argv"][1].endswith("codewire-sdk-0.1.0.tgz"))
        self.assertIn("--access", record["argv"])
        self.assertEqual(record["token"], NPM_TOKEN)
        self.assertNotIn(NPM_TOKEN, " ".join(record["argv"]) + record["config"] + output)
        self.assertIn("${NPM_TOKEN}", record["config"])
        self.assertIn("serves @codewire/sdk@0.1.0", output)

    def test_npm_refuses_a_published_version_before_reading_the_token(self) -> None:
        self.registry.npm_published.add("0.1.0")
        with self.assertRaisesRegex(SystemExit, "already published"):
            self.run_publish("npm", "not-a-token")
        self.assertFalse(self.npm_log.exists())

    def test_pypi_uploads_the_sdist_and_wheel_with_their_own_metadata(self) -> None:
        output = self.run_publish("pypi", PYPI_TOKEN)
        self.assertEqual(self.registry.pypi_files, ["codewire-0.1.0.tar.gz", "codewire-0.1.0-py3-none-any.whl"])
        expected_auth = "Basic " + base64.b64encode(f"__token__:{PYPI_TOKEN}".encode()).decode()
        for (auth, fields, content), filetype, pyversion in zip(
                self.registry.uploads, ["sdist", "bdist_wheel"], ["source", "py3"]):
            self.assertEqual(auth, expected_auth)
            self.assertEqual(fields[":action"], ["file_upload"])
            self.assertEqual(fields["filetype"], [filetype])
            self.assertEqual(fields["pyversion"], [pyversion])
            self.assertEqual(fields["name"], ["codewire"])
            self.assertEqual(fields["version"], ["0.1.0"])
            self.assertEqual(fields["metadata_version"], ["2.4"])
            self.assertEqual(fields["requires_dist"], ["connectrpc==0.11.1", "protobuf==7.35.1"])
            self.assertEqual(fields["project_urls"], ["Homepage, https://codewire.example",
                                                      "Repository, https://git.example"])
            self.assertEqual(fields["license_files"], ["LICENSE"])
            self.assertEqual(fields["provides_extra"], ["test"])
            self.assertEqual(fields["description_content_type"], ["text/markdown"])
            self.assertIn("The readme.", fields["description"][0])
            self.assertEqual(fields["sha256_digest"], [hashlib.sha256(content).hexdigest()])
        self.assertNotIn(PYPI_TOKEN, output)
        self.assertIn("serves codewire 0.1.0", output)

    def test_pypi_refuses_a_published_version_and_another_project(self) -> None:
        self.registry.pypi_files.append("codewire-0.1.0.tar.gz")
        with self.assertRaisesRegex(SystemExit, "already published"):
            self.run_publish("pypi", PYPI_TOKEN)
        self.assertEqual(self.registry.uploads, [])
        self.registry.pypi_files.clear()
        for path in self.dist.iterdir():
            path.unlink()
        make_artifacts(self.dist, name="other")
        with self.assertRaisesRegex(SystemExit, "is not codewire 0.1.0"):
            self.run_publish("pypi", PYPI_TOKEN)
        self.assertEqual(self.registry.uploads, [])

    def test_a_malformed_or_shared_token_file_is_refused(self) -> None:
        with self.assertRaisesRegex(SystemExit, "not the expected registry token"):
            self.run_publish("npm", PYPI_TOKEN)
        with self.assertRaisesRegex(SystemExit, "not the expected registry token"):
            self.run_publish("pypi", NPM_TOKEN)
        with self.assertRaisesRegex(SystemExit, "private to its owner"):
            self.run_publish("pypi", PYPI_TOKEN, mode=0o644)
        self.assertFalse(self.npm_log.exists())
        self.assertEqual(self.registry.uploads, [])


if __name__ == "__main__":
    unittest.main()
