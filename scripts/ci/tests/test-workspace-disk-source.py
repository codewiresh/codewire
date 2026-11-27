#!/usr/bin/env python3
"""Unit tests for scripts/ci/images/workspace-disk-source.py (#5638)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "scripts/ci/images/workspace-disk-source.py"
PIN_REL = Path("deployments/k8s/orchestration/workspace-systemd-image.digest")
WORKSPACE_PIN_REL = Path("crates/codewire-workspace-image/src/pin.rs")
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class WorkspaceDiskSourceTests(unittest.TestCase):
    def run_tool(
        self,
        *args: str,
        env_extra: dict[str, str | None] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        if env_extra:
            for key, value in env_extra.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = value
        return subprocess.run(
            [sys.executable, "-I", str(TOOL), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def make_fixture(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="cw-disk-src-"))
        self.addCleanup(shutil.rmtree, directory, True)
        (directory / PIN_REL).parent.mkdir(parents=True, exist_ok=True)
        (directory / WORKSPACE_PIN_REL).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / WORKSPACE_PIN_REL, directory / WORKSPACE_PIN_REL)
        (directory / PIN_REL).write_text("unpinned\n", encoding="utf-8")
        return directory

    def test_checked_in_pin_passes_check(self) -> None:
        result = self.run_tool("check")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unpinned_delegates_to_workspace_image_pin(self) -> None:
        fixture = self.make_fixture()
        env = {"CODEWIRE_IMAGE_REGISTRY": "registry.example.invalid"}
        digest = self.run_tool("--root", str(fixture), "show", "digest", env_extra=env)
        public = self.run_tool("--root", str(fixture), "show", "public-image", env_extra=env)
        harbor = self.run_tool("--root", str(fixture), "show", "harbor-image", env_extra=env)
        self.assertEqual(digest.returncode, 0, digest.stderr)
        self.assertEqual(public.returncode, 0, public.stderr)
        self.assertEqual(harbor.returncode, 0, harbor.stderr)
        pinned_digest = digest.stdout.strip()
        self.assertTrue(pinned_digest.startswith("sha256:"))
        self.assertEqual(public.stdout.strip(), f"ghcr.io/codewiresh/workspace@{pinned_digest}")
        self.assertEqual(
            harbor.stdout.strip(),
            f"registry.example.invalid/codewire/workspace@{pinned_digest}",
        )

    def test_pinned_systemd_digest_selects_workspace_systemd_repositories(self) -> None:
        fixture = self.make_fixture()
        rendered = self.run_tool("--root", str(fixture), "render", "--digest", DIGEST_A)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertEqual((fixture / PIN_REL).read_text(encoding="utf-8"), f"{DIGEST_A}\n")

        env = {"CODEWIRE_IMAGE_REGISTRY": "registry.example.invalid"}
        digest = self.run_tool("--root", str(fixture), "show", "digest", env_extra=env)
        public = self.run_tool("--root", str(fixture), "show", "public-image", env_extra=env)
        harbor = self.run_tool("--root", str(fixture), "show", "harbor-image", env_extra=env)
        self.assertEqual(digest.stdout.strip(), DIGEST_A)
        self.assertEqual(public.stdout.strip(), f"ghcr.io/codewiresh/workspace-systemd@{DIGEST_A}")
        self.assertEqual(
            harbor.stdout.strip(),
            f"registry.example.invalid/codewire/workspace-systemd@{DIGEST_A}",
        )

        # Render back to unpinned and verify delegation returns cleanly.
        reset = self.run_tool("--root", str(fixture), "render", "--unpinned")
        self.assertEqual(reset.returncode, 0, reset.stderr)
        self.assertEqual((fixture / PIN_REL).read_text(encoding="utf-8"), "unpinned\n")

    def test_harbor_image_requires_valid_registry_host(self) -> None:
        fixture = self.make_fixture()
        (fixture / PIN_REL).write_text(f"{DIGEST_B}\n", encoding="utf-8")
        for bad in (None, "", "registry.example.invalid/path", "https://registry.example.invalid"):
            result = self.run_tool(
                "--root",
                str(fixture),
                "show",
                "harbor-image",
                env_extra={"CODEWIRE_IMAGE_REGISTRY": bad},
            )
            self.assertNotEqual(result.returncode, 0, f"accepted {bad!r}")

    def test_malformed_or_symlink_pin_fails_closed(self) -> None:
        fixture = self.make_fixture()
        for bad in (
            "",
            "\n",
            "latest\n",
            f"{DIGEST_A.upper()}\n",
            f"{DIGEST_A}\n{DIGEST_B}\n",
            f"{DIGEST_A}",
        ):
            (fixture / PIN_REL).write_text(bad, encoding="utf-8")
            result = self.run_tool("--root", str(fixture), "check")
            self.assertNotEqual(result.returncode, 0, f"accepted {bad!r}")

        target = fixture / "elsewhere"
        target.write_text("unpinned\n", encoding="utf-8")
        (fixture / PIN_REL).unlink()
        (fixture / PIN_REL).symlink_to(target)
        result = self.run_tool("--root", str(fixture), "check")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
