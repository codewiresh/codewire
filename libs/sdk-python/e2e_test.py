#!/usr/bin/env python3
"""E2E tests against real Codewire infrastructure.

Requires: CODEWIRE_API_KEY, CODEWIRE_ORG_ID
Optional: CODEWIRE_BASE_URL
"""
import time
import unittest
import uuid

from codewire import Codewire
from codewire.errors import CodewireError


def remove_and_wait(cw, env, timeout=300):
    """Delete returns before the environment is destroyed, and a preset an
    environment still uses cannot be deleted, so wait until it is gone."""
    env.remove()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if cw.environments.get(env.id).state == "destroyed":
                return
        except CodewireError as error:
            if error.status == 404:
                return
            raise
        time.sleep(2)
    raise AssertionError(f"environment {env.id} was not destroyed within {timeout} s")


class E2EPreset(unittest.TestCase):
    # Presets belong to an organization, so the suite makes its own and deletes
    # it after: the account it runs as has none to begin with.
    def test_full_lifecycle(self):
        with Codewire(timeout=300) as cw:
            slug = f"sdk-e2e-{uuid.uuid4().hex[:8]}"
            preset = cw.presets.create(
                name=slug,
                slug=slug,
                project_spec={
                    "schema_version": 1,
                    "image": "python:3.12-slim",
                    "working_directory": "/workspace",
                },
            )
            try:
                self.use_preset_env(cw, slug)
            finally:
                cw.presets.delete(preset["id"])

    def use_preset_env(self, cw, slug):
        env = cw.environments.create(
            project_spec={
                "schema_version": 1,
                "preset": slug,
                "working_directory": "/workspace",
            },
            wait=True,
            wait_timeout=300,
        )
        try:
            result = env.exec(command=["python3", "--version"])
            self.assertEqual(result["exit_code"], 0)
            self.assertIn("Python", result["stdout"])

            env.files.upload(b"hello", "/workspace/test.txt")
            files = env.files.list("/workspace")
            names = [f["name"] for f in files]
            self.assertIn("test.txt", names)
            data = env.files.download("/workspace/test.txt")
            self.assertEqual(data, b"hello")
        finally:
            remove_and_wait(cw, env)


class E2EArbitraryImage(unittest.TestCase):
    def test_exec_on_arbitrary_image(self):
        with Codewire(timeout=300) as cw:
            env = cw.environments.create(
                project_spec={
                    "schema_version": 1,
                    "image": "python:3.12-slim",
                    "working_directory": "/workspace",
                },
                wait=True,
                wait_timeout=300,
            )
            try:
                result = env.exec(command=["python3", "-c", "print(1+1)"])
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["stdout"].strip(), "2")
            finally:
                env.remove()


if __name__ == "__main__":
    unittest.main()
