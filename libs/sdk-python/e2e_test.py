#!/usr/bin/env python3
"""E2E tests against real Codewire infrastructure.

Requires: CODEWIRE_API_KEY, CODEWIRE_ORG_ID
Optional: CODEWIRE_BASE_URL
"""
import unittest
from codewire import Codewire


class E2EFirstParty(unittest.TestCase):
    def test_full_lifecycle(self):
        with Codewire(timeout=300) as cw:
            env = cw.environments.create(
                project_spec={
                    "schema_version": 1,
                    "preset": "python",
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
                env.remove()


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
