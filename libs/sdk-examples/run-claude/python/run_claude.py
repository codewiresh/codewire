#!/usr/bin/env python3
"""Runnable proof that the Python SDK can drive a local VM end-to-end.

Creates a Docker-backed local environment, runs
``claude -p <prompt>`` inside, prints the model's response, and tears down.

Usage::

    uv run sdk/examples/run-claude/python/run_claude.py
    # or, with requirements.lock installed:
    python sdk/examples/run-claude/python/run_claude.py

Requires: docker running, ``cw`` binary on PATH (or ``$CW_BIN`` set), and a
valid ``CLAUDE_CODE_OAUTH_TOKEN`` in ``~/.claude/.credentials.json`` (which
the CLI forwards into the container automatically).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Make the SDK importable when this script is run directly from a git clone.
_repo_python = Path(__file__).resolve().parents[3] / "sdk-python"
if str(_repo_python) not in sys.path:
    sys.path.insert(0, str(_repo_python))

from codewire import Codewire, LocalSpec  # noqa: E402

import os

DEFAULT_IMAGE = "docker.io/library/alpine:3.20"
DEFAULT_CMD = "echo hello from codewire"


def main() -> int:
    image = os.environ.get("CW_EXAMPLE_IMAGE", DEFAULT_IMAGE)
    cmdline = os.environ.get("CW_EXAMPLE_CMD", DEFAULT_CMD)

    cw = Codewire()  # no API key needed for local-only use
    with tempfile.TemporaryDirectory(prefix="cw-example-py-") as workdir:
        print("==> Creating docker local instance…")
        inst = cw.local.create(
            LocalSpec(image=image),
            backend="docker",
            path=workdir,
            wait=True,
        )
        try:
            print(f"    created {inst.name} (backend={inst.backend} status={inst.status})")
            print(f"==> Running: {cmdline}")
            res = inst.exec(command=["sh", "-c", cmdline])

            print(f"\n--- exit {res.exit_code} ---")
            print(res.stdout, end="" if res.stdout.endswith("\n") else "\n")
            print("--- end ---")

            if res.exit_code != 0:
                print("stderr:", file=sys.stderr)
                print(res.stderr, file=sys.stderr)
                return res.exit_code
            return 0
        finally:
            print("==> Removing instance…")
            inst.remove()


if __name__ == "__main__":
    sys.exit(main())
