#!/usr/bin/env python3
"""Synthetic, credential-free tests for the live Codex JSONL boundary."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PARSER_PATH = ROOT / "dev" / "provider-codex-output.py"
WORKLOAD_PATH = ROOT / "dev" / "provider-codex-workload.sh"
SPEC = importlib.util.spec_from_file_location("provider_codex_output", PARSER_PATH)
assert SPEC and SPEC.loader
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


THREAD = "11111111-1111-4111-8111-111111111111"
USAGE = {
    "input_tokens": 10,
    "cached_input_tokens": 2,
    "cache_write_input_tokens": 0,
    "output_tokens": 4,
    "reasoning_output_tokens": 1,
}


def lifecycle(*middle: dict) -> list[dict]:
    return [
        {"type": "thread.started", "thread_id": THREAD},
        {"type": "turn.started"},
        *middle,
        {"type": "turn.completed", "usage": USAGE},
    ]


def message(text: str = "CW_LIVE_CODEX_OK", item_id: str = "item_1") -> dict:
    return {
        "type": "item.completed",
        "item": {"id": item_id, "type": "agent_message", "text": text},
    }


def reasoning(item_id: str = "item_0") -> dict:
    return {
        "type": "item.completed",
        "item": {"id": item_id, "type": "reasoning", "text": "summary"},
    }


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="provider-codex-parser-")
        self.path = Path(self.temporary.name) / "events.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, events: list[dict], *, newline: bool = True) -> None:
        payload = "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events)
        if not newline:
            payload = payload.removesuffix("\n")
        self.path.write_text(payload, encoding="utf-8")

    def parsed(self) -> bool:
        return PARSER.main([str(PARSER_PATH), str(self.path)]) == 0

    def test_accepts_exact_lifecycle(self) -> None:
        self.write(lifecycle(message()))
        self.assertTrue(self.parsed())

    def test_accepts_completed_reasoning_before_message(self) -> None:
        self.write(lifecycle(reasoning(), message()))
        self.assertTrue(self.parsed())

    def test_rejects_wrong_or_duplicate_message(self) -> None:
        for middle in ([message("almost")], [message(), message(item_id="item_2")]):
            with self.subTest(middle=middle):
                self.write(lifecycle(*middle))
                self.assertFalse(self.parsed())

    def test_rejects_tool_file_error_and_active_events(self) -> None:
        forbidden = [
            {"type": "item.completed", "item": {"id": "x", "type": kind, "text": ""}}
            for kind in ("command_execution", "file_change", "mcp_tool_call", "error")
        ] + [{"type": "item.started", "item": {"id": "x", "type": "reasoning", "text": ""}}]
        for event in forbidden:
            with self.subTest(event=event):
                self.write(lifecycle(event, message()))
                self.assertFalse(self.parsed())

    def test_rejects_failed_duplicate_or_trailing_completion(self) -> None:
        variants = [
            lifecycle(message())[:-1] + [{"type": "turn.failed", "error": {"message": "no"}}],
            lifecycle(message()) + [{"type": "turn.completed", "usage": USAGE}],
            lifecycle(message())
            + [{"type": "item.completed", "item": {"id": "late", "type": "reasoning", "text": "late"}}],
        ]
        for events in variants:
            with self.subTest(events=events):
                self.write(events)
                self.assertFalse(self.parsed())

    def test_rejects_malformed_truncated_blank_and_duplicate_fields(self) -> None:
        invalid_payloads = [
            b'{"type":"thread.started"\n',
            b'{"type":"thread.started","type":"turn.started","thread_id":"' + THREAD.encode() + b'"}\n',
            b'\n',
            b'[]\n',
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                self.path.write_bytes(payload)
                self.assertFalse(self.parsed())
        self.write(lifecycle(message()), newline=False)
        self.assertFalse(self.parsed())

    def test_rejects_nested_duplicate_field(self) -> None:
        payload = (
            '{"type":"thread.started","thread_id":"' + THREAD + '"}\n'
            '{"type":"turn.started"}\n'
            '{"type":"item.completed","item":{"id":"item_1","type":"agent_message",'
            '"text":"CW_LIVE_CODEX_OK","text":"CW_LIVE_CODEX_OK"}}\n'
            '{"type":"turn.completed","usage":' + json.dumps(USAGE) + '}\n'
        )
        self.path.write_text(payload, encoding="utf-8")
        self.assertFalse(self.parsed())

    def test_rejects_oversize_without_reading_it(self) -> None:
        with self.path.open("wb") as stream:
            stream.truncate(PARSER.MAX_CAPTURE_BYTES)
        self.assertFalse(self.parsed())

    def test_rejects_reused_item_id_and_reasoning_after_message(self) -> None:
        for events in (
            lifecycle(reasoning("same"), message(item_id="same")),
            lifecycle(message(), reasoning("item_2")),
        ):
            with self.subTest(events=events):
                self.write(events)
                self.assertFalse(self.parsed())

    def test_rejects_schema_drift_and_invalid_usage(self) -> None:
        extra = lifecycle(message())
        extra[0]["new_field"] = True
        negative = lifecycle(message())
        negative[-1]["usage"] = {**USAGE, "output_tokens": -1}
        boolean = lifecycle(message())
        boolean[-1]["usage"] = {**USAGE, "output_tokens": True}
        for events in (extra, negative, boolean):
            with self.subTest(events=events):
                self.write(events)
                self.assertFalse(self.parsed())


class WorkloadContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKLOAD_PATH.read_text(encoding="utf-8")

    def test_fixed_stock_command_and_prompt(self) -> None:
        self.assertIn("readonly CODEX_BIN=/opt/codewire/agents/npm/bin/codex", self.source)
        self.assertIn("readonly EXPECTED_VERSION='codex-cli 0.149.0'", self.source)
        self.assertIn("readonly EXPECTED_CODEX_HOME=/run/codewire-agent/codex", self.source)
        self.assertIn("readonly SCRATCH_PARENT=/dev/shm", self.source)
        self.assertIn("exec --strict-config --ephemeral --json", self.source)
        self.assertIn("--color never --sandbox read-only --skip-git-repo-check --cd /workspace", self.source)
        self.assertIn("Reply with exactly CW_LIVE_CODEX_OK. Do not use tools or inspect files.", self.source)
        for forbidden in ("--ignore-user-config", "--model", "OPENAI_API_KEY", "--dangerously"):
            self.assertNotIn(forbidden, self.source)

    def test_timeout_and_resource_contract(self) -> None:
        self.assertIn("timeout --kill-after=5s 120s", self.source)
        self.assertNotIn("--foreground", self.source)
        self.assertNotIn("--preserve-status", self.source)
        self.assertIn("builtin ulimit -S -c 0 || return 1", self.source)
        self.assertIn("builtin ulimit -H -c 0 || return 1", self.source)
        self.assertIn("builtin ulimit -S -f 1024 || return 1", self.source)
        self.assertIn("builtin ulimit -H -f 1024 || return 1", self.source)
        self.assertIn("file=1048576:1048576:bytes", self.source)
        self.assertIn("</dev/null", self.source)
        self.assertIn("CAPTURE_LIMIT_BYTES=1048576", self.source)

    def test_only_public_receipts_are_literals(self) -> None:
        completed = subprocess.run(
            ["bash", str(WORKLOAD_PATH), "unsupported"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "CW_LIVE_CODEX_ERROR\n")
        self.assertNotIn("cat \"$scratch/events.jsonl\"", self.source)
        self.assertNotIn("cat \"$scratch/codex.err\"", self.source)

    def test_precondition_diagnostic_is_suppressed(self) -> None:
        completed = subprocess.run(
            ["bash", str(WORKLOAD_PATH), "run"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin", "CODEX_HOME": "/missing/private/home"},
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "CW_LIVE_CODEX_ERROR\n")

    def test_limit_setup_succeeds_exactly_and_fails_under_lower_hard_cap(self) -> None:
        success = subprocess.run(
            ["bash", "-c", f'source "$1"; (provider_codex_apply_limits)', "bash", str(WORKLOAD_PATH)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual((success.returncode, success.stdout, success.stderr), (0, "", ""))
        failure = subprocess.run(
            [
                "bash",
                "-c",
                'builtin ulimit -S -f 512; builtin ulimit -H -f 512; '
                'source "$1"; if provider_codex_apply_limits >/dev/null 2>&1; then exit 99; fi',
                "bash",
                str(WORKLOAD_PATH),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual((failure.returncode, failure.stdout, failure.stderr), (0, "", ""))

    def test_real_entrypoint_with_synthetic_stock_command(self) -> None:
        executable_parent = os.environ.get("TMPDIR", "/home/user/t")
        with tempfile.TemporaryDirectory(prefix="cw-codex-entrypoint-", dir=executable_parent) as root_text, \
                tempfile.TemporaryDirectory(prefix="cw-codex-scratch-", dir="/dev/shm") as scratch_text:
            root = Path(root_text)
            scratch = Path(scratch_text)
            home = root / "codex-home"
            home.mkdir(mode=0o700)
            config = home / "config.toml"
            config.write_text("managed = true\n", encoding="utf-8")
            fake = root / "codex"
            fake.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" == 1 && "$1" == --version ]]; then
  printf 'codex-cli 0.149.0\\n'
  exit 0
fi
expected=(exec --strict-config --ephemeral --json --color never --sandbox read-only
  --skip-git-repo-check --cd /workspace
  'Reply with exactly CW_LIVE_CODEX_OK. Do not use tools or inspect files.')
actual=("$@")
[[ "$#" == "${#expected[@]}" ]]
for ((index=0; index < ${#expected[@]}; index++)); do
  [[ "${actual[index]}" == "${expected[index]}" ]]
done
[[ "$CODEX_HOME" == "$EXPECTED_FAKE_CODEX_HOME" ]]
[[ "$(cat "$CODEX_HOME/config.toml")" == 'managed = true' ]]
if [[ "${FAKE_CODEX_FAILURE:-0}" == 1 ]]; then
  printf 'RAW_PROVIDER_STDOUT_MUST_NOT_ESCAPE\\n'
  printf 'RAW_PROVIDER_STDERR_MUST_NOT_ESCAPE\\n' >&2
  exit 1
fi
usage='{"input_tokens":10,"cached_input_tokens":2,"cache_write_input_tokens":0,'
usage+='"output_tokens":4,"reasoning_output_tokens":1}'
printf '%s\\n' \\
  '{"type":"thread.started","thread_id":"11111111-1111-4111-8111-111111111111"}' \\
  '{"type":"turn.started"}' \\
  '{"type":"item.completed","item":{"id":"item_0","type":"reasoning","text":"summary"}}' \\
  '{"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"CW_LIVE_CODEX_OK"}}' \\
  "{\\"type\\":\\"turn.completed\\",\\"usage\\":$usage}"
""",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            parser = root / "provider-codex-output.py"
            parser.write_bytes(PARSER_PATH.read_bytes())
            parser.chmod(0o500)
            wrapper = root / "provider-codex-workload.sh"
            transformed = self.source.replace(
                "readonly CODEX_BIN=/opt/codewire/agents/npm/bin/codex", f"readonly CODEX_BIN={fake}"
            ).replace(
                "readonly EXPECTED_CODEX_HOME=/run/codewire-agent/codex", f"readonly EXPECTED_CODEX_HOME={home}"
            ).replace(
                "readonly SCRATCH_PARENT=/dev/shm", f"readonly SCRATCH_PARENT={scratch}"
            ).replace(
                "readonly WORKLOAD_DIR=/workspace/.cw-provider-codex", f"readonly WORKLOAD_DIR={root}"
            )
            wrapper.write_text(transformed, encoding="utf-8")
            wrapper.chmod(0o700)
            environment = {
                "PATH": "/usr/bin:/bin",
                "CODEX_HOME": str(home),
                "EXPECTED_FAKE_CODEX_HOME": str(home),
            }
            completed = subprocess.run(
                ["bash", str(wrapper), "run"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                             (0, "CW_LIVE_CODEX_OK\n", ""))
            self.assertEqual(config.read_text(encoding="utf-8"), "managed = true\n")
            self.assertEqual(list(scratch.glob(".cw-live-codex.*")), [])

            failed = subprocess.run(
                ["bash", str(wrapper), "run"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**environment, "FAKE_CODEX_FAILURE": "1"},
            )
            self.assertEqual((failed.returncode, failed.stdout, failed.stderr),
                             (1, "", "CW_LIVE_CODEX_ERROR\n"))
            self.assertEqual(list(scratch.glob(".cw-live-codex.*")), [])


if __name__ == "__main__":
    unittest.main()
