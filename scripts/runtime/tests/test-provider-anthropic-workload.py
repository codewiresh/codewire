#!/usr/bin/env python3
"""Synthetic, credential-free tests for the live Anthropic Claude boundary."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PARSER_PATH = ROOT / "dev" / "provider-anthropic-output.py"
WORKLOAD_PATH = ROOT / "dev" / "provider-anthropic-workload.sh"
SPEC = importlib.util.spec_from_file_location("provider_anthropic_output", PARSER_PATH)
assert SPEC and SPEC.loader
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)

MARKER = "CW_LIVE_CLAUDE_OK"
MODEL = "claude-sonnet-4-6"


def lifecycle(*, status: bool = False, assistant_before_stop: bool = False) -> list[dict]:
    frames = [{"type": "system", "subtype": "init"}]
    if status:
        frames.append({"type": "system", "subtype": "status", "status": "requesting"})
    frames.extend([
        {"type": "stream_event", "event": {
            "type": "message_start", "message": {"role": "assistant", "model": MODEL}}},
        {"type": "stream_event", "event": {
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}},
        {"type": "stream_event", "event": {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "CW_LIVE_"}}},
        {"type": "stream_event", "event": {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "CLAUDE_OK"}}},
    ])
    assistant = {"type": "assistant", "message": {
        "role": "assistant", "content": [{"type": "text", "text": MARKER}]}}
    if assistant_before_stop:
        frames.append(assistant)
    frames.extend([
        {"type": "stream_event", "event": {"type": "content_block_stop", "index": 0}},
        {"type": "stream_event", "event": {
            "type": "message_delta", "delta": {"stop_reason": "end_turn"}}},
        {"type": "stream_event", "event": {"type": "message_stop"}},
    ])
    if not assistant_before_stop:
        frames.append(assistant)
    frames.append({"type": "result", "subtype": "success", "is_error": False,
                   "num_turns": 1, "result": MARKER})
    return frames


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="provider-anthropic-parser-")
        self.path = Path(self.temporary.name) / "events.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, frames: list[dict], *, newline: bool = True) -> None:
        payload = "".join(json.dumps(frame, separators=(",", ":")) + "\n" for frame in frames)
        self.path.write_text(payload if newline else payload.removesuffix("\n"), encoding="utf-8")

    def parsed(self) -> bool:
        return PARSER.main([str(PARSER_PATH), str(self.path)]) == 0

    def test_accepts_exact_lifecycle(self) -> None:
        self.write(lifecycle())
        self.assertTrue(self.parsed())

    def test_accepts_request_status_and_early_assembled_message(self) -> None:
        for frames in (lifecycle(status=True), lifecycle(assistant_before_stop=True)):
            with self.subTest(frames=frames):
                self.write(frames)
                self.assertTrue(self.parsed())

    def test_accepts_one_gateway_notice_and_rejects_others(self) -> None:
        # Observed from Claude 2.1.288 through the managed loopback base URL.
        notice = {"type": "system", "subtype": "informational", "level": "warning",
                  "content": PARSER.GATEWAY_NOTICE + " However, this session isn't eligible."}
        good = lifecycle()
        stop = len(good) - 3
        self.write(good[:stop] + [notice] + good[stop:])
        self.assertTrue(self.parsed())
        variants = [
            good[:stop] + [notice, notice] + good[stop:],
            [notice] + good,
            good[:stop] + [dict(notice, level="error")] + good[stop:],
            good[:stop] + [dict(notice, content="Another notice.")] + good[stop:],
            good[:stop] + [notice] + good[stop + 1:],
        ]
        for frames in variants:
            with self.subTest(frames=frames):
                self.write(frames)
                self.assertFalse(self.parsed())

    def test_rejects_each_missing_required_frame(self) -> None:
        good = lifecycle()
        for index in range(len(good)):
            with self.subTest(index=index):
                self.write(good[:index] + good[index + 1:])
                self.assertFalse(self.parsed())

    def test_rejects_wrong_model_text_and_terminal_fields(self) -> None:
        variants = []
        for index, key, value in ((1, "model", "other"), (3, "text", "wrong")):
            frames = lifecycle()
            if index == 1:
                frames[index]["event"]["message"][key] = value
            else:
                frames[index]["event"]["delta"][key] = value
            variants.append(frames)
        for key, value in (("subtype", "error"), ("is_error", True),
                           ("num_turns", 2), ("result", "wrong")):
            frames = lifecycle()
            frames[-1][key] = value
            variants.append(frames)
        for frames in variants:
            with self.subTest(frames=frames):
                self.write(frames)
                self.assertFalse(self.parsed())

    def test_rejects_noninteger_index_and_turn_count(self) -> None:
        for index, path in ((0.0, "event"), (False, "event"), (1.0, "result"), (True, "result")):
            frames = lifecycle()
            if path == "event":
                frames[2]["event"]["index"] = index
            else:
                frames[-1]["num_turns"] = index
            with self.subTest(value=index, path=path):
                self.write(frames)
                self.assertFalse(self.parsed())

    def test_rejects_duplicate_unknown_tool_and_trailing_frames(self) -> None:
        good = lifecycle()
        variants = [
            good[:1] + [copy.deepcopy(good[0])] + good[1:],
            good[:-1] + [{"type": "tool_use", "name": "x"}] + good[-1:],
            good + [{"type": "system", "subtype": "status", "status": "requesting"}],
            good[:-1] + [copy.deepcopy(good[-2])] + good[-1:],
        ]
        for frames in variants:
            with self.subTest(frames=frames):
                self.write(frames)
                self.assertFalse(self.parsed())

    def test_rejects_malformed_blank_nul_nonobject_and_truncation(self) -> None:
        payloads = [b'{"type":"system"\n', b"\n", b"[]\n", b'{"type":"system"}\x00\n']
        for payload in payloads:
            with self.subTest(payload=payload):
                self.path.write_bytes(payload)
                self.assertFalse(self.parsed())
        self.write(lifecycle(), newline=False)
        self.assertFalse(self.parsed())

    def test_rejects_duplicate_fields_at_any_depth(self) -> None:
        self.path.write_text(
            '{"type":"system","subtype":"init","subtype":"init"}\n', encoding="utf-8")
        self.assertFalse(self.parsed())
        payload = "".join(json.dumps(frame) + "\n" for frame in lifecycle())
        payload = payload.replace('"role": "assistant"',
                                  '"role": "assistant", "role": "assistant"', 1)
        self.path.write_text(payload, encoding="utf-8")
        self.assertFalse(self.parsed())

    def test_rejects_oversize_without_reading_it(self) -> None:
        with self.path.open("wb") as stream:
            stream.truncate(PARSER.MAX_CAPTURE_BYTES)
        self.assertFalse(self.parsed())


class WorkloadContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKLOAD_PATH.read_text(encoding="utf-8")

    def test_fixed_stock_command_projection_and_prompt(self) -> None:
        self.assertIn("readonly CLAUDE_BIN=/opt/codewire/agents/npm/bin/claude", self.source)
        self.assertIn("readonly EXPECTED_VERSION='2.1.288 (Claude Code)'", self.source)
        self.assertIn("readonly SCRATCH_PARENT=/dev/shm", self.source)
        self.assertIn("--model claude-sonnet-4-6", self.source)
        self.assertIn("--max-turns 1 --tools '' --strict-mcp-config", self.source)
        self.assertIn("--setting-sources '' --disable-slash-commands --no-session-persistence", self.source)
        self.assertIn("--output-format stream-json --verbose --include-partial-messages", self.source)
        self.assertIn("Reply with exactly CW_LIVE_CLAUDE_OK. Do not use tools or inspect files.", self.source)
        for projected in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
                          "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
            self.assertIn(projected, self.source)
        for forbidden in ("--dangerously", "--permission-mode", "--allowedTools", "--add-dir"):
            self.assertNotIn(forbidden, self.source)

    def test_timeout_and_resource_contract(self) -> None:
        self.assertIn("timeout --kill-after=5s 120s", self.source)
        self.assertNotIn("--foreground", self.source)
        self.assertNotIn("--preserve-status", self.source)
        for command in ("builtin ulimit -S -c 0 || return 1",
                        "builtin ulimit -H -c 0 || return 1",
                        "builtin ulimit -S -f 1024 || return 1",
                        "builtin ulimit -H -f 1024 || return 1"):
            self.assertIn(command, self.source)
        self.assertIn("file=1048576:1048576:bytes", self.source)
        self.assertIn("CAPTURE_LIMIT_BYTES=1048576", self.source)
        self.assertIn("findmnt -nro FSTYPE", self.source)

    def test_only_public_receipts_are_emitted(self) -> None:
        completed = subprocess.run(
            ["bash", str(WORKLOAD_PATH), "unsupported"], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin"})
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                         (2, "", "CW_LIVE_CLAUDE_ERROR\n"))
        self.assertNotIn('cat "$scratch/events.jsonl"', self.source)
        self.assertNotIn('cat "$scratch/claude.err"', self.source)

    def test_precondition_diagnostic_is_suppressed(self) -> None:
        completed = subprocess.run(
            ["bash", str(WORKLOAD_PATH), "run"], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin", "ANTHROPIC_BASE_URL": "https://wrong.invalid"})
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                         (1, "", "CW_LIVE_CLAUDE_ERROR\n"))

    def test_limit_setup_succeeds_exactly_and_fails_under_lower_hard_cap(self) -> None:
        success = subprocess.run(
            ["bash", "-c", 'source "$1"; (provider_anthropic_apply_limits)',
             "bash", str(WORKLOAD_PATH)], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual((success.returncode, success.stdout, success.stderr), (0, "", ""))
        failure = subprocess.run(
            ["bash", "-c", 'builtin ulimit -S -f 512; builtin ulimit -H -f 512; '
             'source "$1"; if provider_anthropic_apply_limits >/dev/null 2>&1; then exit 99; fi',
             "bash", str(WORKLOAD_PATH)], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual((failure.returncode, failure.stdout, failure.stderr), (0, "", ""))

    def test_real_entrypoint_with_synthetic_stock_command(self) -> None:
        # The fake executable may reside on a noexec /tmp; default to this checkout.
        executable_parent = os.environ.get("TMPDIR") or str(ROOT)
        with tempfile.TemporaryDirectory(prefix="cw-anthropic-entrypoint-", dir=executable_parent) as root_text, \
                tempfile.TemporaryDirectory(prefix="cw-anthropic-scratch-", dir="/dev/shm") as scratch_text:
            root = Path(root_text)
            scratch = Path(scratch_text)
            fake = root / "claude"
            fake.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" == 1 && "$1" == --version ]]; then
  if [[ "${FAKE_CLAUDE_VERSION_NUL:-0}" == 1 ]]; then
    printf '2.1.288 (Claude Code)\\0\\n'
  else
    printf '2.1.288 (Claude Code)\\n'
  fi
  exit 0
fi
expected=(-p --model claude-sonnet-4-6 --max-turns 1 --tools '' --strict-mcp-config
  --mcp-config '{"mcpServers":{}}' --setting-sources '' --disable-slash-commands
  --no-session-persistence --output-format stream-json --verbose --include-partial-messages
  'Reply with exactly CW_LIVE_CLAUDE_OK. Do not use tools or inspect files.')
actual=("$@")
[[ "$#" == "${#expected[@]}" ]]
for ((index=0; index < ${#expected[@]}; index++)); do
  [[ "${actual[index]}" == "${expected[index]}" ]]
done
[[ "$ANTHROPIC_BASE_URL" == http://127.0.0.1:38081 ]]
[[ "$ANTHROPIC_AUTH_TOKEN" == codewire-managed ]]
[[ "${ANTHROPIC_API_KEY+x}" == x && -z "$ANTHROPIC_API_KEY" ]]
[[ "${CLAUDE_CODE_OAUTH_TOKEN+x}" == x && -z "$CLAUDE_CODE_OAUTH_TOKEN" ]]
[[ "$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" == 1 && "$CLAUDE_CODE_MAX_RETRIES" == 0 ]]
if [[ "${FAKE_CLAUDE_FAILURE:-0}" == 1 ]]; then
  printf 'RAW_PROVIDER_STDOUT_MUST_NOT_ESCAPE\\n'
  printf 'RAW_PROVIDER_STDERR_MUST_NOT_ESCAPE\\n' >&2
  exit 1
fi
printf '%s\\n' \\
  '{"type":"system","subtype":"init"}' \\
  '{"type":"stream_event","event":{"type":"message_start","message":{"role":"assistant","model":"claude-sonnet-4-6"}}}' \\
  '{"type":"stream_event","event":{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}}' \\
  '{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"CW_LIVE_CLAUDE_OK"}}}' \\
  '{"type":"stream_event","event":{"type":"content_block_stop","index":0}}' \\
  '{"type":"stream_event","event":{"type":"message_delta","delta":{"stop_reason":"end_turn"}}}' \\
  '{"type":"stream_event","event":{"type":"message_stop"}}' \\
  '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"CW_LIVE_CLAUDE_OK"}]}}' \\
  '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"CW_LIVE_CLAUDE_OK"}'
""", encoding="utf-8")
            fake.chmod(0o700)
            parser = root / "provider-anthropic-output.py"
            parser.write_bytes(PARSER_PATH.read_bytes())
            parser.chmod(0o500)
            wrapper = root / "provider-anthropic-workload.sh"
            transformed = self.source.replace(
                "readonly CLAUDE_BIN=/opt/codewire/agents/npm/bin/claude", f"readonly CLAUDE_BIN={fake}"
            ).replace(
                "readonly SCRATCH_PARENT=/dev/shm", f"readonly SCRATCH_PARENT={scratch}"
            ).replace(
                "readonly WORKLOAD_DIR=/workspace/.cw-provider-anthropic", f"readonly WORKLOAD_DIR={root}"
            )
            wrapper.write_text(transformed, encoding="utf-8")
            wrapper.chmod(0o700)
            environment = {
                "PATH": "/usr/bin:/bin",
                "ANTHROPIC_BASE_URL": "http://127.0.0.1:38081",
                "ANTHROPIC_AUTH_TOKEN": "codewire-managed",
                "ANTHROPIC_API_KEY": "",
                "CLAUDE_CODE_OAUTH_TOKEN": "",
            }
            completed = subprocess.run(
                ["bash", str(wrapper), "run"], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
            self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                             (0, "CW_LIVE_CLAUDE_OK\n", ""))
            self.assertEqual(list(scratch.glob(".cw-live-anthropic.*")), [])

            failed = subprocess.run(
                ["bash", str(wrapper), "run"], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**environment, "FAKE_CLAUDE_FAILURE": "1"})
            self.assertEqual((failed.returncode, failed.stdout, failed.stderr),
                             (1, "", "CW_LIVE_CLAUDE_ERROR\n"))
            self.assertNotIn("RAW_PROVIDER", failed.stdout + failed.stderr)
            self.assertEqual(list(scratch.glob(".cw-live-anthropic.*")), [])

            bad_version = subprocess.run(
                ["bash", str(wrapper), "run"], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**environment, "FAKE_CLAUDE_VERSION_NUL": "1"})
            self.assertEqual((bad_version.returncode, bad_version.stdout, bad_version.stderr),
                             (1, "", "CW_LIVE_CLAUDE_ERROR\n"))
            self.assertEqual(list(scratch.glob(".cw-live-anthropic.*")), [])


if __name__ == "__main__":
    unittest.main()
