#!/usr/bin/env python3
"""Synthetic tests for the bounded live OpenAI Responses workload."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_PATH = ROOT / "dev" / "provider-openai-workload.py"
SPEC = importlib.util.spec_from_file_location("provider_openai_workload", WORKLOAD_PATH)
assert SPEC and SPEC.loader
WORKLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKLOAD)

MODEL = "gpt-owner-snapshot:1"
ENVIRONMENT = {
    "OPENAI_BASE_URL": WORKLOAD.EXPECTED_BASE_URL,
    "OPENAI_API_KEY": WORKLOAD.EXPECTED_API_KEY,
}


def response_document(model: str = MODEL, *, reasoning: bool = True) -> dict:
    output = []
    if reasoning:
        output.append({"type": "reasoning", "id": "reasoning_1", "summary": []})
    output.append({
        "type": "message",
        "id": "message_1",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": WORKLOAD.MARKER, "annotations": []}],
    })
    return {
        "id": "response_1",
        "object": "response",
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "model": model,
        "output": output,
    }


class FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200,
                 headers: list[tuple[str, str]] | None = None,
                 leave_open: bool = False, close_error: bool = False) -> None:
        self.body = body
        self.status = status
        self.headers = headers if headers is not None else [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ]
        self.leave_open = leave_open
        self.close_error = close_error
        self.closed = False
        self.close_attempts = 0
        self.offset = 0
        self.read_sizes: list[int] = []

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers

    def read(self, amount: int) -> bytes:
        self.read_sizes.append(amount)
        payload = self.body[self.offset:self.offset + amount]
        self.offset += len(payload)
        if not self.leave_open and self.offset == len(self.body):
            self.closed = True
        return payload

    def isclosed(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.close_attempts += 1
        self.closed = True
        if self.close_error:
            raise RuntimeError("private response close failure")


class FakeConnection:
    def __init__(self, response: FakeResponse, calls: list[tuple]) -> None:
        self.response = response
        self.calls = calls
        self.closed = False

    def request(self, method: str, path: str, *, body: bytes,
                headers: dict[str, str]) -> None:
        self.calls.append((method, path, body, headers))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class WorkloadTests(unittest.TestCase):
    def encoded(self, document: dict | None = None) -> bytes:
        return json.dumps(document or response_document(), separators=(",", ":")).encode("utf-8")

    def connection_factory(self, response: FakeResponse):
        calls: list[tuple] = []
        made: list[tuple[str, int, int, FakeConnection]] = []

        def factory(host: str, port: int, *, timeout: int) -> FakeConnection:
            connection = FakeConnection(response, calls)
            made.append((host, port, timeout, connection))
            return connection

        return factory, calls, made

    def invoke(self, argv: list[str], environment: dict[str, str], factory) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(WORKLOAD, "disable_core_dumps"), \
                mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(WORKLOAD.http.client, "HTTPConnection", factory), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            status = WORKLOAD.main(argv)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_core_limit_is_set_and_verified_exactly(self) -> None:
        with mock.patch.object(WORKLOAD.resource, "setrlimit") as set_limit, \
                mock.patch.object(WORKLOAD.resource, "getrlimit", return_value=(0, 0)):
            WORKLOAD.disable_core_dumps()
        set_limit.assert_called_once_with(WORKLOAD.resource.RLIMIT_CORE, (0, 0))
        with mock.patch.object(WORKLOAD.resource, "setrlimit"), \
                mock.patch.object(WORKLOAD.resource, "getrlimit", return_value=(0, 1)):
            with self.assertRaises(WORKLOAD.InvalidResponse):
                WORKLOAD.disable_core_dumps()

    def test_success_uses_one_exact_request_and_fixed_receipt(self) -> None:
        response = FakeResponse(self.encoded())
        factory, calls, made = self.connection_factory(response)
        result = self.invoke([str(WORKLOAD_PATH), MODEL], ENVIRONMENT, factory)
        self.assertEqual(result, (0, "CW_LIVE_OPENAI_OK\n", ""))
        self.assertEqual([(host, port, timeout) for host, port, timeout, _ in made],
                         [("127.0.0.1", 38_081, 100)])
        self.assertEqual(len(calls), 1)
        method, path, body, headers = calls[0]
        self.assertEqual((method, path), ("POST", "/_codewire/openai/v1/responses"))
        self.assertEqual(headers, {
            "Authorization": "Bearer codewire-managed",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.assertEqual(json.loads(body), {
            "model": MODEL,
            "input": "Reply with exactly CW_LIVE_OPENAI_OK",
            "stream": False,
            "background": False,
            "store": False,
            "tools": [],
            "tool_choice": "none",
            "max_output_tokens": 256,
        })
        self.assertEqual(response.read_sizes, [WORKLOAD.READ_CHUNK_BYTES])
        self.assertTrue(response.closed)
        self.assertTrue(made[0][3].closed)

    def test_accepts_no_reasoning_and_utf8_charset(self) -> None:
        response = FakeResponse(
            self.encoded(response_document(reasoning=False)),
            headers=[("Content-Type", 'Application/JSON; charset="utf-8"')],
        )
        factory, _, _ = self.connection_factory(response)
        self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                         (0, "CW_LIVE_OPENAI_OK\n", ""))

    def test_model_and_projection_reject_before_http(self) -> None:
        invalid_models = ["", "-alias", "has space", "ümlaut", "a" * 129]
        for argv in (["workload"], ["workload", MODEL, "extra"],
                     *[["workload", model] for model in invalid_models]):
            constructor = mock.Mock(side_effect=AssertionError("network attempted"))
            with self.subTest(argv=argv):
                self.assertEqual(self.invoke(argv, ENVIRONMENT, constructor),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))
                constructor.assert_not_called()
        for environment in ({}, {**ENVIRONMENT, "OPENAI_BASE_URL": "https://api.openai.com/v1"},
                            {**ENVIRONMENT, "OPENAI_API_KEY": "owner-material"}):
            constructor = mock.Mock(side_effect=AssertionError("network attempted"))
            with self.subTest(environment=environment):
                self.assertEqual(self.invoke(["workload", MODEL], environment, constructor),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))
                constructor.assert_not_called()

    def test_model_boundaries_are_exact(self) -> None:
        for model in ("a", "A" + "z" * 127, "gpt.owner_snapshot:2026-09-14"):
            response = FakeResponse(self.encoded(response_document(model=model)))
            factory, _, _ = self.connection_factory(response)
            with self.subTest(model=model):
                self.assertEqual(self.invoke(["workload", model], ENVIRONMENT, factory)[0], 0)

    def test_rejects_status_and_response_headers(self) -> None:
        cases = [
            (201, [("Content-Type", "application/json")]),
            (200, []),
            (200, [("Content-Type", "text/event-stream")]),
            (200, [("Content-Type", "application/json; charset=latin1")]),
            (200, [("Content-Type", "application/json"), ("Content-Type", "application/json")]),
            (200, [("Content-Type", "application/json"), ("Content-Encoding", "gzip")]),
            (200, [("Content-Type", "application/json"), ("x-error-json", "opaque")]),
            (200, [("Content-Type", "application/json"), ("Content-Length", "01")]),
            (200, [("Content-Type", "application/json"), ("Content-Length", "1"),
                   ("Content-Length", "1")]),
        ]
        for status, headers in cases:
            response = FakeResponse(self.encoded(), status=status, headers=headers)
            factory, _, made = self.connection_factory(response)
            with self.subTest(status=status, headers=headers):
                self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))
                self.assertTrue(response.closed)
                self.assertTrue(made[0][3].closed)

    def test_rejects_oversize_early_eof_and_unfinished_body(self) -> None:
        cases = [
            FakeResponse(b"x" * (WORKLOAD.MAX_RESPONSE_BYTES + 1),
                         headers=[("Content-Type", "application/json")]),
            FakeResponse(self.encoded(), headers=[("Content-Type", "application/json"),
                                                  ("Content-Length", str(len(self.encoded()) + 1))]),
            FakeResponse(self.encoded(), headers=[("Content-Type", "application/json")],
                         leave_open=True),
            FakeResponse(b"", headers=[("Content-Type", "application/json"),
                                        ("Content-Length", str(WORKLOAD.MAX_RESPONSE_BYTES + 1))]),
        ]
        for response in cases:
            factory, _, made = self.connection_factory(response)
            with self.subTest(headers=response.headers, size=len(response.body)):
                self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))
                self.assertTrue(response.closed)
                self.assertTrue(made[0][3].closed)

    def test_rejects_malformed_duplicate_nonfinite_and_non_utf8_json(self) -> None:
        payloads = [
            b"not json",
            b"[]",
            b'{"object":"response","object":"response"}',
            b'{"object":"response","nested":{"x":1,"x":1}}',
            b'{"object":"response","value":NaN}',
            b'{"object":"response","value":1e999}',
            b'{"object":"response","value":"\xff"}',
            self.encoded() + b" trailing",
        ]
        for payload in payloads:
            response = FakeResponse(payload)
            factory, _, _ = self.connection_factory(response)
            with self.subTest(payload=payload[:60]):
                self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))

    def test_rejects_incomplete_error_or_changed_model(self) -> None:
        variants = []
        for key, value in (("object", "list"), ("status", "incomplete"),
                           ("error", {"message": "private"}),
                           ("incomplete_details", {"reason": "max_output_tokens"}),
                           ("model", MODEL + "-alias"), ("output", None)):
            document = response_document()
            document[key] = value
            variants.append(document)
        for missing in ("id", "error", "incomplete_details"):
            document = response_document()
            del document[missing]
            variants.append(document)
        for invalid_id in ("", 1, None):
            document = response_document()
            document["id"] = invalid_id
            variants.append(document)
        for document in variants:
            response = FakeResponse(self.encoded(document))
            factory, _, _ = self.connection_factory(response)
            with self.subTest(document=document):
                self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))

    def test_rejects_refusal_tool_unknown_and_multiple_messages(self) -> None:
        outputs = [
            [{"type": "message", "status": "completed", "role": "assistant",
              "content": [{"type": "refusal", "refusal": "no"}]}],
            [{"type": "function_call", "name": "tool"}, response_document()["output"][-1]],
            [{"type": "unknown"}, response_document()["output"][-1]],
            [response_document()["output"][-1], copy.deepcopy(response_document()["output"][-1])],
            [{"type": "reasoning", "content": []}, response_document()["output"][-1]],
            [{"type": "reasoning", "tool_calls": []}, response_document()["output"][-1]],
            [{"type": "reasoning", "summary": []}, {"type": "reasoning", "summary": []},
             response_document()["output"][-1]],
            [{"type": "message", "status": "completed", "role": "assistant", "tool_calls": [],
              "content": [{"type": "output_text", "text": WORKLOAD.MARKER}]}],
            [],
        ]
        for output in outputs:
            document = response_document(reasoning=False)
            document["output"] = output
            response = FakeResponse(self.encoded(document))
            factory, _, _ = self.connection_factory(response)
            with self.subTest(output=output):
                self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                                 (1, "", "CW_LIVE_OPENAI_ERROR\n"))

    def test_rejects_message_drift(self) -> None:
        variants = []
        for key, value in (("status", "incomplete"), ("role", "user"),
                           ("content", []),
                           ("content", [{"type": "output_text", "text": "almost"}]),
                           ("content", [{"type": "output_text", "text": WORKLOAD.MARKER}]),
                           ("content", [{"type": "output_text", "text": WORKLOAD.MARKER,
                                         "annotations": [{"type": "url_citation"}]}]),
                           ("content", [{"type": "output_text", "text": WORKLOAD.MARKER},
                                        {"type": "output_text", "text": WORKLOAD.MARKER}])):
            document = response_document(reasoning=False)
            document["output"][0][key] = value
            variants.append(document)
        for document in variants:
            response = FakeResponse(self.encoded(document))
            factory, _, _ = self.connection_factory(response)
            with self.subTest(document=document):
                self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory)[0], 1)

    def test_request_exception_is_private_and_connection_closes(self) -> None:
        class FailingConnection(FakeConnection):
            def request(self, method: str, path: str, *, body: bytes,
                        headers: dict[str, str]) -> None:
                raise RuntimeError("private provider body and owner model")

        made: list[FailingConnection] = []

        def factory(host: str, port: int, *, timeout: int) -> FailingConnection:
            connection = FailingConnection(FakeResponse(self.encoded()), [])
            made.append(connection)
            return connection

        self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                         (1, "", "CW_LIVE_OPENAI_ERROR\n"))
        self.assertTrue(made[0].closed)

    def test_response_close_failure_still_closes_connection_and_emits_only_error(self) -> None:
        response = FakeResponse(self.encoded(), close_error=True)
        factory, _, made = self.connection_factory(response)
        self.assertEqual(self.invoke(["workload", MODEL], ENVIRONMENT, factory),
                         (1, "", "CW_LIVE_OPENAI_ERROR\n"))
        self.assertEqual(response.close_attempts, 1)
        self.assertTrue(made[0][3].closed)

    def test_executable_entrypoint_fails_before_network_with_fixed_receipt(self) -> None:
        completed = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", str(WORKLOAD_PATH), MODEL],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin", "OPENAI_BASE_URL": "https://wrong.invalid/v1",
                 "OPENAI_API_KEY": WORKLOAD.EXPECTED_API_KEY},
        )
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                         (1, "", "CW_LIVE_OPENAI_ERROR\n"))


if __name__ == "__main__":
    unittest.main()
