#!/usr/bin/env python3
"""Focused stdlib-only fixtures; never invokes Codex, Kubernetes or real auth."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / "verify/kind/codex_session.py"
SPEC = importlib.util.spec_from_file_location("kind_codex_session", SOURCE)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)

FAKE = r'''
import json, signal, sys, time
mode = sys.argv[1]
if mode == "stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
def send(value):
    print(json.dumps(value), flush=True)
for line in sys.stdin:
    value = json.loads(line)
    if "id" not in value:
        continue
    request_id = value["id"]
    method = value["method"]
    if mode == "eof":
        break
    if method == "initialize":
        send({"id":request_id,"result":{"codexHome":"/run/codewire-codex/home","platformOs":"linux"}})
    elif method == "thread/start":
        send({"id":request_id,"result":{"thread":{"id":"thread-"+str(request_id),"ephemeral":True,"path":None},"modelProvider":"codewire_openai"}})
    elif method == "turn/start":
        thread_id = value["params"]["threadId"]
        turn_id = "turn-"+str(request_id)
        if mode == "server-request":
            send({"id":99,"method":"item/commandExecution/requestApproval","params":{}})
            continue
        if mode == "wrong-turn":
            completed_id = "foreign-turn"
        else:
            completed_id = turn_id
        send({"method":"item/completed","params":{"threadId":thread_id,"turnId":completed_id,"item":{"type":"agentMessage","text":"CWCODEX149 kind"}}})
        turn = {"id":completed_id,"status":"failed" if mode == "failed" else "completed","error":{"message":"synthetic-private-canary"} if mode == "failed" else None}
        # Notifications deliberately precede the request response.
        send({"method":"turn/completed","params":{"threadId":thread_id,"turn":turn}})
        send({"id":request_id,"result":{"turn":{"id":turn_id,"status":"inProgress"}}})
if mode == "stubborn":
    while True:
        time.sleep(0.01)
'''


class ParserTests(unittest.TestCase):
    def test_fragmented_and_multiple_frames(self):
        frames = driver.Frames()
        self.assertEqual(frames.feed(b'{"id":1,'), [])
        self.assertEqual(frames.feed(b'"result":{}}\n{"method":"initialized"}\n'),
                         [{"id": 1, "result": {}}, {"method": "initialized"}])

    def test_duplicate_fields_fail_closed(self):
        with self.assertRaisesRegex(driver.Failure, "duplicate_rpc_field"):
            driver.Frames().feed(b'{"id":1,"id":2}\n')

    def test_invalid_encoding_and_shape(self):
        for line in (b'\xff\n', b'[]\n', b'null\n', b'\n'):
            with self.subTest(line=line), self.assertRaises(driver.Failure):
                driver.Frames().feed(line)

    def test_unterminated_line_is_bounded(self):
        with self.assertRaisesRegex(driver.Failure, "rpc_line_limit"):
            driver.Frames().feed(b"x" * (driver.MAX_LINE + 1))

    def test_exact_successful_execve_only(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            exact = f'execve("/bin/cat", ["/bin/cat", "{driver.TOKEN}"], 0x123 /* 20 vars */)'
            trace.write_text("\n".join([
                f"100 123.100000 {exact} = 0",
                f"101 123.200000 {exact} = -1 EACCES (Permission denied)",
                f'102 123.300000 execve("/bin/cat", ["/bin/cat", "/wrong"], 0x123 /* 20 vars */) = 0',
                f"103 123.400000 {exact.replace('/bin/cat', '/usr/bin/cat')} = 0",
            ]))
            self.assertEqual(driver.auth_calls(trace), [123.1])

    def test_resumed_execve_is_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            trace.write_text(
                f'100 123.100000 execve("/bin/cat", ["/bin/cat", "{driver.TOKEN}"], 0x123 /* 20 vars */ <unfinished ...>\n'
                '100 123.200000 <... execve resumed>) = 0\n'
                '100 123.300000 <... execve resumed>) = 0\n')
            self.assertEqual(driver.auth_calls(trace), [123.1])

    def test_trace_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            trace.write_bytes(b"x" * (driver.MAX_TRACE + 1))
            with self.assertRaisesRegex(driver.Failure, "trace_limit"):
                driver.auth_calls(trace)

    def test_fingerprint_observes_atomic_replacement_without_exporting_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            replacement = Path(directory) / "replacement"
            token.write_bytes(b"synthetic-token-a")
            with patch.object(driver, "TOKEN", str(token)):
                first = driver.token_fingerprint()
                replacement.write_bytes(b"synthetic-token-b")
                replacement.replace(token)
                self.assertNotEqual(first, driver.token_fingerprint())
                self.assertEqual(len(first), 32)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Unix FIFO boundary")
    def test_fifo_is_rejected_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "fifo"
            os.mkfifo(token)
            started = time.monotonic()
            with patch.object(driver, "TOKEN", str(token)), self.assertRaisesRegex(driver.Failure, "invalid_token_file"):
                driver.token_fingerprint()
            self.assertLess(time.monotonic() - started, 1)


class ProtocolTests(unittest.TestCase):
    @contextlib.contextmanager
    def server(self, mode="success"):
        server = driver.Server([sys.executable, "-u", "-c", FAKE, mode], str(SOURCE.parent))
        try:
            yield server
        finally:
            server.close()
            self.assertIsNotNone(server.process.poll())

    def test_two_turns_same_process_and_notification_before_response(self):
        with self.server() as server:
            pid = server.process.pid
            server.initialize()
            thread = server.thread()
            server.turn(thread, "CW_KIND_BASELINE")
            server.pump(0.02)
            server.turn(thread, "CW_KIND_ROTATION")
            self.assertEqual(server.process.pid, pid)
            self.assertEqual(len(server.completed), 2)
            self.assertEqual({key[0] for key in server.completed}, {thread})

    def test_failed_completion_is_closed_and_does_not_include_payload(self):
        with self.server("failed") as server:
            server.initialize()
            with self.assertRaisesRegex(driver.Failure, "^turn_failed$") as result:
                server.turn(server.thread(), "synthetic")
            self.assertNotIn("canary", str(result.exception))

    def test_unexpected_server_request_is_denied(self):
        with self.server("server-request") as server:
            server.initialize()
            with self.assertRaisesRegex(driver.Failure, "unexpected_server_request"):
                server.turn(server.thread(), "synthetic")

    def test_early_eof_cannot_pass(self):
        with self.server("eof") as server:
            with self.assertRaises(driver.Failure):
                server.initialize()

    def test_other_turn_cannot_satisfy_completion(self):
        with self.server("wrong-turn") as server:
            server.initialize()
            thread = server.thread()
            with self.assertRaisesRegex(driver.Failure, "rpc_timeout"):
                server.turn(thread, "synthetic", time.monotonic() + 0.2)

    def test_uncooperative_process_is_killed_and_reaped(self):
        server = driver.Server([sys.executable, "-u", "-c", FAKE, "stubborn"], str(SOURCE.parent))
        try:
            server.initialize()
        finally:
            with patch.object(driver, "SHUTDOWN_GRACE", 0.05):
                status = server.close()
        self.assertEqual(status, -9)
        self.assertEqual(server.process.poll(), -9)


class AcceptanceTests(unittest.TestCase):
    def test_rotation_wait_requires_change_and_expired_cache_without_active_turn(self):
        clock = [0.0]
        class Idle:
            def pump(self, duration):
                clock[0] += duration
        with patch.object(driver.time, "monotonic", lambda: clock[0]), \
                patch.object(driver, "token_fingerprint", lambda: b"new"):
            driver.observe_rotation(Idle(), b"old", 0.0)
        self.assertGreater(clock[0], 30)
        self.assertLess(clock[0], 31)

    def test_unchanged_projection_times_out(self):
        clock = [0.0]
        class Idle:
            def pump(self, duration):
                clock[0] += duration
        with patch.object(driver.time, "monotonic", lambda: clock[0]), \
                patch.object(driver, "token_fingerprint", lambda: b"same"), \
                patch.object(driver, "ROTATION_TIMEOUT", 0.5), \
                self.assertRaisesRegex(driver.Failure, "projected_token_rotation_timeout"):
            driver.observe_rotation(Idle(), b"same", 0.0)

    def workflow(self, native_calls, rotation_calls=2, durations=(0.0, 0.0, 0.0)):
        calls = []
        clock = [0.0]
        elapsed_by_prompt = dict(zip(
            ("CW_KIND_ROTATION", "CW_KIND_BROKER_RETRY_ONCE", "CW_KIND_NATIVE_REREAD"),
            durations,
        ))
        class Workflow:
            def __init__(self):
                self.threads = 0
                self.inputs = []
                self.deadlines = []
            def initialize(self):
                pass
            def thread(self, deadline=None):
                self.threads += 1
                if self.threads > 1:
                    self.deadlines.append(deadline)
                return str(self.threads)
            def turn(self, thread, prompt, deadline=None):
                self.inputs.append((thread, prompt))
                if prompt != "CW_KIND_BASELINE":
                    self.deadlines.append(deadline)
                count = {"CW_KIND_ROTATION": rotation_calls,
                         "CW_KIND_NATIVE_REREAD": native_calls}.get(prompt, 1)
                calls.extend([clock[0]] * count)
                clock[0] += elapsed_by_prompt.get(prompt, 0.0)
        workflow = Workflow()
        output = io.StringIO()
        with patch.object(driver, "auth_calls", lambda _: list(calls)), \
                patch.object(driver.time, "monotonic", lambda: clock[0]), \
                patch.object(driver, "token_fingerprint", lambda: b"synthetic"), \
                patch.object(driver, "observe_rotation"), \
                contextlib.redirect_stdout(output):
            driver.run(workflow, None)
        return workflow, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_exact_retry_counts_and_fresh_thread_markers(self):
        workflow, events = self.workflow(2, durations=(3.0, 4.0, 5.0))
        self.assertEqual([thread for thread, _ in workflow.inputs], ["1", "1", "2", "3"])
        self.assertEqual([event["event"] for event in events], [
            "baseline_completed", "projected_token_rotated", "rotation_turn_completed",
            "broker_retry_completed", "native_reread_completed",
        ])
        self.assertEqual([event["auth_command_calls"] for event in events[-3:]], [2, 1, 2])
        self.assertEqual(workflow.deadlines, [driver.CACHE_INTERVAL] * 5)

    def test_missing_or_extra_rotation_cache_read_does_not_pass(self):
        for count in (1, 3):
            with self.subTest(count=count), self.assertRaisesRegex(
                    driver.Failure, "rotation_auth_command_count"):
                self.workflow(2, rotation_calls=count)

    def test_individually_short_turns_cannot_exceed_shared_cache_interval(self):
        with self.assertRaisesRegex(driver.Failure, "retry_auth_command_count_or_deadline"):
            self.workflow(2, durations=(10.0, 10.0, 10.0))

    def test_rotation_turn_itself_must_finish_inside_shared_cache_interval(self):
        with self.assertRaisesRegex(driver.Failure, "rotation_auth_command_count_or_deadline"):
            self.workflow(2, durations=(driver.CACHE_INTERVAL, 0.0, 0.0))

    def test_missing_native_reread_does_not_pass(self):
        with self.assertRaisesRegex(driver.Failure, "retry_auth_command_count_or_deadline"):
            self.workflow(1)


if __name__ == "__main__":
    unittest.main()
