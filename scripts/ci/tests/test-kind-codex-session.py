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
        send({"id":request_id,"result":{"codexHome":"/home/codewire/.codex","platformOs":"linux"}})
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
        if mode != "authentication-failed":
            send({"method":"item/completed","params":{"threadId":thread_id,"turnId":completed_id,"item":{"type":"agentMessage","text":"CWCODEX149 kind"}}})
        failed = mode in ("failed", "authentication-failed")
        turn = {"id":completed_id,"status":"failed" if failed else "completed","error":{"message":"synthetic-private-canary"} if failed else None}
        # Notifications deliberately precede the request response.
        send({"method":"turn/completed","params":{"threadId":thread_id,"turn":turn}})
        send({"id":request_id,"result":{"turn":{"id":turn_id,"status":"inProgress"}}})
if mode == "stubborn":
    while True:
        time.sleep(0.01)
'''


MANAGED = driver.MANAGED_HEADER.decode() + "\nmodel_provider = \"codewire_openai\"\n"


@contextlib.contextmanager
def codex_home(config=MANAGED):
    """A synthetic Codex home holding config (or nothing when None)."""
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        if config is not None:
            (home / "config.toml").write_text(config)
        with patch.object(driver, "CODEX_HOME", str(home)):
            yield home


class ProjectionTests(unittest.TestCase):
    def test_both_identity_modes_with_the_daemon_written_config(self):
        with codex_home() as home:
            # Environment-token Pod: rendered selection and home. Identity-free
            # Pod: neither; Codex uses its default home.
            for values in ({"CODEX_HOME": str(home),
                            "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"}, {}):
                with self.subTest(values=values), patch.dict(os.environ, values, clear=True):
                    driver.validate_projection()

    def test_missing_wrong_or_unselected_client_is_rejected(self):
        with codex_home() as home:
            for values in ({"CODEX_HOME": str(home)},
                           {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"},
                           {"CODEX_HOME": str(home),
                            "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:none"},
                           {"CODEX_HOME": "/run/codewire-codex/home",
                            "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"},
                           {"CODEX_HOME": "/synthetic/other-home",
                            "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"}):
                with self.subTest(values=values), patch.dict(os.environ, values, clear=True):
                    with self.assertRaisesRegex(driver.Failure, "^unexpected_projection$"):
                        driver.validate_projection()

    def test_codewires_config_or_none_but_never_a_users_file(self):
        # A delivered ChatGPT login removes Codewire's config.toml; the session
        # forces the same proxy provider itself, so an absent file is fine.
        with codex_home(None), patch.dict(os.environ, {}, clear=True):
            driver.validate_projection()
        header = driver.MANAGED_HEADER.decode()
        for config in ("model_provider = \"codewire_openai\"\n",
                       "\n" + header + "\n", " " + header + "\n", header + "\r\n"):
            with self.subTest(config=config), codex_home(config), \
                    patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(driver.Failure, "^unexpected_projection$"):
                    driver.validate_projection()
        with codex_home(None) as home, tempfile.TemporaryDirectory() as elsewhere:
            target = Path(elsewhere) / "config.toml"
            target.write_text(MANAGED)
            (home / "config.toml").symlink_to(target)
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(driver.Failure, "^unexpected_projection$"):
                    driver.validate_projection()

    def test_no_legacy_ca_override_fallback(self):
        with codex_home() as home:
            for value in ("", "/run/codewire-credentials/gateway-roots/ca.crt", "/synthetic/roots"):
                with self.subTest(value=value), patch.dict(os.environ, {
                        "CODEX_HOME": str(home),
                        "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex",
                        "CODEX_CA_CERTIFICATE": value}, clear=True):
                    with self.assertRaisesRegex(driver.Failure, "^unexpected_projection$"):
                        driver.validate_projection()


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

    def test_expected_exhaustion_requires_failed_terminal_without_success_marker(self):
        with self.server("authentication-failed") as server:
            server.initialize()
            server.turn(server.thread(), "CW_KIND_BROKER_RETRY_EXHAUSTED", expected_failure=True)
            self.assertEqual(server.phase, "idle")
            self.assertEqual(len(server.completed), 1)
            self.assertEqual(server.markers, set())

    def test_exhaustion_cannot_accept_success_or_failed_turn_with_success_output(self):
        for mode in ("success", "failed"):
            with self.subTest(mode=mode), self.server(mode) as server:
                server.initialize()
                with self.assertRaisesRegex(driver.Failure, "^unexpected_exhaustion_terminal$"):
                    server.turn(server.thread(), "CW_KIND_BROKER_RETRY_EXHAUSTED", expected_failure=True)

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


class DiagnosticTests(unittest.TestCase):
    CANARY = "opaque-private-canary\nZXhhbXBsZS1wcml2YXRlLW1hdGVyaWFs\n{\"token\":\"never-print\"}"

    def failed_main(self, script=None, *, wait_for_exit=False, trace_content=None,
                    real_cancellation=False):
        """Run real synthetic children through the actual failure/cleanup path."""
        original_server = driver.Server
        children = []
        output, errors = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "config.toml").write_text(MANAGED)
            def server_factory(argv, cwd):
                self.assertEqual(cwd, "/workspace")
                self.assertEqual(argv[:4], [
                    "/usr/bin/unshare", "--user", "--map-root-user", "--",
                ])
                argv = argv[4:]
                self.assertEqual(argv[:7], [
                    "/usr/bin/strace", "-f", "-ttt", "-e", "trace=execve", "-s", "512",
                ])
                self.assertEqual(argv[7], "-o")
                self.assertEqual(argv[9:], ["--", *driver.CODEX_ARGV])
                trace = Path(argv[8])
                self.assertEqual(trace.parent.parent, home)
                if trace_content is not None:
                    trace.write_text(trace_content)
                if script is None:
                    return original_server([str(home / "absent-private-launcher")], directory)
                server = original_server([sys.executable, "-u", "-c", script], directory)
                children.append(server)
                if wait_for_exit:
                    server.process.wait(timeout=2)
                return server
            signals = (driver.signal.SIGTERM, driver.signal.SIGINT)
            original_handlers = {sig: driver.signal.getsignal(sig) for sig in signals}
            signal_guard = (contextlib.nullcontext() if real_cancellation
                            else patch.object(driver.signal, "signal"))
            try:
                with patch.object(driver, "CODEX_HOME", str(home)), \
                        patch.dict(os.environ, {"CODEX_HOME": str(home),
                                               "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"}, clear=True), \
                        patch.object(driver, "Server", server_factory), signal_guard, \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    status = driver.main()
            finally:
                if real_cancellation:
                    for sig, handler in original_handlers.items():
                        driver.signal.signal(sig, handler)
            self.assertEqual(list(home.iterdir()), [home / "config.toml"])
        self.assertEqual(status, 1)
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(len(children), 0 if script is None else 1)
        for child in children:
            self.assertIsNotNone(child.process.poll())
            if real_cancellation:
                self.assertEqual(child.process.returncode, -driver.signal.SIGKILL)
            self.assertTrue(child.process.stdout.closed)
            self.assertTrue(child.process.stderr.closed)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "failed")
        return events[0], output.getvalue()

    def test_stderr_only_eof_reports_live_child_without_weakening_failure(self):
        event, _ = self.failed_main("import os, sys\nos.close(2)\nfor line in sys.stdin: pass\n")
        self.assertEqual(event, {
            "event": "failed", "stage": "session", "reason": "server_pipe_closed",
            "phase": "initialize", "eof_channel": "stderr", "child_status": None,
            "stderr_class": "none", "codex_exec_succeeded": None,
        })

    def test_stdout_only_eof_remains_a_failure(self):
        event, _ = self.failed_main("import os, sys\nos.close(1)\nfor line in sys.stdin: pass\n")
        self.assertEqual(event["reason"], "server_pipe_closed")
        self.assertEqual(event["eof_channel"], "stdout")
        self.assertIsNone(event["child_status"])

    def test_failed_exit_and_multiline_stderr_are_value_blind(self):
        stderr = self.CANARY + "\nstrace: ptrace(PTRACE_TRACEME, ...): Operation not permitted\n" + self.CANARY + "\n"
        event, output = self.failed_main(
            f"import os\nos.write(2, {stderr.encode()!r})\nos._exit(23)\n",
            wait_for_exit=True, trace_content="",
        )
        self.assertEqual(event, {
            "event": "failed", "stage": "session", "reason": "server_input_closed",
            "phase": "initialize", "eof_channel": None, "child_status": 23,
            "stderr_class": "ptrace_denied_message", "codex_exec_succeeded": False,
        })
        for line in self.CANARY.splitlines():
            self.assertNotIn(line, output)

    def test_absolute_strace_prefix_is_exact_and_value_blind(self):
        for prefix, expected in (
            ("/usr/bin/strace:", "ptrace_denied_message"),
            ("/tmp/strace:", "unclassified"),
            ("opaque/usr/bin/strace:", "unclassified"),
            ("strace-impostor:", "unclassified"),
        ):
            with self.subTest(prefix=prefix):
                stderr = self.CANARY + f"\n{prefix} ptrace(PTRACE_TRACEME, ...): Operation not permitted\n" + self.CANARY + "\n"
                event, output = self.failed_main(
                    f"import os\nos.write(2, {stderr.encode()!r})\nos._exit(23)\n",
                    wait_for_exit=True,
                )
                self.assertEqual(event["stderr_class"], expected)
                for line in self.CANARY.splitlines():
                    self.assertNotIn(line, output)
                self.assertNotIn(prefix, output)

    def test_unrecognized_stderr_does_not_become_a_public_error(self):
        event, output = self.failed_main(
            f"import os\nos.write(2, {self.CANARY.encode()!r})\nos._exit(42)\n",
            wait_for_exit=True,
        )
        self.assertEqual(event["child_status"], 42)
        self.assertEqual(event["stderr_class"], "unclassified")
        for line in self.CANARY.splitlines():
            self.assertNotIn(line, output)

    def test_namespace_launch_denial_is_closed_without_fallback(self):
        for prefix, expected in (
            ("unshare:", "user_namespace_denied_message"),
            ("/usr/bin/unshare:", "user_namespace_denied_message"),
            ("/tmp/unshare:", "unclassified"),
            ("opaque/usr/bin/unshare:", "unclassified"),
        ):
            with self.subTest(prefix=prefix):
                stderr = self.CANARY + f"\n{prefix} unshare failed: Operation not permitted\n" + self.CANARY + "\n"
                event, output = self.failed_main(
                    f"import os\nos.write(2, {stderr.encode()!r})\nos._exit(1)\n",
                    wait_for_exit=True, trace_content="",
                )
                self.assertEqual(event["child_status"], 1)
                self.assertIs(event["codex_exec_succeeded"], False)
                self.assertEqual(event["stderr_class"], expected)
                for line in self.CANARY.splitlines():
                    self.assertNotIn(line, output)

    def test_cancellation_reaps_the_synthetic_namespace_launcher(self):
        # The fixture replaces only the asserted launcher argv with Python.
        # Its real child delivers SIGTERM after main has installed its handler
        # and sent initialize, then ignores cleanup TERM to require owned KILL.
        script = (
            "import os, signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "sys.stdin.readline()\n"
            f"os.write(2, {self.CANARY.encode()!r})\n"
            "os.kill(os.getppid(), signal.SIGTERM)\n"
            "while True: time.sleep(0.01)\n"
        )
        with patch.object(driver, "SHUTDOWN_GRACE", 0.05):
            event, output = self.failed_main(script, real_cancellation=True)
        self.assertEqual(event["reason"], "interrupted")
        self.assertEqual(event["phase"], "initialize")
        self.assertIsNone(event["child_status"])
        self.assertEqual(event["stderr_class"], "unclassified")
        for line in self.CANARY.splitlines():
            self.assertNotIn(line, output)

    def test_cancellation_after_stderr_read_keeps_the_diagnostic(self):
        # Deliver the real signal after bytes leave the real child pipe but
        # before the driver records them. No scheduling luck or sleep is needed.
        script = (
            "import os, signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "sys.stdin.readline()\n"
            f"os.write(2, {self.CANARY.encode()!r})\n"
            "while True: time.sleep(0.01)\n"
        )
        original_read = os.read
        original_mask = driver.signal.pthread_sigmask(driver.signal.SIG_BLOCK, [])
        for interruption in (driver.signal.SIGTERM, driver.signal.SIGINT):
            with self.subTest(interruption=interruption):
                delivered = []
                def read_then_interrupt(fd, size):
                    data = original_read(fd, size)
                    if data == self.CANARY.encode() and not delivered:
                        delivered.append(interruption)
                        os.kill(os.getpid(), interruption)
                    return data
                with patch.object(driver, "SHUTDOWN_GRACE", 0.05), \
                        patch.object(driver.os, "read", read_then_interrupt):
                    event, output = self.failed_main(script, real_cancellation=True)
                self.assertEqual(delivered, [interruption])
                self.assertEqual(event["reason"], "interrupted")
                self.assertEqual(event["phase"], "initialize")
                self.assertIsNone(event["child_status"])
                self.assertEqual(event["stderr_class"], "unclassified")
                self.assertEqual(driver.signal.pthread_sigmask(driver.signal.SIG_BLOCK, []), original_mask)
                for line in self.CANARY.splitlines():
                    self.assertNotIn(line, output)

    def test_cancellation_without_stderr_does_not_invent_a_diagnostic(self):
        for interruption in (driver.signal.SIGTERM, driver.signal.SIGINT):
            with self.subTest(interruption=interruption):
                script = (
                    "import os, signal, sys, time\n"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    "sys.stdin.readline()\n"
                    f"os.kill(os.getppid(), {int(interruption)})\n"
                    "while True: time.sleep(0.01)\n"
                )
                with patch.object(driver, "SHUTDOWN_GRACE", 0.05):
                    event, _ = self.failed_main(script, real_cancellation=True)
                self.assertEqual(event["reason"], "interrupted")
                self.assertEqual(event["phase"], "initialize")
                self.assertIsNone(event["child_status"])
                self.assertEqual(event["stderr_class"], "none")

    def test_stderr_read_restores_the_exact_signal_mask_on_every_exit(self):
        original_sigmask = driver.signal.pthread_sigmask
        previous = original_sigmask(driver.signal.SIG_BLOCK, {driver.signal.SIGUSR1})
        expected = original_sigmask(driver.signal.SIG_BLOCK, [])
        try:
            for scenario in ("data", "eof", "read_error", "record_error", "block_error"):
                with self.subTest(scenario=scenario), contextlib.ExitStack() as patches:
                    # Only the bounded collector is exercised here; the tests
                    # above exercise real children, pipes, interruption and cleanup.
                    server = driver.Server.__new__(driver.Server)
                    server.stderr_bytes = 0
                    server.stderr_prefix = bytearray()
                    payload = b"" if scenario == "eof" else b"synthetic-stderr"
                    read = patches.enter_context(patch.object(driver.os, "read", return_value=payload))
                    if scenario == "read_error":
                        read.side_effect = OSError("synthetic read failure")
                    if scenario == "record_error":
                        patches.enter_context(patch.object(server, "observe_stderr", side_effect=RuntimeError("synthetic record failure")))
                    if scenario == "block_error":
                        def block_then_fail(how, mask):
                            result = original_sigmask(how, mask)
                            if how == driver.signal.SIG_BLOCK and mask == {driver.signal.SIGTERM, driver.signal.SIGINT}:
                                raise RuntimeError("synthetic pending handler")
                            return result
                        patches.enter_context(patch.object(driver.signal, "pthread_sigmask", block_then_fail))
                    if scenario.endswith("error"):
                        with self.assertRaises(OSError if scenario == "read_error" else RuntimeError):
                            server._read_stderr(123)
                    else:
                        self.assertEqual(server._read_stderr(123), payload)
                        self.assertEqual(server.stderr_bytes, len(payload))
                    self.assertEqual(original_sigmask(driver.signal.SIG_BLOCK, []), expected)
        finally:
            original_sigmask(driver.signal.SIG_SETMASK, previous)

    def test_failed_launch_does_not_disclose_executable_path(self):
        event, output = self.failed_main()
        self.assertEqual(event, {
            "event": "failed", "stage": "startup", "reason": "process_start_not_found", "phase": "launch",
        })
        self.assertNotIn("absent-private-launcher", output)

    @staticmethod
    def strace_execve(argv):
        quoted = ", ".join(driver.strace_string(argument) for argument in argv)
        return f'execve({driver.strace_string(argv[0])}, [{quoted}], 0x123 /* 20 vars */)'

    def test_session_forces_the_daemons_proxy_provider(self):
        overrides = driver.CODEX_OVERRIDES[1::2]
        self.assertEqual(driver.CODEX_OVERRIDES[0::2], ("-c",) * len(overrides))
        values = dict(value.split("=", 1) for value in overrides)
        self.assertEqual(len(values), len(overrides))
        self.assertEqual(values["model_provider"], '"codewire_openai"')
        self.assertEqual(values["model_providers.codewire_openai.base_url"],
                         '"http://127.0.0.1:38081/v1"')
        self.assertEqual(values["model_providers.codewire_openai.requires_openai_auth"], "false")
        self.assertEqual(values["chatgpt_base_url"], '"http://127.0.0.1:9/backend-api/"')
        # No token, auth command, key or header reaches Codex through an override.
        segments = {segment for key in values for segment in key.split(".")}
        for forbidden in ("auth", "experimental_bearer_token", "env_key", "http_headers",
                          "env_http_headers", "OPENAI_API_KEY"):
            self.assertNotIn(forbidden, segments)
        self.assertFalse(any("token" in value.lower() for value in values.values()))
        self.assertEqual(driver.CODEX_ARGV[:4],
                         (driver.CODEX, "app-server", "--stdio", "--strict-config"))

    def test_strace_strings_escape_quotes_and_backslashes(self):
        self.assertEqual(driver.strace_string('a="b"\\c'), '"a=\\"b\\"\\\\c"')

    def test_exact_codex_exec_is_not_confused_with_failed_or_other_commands(self):
        exact = self.strace_execve(driver.CODEX_ARGV)
        # The previous argv, without the forced proxy provider, is not this session.
        unforced = self.strace_execve(driver.CODEX_ARGV[:4])
        other_provider = self.strace_execve(tuple(
            argument.replace('"codewire_openai"', '"openai"') for argument in driver.CODEX_ARGV))
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            for operation in (exact + " = -1 EACCES (Permission denied)",
                              exact.replace('"--strict-config"', '"--help"') + " = 0",
                              exact.replace(driver.CODEX, "/other/codex") + " = 0",
                              unforced + " = 0", other_provider + " = 0"):
                with self.subTest(operation=operation):
                    trace.write_text(f"100 123.100000 {operation}\n")
                    self.assertIs(driver.codex_exec_succeeded(trace), False)
            trace.write_text(f"100 123.100000 {exact} = 0\n")
            self.assertIs(driver.codex_exec_succeeded(trace), True)
            trace.write_text(f"100 123.100000 {exact[:-1]} <unfinished ...>\n"
                             "100 123.200000 <... execve resumed>) = 0\n")
            self.assertIs(driver.codex_exec_succeeded(trace), True)

    def test_unavailable_invalid_or_oversize_trace_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            self.assertIsNone(driver.codex_exec_succeeded(trace))
            for raw in (b"\xff", b"x" * (driver.MAX_TRACE + 1)):
                trace.write_bytes(raw)
                self.assertIsNone(driver.codex_exec_succeeded(trace))

    def test_stderr_diagnostic_retention_is_bounded(self):
        server = driver.Server([sys.executable, "-u", "-c", "import sys\nfor line in sys.stdin: pass"], str(SOURCE.parent))
        try:
            server.observe_stderr(b"x" * driver.MAX_STDERR_DIAGNOSTIC)
            server.observe_stderr(self.CANARY.encode())
            self.assertEqual(len(server.stderr_prefix), driver.MAX_STDERR_DIAGNOSTIC)
            self.assertEqual(server.stderr_bytes, driver.MAX_STDERR_DIAGNOSTIC + len(self.CANARY.encode()))
            self.assertNotIn(self.CANARY.encode(), server.stderr_prefix)
        finally:
            server.close()
        self.assertIsNotNone(server.process.poll())

    def test_stderr_output_limit_remains_a_failure(self):
        with patch.object(driver, "MAX_OUTPUT", 128):
            event, _ = self.failed_main(
                "import os, sys\nfor line in sys.stdin: os.write(2, b'x' * 4096)\n")
        self.assertEqual(event["reason"], "stderr_output_limit")
        self.assertEqual(event["stderr_class"], "unclassified")

    def test_fixed_rpc_phases_do_not_include_request_values(self):
        server = driver.Server([sys.executable, "-u", "-c", FAKE, "wrong-turn"], str(SOURCE.parent))
        try:
            server.initialize()
            self.assertEqual(server.phase, "initialize")
            thread = server.thread()
            self.assertEqual(server.phase, "thread_start")
            with self.assertRaisesRegex(driver.Failure, "rpc_timeout"):
                server.turn(thread, self.CANARY, time.monotonic() + 0.2)
            self.assertEqual(server.phase, "turn_completion")
        finally:
            server.close()


class AcceptanceTests(unittest.TestCase):
    def test_rotation_wait_requires_change_and_expired_hosted_epoch_without_active_turn(self):
        clock = [0.0]
        class Idle:
            def pump(self, duration):
                clock[0] += duration
        with patch.object(driver.time, "monotonic", lambda: clock[0]), \
                patch.object(driver, "token_fingerprint", lambda: b"new"):
            driver.observe_rotation(Idle(), b"old", 0.0)
        self.assertGreater(clock[0], 600)
        self.assertLess(clock[0], 601)

    def test_epoch_bound_matches_production_gateway(self):
        gateway = SOURCE.parents[4] / "crates/codewire-gateway/src/hosted_bridge.rs"
        self.assertIn("const EPOCH_MAX_LIFETIME: Duration = Duration::from_secs(600);",
                      gateway.read_text())
        self.assertEqual(driver.HOSTED_EPOCH_MAX_LIFETIME, 600.0)

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

    def workflow(self, legacy_calls=0, codex_calls=1, durations=(0.0, 0.0, 0.0)):
        calls = []
        clock = [0.0]
        elapsed_by_prompt = dict(zip(
            ("CW_KIND_ROTATION", "CW_KIND_BROKER_RETRY_ONCE", "CW_KIND_BROKER_RETRY_EXHAUSTED"),
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
            def turn(self, thread, prompt, deadline=None, *, expected_failure=False):
                self.inputs.append((thread, prompt, expected_failure))
                if prompt != "CW_KIND_BASELINE":
                    self.deadlines.append(deadline)
                calls.extend([clock[0]] * legacy_calls)
                clock[0] += elapsed_by_prompt.get(prompt, 0.0)
        workflow = Workflow()
        output = io.StringIO()
        with patch.object(driver, "auth_calls", lambda _: list(calls)), \
                patch.object(driver, "codex_exec_calls", lambda _: [0.0] * codex_calls), \
                patch.object(driver.time, "monotonic", lambda: clock[0]), \
                patch.object(driver, "token_fingerprint", lambda: b"synthetic"), \
                patch.object(driver, "observe_rotation"), \
                contextlib.redirect_stdout(output):
            driver.run(workflow, None)
        return workflow, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_no_legacy_auth_and_fresh_thread_markers_with_failed_exhaustion(self):
        workflow, events = self.workflow(durations=(3.0, 4.0, 5.0))
        self.assertEqual([thread for thread, _, _ in workflow.inputs], ["1", "1", "2", "3"])
        self.assertEqual([failure for _, _, failure in workflow.inputs], [False, False, False, True])
        self.assertEqual([event["event"] for event in events], [
            "baseline_completed", "projected_token_rotated", "rotation_turn_completed",
            "broker_retry_completed", "broker_retry_exhausted",
        ])
        self.assertEqual([event["legacy_auth_commands"] for event in events[-3:]], [0, 0, 0])
        self.assertEqual(workflow.deadlines, [driver.SCENARIO_TIMEOUT] * 5)

    def test_any_legacy_auth_command_or_second_codex_process_is_rejected(self):
        with self.assertRaisesRegex(driver.Failure, "legacy_auth_command_executed"):
            self.workflow(legacy_calls=1)
        for count in (0, 2):
            with self.subTest(count=count), self.assertRaisesRegex(
                    driver.Failure, "unexpected_codex_process_count"):
                self.workflow(codex_calls=count)

    def test_individually_short_turns_cannot_exceed_shared_scenario_deadline(self):
        with self.assertRaisesRegex(driver.Failure, "retry_scenario_deadline"):
            self.workflow(durations=(10.0, 10.0, 10.0))

    def test_rotation_turn_itself_must_finish_inside_shared_scenario_deadline(self):
        with self.assertRaisesRegex(driver.Failure, "rotation_turn_deadline"):
            self.workflow(durations=(driver.SCENARIO_TIMEOUT, 0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
