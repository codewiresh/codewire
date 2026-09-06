#!/usr/bin/env python3
"""Managed Kind only: one stock Codex process, four completed synthetic turns.

The caller pipes this file into the actual workspace's python3. There are no
provider/token/config overrides. Protocol is pinned to Codex 0.149.0 commit
758ef40f50c1a458425c7cfbf1eb12cbc07af0b0. Never print raw RPC, stderr, trace,
token bytes or fingerprints: stdout is the closed acceptance event stream.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time


CODEX = "/opt/codewire/agents/npm/bin/codex"
CODEX_HOME = "/run/codewire-codex/home"
ROOTS = "/run/codewire-credentials/gateway-roots/ca.crt"
TOKEN = "/run/codewire-credentials/workspace/token"
MARKER = "CWCODEX149 kind"
MAX_LINE = 1024 * 1024
MAX_OUTPUT = 8 * MAX_LINE
MAX_TRACE = 1024 * 1024
RPC_TIMEOUT = 60.0
ROTATION_TIMEOUT = 720.0
CACHE_INTERVAL = 30.0
SHUTDOWN_GRACE = 5.0


class Failure(Exception):
    """Only fixed reason identifiers may enter the public event stream."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Failure("duplicate_rpc_field")
        result[key] = value
    return result


class Frames:
    def __init__(self):
        self.pending = bytearray()
        self.total = 0

    def feed(self, data):
        self.total += len(data)
        if self.total > MAX_OUTPUT:
            raise Failure("rpc_output_limit")
        self.pending.extend(data)
        result = []
        while b"\n" in self.pending:
            line, _, remaining = self.pending.partition(b"\n")
            self.pending = bytearray(remaining)
            if not line or len(line) > MAX_LINE:
                raise Failure("invalid_rpc_line")
            try:
                value = json.loads(line, object_pairs_hook=unique_object)
            except (ValueError, UnicodeError):
                raise Failure("invalid_rpc_json") from None
            if not isinstance(value, dict):
                raise Failure("invalid_rpc_shape")
            result.append(value)
        if len(self.pending) > MAX_LINE:
            raise Failure("rpc_line_limit")
        return result


def token_fingerprint():
    # Follow Kubernetes' atomic projection symlink, but never block on a FIFO
    # or consume a device/oversize file. Only the digest leaves this function.
    try:
        fd = os.open(TOKEN, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as token:
            if not stat.S_ISREG(os.fstat(token.fileno()).st_mode):
                raise Failure("invalid_token_file")
            value = token.read(16 * 1024 + 1)
    except OSError:
        raise Failure("token_unavailable") from None
    if not value or len(value) > 16 * 1024:
        raise Failure("invalid_token_size")
    return hashlib.sha256(value).digest()


def auth_calls(trace):
    """Count only successful exact fixed-command execve calls, never buffers."""
    try:
        with trace.open("rb") as source:
            raw = source.read(MAX_TRACE + 1)
    except OSError:
        raise Failure("trace_unavailable") from None
    if len(raw) > MAX_TRACE:
        raise Failure("trace_limit")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise Failure("invalid_trace") from None
    prefix = f'execve("/bin/cat", ["/bin/cat", "{TOKEN}"], '
    pending = {}
    calls = []
    for line in lines:
        match = re.fullmatch(r"(\d+)\s+(\d+\.\d+)\s+(.*)", line)
        if not match:
            continue
        pid, timestamp, operation = match.groups()
        if operation.startswith(prefix):
            if operation.endswith(" = 0"):
                calls.append(float(timestamp))
            elif operation.endswith("<unfinished ...>"):
                pending[pid] = float(timestamp)
        elif operation.startswith("<... execve resumed>") and pid in pending:
            started = pending.pop(pid)
            if operation.endswith(" = 0"):
                calls.append(started)
    return sorted(calls)


class Server:
    def __init__(self, argv, cwd):
        self.selector = selectors.DefaultSelector()
        self.frames = Frames()
        self.stderr_bytes = 0
        self.responses = {}
        self.response_ids = set()
        self.completed = {}
        self.markers = set()
        self.next_id = 0
        self.process = None
        try:
            self.process = subprocess.Popen(
                argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, bufsize=0,
            )
            for name in ("stdout", "stderr"):
                pipe = getattr(self.process, name)
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, name)
        except BaseException:
            if self.process is not None:
                self.close()
            else:
                self.selector.close()
            raise

    def receive(self, value):
        if "id" in value:
            if "method" in value:
                raise Failure("unexpected_server_request")
            request_id = value["id"]
            if type(request_id) is not int or not 1 <= request_id <= self.next_id:
                raise Failure("unknown_rpc_id")
            if request_id in self.response_ids or ("result" in value) == ("error" in value):
                raise Failure("invalid_rpc_response")
            self.response_ids.add(request_id)
            self.responses[request_id] = value
            return
        method = value.get("method")
        if not isinstance(method, str):
            raise Failure("invalid_rpc_notification")
        params = value.get("params", {})
        if not isinstance(params, dict):
            raise Failure("invalid_rpc_parameters")
        if method == "item/completed":
            item = params.get("item", {})
            if not isinstance(item, dict):
                raise Failure("invalid_item")
            if item.get("type") == "agentMessage":
                if item.get("text") != MARKER:
                    raise Failure("unexpected_agent_output")
                self.markers.add(self.turn_key(params.get("threadId"), params.get("turnId")))
        elif method == "turn/completed":
            turn = params.get("turn", {})
            if not isinstance(turn, dict):
                raise Failure("invalid_turn")
            key = self.turn_key(params.get("threadId"), turn.get("id"))
            if key in self.completed or len(self.completed) >= 8:
                raise Failure("duplicate_completed_turn")
            self.completed[key] = turn

    @staticmethod
    def turn_key(thread_id, turn_id):
        if not all(isinstance(value, str) and 0 < len(value) <= 128
                   for value in (thread_id, turn_id)):
            raise Failure("invalid_turn_identity")
        return thread_id, turn_id

    def pump(self, timeout, closing=False):
        for key, _ in self.selector.select(max(0, timeout)):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                self.selector.unregister(key.fileobj)
                if not closing:
                    raise Failure("server_pipe_closed")
                continue
            if key.data == "stdout":
                if not closing:
                    for value in self.frames.feed(data):
                        self.receive(value)
            else:
                self.stderr_bytes += len(data)
                if self.stderr_bytes > MAX_OUTPUT and not closing:
                    raise Failure("stderr_output_limit")
        if self.process.poll() is not None and not closing:
            raise Failure("server_exited")

    def until(self, predicate, deadline):
        while not predicate():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("rpc_timeout")
            self.pump(min(remaining, 0.25))

    def send(self, value):
        encoded = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        try:
            if self.process.stdin.write(encoded) != len(encoded):
                raise Failure("short_rpc_write")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise Failure("server_input_closed") from None

    def request(self, method, params, deadline=None):
        self.next_id += 1
        request_id = self.next_id
        self.send({"id": request_id, "method": method, "params": params})
        self.until(lambda: request_id in self.responses,
                   deadline if deadline is not None else time.monotonic() + RPC_TIMEOUT)
        response = self.responses.pop(request_id)
        if "error" in response or not isinstance(response.get("result"), dict):
            raise Failure("rpc_rejected")
        return response["result"]

    def initialize(self):
        result = self.request("initialize", {"clientInfo": {
            "name": "codewire_kind_credentials", "title": "Codewire Kind", "version": "1",
        }})
        if result.get("codexHome") != CODEX_HOME or result.get("platformOs") != "linux":
            raise Failure("unexpected_server_identity")
        self.send({"method": "initialized"})

    def thread(self, deadline=None):
        result = self.request("thread/start", {
            "model": "codewire-synthetic", "cwd": "/workspace",
            "approvalPolicy": "never", "sandbox": "read-only", "ephemeral": True,
        }, deadline)
        thread = result.get("thread", {})
        if not isinstance(thread, dict) or thread.get("ephemeral") is not True or thread.get("path") is not None:
            raise Failure("non_ephemeral_thread")
        thread_id = thread.get("id")
        self.turn_key(thread_id, "pending")
        if result.get("modelProvider") != "codewire_openai":
            raise Failure("unexpected_model_provider")
        return thread_id

    def turn(self, thread_id, prompt, deadline=None):
        deadline = deadline if deadline is not None else time.monotonic() + RPC_TIMEOUT
        result = self.request("turn/start", {
            "threadId": thread_id, "input": [{"type": "text", "text": prompt}],
        }, deadline)
        turn = result.get("turn", {})
        if not isinstance(turn, dict):
            raise Failure("invalid_started_turn")
        key = self.turn_key(thread_id, turn.get("id"))
        self.until(lambda: key in self.completed, deadline)
        completed = self.completed[key]
        if completed.get("status") != "completed" or completed.get("error") is not None:
            raise Failure("turn_failed")
        if key not in self.markers:
            raise Failure("missing_synthetic_output")

    def close(self):
        try:
            self.process.stdin.close()
            for next_signal in (None, signal.SIGTERM, signal.SIGKILL):
                if next_signal is not None:
                    try:
                        os.killpg(self.process.pid, next_signal)
                    except ProcessLookupError:
                        pass
                deadline = time.monotonic() + SHUTDOWN_GRACE
                while self.process.poll() is None and time.monotonic() < deadline:
                    self.pump(0.1, closing=True)
                if self.process.poll() is not None:
                    return self.process.wait()
            raise Failure("server_cleanup_timeout")
        finally:
            self.selector.close()
            self.process.stdout.close()
            self.process.stderr.close()


def observe_rotation(server, initial, baseline_completed):
    deadline = time.monotonic() + ROTATION_TIMEOUT
    while True:
        changed = token_fingerprint() != initial
        if changed and time.monotonic() - baseline_completed > CACHE_INTERVAL:
            return
        if time.monotonic() >= deadline:
            raise Failure("projected_token_rotation_timeout")
        server.pump(0.25)


def run(server, trace):
    server.initialize()
    thread_id = server.thread()
    server.turn(thread_id, "CW_KIND_BASELINE")
    baseline_completed = time.monotonic()
    # Snapshot AFTER completion: a replacement during initial thread setup
    # must not masquerade as rotation during the deliberately idle interval.
    initial = token_fingerprint()
    baseline_calls = len(auth_calls(trace))
    if baseline_calls < 1:
        raise Failure("missing_initial_auth_command")
    emit("baseline_completed", auth_command_calls=baseline_calls)
    observe_rotation(server, initial, baseline_completed)
    emit("projected_token_rotated", changed=True,
         elapsed_ms=int((time.monotonic() - baseline_completed) * 1000))
    # Pinned Codex has separate shared model-catalog and per-thread request
    # auth caches. Second-turn pre-compaction refreshes the expired catalog
    # cache before the request refreshes its own. Keep all remaining work in
    # one cache interval so fresh threads cannot refresh the catalog again.
    deadline = time.monotonic() + CACHE_INTERVAL
    before = len(auth_calls(trace))
    server.turn(thread_id, "CW_KIND_ROTATION", deadline)
    calls = len(auth_calls(trace)) - before
    if calls != 2 or not time.monotonic() < deadline:
        raise Failure("rotation_auth_command_count_or_deadline")
    emit("rotation_turn_completed", auth_command_calls=calls)

    for prompt, event, expected in (
        ("CW_KIND_BROKER_RETRY_ONCE", "broker_retry_completed", 1),
        ("CW_KIND_NATIVE_REREAD", "native_reread_completed", 2),
    ):
        before = len(auth_calls(trace))
        started = time.monotonic()
        # Fresh threads avoid interpreting an earlier test marker retained in
        # conversation history as the current synthetic provider scenario.
        thread_id = server.thread(deadline)
        server.turn(thread_id, prompt, deadline)
        observed = auth_calls(trace)[before:]
        elapsed = time.monotonic() - started
        if len(observed) != expected or not time.monotonic() < deadline:
            raise Failure("retry_auth_command_count_or_deadline")
        if expected == 2 and not 0 <= observed[1] - observed[0] < CACHE_INTERVAL:
            raise Failure("native_reread_cache_deadline")
        emit(event, auth_command_calls=len(observed), elapsed_ms=int(elapsed * 1000))


def main():
    stage = "startup"
    server = None
    success = False
    def interrupted(_signum, _frame):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if os.environ.get("CODEX_HOME") != CODEX_HOME or os.environ.get("CODEX_CA_CERTIFICATE") != ROOTS:
            raise Failure("unexpected_projection")
        if Path(CODEX_HOME).resolve() != Path(CODEX_HOME):
            raise Failure("unexpected_home_path")
        with tempfile.TemporaryDirectory(prefix="kind-session-", dir=CODEX_HOME) as scratch:
            trace = Path(scratch) / "execve.trace"
            server = Server([
                "/usr/bin/strace", "-f", "-ttt", "-e", "trace=execve", "-s", "512",
                "-o", str(trace), "--", CODEX, "app-server", "--stdio", "--strict-config",
            ], "/workspace")
            stage = "session"
            try:
                run(server, trace)
            except BaseException:
                # Repeated interruption must not abandon an owned child while
                # the first cancellation is being drained. Keep the original
                # closed failure if cleanup has an independent problem.
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                try:
                    server.close()
                except Exception:
                    pass
                server = None
                raise
            else:
                stage = "cleanup"
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                status = server.close()
                if status != 0:
                    raise Failure("server_shutdown_failed")
                server = None
            success = True
    except Failure as error:
        emit("failed", stage=stage, reason=str(error))
    except Exception:
        emit("failed", stage=stage, reason="driver_failure")
    if success:
        emit("complete", turns=4, same_process=True, token_changed=True)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
