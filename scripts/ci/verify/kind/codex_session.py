#!/usr/bin/env python3
"""Managed Kind only: one stock Codex process, three successes and one denial.

The caller pipes this file into the actual workspace's python3. Protocol is
pinned to Codex 0.160.0 commit a956835d020762cb2b570053af06f643a11c0ecc. Never
print raw RPC, stderr, trace, token bytes or fingerprints: stdout is the
closed acceptance event stream.

This session covers the proxy route. Once the daemon delivers Codex's own
ChatGPT login it removes Codewire's config.toml (codex_login.py covers that
route), so the session forces the same proxy provider with CODEX_OVERRIDES
and points Codex's ChatGPT backend at a closed loopback port. There are no
token or auth overrides.

The harness runs the tracer and Codex in one fresh user namespace, mapping only
the calling user to namespace root. This is harness-local tracing authority,
not added host/Pod privilege or product configuration. Network, mount and PID
namespaces and projected token mounts remain unchanged. Namespace failure is
fatal; there is no untraced fallback.
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
import sys
import tempfile
import time


CODEX = "/opt/codewire/agents/npm/bin/codex"
# The daemon's proxy provider (codewire-access CodexProviderProjection's
# loopback form), forced whether or not Codewire's config.toml is present.
# A ChatGPT login in auth.json would otherwise send Codex's account, settings
# and analytics calls to chatgpt.com through blocked egress; a closed loopback
# port fails them at once. The provider itself sends no OpenAI auth.
CODEX_OVERRIDES = (
    "-c", 'model_provider="codewire_openai"',
    "-c", 'model_providers.codewire_openai.name="Codewire OpenAI"',
    "-c", 'model_providers.codewire_openai.base_url="http://127.0.0.1:38081/v1"',
    "-c", 'model_providers.codewire_openai.wire_api="responses"',
    "-c", "model_providers.codewire_openai.requires_openai_auth=false",
    "-c", "model_providers.codewire_openai.supports_websockets=false",
    "-c", "features.enable_request_compression=false",
    "-c", 'chatgpt_base_url="http://127.0.0.1:9/backend-api/"',
)
CODEX_ARGV = (CODEX, "app-server", "--stdio", "--strict-config", *CODEX_OVERRIDES)
# Codex's default home on the persistent home volume; the daemon writes
# Codewire's config.toml there, first line MANAGED_HEADER.
CODEX_HOME = "/home/codewire/.codex"
MANAGED_HEADER = b"# Managed by Codewire. Delete this line to manage this file yourself."
MAX_MANAGED_CONFIG = 64 * 1024
TOKEN = "/run/codewire-credentials/workspace/token"
MARKER = "CWCODEX149 kind"
MAX_LINE = 1024 * 1024
MAX_OUTPUT = 8 * MAX_LINE
MAX_TRACE = 1024 * 1024
MAX_STDERR_DIAGNOSTIC = 4096
RPC_TIMEOUT = 60.0
ROTATION_TIMEOUT = 720.0
# The production hosted gateway expires each epoch after at most 600 seconds.
# Waiting strictly beyond that bound after baseline completion cannot reuse
# baseline's epoch. Host-side authenticated admission logs prove fresh tokens;
# time or the changed file by itself is not sufficient acceptance evidence.
HOSTED_EPOCH_MAX_LIFETIME = 600.0
# The host creates this file when the credential fixture records a fresh-token
# admission for this environment: the relay's successor epoch authenticated
# with the replaced workspace token. With the replaced token it ends the idle
# before the epoch bound (codex_session.py <marker>).
ADMISSION_MARKER = re.compile(r"/tmp/codewire-kind-fresh-admission-[0-9]{1,12}")
SCENARIO_TIMEOUT = 30.0
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


def successful_exec_calls(trace, prefix):
    """Read bounded private trace data; return only exact exec timestamps."""
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


def auth_calls(trace):
    """Negative assertion: selected loopback clients never invoke legacy auth."""
    return successful_exec_calls(
        trace, f'execve("/bin/cat", ["/bin/cat", "{TOKEN}"], ')


def strace_string(value):
    """A string as strace prints it: quoted, with quotes and backslashes escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def codex_exec_calls(trace):
    arguments = ", ".join(strace_string(argument) for argument in CODEX_ARGV)
    prefix = f'execve({strace_string(CODEX)}, [{arguments}], '
    return successful_exec_calls(trace, prefix)


def codex_exec_succeeded(trace):
    # This proves only exec of the pinned launcher, not a working app-server.
    try:
        return bool(codex_exec_calls(trace))
    except Failure:
        return None


def validate_process_trace(trace):
    if len(codex_exec_calls(trace)) != 1:
        raise Failure("unexpected_codex_process_count")
    if auth_calls(trace):
        raise Failure("legacy_auth_command_executed")


class Server:
    def __init__(self, argv, cwd):
        self.selector = selectors.DefaultSelector()
        self.frames = Frames()
        self.stderr_bytes = 0
        self.stderr_prefix = bytearray()
        self.phase = "launch"
        self.eof_channel = None
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
        except BaseException as error:
            if self.process is not None:
                self.close()
            else:
                self.selector.close()
            if isinstance(error, FileNotFoundError):
                raise Failure("process_start_not_found") from None
            if isinstance(error, PermissionError):
                raise Failure("process_start_permission_denied") from None
            if isinstance(error, OSError):
                raise Failure("process_start_os_error") from None
            raise

    def observe_stderr(self, data):
        self.stderr_bytes += len(data)
        remaining = MAX_STDERR_DIAGNOSTIC - len(self.stderr_prefix)
        self.stderr_prefix.extend(data[:remaining])

    def _read_stderr(self, fd):
        # This single-threaded collector reads a nonblocking pipe. Defer only
        # its cancellation signals until consumed bytes have been recorded.
        # Query first: blocking itself may deliver an already-pending Python
        # handler, so the mask-changing call belongs inside the restoration guard.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            data = os.read(fd, 65536)
            self.observe_stderr(data)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        return data

    def failure_diagnostics(self, trace):
        # Sample status before closing stdin or sending cleanup signals. A null
        # status is unknown/still running, never the later forced-cleanup exit.
        status = self.process.poll()
        # EOF on stdout can be delivered before already-written stderr. Read
        # at most one nonblocking chunk, without waiting for new child output.
        try:
            self.observe_stderr(os.read(self.process.stderr.fileno(), 65536))
        except (OSError, ValueError):
            pass
        stderr_class = "unclassified" if self.stderr_bytes else "none"
        # A deliberately small diagnostic clue, not a general redactor and not
        # proof of the effective host policy. No captured bytes leave here.
        for line in bytes(self.stderr_prefix).split(b"\n")[:-1]:
            if line in (
                b"unshare: unshare failed: Operation not permitted",
                b"/usr/bin/unshare: unshare failed: Operation not permitted",
            ):
                stderr_class = "user_namespace_denied_message"
                break
            if (line.startswith((b"strace: ", b"/usr/bin/strace: "))
                    and line.endswith(b": Operation not permitted")
                    and any(marker in line for marker in (
                        b"ptrace(PTRACE_TRACEME,", b"ptrace(PTRACE_SEIZE,",
                        b"PTRACE_TRACEME:", b"PTRACE_SEIZE:",
                    ))):
                stderr_class = "ptrace_denied_message"
                break
        return {
            "phase": self.phase,
            "eof_channel": self.eof_channel,
            "child_status": status,
            "stderr_class": stderr_class,
            "codex_exec_succeeded": codex_exec_succeeded(trace),
        }

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
            fd = key.fileobj.fileno()
            data = self._read_stderr(fd) if key.data == "stderr" else os.read(fd, 65536)
            if not data:
                self.selector.unregister(key.fileobj)
                if not closing:
                    self.eof_channel = key.data
                    raise Failure("server_pipe_closed")
                continue
            if key.data == "stdout":
                if not closing:
                    for value in self.frames.feed(data):
                        self.receive(value)
            else:
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
        self.phase = "initialize"
        result = self.request("initialize", {"clientInfo": {
            "name": "codewire_kind_credentials", "title": "Codewire Kind", "version": "1",
        }})
        if result.get("codexHome") != CODEX_HOME or result.get("platformOs") != "linux":
            raise Failure("unexpected_server_identity")
        self.send({"method": "initialized"})

    def thread(self, deadline=None):
        self.phase = "thread_start"
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

    def turn(self, thread_id, prompt, deadline=None, *, expected_failure=False):
        self.phase = "turn_start"
        deadline = deadline if deadline is not None else time.monotonic() + RPC_TIMEOUT
        result = self.request("turn/start", {
            "threadId": thread_id, "input": [{"type": "text", "text": prompt}],
        }, deadline)
        turn = result.get("turn", {})
        if not isinstance(turn, dict):
            raise Failure("invalid_started_turn")
        key = self.turn_key(thread_id, turn.get("id"))
        self.phase = "turn_completion"
        self.until(lambda: key in self.completed, deadline)
        completed = self.completed[key]
        if expected_failure:
            # The host verifies the exact 401 -> refresh -> 400 transcript;
            # double-401 forwarding is separate broker unit proof. Require a
            # real failed terminal here, not an RPC
            # timeout, interrupted turn, or successful third request.
            if (completed.get("status") != "failed"
                    or not isinstance(completed.get("error"), dict)
                    or not completed["error"] or key in self.markers):
                raise Failure("unexpected_exhaustion_terminal")
        else:
            if completed.get("status") != "completed" or completed.get("error") is not None:
                raise Failure("turn_failed")
            if key not in self.markers:
                raise Failure("missing_synthetic_output")
        self.phase = "idle"

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


def observe_rotation(server, initial, baseline_completed, admitted=lambda: False):
    """Idle until the projected token has been replaced and a fresh-token
    epoch admitted: the host's admission mark, or else waiting past the epoch
    bound. Returns the seconds after baseline when the replacement was seen,
    and whether the admission mark ended the idle."""
    server.phase = "token_rotation"
    deadline = time.monotonic() + ROTATION_TIMEOUT
    rotated = None
    while True:
        now = time.monotonic()
        if now >= deadline:
            raise Failure("projected_token_rotation_timeout")
        if rotated is None and token_fingerprint() != initial:
            rotated = now - baseline_completed
        if rotated is not None:
            if admitted():
                return rotated, True
            if now - baseline_completed > HOSTED_EPOCH_MAX_LIFETIME:
                return rotated, False
        server.pump(0.25)


def run(server, trace, admitted=lambda: False):
    server.initialize()
    thread_id = server.thread()
    server.turn(thread_id, "CW_KIND_BASELINE")
    baseline_completed = time.monotonic()
    # Snapshot AFTER completion: a replacement during initial thread setup
    # must not masquerade as rotation during the deliberately idle interval.
    initial = token_fingerprint()
    validate_process_trace(trace)
    emit("baseline_completed", codex_processes=1, legacy_auth_commands=0)
    rotated, fresh_admission = observe_rotation(server, initial, baseline_completed, admitted)
    emit("projected_token_rotated", changed=True, rotated_ms=int(rotated * 1000),
         fresh_admission=fresh_admission,
         elapsed_ms=int((time.monotonic() - baseline_completed) * 1000))
    # The same stock process continues through the new hosted epoch. The
    # remaining original deadlines bound the entire retry/exhaustion journey,
    # not a removed Codex auth-command cache. No harness request is replayed.
    deadline = time.monotonic() + SCENARIO_TIMEOUT
    server.turn(thread_id, "CW_KIND_ROTATION", deadline)
    validate_process_trace(trace)
    if not time.monotonic() < deadline:
        raise Failure("rotation_turn_deadline")
    emit("rotation_turn_completed", legacy_auth_commands=0)

    for prompt, event, expected_failure in (
        ("CW_KIND_BROKER_RETRY_ONCE", "broker_retry_completed", False),
        ("CW_KIND_BROKER_RETRY_EXHAUSTED", "broker_retry_exhausted", True),
    ):
        started = time.monotonic()
        # Fresh threads avoid interpreting an earlier test marker retained in
        # conversation history as the current synthetic provider scenario.
        thread_id = server.thread(deadline)
        server.turn(thread_id, prompt, deadline, expected_failure=expected_failure)
        validate_process_trace(trace)
        elapsed = time.monotonic() - started
        if not time.monotonic() < deadline:
            raise Failure("retry_scenario_deadline")
        emit(event, legacy_auth_commands=0, elapsed_ms=int(elapsed * 1000))


def managed_config(path):
    """Whether path is Codewire's daemon-written file: regular, not a symlink,
    first line exactly the managed header."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    with os.fdopen(descriptor, "rb") as source:
        contents = source.read(MAX_MANAGED_CONFIG + 1)
    return contents.split(b"\n", 1)[0] == MANAGED_HEADER


def validate_projection():
    # Selected Codex uses the daemon-owned loopback route. The daemon's own
    # ~/.codex/config.toml configures it until a delivered ChatGPT login
    # removes that file; never a user's file or a symlink. An
    # environment-token Pod also renders the selection and CODEX_HOME; an
    # identity-free Pod renders neither, and this kubectl-exec'd driver then
    # relies on Codex's default home. The gateway's public roots are not a
    # Codex environment override, even when that mount exists.
    rendered = (os.environ.get("CODEX_HOME"),
                os.environ.get("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"))
    config = Path(CODEX_HOME) / "config.toml"
    if (rendered not in {(None, None), (CODEX_HOME, "v1:codex")}
            or "CODEX_CA_CERTIFICATE" in os.environ
            or (os.path.lexists(config) and not managed_config(config))):
        raise Failure("unexpected_projection")


def main(argv=()):
    stage = "startup"
    server = None
    success = False
    diagnostics = {"phase": "launch"}
    def interrupted(_signum, _frame):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if len(argv) > 1 or (argv and not ADMISSION_MARKER.fullmatch(argv[0])):
            raise Failure("arguments")
        marker = Path(argv[0]) if argv else None
        if marker is not None and os.path.lexists(marker):
            raise Failure("admission_marker_present")
        def admitted():
            return marker is not None and marker.is_file()
        validate_projection()
        if Path(CODEX_HOME).resolve() != Path(CODEX_HOME):
            raise Failure("unexpected_home_path")
        with tempfile.TemporaryDirectory(prefix="kind-session-", dir=CODEX_HOME) as scratch:
            trace = Path(scratch) / "execve.trace"
            server = Server([
                "/usr/bin/unshare", "--user", "--map-root-user", "--",
                "/usr/bin/strace", "-f", "-ttt", "-e", "trace=execve", "-s", "512",
                "-o", str(trace), "--", *CODEX_ARGV,
            ], "/workspace")
            stage = "session"
            try:
                run(server, trace, admitted)
            except BaseException:
                # Repeated interruption must not abandon an owned child while
                # the first cancellation is being drained. Keep the original
                # closed failure if cleanup has an independent problem.
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                try:
                    diagnostics = server.failure_diagnostics(trace)
                except Exception:
                    diagnostics = {"phase": "diagnostic_unavailable"}
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
        emit("failed", stage=stage, reason=str(error), **diagnostics)
    except Exception:
        emit("failed", stage=stage, reason="driver_failure", **diagnostics)
    if success:
        emit("complete", turns=4, completed=3, failed=1, same_process=True, token_changed=True)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
