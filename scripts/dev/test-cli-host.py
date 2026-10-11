#!/usr/bin/env python3
"""Observed Linux/macOS host CLI journey, with synthetic native peers by default.

Run against a built cw, without replacing HOME or accessing login files:
  scripts/dev/test-cli-host.py --cw target/debug/cw
  scripts/dev/test-cli-host.py --cw target/debug/cw --native-agents

The native option uses the installed agents' ordinary login. It proves a Codex
lead can invoke cw itself and a Claude worker's result starts a parent turn.
All runtime/config/workspace files and processes belong to this invocation.
Linux joins every owned descendant through a child subreaper. Darwin has none,
so macOS runs the journey as a new session leader and requires that no live
process remains in that session or names the journey's private root by its
working directory or arguments (see owned_family).
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


WALL = 0x40000000  # Linux __WALL includes non-SIGCHLD clone children.
LINUX = sys.platform.startswith("linux")
MACOS = sys.platform == "darwin"


def require_owned_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    enabled = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1:
        raise AssertionError("host journey lost its owned-family subreaper")


def arm_owned_family():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise AssertionError("cannot enable host journey owned-family subreaper")
    require_owned_subreaper()
    Path("/proc/thread-self/children").read_text()
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WALL)
    except ChildProcessError:
        return
    raise AssertionError("host journey must begin without existing children")


def reap_owned_family(timeout=10):
    """Join only kernel-owned children; live or unknown custody stays failure."""
    require_owned_subreaper()
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() >= deadline:
            raise AssertionError("host journey owned-family cleanup remains unknown")
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG | WALL)
        except ChildProcessError:
            return
        if not pid:
            time.sleep(0.02)


class Darwin:
    """libproc views of processes; Darwin has no subreaper or /proc."""
    ALL_PIDS = 1
    BSDINFO, BSDINFO_SIZE, SZOMB = 3, 136, 5  # struct proc_bsdinfo; pbi_status at 4
    # struct proc_vnodepathinfo: cwd vnode_info (152 bytes), then its path.
    VNODEPATHINFO, VNODEPATHINFO_SIZE, VNODE_INFO_SIZE, MAXPATHLEN = 9, 2352, 152, 1024

    def __init__(self):
        self.lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                          ctypes.c_void_p, ctypes.c_int]

    def pids(self):
        size = self.lib.proc_listpids(self.ALL_PIDS, 0, None, 0)
        if size <= 0:
            raise AssertionError("host journey cannot list processes")
        buffer = (ctypes.c_int * (size // 4 + 256))()
        used = self.lib.proc_listpids(self.ALL_PIDS, 0, buffer, ctypes.sizeof(buffer))
        if used <= 0 or used >= ctypes.sizeof(buffer):
            raise AssertionError("host journey cannot list processes")
        return [pid for pid in buffer[:used // 4] if pid > 0]

    def info(self, pid, flavor, size):
        buffer = ctypes.create_string_buffer(size)
        if self.lib.proc_pidinfo(pid, flavor, 0, buffer, size) != size:
            return None
        return buffer.raw

    def live(self, pid):
        # proc_pidinfo refuses a zombie, which kill(pid, 0) still accepts.
        info = self.info(pid, self.BSDINFO, self.BSDINFO_SIZE)
        return info is not None and int.from_bytes(info[4:8], sys.byteorder) != self.SZOMB

    def cwd(self, pid):
        info = self.info(pid, self.VNODEPATHINFO, self.VNODEPATHINFO_SIZE)
        if info is None:
            return None
        path = info[self.VNODE_INFO_SIZE:self.VNODE_INFO_SIZE + self.MAXPATHLEN]
        return os.fsdecode(path.split(b"\0", 1)[0])


def arm_owned_session():
    """Run the journey as the leader of a new session (macOS).

    A forked child that calls setsid cannot share its session with any earlier
    process. The parent forwards termination signals, so an interrupted journey
    still runs its own cleanup, and relays the child's exit status.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    child = os.fork()
    if child:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, lambda received, _: os.kill(child, received))
        _, status = os.waitpid(child, 0)
        code = os.waitstatus_to_exitcode(status)
        os._exit(code if code >= 0 else 128 - code)
    os.setsid()


def owned_family(root):
    """Live processes that this macOS journey owns, by pid.

    Darwin reparents an orphan to launchd, so ancestry cannot be followed after
    a descendant's parent exits. The host daemon and its sessions also start new
    sessions. Ownership is therefore this journey's own session, or a process
    whose working directory is inside, or whose arguments name, its private
    root. Every journey runtime process starts with such a directory or argument.
    """
    darwin = Darwin()
    roots = {str(root), os.path.realpath(root)}
    me, session = os.getpid(), os.getsid(0)
    listed = subprocess.run(["/bin/ps", "-axww", "-o", "pid=", "-o", "command="],
                            capture_output=True, text=True, check=True).stdout
    commands = {}
    for line in listed.splitlines():
        pid, _, command = line.strip().partition(" ")
        commands[int(pid)] = command
    found = {}
    for pid in darwin.pids():
        if pid == me or not darwin.live(pid):
            continue
        try:
            in_session = os.getsid(pid) == session
        except OSError:
            in_session = False
        cwd = darwin.cwd(pid) or ""
        command = commands.get(pid, "")
        if (in_session or any(cwd == r or cwd.startswith(r + "/") for r in roots)
                or any(r in command for r in roots)):
            found[pid] = command or cwd
    return found


def reap_marked_family(root, timeout=10):
    """Join this journey's children and require its owned family to be gone."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        remaining = owned_family(root)
        if not remaining:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"host journey owned-family cleanup remains unknown: {remaining}")
        time.sleep(0.2)


class Journey:
    def __init__(self, cw, native):
        state = Path.home() / ".local/state"
        state.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="cw-proof-", dir=state))
        self.workspace = self.root / "project"
        self.workspace.mkdir(mode=0o700)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("CODEWIRE_")}
        self.env.update(CW_HOST_DATA_DIR=str(self.root / "hosts"), CW_CONFIG_DIR=str(self.root / "config"))
        self.cw = str(Path(cw).resolve())
        self.native = native
        self.environment = None
        self.owned_sessions = []
        self.checks = []
        self.sentinel = subprocess.Popen(["sleep", "300"], start_new_session=True)
        if not native:
            programs = self.root / "bin"
            programs.mkdir(mode=0o700)
            fixture = Path(__file__).with_name("fixtures") / "agent-peer.py"
            for name in ("codex", "claude"):
                target = programs / name
                shutil.copyfile(fixture, target)
                target.chmod(0o700)
            self.env["PATH"] = str(programs) + os.pathsep + self.env.get("PATH", "")

    def call(self, *args, ok=True, timeout=45, data=False):
        result = subprocess.run([self.cw, *args], env=self.env, cwd=self.workspace,
                                text=True, capture_output=True, timeout=timeout)
        if ok and result.returncode != 0:
            raise AssertionError(f"cw {args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        if not ok and result.returncode == 0:
            raise AssertionError(f"cw {args}: unexpectedly succeeded")
        return json.loads(result.stdout) if data else result

    def check(self, label):
        assert self.sentinel.poll() is None, "unrelated process was killed"
        self.checks.append(label)
        print(f"cli-host: {label} PASS", flush=True)

    def launch(self, name, command=None, agent=None, parent=None, prompt=None, model=None, ok=True, detach=True):
        args = ["run", self.environment, "--name", name]
        if detach:
            args += ["--detach"]
        args += ["--output", "json"]
        if agent:
            args += ["--agent", agent]
            if agent == "claude":
                args += ["--effort", "xhigh"]
        else:
            args += ["--no-tty"]
        if parent:
            args += ["--parent", parent]
        if prompt:
            args += ["--prompt", prompt]
        if model:
            args += ["--model", model]
        if command:
            args += ["--", *command]
        launched = self.call(*args, timeout=60, data=True, ok=ok)
        view = launched["session"] if agent else launched
        self.owned_sessions.append(view["session_id"])
        return launched

    def inbox(self, name):
        return self.call("inbox", self.environment, name, "--output", "json", data=True)

    def until(self, probe, predicate, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = probe()
            if predicate(value):
                return value
            time.sleep(0.2)
        raise AssertionError("acceptance deadline expired")

    def wait_message(self, message_id, ok=True):
        result = self.call("wait", "--message", message_id, "--timeout", "3m", "--output", "json",
                           ok=ok, timeout=190)
        return json.loads(result.stdout)

    def run(self):
        created = self.call("env", "create", "--local", "--type", "host", "--name", "proof",
                            "--path", str(self.workspace), "--output", "json", data=True)
        self.environment = created["id"]
        assert created["type"] == "host"
        assert self.call("list", self.environment, "--output", "json", data=True) == []
        self.check("create/empty")

        self.launch("reader", ["sh", "-c", 'read -r value; printf "RECEIVED:%s" "$value"'])
        self.call("send", self.environment, "reader", "part", "--no-newline")
        self.call("wait", self.environment, "reader", "--timeout", "1s", ok=False)
        self.call("send", self.environment, "reader", "--", "-rest")
        waited = self.call("wait", self.environment, "reader", "--timeout", "10s", "--output", "json", data=True)
        assert waited["output"] == "RECEIVED:part-rest" and waited["eof"], waited
        assert self.call("logs", self.environment, "reader").stdout == waited["output"]
        self.call("run", self.environment, "--name", "reader", "--detach", "--", "true", ok=False)
        self.check("acknowledged-send/partial/wait/logs/unique-name")

        if not self.native:
            self.prove_logs_pagination()

        child_pid_file = self.workspace / "child.pid"
        owned = self.launch("tree", ["sh", "-c", 'sleep 300 & echo $! > "$1"; wait', "sh", str(child_pid_file)])
        self.until(child_pid_file.exists, bool)
        child_pid = int(child_pid_file.read_text())
        if MACOS:
            assert child_pid in owned_family(self.root), "owned-family scan misses a session descendant"
        stopped = self.call("stop", self.environment, "tree", "--output", "json", data=True)[0]
        assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        assert not process_alive(child_pid), "ordinary child survived Stop"
        self.launch("child", ["true"], parent=owned["session_id"])
        views = self.call("list", self.environment, "--output", "json", data=True)
        assert next(v for v in views if v["name"] == "child")["parent_session_id"] == owned["session_id"]
        self.check("owned-tree-stop/unrelated-process/parent-identity")

        self.launch("lead", agent="codex")
        self.until(lambda: self.inbox("lead"), lambda v: v["driver"] and v["driver"]["phase"] == "idle")
        text = "Reply with exactly LEAD_READY. Do not use tools." if self.native else "FIRST"
        message = self.call("msg", self.environment, "lead", text, "--output", "json", data=True)
        complete = self.wait_message(message["id"])
        assert complete["state"] == "completed" and complete["native_acknowledged"], complete
        self.call("send", self.environment, "lead", "raw", ok=False)
        self.check("managed-task/completion/raw-input-rejection")

        worker_text = "Reply with exactly WORKER_READY. Do not use tools." if self.native else "WORKER"
        worker = self.launch("worker", agent="claude", parent="lead", prompt=worker_text)
        assert worker["effort"] == "xhigh", worker
        worker_result = self.wait_message(worker["message"]["id"])
        assert worker_result["state"] == "completed" and worker_result["native_acknowledged"], worker_result
        parent = self.until(lambda: self.inbox("lead"),
                            lambda v: any(m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]),
                            timeout=180)
        notifications = [m for m in parent["messages"] if m["action"] == "notification"]
        assert len(notifications) == 1 and notifications[0]["source"]["session_id"] == worker["session"]["session_id"]
        self.call("steer", self.environment, "worker", "unsupported", ok=False)
        self.check("claude-worker/native-ack/idle-parent-wake/no-duplicate")

        if self.native:
            saved_thread = self.inbox("lead")["driver"]["native_thread_id"]
            self.call("stop", self.environment, "lead")
            restarted = self.call("restart", self.environment, "lead", "--output", "json", data=True)[0]
            assert restarted["session_id"] == parent["session_id"], restarted
            command = [self.cw, "run", self.environment, "--name", "lead-command", "--detach", "--no-tty", "--", "printf", "LEAD_COMMAND"]
            text = ("Run this exact command once, using your command tool: " +
                    " ".join(__import__("shlex").quote(a) for a in command) +
                    ". Do not run any other command or edit files. Then reply LEAD_COMMAND_STARTED.")
            message = self.call("msg", self.environment, "lead", text, "--output", "json", data=True)
            result = self.wait_message(message["id"])
            assert result["state"] == "completed", result
            output = self.call("wait", self.environment, "lead-command", "--timeout", "10s").stdout
            assert output == "LEAD_COMMAND", output
            assert self.inbox("lead")["driver"]["native_thread_id"] == saved_thread
            self.check("codex-resume/lead-initiated-cw-command/actual-host-policy")
            saved_thread = self.inbox("worker")["driver"]["native_thread_id"]
            self.call("stop", self.environment, "worker")
            self.call("restart", self.environment, "worker")
            resumed = self.call("msg", self.environment, "worker",
                                "Reply with exactly CLAUDE_RESUMED. Do not use tools.",
                                "--output", "json", data=True)
            assert self.wait_message(resumed["id"])["state"] == "completed"
            assert self.inbox("worker")["driver"]["native_thread_id"] == saved_thread
            self.until(lambda: self.inbox("lead"), lambda v: sum(
                m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]) == 2,
                timeout=180)
            self.check("claude-xhigh/resume/same-conversation/parent-wake")
        else:
            holding = self.call("msg", self.environment, "lead", "HOLD", "--output", "json", data=True)
            self.until(lambda: self.inbox("lead"), lambda v: v["driver"]["current_turn_id"] is not None)
            self.call("steer", self.environment, "lead", "bad", "--turn-id", "other-turn", ok=False)
            steered = self.call("steer", self.environment, "lead", "finish", "--output", "json", data=True)
            assert self.wait_message(holding["id"])["result"] == "STEERED"
            assert self.wait_message(steered["id"])["state"] == "completed"
            holding = self.call("msg", self.environment, "worker", "HOLD", "--output", "json", data=True)
            # Acceptance precedes the driver's active-turn publication.
            self.until(lambda: self.inbox("worker"), lambda v: v["driver"]["active_message_id"] == holding["id"])
            interrupted = self.call("interrupt", self.environment, "worker", "--output", "json", data=True)
            assert self.wait_message(interrupted["id"])["state"] == "completed"
            assert self.wait_message(holding["id"], ok=False)["state"] == "interrupted"
            self.check("expected-turn-steer/claude-interrupt")
            self.prove_outbox_recovery()

        self.call("env", "stop", "--local", self.environment)
        self.call("env", "start", "--local", self.environment)
        listed = self.call("list", self.environment, "--output", "json", data=True)
        assert any(v["name"] == "reader" and v["state"] == "Exited" for v in listed)
        assert (self.workspace / "child.pid").exists()
        self.check("graceful-shutdown/reload/workspace-preserved")

        # A new process owner must not recover inline launch values from disk.
        projected = self.call("run", self.environment, "--name", "projection", "--detach", "--no-tty",
                              "--env", "CW_FIXTURE_VALUE=synthetic-only", "--output", "json", "--",
                              "sh", "-c", 'printf %s "$CW_FIXTURE_VALUE"', data=True)
        assert self.call("wait", self.environment, "projection", "--timeout", "10s").stdout == "synthetic-only"
        metadata = self.root / "hosts" / self.environment / "sessions" / projected["session_id"] / "session.json"
        assert "synthetic-only" not in metadata.read_text() and '"env"' not in metadata.read_text()
        self.call("env", "stop", "--local", self.environment)
        self.call("env", "start", "--local", self.environment)
        refused = self.call("restart", self.environment, "projection", ok=False)
        assert "launch a new session" in refused.stderr, refused.stderr
        self.check("launch-projection/not-persisted/reload-refuses-stale-replay")

    def prove_logs_pagination(self):
        page_size = 256 * 1024
        prefix = b"history-line\n" * ((page_size - 2) // len(b"history-line\n"))
        padding = b"x" * (page_size - 2 - len(prefix))
        rows = b"history-line\n" * 30000
        marker = b"CLI_LOGS_PAGINATION_END\n"
        visible = b"PAGE_BOUNDARY_VISIBLE"
        encoded = prefix + padding + b"\x1b[31m" + visible + b"\x1b[0m\n" + rows + marker
        plain = prefix + padding + visible + b"\n" + rows + marker
        # The initial replay page ends between ESC and its CSI body. The process
        # remains running until follow is attached, so ordinary logs must return.
        program = (
            "import sys; n=256*1024; row=b'history-line\\n'; "
            "prefix=row*((n-2)//len(row)); padding=b'x'*(n-2-len(prefix)); "
            "sys.stdout.buffer.write(prefix+padding+b'\\x1b[31mPAGE_BOUNDARY_VISIBLE\\x1b[0m\\n'"
            "+row*30000+b'CLI_LOGS_PAGINATION_END\\n'); sys.stdout.buffer.flush(); "
            "sys.stdin.readline(); sys.stdout.buffer.write(b'\\x1b['); sys.stdout.buffer.flush(); "
            "sys.stdin.readline(); sys.stdout.buffer.write(b'32mCLI_LOGS_FOLLOW_END\\x1b'); "
            "sys.stdout.buffer.flush(); sys.stdin.readline(); "
            "sys.stdout.buffer.write(b'[0m\\n'); sys.stdout.buffer.flush()"
        )
        self.launch("history", [sys.executable, "-c", program])
        self.until(lambda: self.call("list", self.environment, "--output", "json", data=True),
                   lambda views: any(v["name"] == "history" and
                                     v["output_end_offset"] == len(encoded) for v in views))
        assert len(encoded) > page_size * 2
        assert self.call("logs", self.environment, "history", timeout=10).stdout == plain.decode()
        assert self.call("logs", self.environment, "history", "--raw", timeout=10).stdout == encoded.decode()
        assert self.call("logs", self.environment, "history", "--tail", "0").stdout == ""
        assert self.call("logs", self.environment, "history", "--tail", "1").stdout == marker.decode()
        assert self.call("logs", self.environment, "history", "--tail", "70").stdout == (
            b"history-line\n" * 69 + marker).decode()
        assert self.call("logs", self.environment, "history", "--tail", "30002").stdout == (
            padding + visible + b"\n" + rows + marker).decode()
        assert self.call("logs", self.environment, "history", "--tail", "30002", "--raw").stdout == (
            padding + b"\x1b[31m" + visible + b"\x1b[0m\n" + rows + marker).decode()

        followers = []
        try:
            for raw in (False, True):
                args = [self.cw, "logs", self.environment, "history", "--tail", "1", "--follow"]
                if raw:
                    args += ["--raw"]
                follower = subprocess.Popen(args, env=self.env, cwd=self.workspace, text=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                followers.append((raw, follower))
                ready, _, _ = select.select([follower.stdout], [], [], 10)
                assert ready, "follow did not emit the initial history tail"
                assert follower.stdout.readline() == marker.decode()

            # Require durable observation of each partial CSI before the next
            # write, so the live filter must retain state across output chunks.
            live_end = len(encoded)
            for command, piece in (("color", b"\x1b["),
                                   ("text", b"32mCLI_LOGS_FOLLOW_END\x1b"),
                                   ("reset", b"[0m\n")):
                self.call("send", self.environment, "history", command)
                live_end += len(piece)
                self.until(lambda: self.call("list", self.environment, "--output", "json", data=True),
                           lambda views: any(v["name"] == "history" and
                                             v["output_end_offset"] == live_end for v in views))
            for raw, follower in followers:
                output, errors = follower.communicate(timeout=15)
                assert follower.returncode == 0, errors
                expected = ("\x1b[32mCLI_LOGS_FOLLOW_END\x1b[0m\n" if raw else
                            "CLI_LOGS_FOLLOW_END\n")
                assert output == expected, f"raw={raw}: follow changed bytes or replayed drained history"
        finally:
            for _, follower in followers:
                if follower.poll() is None:
                    follower.terminate()
                    follower.wait(timeout=5)
        self.call("wait", self.environment, "history", "--timeout", "10s")
        self.check("logs/paginated-history/final-tail/raw-ansi/bounded-read/follow-cursor")

    def prove_outbox_recovery(self):
        lead = self.inbox("lead")
        saved_thread = lead["driver"]["native_thread_id"]
        parked = self.launch("parked", agent="codex", parent="lead", prompt="HOLD")
        self.until(lambda: self.inbox("parked"), lambda v: v["driver"]["current_turn_id"] is not None)
        self.call("stop", self.environment, "lead")
        self.call("steer", self.environment, "parked", "finish")
        source = self.wait_message(parked["message"]["id"])
        self.until(lambda: self.inbox("lead"), lambda v: any(
            m["source"] and m["source"]["message_id"] == source["id"] and m["state"] == "undelivered"
            for m in v["messages"]))
        self.call("stop", self.environment, "parked")
        registry = self.root / "hosts" / self.environment / "agents"
        path = registry / parked["driver_id"] / "messages" / (source["id"] + ".json")
        persisted = json.loads(path.read_text())
        notification_id = persisted["notification"]["message_id"]
        receiver = registry / lead["driver_id"] / "messages" / (notification_id + ".json")
        assert json.loads(receiver.read_text())["state"] == "undelivered"
        # Seed the durable cut point: result saved, notification not yet made.
        # Both drivers are stopped and this receiver has never accepted it.
        receiver.unlink()
        persisted["notification"] = None
        path.write_text(json.dumps(persisted))
        native_thread = self.inbox("parked")["driver"]["native_thread_id"]
        trace = self.workspace / ("peer-" + native_thread + ".jsonl")
        turns = trace.read_text().count('"turn/start"')
        self.call("restart", self.environment, "parked")
        self.until(receiver.exists, bool)
        self.call("restart", self.environment, "lead")
        result = self.wait_message(notification_id)
        assert result["state"] == "completed" and result["native_acknowledged"], result
        recovered = self.inbox("lead")
        assert recovered["driver"]["native_thread_id"] == saved_thread
        assert len([m for m in recovered["messages"] if m["id"] == notification_id]) == 1
        assert trace.read_text().count('"turn/start"') == turns, "completed worker task was replayed"
        self.check("stopped-parent/outbox-cut-point/restart/wake-once/no-task-replay")

        failed = self.launch("startup-failure", agent="codex", parent="lead", prompt="never issued",
                             model="fixture-startup-failure", ok=False, detach=False)
        failed_message = self.wait_message(failed["message"]["id"], ok=False)
        assert failed_message["state"] == "error", failed_message
        assert not failed_message["native_acknowledged"], failed_message
        assert failed_message["started_at"] is None and failed_message["turn_id"] is None, failed_message
        assert "native agent startup failed before issuing this task" in failed_message["error"], failed_message
        failed_driver = self.inbox("startup-failure")["driver"]
        assert failed_driver["native_thread_id"] is None, failed_driver
        assert not failed_driver["native_thread_established"], failed_driver
        assert failed_driver["current_turn_id"] is None and failed_driver["active_message_id"] is None, failed_driver
        failure_notification = self.until(lambda: self.inbox("lead"), lambda v: any(
            m["source"] and m["source"]["message_id"] == failed["message"]["id"] and m["state"] == "completed"
            for m in v["messages"]))
        assert failure_notification["driver"]["phase"] == "idle"
        self.check("native-startup-failure/queued-task-settled/parent-wake")

    def cleanup(self, preserve=False):
        try:
            try:
                if self.environment:
                    if preserve:
                        self.call("env", "stop", "--local", self.environment)
                        print(f"cli-host: failed-journey evidence retained: {self.root}", file=sys.stderr)
                    else:
                        result = self.call("env", "rm", "--local", self.environment, "--yes")
                        assert (self.workspace / "child.pid").exists(), "workspace removed with runtime"
                        self.check("remove-runtime/preserve-project")
            finally:
                self.sentinel.terminate()
                self.sentinel.wait(timeout=5)
                if MACOS:
                    reap_marked_family(self.root)
                else:
                    reap_owned_family()
            if not preserve:
                self.remove_files()
        except Exception:
            print(f"cli-host: runtime retained for diagnosis: {self.root}", file=sys.stderr)
            raise

    def remove_files(self):
        shutil.rmtree(self.root)


def process_alive(pid):
    if MACOS:
        return Darwin().live(pid)
    stat = Path(f"/proc/{pid}/stat")
    try:
        fields = stat.read_text().rsplit(") ", 1)[1].split()
        return fields[0] not in ("Z", "X")
    except FileNotFoundError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cw", required=True)
    parser.add_argument("--native-agents", action="store_true")
    args = parser.parse_args()
    if not (LINUX or MACOS):
        parser.error("trusted host placement is qualified on Linux and macOS")
    if MACOS:
        arm_owned_session()
    else:
        arm_owned_family()
    journey = Journey(args.cw, args.native_agents)
    passed = False
    try:
        journey.run()
        passed = True
    finally:
        journey.cleanup(preserve=not passed)
    print(json.dumps({"status": "passed", "native_agents": args.native_agents, "checks": journey.checks}))


if __name__ == "__main__":
    main()
