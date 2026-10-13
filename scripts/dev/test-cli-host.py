#!/usr/bin/env python3
"""Observed Linux/macOS host CLI journey, with synthetic native peers by default.

Run against a built cw, without replacing HOME or accessing login files:
  scripts/dev/test-cli-host.py --cw target/debug/cw
  scripts/dev/test-cli-host.py --cw target/debug/cw --native-agents
  scripts/dev/test-cli-host.py --cw target/debug/cw --real-noel /path/to/noel

The native option uses the installed agents' ordinary login. It proves a Codex
lead can invoke cw itself and a Claude worker's result starts a parent turn.
The real-noel option runs only the noel journey, with that binary as noel and
its faux/echo model; noel gets a private HOME and pi agent directory, offline.
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
    # The workspace file whose survival proves that removal kept the project.
    preserved = "child.pid"

    def __init__(self, cw, native, real_noel=None):
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
            for name in ("codex", "claude", "noel"):
                target = programs / name
                shutil.copyfile(real_noel if name == "noel" and real_noel else fixture, target)
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

    def launch(self, name, command=None, agent=None, parent=None, prompt=None, model=None, ok=True, detach=True,
               env=()):
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
        for value in env:
            args += ["--env", value]
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
            if LINUX:
                self.prove_noel()
            else:
                refused = self.call("run", self.environment, "--name", "noel", "--agent", "noel",
                                    "--model", "faux/echo", "--detach", ok=False)
                assert "only on trusted Linux hosts" in refused.stderr, refused.stderr
                self.check("noel-refused-on-macos")

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

    def noel_trace(self, name):
        """What the synthetic noel of conversation NAME received, in order."""
        session = self.inbox(name)["driver"]["native_thread_id"]
        lines = (self.workspace / f"peer-noel-{session}.jsonl").read_text().splitlines()
        return [json.loads(line) for line in lines]

    def received(self, name):
        return [entry["received"] for entry in self.noel_trace(name) if "received" in entry]

    def held(self, name, text):
        """Send TEXT and wait until noel names the run it started."""
        message = self.call("msg", self.environment, name, text, "--output", "json", data=True)
        self.until(lambda: self.inbox(name), lambda v: v["driver"]["active_message_id"] == message["id"]
                   and v["driver"]["current_turn_id"] is not None)
        return message, self.inbox(name)["driver"]["current_turn_id"]

    def timed(self, *args, **kwargs):
        started = time.monotonic()
        result = self.call(*args, **kwargs)
        elapsed = time.monotonic() - started
        assert elapsed < 30, f"cw {args} took {elapsed:.1f}s"
        return result, elapsed

    def wakes(self, lead, count):
        """The lead noel is woken once per finished worker message."""
        inbox = self.until(lambda: self.inbox(lead), lambda v: sum(
            m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]) >= count,
            timeout=60)
        notifications = [m for m in inbox["messages"] if m["action"] == "notification"]
        assert len(notifications) == count, notifications
        sources = {m["source"]["message_id"] for m in notifications}
        assert len(sources) == count, notifications
        prompts = [r for r in self.received(lead) if r["type"] == "prompt"
                   and "[Codewire] Managed worker" in r["message"]]
        assert len(prompts) == count, prompts
        return notifications

    def prove_noel(self):
        """noel over its RPC protocol, against the synthetic noel peer."""
        env = self.environment
        refused = self.call("run", env, "--name", "noel-bare", "--agent", "noel", "--detach", ok=False)
        assert "needs --model PROVIDER/ID" in refused.stderr, refused.stderr
        refused = self.call("run", env, "--name", "noel-ultra", "--agent", "noel", "--model", "faux/echo",
                            "--effort", "ultra", "--detach", ok=False)
        assert "noel --effort supports" in refused.stderr, refused.stderr
        # A pi build from before its RPC protocol answers JSON-RPC: startup
        # fails at once and the task is never issued.
        legacy = self.launch("noel-legacy", agent="noel", model="fixture/json-rpc", prompt="never issued",
                             ok=False, detach=False)
        failed = self.wait_message(legacy["message"]["id"], ok=False)
        assert failed["state"] == "error" and "older build of pi" in failed["error"], failed
        assert not failed["native_acknowledged"] and failed["started_at"] is None, failed
        driver = self.inbox("noel-legacy")["driver"]
        assert driver["phase"] == "failed" and "JSON-RPC" in driver["last_error"], driver
        self.check("noel-launch-refusals/legacy-json-rpc-startup-refused")

        lead = self.launch("noel-lead", agent="noel", model="faux/echo", prompt="Hello")
        first = self.wait_message(lead["message"]["id"])
        assert first["state"] == "completed" and first["result"] == "[faux/echo] Hello", first
        assert first["native_acknowledged"] and first["turn_id"], first
        assert first["usage"] == {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0,
                                  "totalTokens": 0, "cost": 0.0, "messages": 1}, first
        driver = self.inbox("noel-lead")["driver"]
        assert driver["phase"] == "idle" and driver["native_thread_established"], driver
        assert driver["capabilities"]["steer"] and driver["capabilities"]["interrupt"], driver
        session = driver["native_thread_id"]
        assert "[faux/echo] Hello" in self.call("inbox", env, "noel-lead").stdout
        assert "says: [faux/echo] Hello" in self.call("logs", env, "noel-lead").stdout
        trace = self.noel_trace("noel-lead")
        assert trace[0] == {"event": "start", "argv": ["--mode", "rpc", "--session-id", session,
                                                       "--model", "faux/echo"]}, trace[0]
        received = self.received("noel-lead")
        assert [(r["type"], "id" in r) for r in received[:4]] == [
            ("get_state", True), ("clear_queue", True), ("clear_queue", False), ("prompt", True)], received
        assert received[3]["message"] == "Hello" and received[3]["requestId"] == first["id"], received
        self.check("noel-identity/startup-handshake/first-turn/inbox-and-logs")

        # A message sent while noel is busy waits in the Codewire mailbox; a
        # steer for another run never reaches noel; a steer is acknowledged.
        holding, run = self.held("noel-lead", "HOLD")
        queued = self.call("msg", env, "noel-lead", "QUEUED", "--output", "json", data=True)
        assert queued["state"] == "accepted" and self.inbox("noel-lead")["driver"]["queued"] == 1
        fenced = self.call("steer", env, "noel-lead", "fenced", "--turn-id",
                           "00000000-0000-4000-8000-000000000000", ok=False)
        assert "nothing was steered" in fenced.stderr, fenced.stderr
        steered, steer_time = self.timed("steer", env, "noel-lead", "finish", "--turn-id", run,
                                         "--output", "json")
        steered = json.loads(steered.stdout)
        # The synthetic run ends as soon as the steer is delivered.
        assert steered["native_acknowledged"] and steered["state"] in ("running", "completed"), steered
        held = self.wait_message(holding["id"])
        assert held["result"] == "[faux/echo] finish" and held["turn_id"] == run, held
        assert self.wait_message(steered["id"])["state"] == "completed"
        assert self.wait_message(queued["id"])["result"] == "[faux/echo] QUEUED"
        steers = [r for r in self.received("noel-lead") if r["type"] == "steer"]
        assert steers == [{"id": steers[0]["id"], "type": "steer", "message": "finish",
                           "expectedRunId": run}], steers
        self.check(f"noel-busy-mailbox/fenced-steer/steer-acknowledged-{steer_time:.2f}s")

        # A steer that reaches noel after its run settled is refused by noel.
        late, run = self.held("noel-lead", "LATE")
        refused = self.call("steer", env, "noel-lead", "too late", ok=False)
        assert f"noel refused the steer: expectedRunId {run} does not match: no run is active" in refused.stderr, \
            refused.stderr
        assert self.wait_message(late["id"])["result"] == "[faux/echo] LATE"
        self.check("noel-late-steer-refused")

        # An abort is acknowledged by the run's settlement. The steer it left
        # queued in noel never joins the next message.
        holding, run = self.held("noel-lead", "HOLD")
        waiting = self.call("steer", env, "noel-lead", "WAIT", "--output", "json", data=True)
        assert waiting["native_acknowledged"], waiting
        interrupted, abort_time = self.timed("interrupt", env, "noel-lead", "--output", "json")
        interrupted = json.loads(interrupted.stdout)
        assert self.wait_message(interrupted["id"])["state"] == "completed"
        assert self.wait_message(holding["id"], ok=False)["state"] == "interrupted"
        assert self.wait_message(waiting["id"], ok=False)["state"] == "interrupted"
        aborts = [r for r in self.received("noel-lead") if r["type"] == "abort"]
        assert len(aborts) == 1 and aborts[0]["expectedRunId"] == run, aborts
        following = self.call("msg", env, "noel-lead", "NEXT", "--output", "json", data=True)
        assert self.wait_message(following["id"])["result"] == "[faux/echo] NEXT"
        self.check(f"noel-interrupt-acknowledged-{abort_time:.2f}s/queued-steer-not-replayed")

        dialog = self.call("msg", env, "noel-lead", "DIALOG", "--output", "json", data=True)
        assert self.wait_message(dialog["id"])["result"] == "[faux/echo] DIALOG"
        answers = [r for r in self.received("noel-lead") if r["type"] == "extension_ui_response"]
        assert len(answers) == 1 and answers[0]["cancelled"] is True and answers[0]["id"], answers
        self.check("noel-dialog-declined")

        # A worker's result wakes the lead exactly once. An explicit stop
        # mid-run ends noel as it ends Codex and Claude: the host stop signals
        # the driver and the agent together, so the message's outcome is
        # unknown, and noel's run stays interrupted. After a restart the next
        # message answers normally; the cut-off run is never resumed.
        worker = self.launch("noel-worker", agent="noel", model="faux/echo", parent="noel-lead", prompt="WORKER")
        assert self.wait_message(worker["message"]["id"])["result"] == "[faux/echo] WORKER"
        self.wakes("noel-lead", 1)
        cut = self.stop_mid_run("noel-worker", turn=True)
        assert cut["state"] == "unknown", cut
        trace = self.noel_trace("noel-worker")
        restart = max(i for i, e in enumerate(trace) if e.get("event") == "start")
        ending = trace[restart - 1]
        assert ending["event"] in ("sigterm", "eof") and ending["active"] is True, trace[:restart]
        assert not any(e.get("received", {}).get("type") == "abort" for e in trace), trace
        again = self.call("msg", env, "noel-worker", "AGAIN", "--output", "json", data=True)
        assert self.wait_message(again["id"])["result"] == "[faux/echo] AGAIN"
        starts = [e for e in trace if e.get("event") == "start"]
        assert len(starts) == 2 and starts[0] == starts[1], starts
        notifications = self.wakes("noel-lead", 3)
        assert cut["id"] in {m["source"]["message_id"] for m in notifications}
        for name, agent in (("codex-stopped", "codex"), ("claude-stopped", "claude")):
            self.launch(name, agent=agent)
            self.until(lambda: self.inbox(name), lambda v: v["driver"] and v["driver"]["phase"] == "idle")
            other = self.stop_mid_run(name, turn=agent == "codex")
            assert other["state"] == cut["state"], (agent, other)
        print(f"cli-host: noel stop mid-run: {cut['state']}: {cut['error']}", flush=True)
        self.check(f"noel-worker-wakes-lead-once/stop-mid-run-{cut['state']}-like-codex-and-claude-"
                   f"after-{ending['event']}/restart-answers-next")

    def stop_mid_run(self, name, turn):
        """Stop NAME while its HOLD message runs, then restart it, and return
        that message as Codewire recorded it. TURN waits for the native turn
        ID as well, which Claude does not report."""
        holding = self.call("msg", self.environment, name, "HOLD", "--output", "json", data=True)
        self.until(lambda: self.inbox(name), lambda v: v["driver"]["active_message_id"] == holding["id"]
                   and (not turn or v["driver"]["current_turn_id"] is not None))
        stopped = self.call("stop", self.environment, name, "--output", "json", data=True)[0]
        assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        self.call("restart", self.environment, name)
        self.until(lambda: self.inbox(name), lambda v: v["driver"]["phase"] == "idle")
        return self.wait_message(holding["id"], ok=False)

    def run_real_noel(self):
        """The noel journey with the real binary: faux/echo, private pi state."""
        created = self.call("env", "create", "--local", "--type", "host", "--name", "proof",
                            "--path", str(self.workspace), "--output", "json", data=True)
        self.environment = env = created["id"]
        self.preserved = "noel-proof.txt"
        (self.workspace / self.preserved).write_text("workspace\n")
        home, agent = self.root / "noel-home", self.root / "pi-agent"
        home.mkdir(mode=0o700)
        agent.mkdir(mode=0o700)
        private = [f"HOME={home}", f"PI_CODING_AGENT_DIR={agent}", "PI_OFFLINE=1"]
        self.check("create-host-environment")

        lead = self.launch("noel-lead", agent="noel", model="faux/echo", prompt="Hello", env=private)
        first = self.wait_message(lead["message"]["id"])
        assert first["state"] == "completed" and first["result"] == "[faux/echo] Hello", first
        inbox = self.call("inbox", env, "noel-lead").stdout
        assert "[faux/echo] Hello" in inbox, inbox
        session = self.inbox("noel-lead")["driver"]["native_thread_id"]
        journal = agent / "sessions" / f"{session}.jsonl"

        def said(role, journal=journal):
            """What noel saved in its session journal for ROLE."""
            entries = [json.loads(line) for line in journal.read_text().splitlines()]
            return [e["message"]["content"] for e in entries
                    if e.get("type") == "message" and e["message"]["role"] == role]

        print(f"cli-host: noel inbox: {inbox.splitlines()[-1]}", flush=True)
        self.check("real-noel-first-turn/inbox-shows-reply")

        again = self.call("msg", env, "noel-lead", "Again", "--output", "json", data=True)
        assert self.wait_message(again["id"])["result"] == "[faux/echo] Again"
        assert self.inbox("noel-lead")["driver"]["native_thread_id"] == session
        assert said("user") == ["Hello", "Again"], said("user")
        assert said("assistant") == ["[faux/echo] Hello", "[faux/echo] Again"], said("assistant")
        self.check("real-noel-msg-continues-same-session")

        worker = self.launch("noel-worker", agent="noel", model="faux/echo", parent="noel-lead",
                             prompt="Work", env=private)
        assert self.wait_message(worker["message"]["id"])["result"] == "[faux/echo] Work"
        inbox = self.until(lambda: self.inbox("noel-lead"), lambda v: any(
            m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]), timeout=60)
        time.sleep(11)  # one more parent inbox scan, which must not admit it again
        inbox = self.inbox("noel-lead")
        notifications = [m for m in inbox["messages"] if m["action"] == "notification"]
        assert len(notifications) == 1, notifications
        assert notifications[0]["source"]["message_id"] == worker["message"]["id"], notifications
        wakes = [text for text in said("user") if "[Codewire] Managed worker" in text]
        assert len(wakes) == 1, said("user")
        self.check("real-noel-worker-wakes-lead-exactly-once")

        slow = private + ["PI_FAUX_STREAM_DELAY_MS=200", "PI_FAUX_STREAM_CHARS=1"]
        self.launch("noel-slow", agent="noel", model="faux/echo", parent="noel-lead", env=slow)
        self.until(lambda: self.inbox("noel-slow"), lambda v: v["driver"] and v["driver"]["phase"] == "idle")
        story_text = "Write a long story about a lighthouse keeper and the sea."
        story, run = self.held("noel-slow", story_text)
        refused = self.call("steer", env, "noel-slow", "Wrong run", "--turn-id",
                            "00000000-0000-4000-8000-000000000000", ok=False)
        assert "nothing was steered" in refused.stderr, refused.stderr
        steered, steer_time = self.timed("steer", env, "noel-slow", "Be brief.", "--turn-id", run,
                                         "--output", "json")
        steered = json.loads(steered.stdout)
        assert steered["native_acknowledged"] and steered["turn_id"] == run, steered
        interrupted, abort_time = self.timed("interrupt", env, "noel-slow", "--output", "json")
        interrupted = json.loads(interrupted.stdout)
        assert self.wait_message(interrupted["id"])["state"] == "completed"
        story = self.wait_message(story["id"], ok=False)
        assert story["state"] == "interrupted", story
        assert self.wait_message(steered["id"], ok=False)["state"] == "interrupted"
        print(f"cli-host: noel steer acknowledged in {steer_time:.2f}s, interrupt in {abort_time:.2f}s; "
              f"interrupted reply so far: {story['result']!r}", flush=True)
        self.check("real-noel-steer-fenced-and-acknowledged/interrupt-acknowledged")

        second_text = "Tell another long story, about the mountains."
        second, run = self.held("noel-slow", second_text)
        stopped = self.call("stop", env, "noel-slow", "--output", "json", data=True)[0]
        assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        ended = [line for line in self.call("logs", env, "noel-slow").stdout.splitlines()
                 if "native agent" in line]
        slow_session = self.inbox("noel-slow")["driver"]["native_thread_id"]
        self.call("restart", env, "noel-slow")
        self.until(lambda: self.inbox("noel-slow"), lambda v: v["driver"]["phase"] == "idle")
        # As for Codex and Claude, an explicit stop mid-run leaves the
        # message's outcome unknown.
        second = self.wait_message(second["id"], ok=False)
        assert second["state"] == "unknown", second
        print(f"cli-host: noel stop mid-run: message {second['state']} ({second['error']}); "
              f"driver: {ended[-1] if ended else '-'}", flush=True)
        self.check("real-noel-stop-mid-turn-leaves-outcome-unknown")

        short = self.call("msg", env, "noel-slow", "Short.", "--output", "json", data=True)
        assert self.wait_message(short["id"])["result"] == "[faux/echo] Short."
        assert self.inbox("noel-slow")["driver"]["native_thread_id"] == slow_session
        # noel saved both stories' prompts and neither reply: it never saves
        # an aborted reply, and the stopped run stayed interrupted until the
        # next prompt answered normally, without resuming it. The steer the
        # interrupt left queued was cleared before that prompt, not joined.
        slow_journal = agent / "sessions" / f"{slow_session}.jsonl"
        assert said("user", slow_journal) == [story_text, second_text, "Short."], said("user", slow_journal)
        assert said("assistant", slow_journal) == ["[faux/echo] Short."], said("assistant", slow_journal)
        self.check("real-noel-restart-answers-next/stopped-run-not-resumed/queued-steer-not-replayed")

        # The lead heard once about each finished worker message, including
        # the one the interrupt ended and the one the stop cut off.
        finished = {worker["message"]["id"], story["id"], second["id"], short["id"]}
        inbox = self.until(lambda: self.inbox("noel-lead"), lambda v: sum(
            m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]) >= 4, timeout=60)
        notifications = [m for m in inbox["messages"] if m["action"] == "notification"]
        assert {m["source"]["message_id"] for m in notifications} == finished, notifications
        assert len(notifications) == 4, notifications
        wakes = [text for text in said("user") if "[Codewire] Managed worker" in text]
        assert len(wakes) == 4, wakes
        assert [sum(f"as {state}." in text for text in wakes) for state in ("interrupted", "unknown")] == [1, 1], wakes
        self.check("real-noel-lead-woken-once-per-worker-message")

    def cleanup(self, preserve=False):
        try:
            try:
                if self.environment:
                    if preserve:
                        self.call("env", "stop", "--local", self.environment)
                        print(f"cli-host: failed-journey evidence retained: {self.root}", file=sys.stderr)
                    else:
                        result = self.call("env", "rm", "--local", self.environment, "--yes")
                        assert (self.workspace / self.preserved).exists(), "workspace removed with runtime"
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
    agents = parser.add_mutually_exclusive_group()
    agents.add_argument("--native-agents", action="store_true")
    agents.add_argument("--real-noel", metavar="PATH",
                        help="run the noel journey with this noel binary instead of the synthetic peer")
    args = parser.parse_args()
    if args.real_noel and not LINUX:
        parser.error("noel managed conversations are qualified only on Linux hosts")
    if not (LINUX or MACOS):
        parser.error("trusted host placement is qualified on Linux and macOS")
    if MACOS:
        arm_owned_session()
    else:
        arm_owned_family()
    journey = Journey(args.cw, args.native_agents, args.real_noel)
    passed = False
    try:
        if args.real_noel:
            journey.run_real_noel()
        else:
            journey.run()
        passed = True
    finally:
        journey.cleanup(preserve=not passed)
    print(json.dumps({"status": "passed", "native_agents": args.native_agents,
                      "real_noel": args.real_noel, "checks": journey.checks}))


if __name__ == "__main__":
    main()
