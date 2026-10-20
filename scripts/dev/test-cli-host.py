#!/usr/bin/env python3
"""Observed Linux/macOS host CLI journey, with synthetic native peers by default.

Run against a built cw, without replacing HOME or accessing login files:
  scripts/dev/test-cli-host.py --cw target/debug/cw
  scripts/dev/test-cli-host.py --cw target/debug/cw --native-agents
  scripts/dev/test-cli-host.py --cw target/debug/cw --real-noel /path/to/noel

The native option uses the installed agents' ordinary login. It proves a Codex
lead can invoke cw itself and a Claude worker's result starts a parent turn.
Inherited CW_ENVIRONMENT and CW_SESSION_ID are dropped: a journey run by a
managed agent never hands its own conversation identity to the host it starts.
The real-noel option runs only the noel journey, with that binary as noel and
its faux/echo and faux/script models; noel gets a private HOME and noel
directory, offline. Both noel journeys kill noel and its driver mid-turn with
SIGKILL and prove noel resumes the run once. Both also take the environment
down mid-turn and prove that the message is paused, not ended, and that
starting the environment resumes the run with no `cw restart`. Both stop a
conversation while the host daemon's record helper fails and prove that the
message is never paused and never resumed. Both prove that only a noel
conversation is given the delegation skill, in its own driver directory; the
real-noel journey then has a scripted lead run every command of that skill.
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
import pty
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


WALL = 0x40000000  # Linux __WALL includes non-SIGCHLD clone children.
# A host conversation's own identity, given only to its native agent.
IDENTITY = ("CW_ENVIRONMENT", "CW_SESSION_ID")
INTERRUPT_LOGGED = "interrupted the active run before stopping"
PAUSE_LOGGED = "paused the active run before shutting down"
HELPER_FAILED_LOGGED = "could not check for an active run to interrupt before stopping"
STOPPED_IN_FLIGHT = "its conversation was stopped while this was in flight; outcome unknown; not replayed"
RESUME_LOGGED = "restarted paused noel conversation"
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
                    if not key.startswith("CODEWIRE_") and key not in IDENTITY}
        self.env.update(CW_HOST_DATA_DIR=str(self.root / "hosts"), CW_CONFIG_DIR=str(self.root / "config"))
        self.cw = str(Path(cw).resolve())
        if LINUX:
            # The host daemon runs its managed record helper, which interrupts
            # a noel run before a stop, only from an image with one link and
            # no group or other write, as an installed cw is. A Cargo build
            # links its output twice, so the journey runs its own copy.
            private = self.root / "cw"
            subprocess.run(["cp", "--reflink=auto", self.cw, str(private)], check=True)
            private.chmod(0o700)
            self.cw = str(private)
        self.native = native
        self.environment = None
        self.extra_environments = []
        self.owned_sessions = []
        self.session_ids = {}
        self.driver_ids = {}
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

    def call(self, *args, ok=True, timeout=45, data=False, env=None):
        result = subprocess.run([self.cw, *args], env=env or self.env, cwd=self.workspace,
                                text=True, capture_output=True, timeout=timeout)
        if ok and result.returncode != 0:
            raise AssertionError(f"cw {args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        if ok is False and result.returncode == 0:
            raise AssertionError(f"cw {args}: unexpectedly succeeded")
        return json.loads(result.stdout) if data else result

    def check(self, label):
        assert self.sentinel.poll() is None, "unrelated process was killed"
        self.checks.append(label)
        print(f"cli-host: {label} PASS", flush=True)

    def launch(self, name, command=None, agent=None, parent=None, prompt=None, model=None, ok=True, detach=True,
               env=()):
        args = ["run", "--in", self.environment, "--name", name]
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
        self.session_ids[name] = view["session_id"]
        if agent:
            self.driver_ids[name] = launched["driver_id"]
        return launched

    def inbox(self, name):
        return self.call("inbox", self.environment, "--session", name, "--output", "json", data=True)

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
        # The host daemon this starts inherits a conversation identity, as
        # one a lead's own cw started would. No session ever sees it.
        stale = dict(self.env, CW_ENVIRONMENT="stale-environment", CW_SESSION_ID="session-stale")
        created = self.call("create", "--local", "--type", "host", "--name", "proof",
                            "--path", str(self.workspace), "--output", "json", data=True, env=stale)
        self.environment = created["id"]
        assert created["type"] == "host"
        assert self.call("ls", self.environment, "--output", "json", data=True) == []
        self.check("create/empty")

        self.launch("identity", ["sh", "-c", 'printf "%s|%s" "${CW_ENVIRONMENT-unset}" "${CW_SESSION_ID-unset}"'])
        assert self.call("wait", self.environment, "--session", "identity", "--timeout", "10s").stdout == "unset|unset"
        self.check("ordinary-session-inherits-no-conversation-identity")

        self.launch("reader", ["sh", "-c", 'read -r value; printf "RECEIVED:%s" "$value"'])
        self.call("send", self.environment, "--session", "reader", "part", "--no-newline")
        self.call("wait", self.environment, "--session", "reader", "--timeout", "1s", ok=False)
        self.call("send", self.environment, "--session", "reader", "--", "-rest")
        waited = self.call("wait", self.environment, "--session", "reader", "--timeout", "10s", "--output", "json", data=True)
        assert waited["output"] == "RECEIVED:part-rest" and waited["eof"], waited
        assert self.call("logs", self.environment, "--session", "reader").stdout == waited["output"]
        self.call("run", "--in", self.environment, "--name", "reader", "--detach", "--", "true", ok=False)
        self.check("acknowledged-send/partial/wait/logs/unique-name")

        if not self.native:
            self.prove_logs_pagination()

        child_pid_file = self.workspace / "child.pid"
        owned = self.launch("tree", ["sh", "-c", 'sleep 300 & echo $! > "$1"; wait', "sh", str(child_pid_file)])
        self.until(child_pid_file.exists, bool)
        child_pid = int(child_pid_file.read_text())
        if MACOS:
            assert child_pid in owned_family(self.root), "owned-family scan misses a session descendant"
        stopped = self.call("stop", self.environment, "--session", "tree", "--output", "json", data=True)[0]
        assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        assert not process_alive(child_pid), "ordinary child survived Stop"
        self.launch("child", ["true"], parent=owned["session_id"])
        views = self.call("ls", self.environment, "--output", "json", data=True)
        assert next(v for v in views if v["name"] == "child")["parent_session_id"] == owned["session_id"]
        self.check("owned-tree-stop/unrelated-process/parent-identity")

        self.launch("lead", agent="codex")
        self.until(lambda: self.inbox("lead"), lambda v: v["driver"] and v["driver"]["phase"] == "idle")
        text = "Reply with exactly LEAD_READY. Do not use tools." if self.native else "FIRST"
        message = self.call("msg", self.environment, "--session", "lead", text, "--output", "json", data=True)
        complete = self.wait_message(message["id"])
        assert complete["state"] == "completed" and complete["native_acknowledged"], complete
        self.call("send", self.environment, "--session", "lead", "raw", ok=False)
        if not self.native:
            self.knows_itself("codex", "lead")
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
        self.call("steer", self.environment, "--session", "worker", "unsupported", ok=False)
        if not self.native:
            self.knows_itself("claude", "worker")
        self.check("claude-worker/native-ack/idle-parent-wake/no-duplicate")

        if self.native:
            saved_thread = self.inbox("lead")["driver"]["native_thread_id"]
            self.call("stop", self.environment, "--session", "lead")
            restarted = self.call("restart", self.environment, "--session", "lead", "--output", "json", data=True)[0]
            assert restarted["session_id"] == parent["session_id"], restarted
            command = [self.cw, "run", "--in", self.environment, "--name", "lead-command", "--detach", "--no-tty", "--", "printf", "LEAD_COMMAND"]
            text = ("Run this exact command once, using your command tool: " +
                    " ".join(__import__("shlex").quote(a) for a in command) +
                    ". Do not run any other command or edit files. Then reply LEAD_COMMAND_STARTED.")
            message = self.call("msg", self.environment, "--session", "lead", text, "--output", "json", data=True)
            result = self.wait_message(message["id"])
            assert result["state"] == "completed", result
            output = self.call("wait", self.environment, "--session", "lead-command", "--timeout", "10s").stdout
            assert output == "LEAD_COMMAND", output
            assert self.inbox("lead")["driver"]["native_thread_id"] == saved_thread
            self.check("codex-resume/lead-initiated-cw-command/actual-host-policy")
            saved_thread = self.inbox("worker")["driver"]["native_thread_id"]
            self.call("stop", self.environment, "--session", "worker")
            self.call("restart", self.environment, "--session", "worker")
            resumed = self.call("msg", self.environment, "--session", "worker",
                                "Reply with exactly CLAUDE_RESUMED. Do not use tools.",
                                "--output", "json", data=True)
            assert self.wait_message(resumed["id"])["state"] == "completed"
            assert self.inbox("worker")["driver"]["native_thread_id"] == saved_thread
            self.until(lambda: self.inbox("lead"), lambda v: sum(
                m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]) == 2,
                timeout=180)
            self.check("claude-xhigh/resume/same-conversation/parent-wake")
        else:
            holding = self.call("msg", self.environment, "--session", "lead", "HOLD", "--output", "json", data=True)
            self.until(lambda: self.inbox("lead"), lambda v: v["driver"]["current_turn_id"] is not None)
            self.call("steer", self.environment, "--session", "lead", "bad", "--turn-id", "other-turn", ok=False)
            steered = self.call("steer", self.environment, "--session", "lead", "finish", "--output", "json", data=True)
            assert self.wait_message(holding["id"])["result"] == "STEERED"
            assert self.wait_message(steered["id"])["state"] == "completed"
            holding = self.call("msg", self.environment, "--session", "worker", "HOLD", "--output", "json", data=True)
            # Acceptance precedes the driver's active-turn publication.
            self.until(lambda: self.inbox("worker"), lambda v: v["driver"]["active_message_id"] == holding["id"])
            interrupted = self.call("interrupt", self.environment, "--session", "worker", "--output", "json", data=True)
            assert self.wait_message(interrupted["id"])["state"] == "completed"
            assert self.wait_message(holding["id"], ok=False)["state"] == "interrupted"
            self.check("expected-turn-steer/claude-interrupt")
            self.prove_outbox_recovery()
            if LINUX:
                self.prove_noel()
            else:
                refused = self.call("run", "--in", self.environment, "--name", "noel", "--agent", "noel",
                                    "--model", "faux/echo", "--detach", ok=False)
                assert "only on trusted Linux hosts" in refused.stderr, refused.stderr
                self.check("noel-refused-on-macos")

        # Taking the whole environment down pauses a noel run instead, and
        # starting the environment again resumes it without `cw restart`.
        # Codex and Claude cannot resume a run: their message ends unknown.
        paused = waiter = None
        if LINUX and not self.native:
            self.launch("paused-lead", agent="noel", model="faux/echo")
            self.idle("paused-lead")
            paused = self.pause(lead="paused-lead")
            waiter = self.waiting(paused["paused-noel"][0]["id"])
        self.call("stop", "--local", self.environment)
        if paused:
            self.prove_paused(paused, lead="paused-lead")
            # The synthetic noel holds its restarted conversation's startup,
            # so the paused message can be read before noel resumes its run.
            hold_start = self.workspace / f"noel-hold-start-{paused['paused-noel'][2]}"
            hold_start.write_text("")
        self.call("start", "--local", self.environment)
        listed = self.call("ls", self.environment, "--output", "json", data=True)
        assert any(v["name"] == "reader" and v["state"] == "Exited" for v in listed)
        assert (self.workspace / "child.pid").exists()
        if paused:
            self.prove_shown_paused(paused, hold_start)
            self.prove_resumed(paused, "paused-lead", waiter)
            self.check("env-stop-pauses-noel-run/parent-told-once/wait-goes-on/"
                       "env-start-resumes-without-restart/lead-hears-pause-then-final/"
                       "codex-and-claude-unknown-and-not-restarted")
            self.prove_killed_first("paused-lead")
            self.check("env-stop-with-driver-killed-in-the-grace/same-pause-and-resume")
            self.prove_signalled("paused-lead")
            self.check("host-shutdown-signals-daemon-and-driver-at-once/driver-pauses-by-takedown-marker/"
                       "daemon-start-in-running-environment-resumes")
            for killed_first in (False, True):
                self.prove_stopped_without_helper("paused-noel", "paused-lead", killed_first)
            self.check("explicit-stop-with-failed-record-helper/daemon-stop-intent-on-disk/never-paused/"
                       "driver-killed-first-never-resumed/lead-hears-once")
            self.prove_removed()
            self.check("env-rm-removes-paused-message/waiting-cw-wait-ends-unknown")
        self.check("graceful-shutdown/reload/workspace-preserved")

        # A new process owner must not recover inline launch values from disk.
        projected = self.call("run", "--in", self.environment, "--name", "projection", "--detach", "--no-tty",
                              "--env", "CW_FIXTURE_VALUE=synthetic-only", "--output", "json", "--",
                              "sh", "-c", 'printf %s "$CW_FIXTURE_VALUE"', data=True)
        assert self.call("wait", self.environment, "--session", "projection", "--timeout", "10s").stdout == "synthetic-only"
        metadata = self.root / "hosts" / self.environment / "sessions" / projected["session_id"] / "session.json"
        assert "synthetic-only" not in metadata.read_text() and '"env"' not in metadata.read_text()
        self.call("stop", "--local", self.environment)
        self.call("start", "--local", self.environment)
        refused = self.call("restart", self.environment, "--session", "projection", ok=False)
        assert "launch a new session" in refused.stderr, refused.stderr
        self.check("launch-projection/not-persisted/reload-refuses-stale-replay")

    def knows_itself(self, agent, name):
        """The synthetic AGENT of conversation NAME was given its own
        environment and session at every start, and no peer a stale copy."""
        seen = [json.loads(line) for line in
                (self.workspace / "agent-identity.jsonl").read_text().splitlines()]
        own = [e for e in seen if e["agent"] == agent and e["session"] == self.session_ids[name]]
        assert own and all(e["environment"] == self.environment for e in own), seen
        # Only noel is launched with a skill, and only its conversation holds one.
        assert all(("--skill" in e["argv"]) == (agent == "noel") for e in own), own
        skills = self.root / "hosts" / self.environment / "agents" / self.driver_ids[name] / "skills"
        assert skills.exists() == (agent == "noel"), skills
        assert not any(e["environment"] == "stale-environment" or e["session"] == "session-stale"
                       for e in seen), seen

    def delegation_skill(self, name):
        """The delegation skill cw wrote for noel conversation NAME: in its
        own driver directory, the owner's alone, with every command naming
        this journey's cw by its path. Returns the file and its commands."""
        directory = (self.root / "hosts" / self.environment / "agents" / self.driver_ids[name]
                     / "skills" / "codewire-delegation")
        file = directory / "SKILL.md"
        for path, kind, mode in ((directory.parent, stat.S_ISDIR, 0o700), (directory, stat.S_ISDIR, 0o700),
                                 (file, stat.S_ISREG, 0o600)):
            status = path.lstat()
            assert kind(status.st_mode) and stat.S_IMODE(status.st_mode) == mode, (path, oct(status.st_mode))
        assert [entry.name for entry in directory.iterdir()] == ["SKILL.md"], list(directory.iterdir())
        commands = skill_commands(file.read_text())
        assert commands and all(shlex.split(command)[0] == self.cw for command in commands), commands
        return file, commands

    def pause(self, agents=("noel", "codex", "claude"), text="HOLD", env=(), lead=None):
        """A conversation of each agent running TEXT (Codex and Claude HOLD)
        when the whole environment goes down. Only noel gets ENV; with LEAD,
        noel's conversation is that conversation's worker."""
        for agent in agents:
            noel = agent == "noel"
            self.launch("paused-" + agent, agent=agent, model="faux/echo" if noel else None,
                        env=env if noel else (), parent=lead if noel else None)
            self.idle("paused-" + agent)
        paused = {}
        for agent in agents:
            name = "paused-" + agent
            message, run = self.hold(name, turn=agent != "claude", text=text if agent == "noel" else "HOLD")
            paused[name] = (message, run, self.noel_session(name) if agent == "noel" else None)
        return paused

    def record_file(self, name, message_id):
        """NAME's message record as saved, read without its daemon."""
        path = (self.root / "hosts" / self.environment / "agents" / self.driver_ids[name] / "messages"
                / (message_id + ".json"))
        return json.loads(path.read_text())

    def notices(self, lead, message_id):
        """The notices LEAD's inbox holds for a worker's message, oldest
        first, read without its daemon."""
        inbox = self.root / "hosts" / self.environment / "agents" / self.driver_ids[lead] / "messages"
        records = [json.loads(path.read_text()) for path in inbox.glob("*.json")]
        return sorted((r for r in records if r["action"] == "notification" and r["source"]
                       and r["source"]["message_id"] == message_id), key=lambda r: r["created_at"])

    def waiting(self, message_id, env=None):
        """A `cw wait --message` left running in the background."""
        return subprocess.Popen([self.cw, "wait", "--message", message_id, "--timeout", "4m", "--output", "json"],
                                env=env or self.env, cwd=self.workspace, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def waited(self, waiter, message, result):
        """The background wait went on through the pause, said so, and
        returned only the final record, as a consumer that knows only final
        states reads it."""
        out, err = waiter.communicate(timeout=240)
        assert waiter.returncode == 0, (waiter.returncode, out, err)
        final = json.loads(out)
        assert final["id"] == message["id"] and final["state"] == "completed", final
        assert final["state"] in ("completed", "error", "interrupted", "unknown"), final
        assert final["result"] == result, final
        said = f"message {message['id']} paused: environment stopped; waiting for its conversation to start again"
        assert err.count(said) == 1, err

    def daemon_logged(self, name, text):
        """How many daemon log lines say TEXT about NAME's session."""
        log = (self.root / "hosts" / self.environment / "daemon.log").read_text()
        return sum(text in line and self.session_ids[name] in line for line in log.splitlines())

    def prove_paused(self, paused, env=(), lead=None):
        """With the environment down, noel's message is paused, not ended:
        the host daemon paused it before it signalled the conversation, its
        parent's one notice waits in the parent's inbox, and noel's run stays
        interrupted in its journal, resumable and never aborted. Nothing was
        interrupted first."""
        message, run, session = paused["paused-noel"]
        if not env:
            self.signalled_mid_run("paused-noel", session)
        last = self.noel_last_run(session, env)
        assert last == {"runId": run, "requestId": message["id"], "status": "interrupted",
                        "phase": "model"}, last
        for name in paused:
            assert self.interrupts_logged(name) == 0, name
        record = self.record_file("paused-noel", message["id"])
        assert record["state"] == "paused" and record["pause"]["reason"] == "environment_stopped", record
        assert record["finished_at"] is None and record["error"] is None, record
        assert "native_resumed" not in record and record["turn_id"] == run, record
        assert self.daemon_logged("paused-noel", PAUSE_LOGGED) == 1
        for name in paused:
            if name != "paused-noel":
                assert self.daemon_logged(name, PAUSE_LOGGED) == 0, name
        if lead:
            notes = self.notices(lead, message["id"])
            assert len(notes) == 1 and notes[0]["state"] == "requested", notes
            assert f"paused message {message['id']}: its environment stopped" in notes[0]["text"], notes
            assert record["pause_notification"]["message_id"] == notes[0]["id"], record
            assert record["notification"] is None, record

    def prove_shown_paused(self, paused, hold_start):
        """Its conversation is starting again and noel has not answered yet:
        `cw inbox`, the message status line and `cw wait` show the message
        paused, in text and as JSON, and a wait that times out fails. Then
        the held start is released."""
        env = self.environment
        message, _, _ = paused["paused-noel"]
        inbox = self.until(lambda: self.inbox("paused-noel"), lambda v: v["session_state"] == "Running")
        shown = next(m for m in inbox["messages"] if m["id"] == message["id"])
        assert shown["state"] == "paused" and shown["pause"]["reason"] == "environment_stopped", shown
        text = self.call("inbox", env, "--session", "paused-noel").stdout
        line = next(line for line in text.splitlines() if line.startswith(message["id"]))
        assert line.split("\t")[2] == "paused: environment stopped", text
        print(f"cli-host: noel inbox while paused: {line}", flush=True)
        status = self.call("wait", "--message", message["id"], "--timeout", "1s", ok=False)
        assert status.stdout.strip() == f"{message['id']}\tpaused: environment stopped", status.stdout
        assert f"message {message['id']} paused: environment stopped; waiting" in status.stderr, status.stderr
        assert "it is still paused: environment stopped and its outcome is unknown, not success" in status.stderr, \
            status.stderr
        # A consumer of the JSON that knows only final states reads a
        # failure, never a paused message as a result.
        printed = self.call("wait", "--message", message["id"], "--timeout", "1s", "--output", "json", ok=False)
        assert json.loads(printed.stdout)["state"] == "paused", printed.stdout
        hold_start.unlink()

    def told_pause_then_final(self, lead, message, said=None):
        """LEAD heard once that MESSAGE paused and once, after that, that it
        completed, and started one turn for each: SAID lists the lead's
        prompts (by default the synthetic noel's)."""
        mine = lambda v: [m for m in v["messages"] if m["action"] == "notification"
                          and m["source"]["message_id"] == message["id"]]
        inbox = self.until(lambda: self.inbox(lead),
                           lambda v: sum(m["state"] == "completed" for m in mine(v)) >= 2, timeout=120)
        notes = mine(inbox)
        assert len(notes) == 2, notes
        assert "paused message" in notes[0]["text"] and "as completed" in notes[1]["text"], notes
        said = said() if said else [r["message"] for r in self.received(lead) if r["type"] == "prompt"]
        heard = [text for text in said if message["id"] in text]
        assert len(heard) == 2 and "paused message" in heard[0] and "finished message" in heard[1], heard

    def prove_resumed(self, paused, lead, waiter):
        """Starting the environment restarted the paused noel conversation by
        itself, and no other: noel resumed the run, uncounted as a crash, and
        the waiting `cw wait` returned its reply. Codex and Claude, and the
        idle lead, stayed stopped; restarted, Codex's and Claude's messages
        are unknown as before, and the lead hears of the pause once and then
        of the final state once."""
        env = self.environment
        message, run, _ = paused["paused-noel"]
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "[faux/echo] HOLD", done
        assert done["turn_id"] == run and "native_resumed" not in done, done
        assert done["pause"]["reason"] == "environment_stopped", done
        self.waited(waiter, message, "[faux/echo] HOLD")
        assert self.daemon_logged("paused-noel", RESUME_LOGGED) == 1
        trace = self.noel_trace("paused-noel")
        received = [entry["received"] for entry in trace if "received" in entry]
        assert len([r for r in received if r["type"] == "prompt" and r.get("requestId") == message["id"]]) == 1
        begin = max(i for i, entry in enumerate(trace) if entry.get("event") == "start")
        handshake = [e["received"] for e in trace[begin:] if "received" in e][:3]
        assert handshake == [{"id": 1, "type": "get_state"}, {"id": 2, "type": "clear_queue"},
                             {"id": 3, "type": "resume_run", "expectedRunId": run}], handshake
        inbox = self.call("inbox", env, "--session", "paused-noel").stdout
        line = next(line for line in inbox.splitlines() if line.startswith(message["id"]))
        assert line.endswith("(resumed after its environment stopped)"), inbox
        logs = self.call("logs", env, "--session", "paused-noel").stdout
        assert f"message {message['id']} resumed by noel after its environment stopped: run {run}" in logs, logs
        print(f"cli-host: noel inbox after its environment restarted: {line}", flush=True)
        views = {v["name"]: v for v in self.call("ls", env, "--output", "json", data=True)}
        for name in [n for n in paused if n != "paused-noel"] + [lead]:
            assert views[name]["state"] == "Stopped", views[name]
            assert self.daemon_logged(name, RESUME_LOGGED) == 0, name
        for name, (other, _, _) in paused.items():
            if name == "paused-noel":
                continue
            self.call("restart", env, "--session", name)
            self.idle(name)
            record = self.wait_message(other["id"], ok=False)
            assert record["state"] == "unknown" and "pause" not in record, (name, record)
        self.call("restart", env, "--session", lead)
        self.told_pause_then_final(lead, message)
        reply = self.call("msg", env, "--session", "paused-noel", "AFTER", "--output", "json", data=True)
        assert self.wait_message(reply["id"])["result"] == "[faux/echo] AFTER"

    def prove_killed_first(self, lead):
        """The same takedown with a driver that cannot act on its signal: it
        is stopped, so the host daemon kills it when the grace ends. The
        daemon paused the message before it signalled, so the outcome is the
        same."""
        env = self.environment
        message, run = self.hold("paused-noel")
        waiter = self.waiting(message["id"])
        os.kill(self.driver_pid("paused-noel"), signal.SIGSTOP)
        self.call("stop", "--local", env)
        record = self.record_file("paused-noel", message["id"])
        assert record["state"] == "paused" and record["pause"]["reason"] == "environment_stopped", record
        assert self.daemon_logged("paused-noel", PAUSE_LOGGED) == 2
        notes = self.notices(lead, message["id"])
        assert len(notes) == 1 and "paused message" in notes[0]["text"], notes
        self.call("start", "--local", env)
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "[faux/echo] HOLD", done
        assert done["turn_id"] == run and "native_resumed" not in done, done
        self.waited(waiter, message, "[faux/echo] HOLD")
        assert self.daemon_logged("paused-noel", RESUME_LOGGED) == 2
        self.call("restart", env, "--session", lead)
        self.told_pause_then_final(lead, message)

    def daemon_pid(self):
        """The environment's live host daemon."""
        found = [pid for pid, _, argv in self.processes() if "_host-daemon" in argv and self.environment in argv]
        assert len(found) == 1, found
        return found[0]

    def prove_signalled(self, lead):
        """A host that shuts down signals every process at once: the
        conversation's driver and noel as well as the environment's daemon.
        The daemon writes the takedown marker before it stops anything, so
        the driver, signalled before the daemon's helper could pause its
        message, pauses it by that evidence. The environment was never
        stopped, so the next command starts its daemon again, and that start
        resumes the run."""
        env = self.environment
        message, run = self.hold("paused-noel")
        daemon, driver = self.daemon_pid(), self.driver_pid("paused-noel")
        marker = self.root / "hosts" / env / "shutdown.json"
        assert not marker.exists()
        os.kill(daemon, signal.SIGTERM)
        os.killpg(driver, signal.SIGTERM)
        self.until(lambda: process_alive(daemon), lambda alive: not alive)
        assert marker.exists(), "a signalled host daemon wrote no takedown marker"
        record = self.record_file("paused-noel", message["id"])
        assert record["state"] == "paused" and record["pause"]["reason"] == "environment_stopped", record
        notes = self.notices(lead, message["id"])
        assert len(notes) == 1 and "paused message" in notes[0]["text"], notes
        resumes = self.daemon_logged("paused-noel", RESUME_LOGGED)
        # Any command in a running environment starts its daemon: this wait
        # may, and so does the listing after it.
        waiter = self.waiting(message["id"])
        views = {v["name"]: v for v in self.call("ls", env, "--output", "json", data=True)}
        assert views[lead]["state"] != "Running", views[lead]
        assert not marker.exists()
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "[faux/echo] HOLD", done
        assert done["turn_id"] == run and "native_resumed" not in done, done
        self.waited(waiter, message, "[faux/echo] HOLD")
        assert self.daemon_logged("paused-noel", RESUME_LOGGED) == resumes + 1
        self.call("restart", env, "--session", lead)
        self.told_pause_then_final(lead, message)

    def stop_intent(self, name):
        """Where the host daemon records an explicit stop of NAME before it
        signals the conversation."""
        return (self.root / "hosts" / self.environment / "sessions" / self.session_ids[name]
                / "stop-intent.json")

    def stop_without_helper(self, name, killed_first):
        """`cw stop ENV --session NAME` while the host daemon's record helper fails: the
        daemon refuses to run its helper from an image with a second link, so
        nothing interrupts the run and no stop interrupt is recorded. With
        KILLED_FIRST the driver cannot act on its signal either: it is
        stopped, so the daemon kills it when the grace ends. The daemon's own
        stop intent is on disk all the same."""
        refused = self.daemon_logged(name, HELPER_FAILED_LOGGED)
        interrupts = self.interrupts_logged(name)
        intent = self.stop_intent(name)
        assert not intent.exists(), intent
        driver = self.driver_pid(name)
        link = Path(self.cw + ".second-link")
        os.link(self.cw, link)
        try:
            if killed_first:
                os.kill(driver, signal.SIGSTOP)
            stopped = self.call("stop", self.environment, "--session", name, "--output", "json", data=True)[0]
        finally:
            link.unlink()
        assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        assert self.daemon_logged(name, HELPER_FAILED_LOGGED) == refused + 1
        assert self.interrupts_logged(name) == interrupts
        assert intent.exists(), "the host daemon recorded no stop intent"

    def prove_stopped_without_helper(self, name, lead, killed_first):
        """An explicit stop whose record helper failed never pauses NAME's
        running message and nothing resumes it: the driver that handles its
        signal ends the message unknown by the daemon's stop intent, and the
        driver that is killed first leaves it running for the next start,
        which ends it unknown by the same intent. LEAD hears of it once."""
        env = self.environment
        message, run = self.hold(name)
        self.stop_without_helper(name, killed_first)
        record = self.record_file(name, message["id"])
        assert record["state"] in ("running", "unknown") and "pause" not in record, record
        if killed_first:
            assert record["state"] == "running", record
        records = self.root / "hosts" / env / "agents" / self.driver_ids[name] / "messages"
        stops = [r for r in (json.loads(path.read_text()) for path in records.glob("*.json"))
                 if r["action"] == "interrupt" and r.get("expected_active_message_id") == message["id"]]
        assert not stops, stops
        self.call("restart", env, "--session", name)
        self.idle(name)
        done = self.wait_message(message["id"], ok=False)
        assert done["state"] == "unknown" and "pause" not in done and "native_resumed" not in done, done
        if killed_first:
            assert done["error"] == STOPPED_IN_FLIGHT, done
        assert not self.stop_intent(name).exists(), "the next start left the stop intent"
        received = [entry["received"] for entry in self.noel_trace(name) if "received" in entry]
        assert not any(r["type"] == "resume_run" and r.get("expectedRunId") == run for r in received), received
        self.heard_once(lead, message)
        notes = self.notices(lead, message["id"])
        assert len(notes) == 1 and "paused message" not in notes[0]["text"], notes
        reply = self.call("msg", env, "--session", name, "AFTER", "--output", "json", data=True)
        assert self.wait_message(reply["id"])["result"] == "[faux/echo] AFTER"

    def prove_removed(self):
        """Removing an environment removes a paused message with it. A `cw
        wait` on that message ends at once: its outcome is unknown."""
        main = self.environment
        created = self.call("create", "--local", "--type", "host", "--name", "removed",
                            "--path", str(self.workspace), "--output", "json", data=True)
        self.environment = created["id"]
        self.extra_environments.append(created["id"])
        try:
            self.launch("removed-noel", agent="noel", model="faux/echo")
            self.idle("removed-noel")
            message, _ = self.hold("removed-noel")
            waiter = self.waiting(message["id"])
            self.call("stop", "--local", self.environment)
            assert self.record_file("removed-noel", message["id"])["state"] == "paused"
            self.call("rm", "--local", self.environment, "--yes")
            self.extra_environments.remove(created["id"])
            out, err = waiter.communicate(timeout=120)
            assert waiter.returncode != 0, (out, err)
            assert json.loads(out)["state"] == "paused", out
            assert (f"message {message['id']} is paused: environment stopped, but its environment was removed; "
                    "its outcome is unknown") in err, err
        finally:
            self.environment = main

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
        self.until(lambda: self.call("ls", self.environment, "--output", "json", data=True),
                   lambda views: any(v["name"] == "history" and
                                     v["output_end_offset"] == len(encoded) for v in views))
        assert len(encoded) > page_size * 2
        assert self.call("logs", self.environment, "--session", "history", timeout=10).stdout == plain.decode()
        assert self.call("logs", self.environment, "--session", "history", "--raw", timeout=10).stdout == encoded.decode()
        assert self.call("logs", self.environment, "--session", "history", "--tail", "0").stdout == ""
        assert self.call("logs", self.environment, "--session", "history", "--tail", "1").stdout == marker.decode()
        assert self.call("logs", self.environment, "--session", "history", "--tail", "70").stdout == (
            b"history-line\n" * 69 + marker).decode()
        assert self.call("logs", self.environment, "--session", "history", "--tail", "30002").stdout == (
            padding + visible + b"\n" + rows + marker).decode()
        assert self.call("logs", self.environment, "--session", "history", "--tail", "30002", "--raw").stdout == (
            padding + b"\x1b[31m" + visible + b"\x1b[0m\n" + rows + marker).decode()

        followers = []
        try:
            for raw in (False, True):
                args = [self.cw, "logs", self.environment, "--session", "history", "--tail", "1", "--follow"]
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
                self.call("send", self.environment, "--session", "history", command)
                live_end += len(piece)
                self.until(lambda: self.call("ls", self.environment, "--output", "json", data=True),
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
        self.call("wait", self.environment, "--session", "history", "--timeout", "10s")
        self.check("logs/paginated-history/final-tail/raw-ansi/bounded-read/follow-cursor")

    def prove_outbox_recovery(self):
        lead = self.inbox("lead")
        saved_thread = lead["driver"]["native_thread_id"]
        parked = self.launch("parked", agent="codex", parent="lead", prompt="HOLD")
        self.until(lambda: self.inbox("parked"), lambda v: v["driver"]["current_turn_id"] is not None)
        self.call("stop", self.environment, "--session", "lead")
        self.call("steer", self.environment, "--session", "parked", "finish")
        source = self.wait_message(parked["message"]["id"])
        self.until(lambda: self.inbox("lead"), lambda v: any(
            m["source"] and m["source"]["message_id"] == source["id"] and m["state"] == "undelivered"
            for m in v["messages"]))
        self.call("stop", self.environment, "--session", "parked")
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
        self.call("restart", self.environment, "--session", "parked")
        self.until(receiver.exists, bool)
        self.call("restart", self.environment, "--session", "lead")
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

    def noel_session(self, name):
        return self.inbox(name)["driver"]["native_thread_id"]

    def noel_trace(self, name, session=None):
        """What the synthetic noel of conversation NAME received, in order."""
        session = session or self.noel_session(name)
        lines = (self.workspace / f"peer-noel-{session}.jsonl").read_text().splitlines()
        return [json.loads(line) for line in lines]

    def received(self, name):
        return [entry["received"] for entry in self.noel_trace(name) if "received" in entry]

    def held(self, name, text):
        """Send TEXT and wait until noel names the run it started."""
        message = self.call("msg", self.environment, "--session", name, text, "--output", "json", data=True)
        self.until(lambda: self.inbox(name), lambda v: v["driver"]["active_message_id"] == message["id"]
                   and v["driver"]["current_turn_id"] is not None)
        return message, self.inbox(name)["driver"]["current_turn_id"]

    def hold(self, name, turn=True, text="HOLD"):
        """Send TEXT to NAME and wait until its driver runs it and, with TURN,
        until the agent names its turn, which Claude does not report."""
        message = self.call("msg", self.environment, "--session", name, text, "--output", "json", data=True)
        self.until(lambda: self.inbox(name), lambda v: v["driver"]["active_message_id"] == message["id"]
                   and (not turn or v["driver"]["current_turn_id"] is not None))
        return message, self.inbox(name)["driver"]["current_turn_id"]

    def idle(self, name):
        return self.until(lambda: self.inbox(name), lambda v: v["driver"] and v["driver"]["phase"] == "idle")

    def interrupts_logged(self, name):
        """How often the host daemon logged interrupting NAME's run before
        stopping it."""
        log = (self.root / "hosts" / self.environment / "daemon.log").read_text()
        session = self.session_ids[name]
        return sum(INTERRUPT_LOGGED in line and session in line for line in log.splitlines())

    def aborted_before_signal(self, name, run, session=None):
        """The synthetic noel of NAME was sent `abort {expectedRunId: RUN}`
        and settled the run before the stop's signal or EOF reached it."""
        trace = self.noel_trace(name, session)
        aborts = [i for i, entry in enumerate(trace) if entry.get("received", {}).get("type") == "abort"
                  and entry["received"].get("expectedRunId") == run]
        assert len(aborts) == 1, trace
        ends = [entry for entry in trace[aborts[0]:] if entry.get("event") in ("sigterm", "eof")]
        assert ends and ends[0]["active"] is False, trace

    def signalled_mid_run(self, name, session=None):
        """The synthetic noel of NAME was signalled with its last prompt's run
        still active, and was never sent an abort for it."""
        trace = self.noel_trace(name, session)
        prompt = max(i for i, entry in enumerate(trace) if entry.get("received", {}).get("type") == "prompt")
        rest = trace[prompt:]
        assert not any(entry.get("received", {}).get("type") == "abort" for entry in rest), trace
        ends = [entry for entry in rest if entry.get("event") in ("sigterm", "eof")]
        assert ends and ends[0]["active"] is True, trace

    def noel_last_run(self, session, env=()):
        """noel's own record of its session's last run, `get_state.lastRun`,
        read by running the staged noel on that session while its
        conversation is stopped."""
        probe = dict(self.env)
        probe.update(value.split("=", 1) for value in env)
        result = subprocess.run([str(self.root / "bin" / "noel"), "--mode", "rpc", "--session-id", session,
                                 "--model", "faux/echo"], input='{"id": 1, "type": "get_state"}\n',
                                env=probe, cwd=self.workspace, text=True, capture_output=True, timeout=60)
        replies = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        reply = next((r for r in replies if r.get("type") == "response" and r.get("id") == 1), None)
        assert reply and reply["success"] and reply["data"]["sessionId"] == session, (result, replies)
        return reply["data"].get("lastRun")

    def stop_confirmed(self, name):
        """`cw stop ENV --session NAME` at a terminal, answering yes when it asks whether to
        stop the running children too."""
        controller, terminal = pty.openpty()
        stop = subprocess.Popen([self.cw, "stop", self.environment, "--session", name, "--output", "json"],
                                env=self.env, cwd=self.workspace, stdin=terminal, stdout=subprocess.PIPE,
                                stderr=terminal)
        os.close(terminal)
        asked, answered = b"", False
        deadline = time.monotonic() + 120
        try:
            while stop.poll() is None:
                assert time.monotonic() < deadline, f"cw stop did not finish: {asked!r}"
                ready, _, _ = select.select([controller], [], [], 0.2)
                if ready:
                    try:
                        asked += os.read(controller, 4096)
                    except OSError:
                        break
                if not answered and b"[Y/n]" in asked:
                    os.write(controller, b"y\n")
                    answered = True
            output = stop.communicate(timeout=60)[0]
        finally:
            if stop.poll() is None:
                stop.kill()
                stop.wait()
            os.close(controller)
        assert answered and stop.returncode == 0, (stop.returncode, asked)
        return json.loads(output), asked.decode(errors="replace")

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
        refused = self.call("run", "--in", env, "--name", "noel-bare", "--agent", "noel", "--detach", ok=False)
        assert "needs --model PROVIDER/ID" in refused.stderr, refused.stderr
        refused = self.call("run", "--in", env, "--name", "noel-ultra", "--agent", "noel", "--model", "faux/echo",
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
        self.knows_itself("noel", "noel-lead")
        assert driver["capabilities"]["steer"] and driver["capabilities"]["interrupt"], driver
        session = driver["native_thread_id"]
        assert "[faux/echo] Hello" in self.call("inbox", env, "--session", "noel-lead").stdout
        assert "says: [faux/echo] Hello" in self.call("logs", env, "--session", "noel-lead").stdout
        trace = self.noel_trace("noel-lead")
        skill, _ = self.delegation_skill("noel-lead")
        assert trace[0]["event"] == "start" and trace[0]["argv"] == [
            "--mode", "rpc", "--session-id", session, "--model", "faux/echo", "--skill", str(skill.parent)], trace[0]
        assert (trace[0]["skill"]["name"], trace[0]["skill"]["file"]) == ("codewire-delegation", str(skill)), trace[0]
        received = self.received("noel-lead")
        assert [(r["type"], "id" in r) for r in received[:4]] == [
            ("get_state", True), ("clear_queue", True), ("clear_queue", False), ("prompt", True)], received
        assert received[3]["message"] == "Hello" and received[3]["requestId"] == first["id"], received
        self.check("noel-identity/startup-handshake/first-turn/inbox-and-logs")

        # A message sent while noel is busy waits in the Codewire mailbox; a
        # steer for another run never reaches noel; a steer is acknowledged.
        holding, run = self.held("noel-lead", "HOLD")
        queued = self.call("msg", env, "--session", "noel-lead", "QUEUED", "--output", "json", data=True)
        assert queued["state"] == "accepted" and self.inbox("noel-lead")["driver"]["queued"] == 1
        fenced = self.call("steer", env, "--session", "noel-lead", "fenced", "--turn-id",
                           "00000000-0000-4000-8000-000000000000", ok=False)
        assert "nothing was steered" in fenced.stderr, fenced.stderr
        steered, steer_time = self.timed("steer", env, "--session", "noel-lead", "finish", "--turn-id", run,
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
        refused = self.call("steer", env, "--session", "noel-lead", "too late", ok=False)
        assert f"noel refused the steer: expectedRunId {run} does not match: no run is active" in refused.stderr, \
            refused.stderr
        assert self.wait_message(late["id"])["result"] == "[faux/echo] LATE"
        self.check("noel-late-steer-refused")

        # An abort is acknowledged by the run's settlement. The steer it left
        # queued in noel never joins the next message.
        holding, run = self.held("noel-lead", "HOLD")
        waiting = self.call("steer", env, "--session", "noel-lead", "WAIT", "--output", "json", data=True)
        assert waiting["native_acknowledged"], waiting
        interrupted, abort_time = self.timed("interrupt", env, "--session", "noel-lead", "--output", "json")
        interrupted = json.loads(interrupted.stdout)
        assert self.wait_message(interrupted["id"])["state"] == "completed"
        assert self.wait_message(holding["id"], ok=False)["state"] == "interrupted"
        assert self.wait_message(waiting["id"], ok=False)["state"] == "interrupted"
        aborts = [r for r in self.received("noel-lead") if r["type"] == "abort"]
        assert len(aborts) == 1 and aborts[0]["expectedRunId"] == run, aborts
        following = self.call("msg", env, "--session", "noel-lead", "NEXT", "--output", "json", data=True)
        assert self.wait_message(following["id"])["result"] == "[faux/echo] NEXT"
        self.check(f"noel-interrupt-acknowledged-{abort_time:.2f}s/queued-steer-not-replayed")

        dialog = self.call("msg", env, "--session", "noel-lead", "DIALOG", "--output", "json", data=True)
        assert self.wait_message(dialog["id"])["result"] == "[faux/echo] DIALOG"
        answers = [r for r in self.received("noel-lead") if r["type"] == "extension_ui_response"]
        assert len(answers) == 1 and answers[0]["cancelled"] is True and answers[0]["id"], answers
        self.check("noel-dialog-declined")

        # A notification, such as an account failover switch, is shown in the
        # session log and needs no answer.
        notified = self.call("msg", env, "--session", "noel-lead", "NOTIFY", "--output", "json", data=True)
        assert self.wait_message(notified["id"])["result"] == "[faux/echo] NOTIFY"
        assert [r for r in self.received("noel-lead") if r["type"] == "extension_ui_response"] == answers
        logs = self.call("logs", env, "--session", "noel-lead").stdout
        assert ("noel warning: fixture account first is rate limited until 14:05 UTC; "
                "switched to second") in logs, logs[-2000:]
        assert "declined noel notify dialog" not in logs
        self.check("noel-notify-logged-unanswered")

        # A worker's result wakes the lead exactly once. An explicit stop
        # mid-run interrupts noel's run first: noel is sent the abort and
        # settles the run before the stop signals it, the message ends
        # interrupted, and the lead hears about it. After a restart the next
        # message answers normally. Codex and Claude keep their stop: the
        # signal ends the turn and its outcome is unknown.
        worker = self.launch("noel-worker", agent="noel", model="faux/echo", parent="noel-lead", prompt="WORKER")
        assert self.wait_message(worker["message"]["id"])["result"] == "[faux/echo] WORKER"
        self.wakes("noel-lead", 1)
        # Every launch writes the skill again, as a cw upgrade needs: a stale
        # one that others could read is replaced when the worker restarts.
        skill, _ = self.delegation_skill("noel-worker")
        current = skill.read_text()
        skill.write_text("an older cw wrote this\n")
        skill.chmod(0o644)
        cut, run, stop_time = self.stop_mid_run("noel-worker", turn=True)
        assert cut["state"] == "interrupted" and cut["turn_id"] == run, cut
        self.aborted_before_signal("noel-worker", run)
        assert self.interrupts_logged("noel-worker") == 1
        again = self.call("msg", env, "--session", "noel-worker", "AGAIN", "--output", "json", data=True)
        assert self.wait_message(again["id"])["result"] == "[faux/echo] AGAIN"
        starts = [e for e in self.noel_trace("noel-worker") if e.get("event") == "start"]
        assert len(starts) == 2 and starts[0] == starts[1], starts
        assert self.delegation_skill("noel-worker")[0].read_text() == current
        self.check("noel-delegation-skill/own-driver-directory/owner-only/names-this-cw/passed-as-skill/"
                   "rewritten-at-restart/codex-and-claude-get-none")
        notifications = self.wakes("noel-lead", 3)
        assert cut["id"] in {m["source"]["message_id"] for m in notifications}
        for name, agent in (("codex-stopped", "codex"), ("claude-stopped", "claude")):
            self.launch(name, agent=agent)
            self.idle(name)
            other, _, _ = self.stop_mid_run(name, turn=agent == "codex")
            assert other["state"] == "unknown", (agent, other)
            assert self.interrupts_logged(name) == 0
        self.check(f"noel-worker-wakes-lead-once/stop-mid-run-interrupted-in-{stop_time:.2f}s/"
                   "abort-before-signal/restart-answers-next/codex-and-claude-stop-unknown")

        # cw restart interrupts the same way; Codex and Claude are unchanged.
        cut, run, restart_time = self.stop_mid_run("noel-worker", turn=True, verb="restart")
        assert cut["state"] == "interrupted" and cut["turn_id"] == run, cut
        assert self.interrupts_logged("noel-worker") == 2
        self.aborted_before_signal("noel-worker", run)
        after = self.call("msg", env, "--session", "noel-worker", "AFTER", "--output", "json", data=True)
        assert self.wait_message(after["id"])["result"] == "[faux/echo] AFTER"
        for name, agent in (("codex-stopped", "codex"), ("claude-stopped", "claude")):
            other, _, _ = self.stop_mid_run(name, turn=agent == "codex", verb="restart")
            assert other["state"] == "unknown", (agent, other)
            assert self.interrupts_logged(name) == 0
        self.check(f"noel-restart-mid-run-interrupted-in-{restart_time:.2f}s/codex-and-claude-restart-unknown")

        all_time = self.prove_cascade("tree", lambda lead: self.call(
            "stop", env, "--session", lead, "--all", "--output", "json", data=True))
        self.check(f"stop-all-interrupts-every-noel-run-first-in-{all_time:.2f}s/codex-and-claude-unknown")
        asked = []

        def confirmed(lead):
            stopped, prompt = self.stop_confirmed(lead)
            asked.append(prompt)
            return stopped
        confirmed_time = self.prove_cascade("asked", confirmed)
        assert "Also stop 3 running child sessions" in asked[0], asked
        self.check(f"confirmed-cascade-interrupts-every-noel-run-first-in-{confirmed_time:.2f}s/"
                   "codex-and-claude-unknown")
        self.prove_noel_resume()

    def prove_noel_resume(self):
        """A crash leaves a noel run interrupted, and its message running:
        noel resumes the run once, and the lead hears once, at the end. Codex
        and Claude end such a message unknown, as before."""
        env = self.environment
        lead = "resume-lead"
        self.launch(lead, agent="noel", model="faux/echo")
        self.idle(lead)
        self.launch("resumed", agent="noel", model="faux/echo", parent=lead)
        self.idle("resumed")

        # noel is killed mid-turn: the driver starts it again and resumes.
        message, run = self.held("resumed", "HOLD")
        os.kill(self.native_pid("resumed", "noel"), signal.SIGKILL)
        resumed = self.wait_message(message["id"])
        assert resumed["state"] == "completed" and resumed["result"] == "[faux/echo] HOLD", resumed
        assert resumed["native_resumed"] == 1 and resumed["turn_id"] == run, resumed
        self.resumed_once("resumed", message, run)
        self.heard_once(lead, message)
        self.check("noel-killed-mid-turn/restarted-once/resumed-once/lead-woken-once/inbox-notes-resume")

        # The driver is killed mid-turn: `cw restart` resumes the run.
        message, run = self.held("resumed", "HOLD")
        os.kill(self.driver_pid("resumed"), signal.SIGKILL)
        self.ended("resumed")
        self.call("restart", env, "--session", "resumed")
        resumed = self.wait_message(message["id"])
        assert resumed["state"] == "completed" and resumed["result"] == "[faux/echo] HOLD", resumed
        assert resumed["native_resumed"] == 1 and resumed["turn_id"] == run, resumed
        self.resumed_once("resumed", message, run)
        self.heard_once(lead, message)
        self.check("driver-killed-mid-turn/restart-resumes-once/lead-woken-once")

        # The driver dies after sending resume_run, before the run settles:
        # the next start resumes it again, counted, and the lead hears once.
        message, run = self.held("resumed", "HOLD2")
        os.kill(self.native_pid("resumed", "noel"), signal.SIGKILL)
        resume = {"id": 3, "type": "resume_run", "expectedRunId": run}
        self.until(lambda: self.received("resumed")[-1], lambda last: last == resume)
        # Counted before resume_run was sent.
        assert self.message_record("resumed", message["id"])["native_resumed"] == 1
        os.kill(self.driver_pid("resumed"), signal.SIGKILL)
        self.ended("resumed")
        assert self.message_record("resumed", message["id"])["state"] == "running"
        self.call("restart", env, "--session", "resumed")
        resumed = self.wait_message(message["id"])
        assert resumed["state"] == "completed" and resumed["result"] == "[faux/echo] HOLD2", resumed
        assert resumed["native_resumed"] == 2, resumed
        self.resumed_once("resumed", message, run, resumes=2)
        self.heard_once(lead, message)
        self.check("driver-killed-after-resume-run/resumed-again-counted-twice/lead-woken-once")

        # Codex and Claude: a killed driver or native agent leaves the
        # message unknown, as before, and the agent is never started again
        # within a driver.
        for agent in ("codex", "claude"):
            name = agent + "-crashed"
            self.launch(name, agent=agent, parent=lead)
            self.idle(name)
            message, _ = self.hold(name, turn=agent == "codex")
            os.kill(self.driver_pid(name), signal.SIGKILL)
            self.ended(name)
            self.call("restart", env, "--session", name)
            self.idle(name)
            record = self.wait_message(message["id"], ok=False)
            assert record["state"] == "unknown" and record["error"] == (
                "the driver restarted while this was in flight; outcome unknown; not replayed"), record
            assert "native_resumed" not in record, record
            self.heard_once(lead, message)
            message, _ = self.hold(name, turn=agent == "codex")
            starts = self.peer_starts(agent, name)
            os.kill(self.native_pid(name, agent), signal.SIGKILL)
            record = self.wait_message(message["id"], ok=False)
            assert record["state"] == "unknown" and "the turn outcome is unknown and is not replayed" in \
                record["error"], record
            self.ended(name)
            assert self.peer_starts(agent, name) == starts, f"{agent} was started again"
            self.heard_once(lead, message)
            self.call("restart", env, "--session", name)
            self.idle(name)
            after = self.call("msg", env, "--session", name, "AFTER", "--output", "json", data=True)
            assert self.wait_message(after["id"])["result"] == "RESULT:AFTER"
        self.check("codex-and-claude-killed-driver-or-agent-unknown-as-before/never-restarted")

    def processes(self):
        """Live processes as (pid, parent pid, argv)."""
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
                argv = (entry / "cmdline").read_bytes().split(b"\0")[:-1]
            except OSError:
                continue
            if argv and stat[0] not in ("Z", "X"):
                yield int(entry.name), int(stat[1]), [arg.decode(errors="replace") for arg in argv]

    def driver_pid(self, name):
        """The live driver of conversation NAME."""
        driver = self.inbox(name)["driver_id"]
        found = [pid for pid, _, argv in self.processes() if "_agent-driver" in argv and driver in argv]
        assert len(found) == 1, (name, found)
        return found[0]

    def native_pid(self, name, agent):
        """The live native agent of conversation NAME: its driver's AGENT."""
        driver, program = self.driver_pid(name), str(self.root / "bin" / agent)
        found = [pid for pid, parent, argv in self.processes() if parent == driver and program in argv]
        assert len(found) == 1, (name, found)
        return found[0]

    def ended(self, name):
        """Waits until conversation NAME's session no longer runs."""
        return self.until(lambda: next(v for v in self.call("ls", self.environment, "--output", "json",
                                                             data=True) if v["name"] == name),
                          lambda view: view["state"] != "Running")

    def message_record(self, name, message_id):
        return next(m for m in self.inbox(name)["messages"] if m["id"] == message_id)

    def peer_starts(self, agent, name):
        """How often the synthetic AGENT of conversation NAME started."""
        seen = [json.loads(line) for line in
                (self.workspace / "agent-identity.jsonl").read_text().splitlines()]
        return sum(e["agent"] == agent and e["session"] == self.session_ids[name] for e in seen)

    def heard_once(self, lead, message, said=None):
        """LEAD heard exactly once that MESSAGE finished, and started one turn
        for it: SAID lists the lead's prompts (by default the synthetic
        noel's)."""
        inbox = self.until(lambda: self.inbox(lead), lambda v: any(
            m["action"] == "notification" and m["source"]["message_id"] == message["id"]
            and m["state"] == "completed" for m in v["messages"]), timeout=60)
        notes = [m for m in inbox["messages"] if m["action"] == "notification"
                 and m["source"]["message_id"] == message["id"]]
        assert len(notes) == 1, notes
        said = said() if said else [r["message"] for r in self.received(lead) if r["type"] == "prompt"]
        assert sum(message["id"] in text for text in said) == 1, said

    def resumed_once(self, name, message, run, resumes=1):
        """MESSAGE was prompted once, and its RUN resumed RESUMES times, each
        by a new synthetic noel of NAME that was first asked how its last run
        stood and had its queue cleared. The inbox and the session log say
        noel resumed it."""
        trace = self.noel_trace(name)
        received = [entry["received"] for entry in trace if "received" in entry]
        prompts = [r for r in received if r["type"] == "prompt" and r.get("requestId") == message["id"]]
        assert len(prompts) == 1, prompts
        begins = [i for i, entry in enumerate(trace) if entry.get("event") == "start"]
        handshakes = [[e["received"] for e in trace[i:] if "received" in e][:3] for i in begins[-resumes:]]
        assert handshakes == [[{"id": 1, "type": "get_state"}, {"id": 2, "type": "clear_queue"},
                               {"id": 3, "type": "resume_run", "expectedRunId": run}]] * resumes, handshakes
        assert sum(r["type"] == "resume_run" and r["expectedRunId"] == run for r in received) == resumes
        note = "(resumed by noel)" if resumes == 1 else f"(resumed by noel {resumes} times)"
        inbox = self.call("inbox", self.environment, "--session", name).stdout
        assert next(line for line in inbox.splitlines() if line.startswith(message["id"])).endswith(note), inbox
        logs = self.call("logs", self.environment, "--session", name).stdout
        assert f"message {message['id']} resumed by noel: run {run}, resume {resumes} of 3" in logs, logs

    def tree(self, prefix, agents=("noel", "codex", "claude"), text="HOLD", env=()):
        """A noel lead and a worker of each agent, every one running TEXT.
        Only noel gets ENV."""
        lead = prefix + "-lead"
        self.launch(lead, agent="noel", model="faux/echo", env=env)
        self.idle(lead)
        for agent in agents:
            name = f"{prefix}-{agent}"
            noel = agent == "noel"
            self.launch(name, agent=agent, parent=lead, model="faux/echo" if noel else None,
                        env=env if noel else ())
            self.idle(name)
        held = {f"{prefix}-{agent}": self.hold(f"{prefix}-{agent}", turn=agent != "claude",
                                               text=text if agent == "noel" else "HOLD")
                for agent in agents}
        held[lead] = self.hold(lead, text=text)
        return lead, held

    def prove_cascade(self, prefix, stop, agents=("noel", "codex", "claude"), text="HOLD", env=()):
        """STOP stops a lead and its running workers. Every noel run is
        interrupted before its conversation is signalled; Codex and Claude
        turns end unknown as before. Returns how long STOP took."""
        lead, held = self.tree(prefix, agents, text, env)
        started = time.monotonic()
        stopped = stop(lead)
        took = time.monotonic() - started
        assert {view["name"] for view in stopped} == set(held), stopped
        assert all(view["state"] == "Stopped" and not view["cleanup_unknown"] for view in stopped), stopped
        noels = [lead, prefix + "-noel"]
        for name in noels:
            message, run = held[name]
            record = self.wait_message(message["id"], ok=False)
            assert record["state"] == "interrupted" and record["turn_id"] == run, record
            assert self.interrupts_logged(name) == 1, name
            if not env:
                self.aborted_before_signal(name, run)
            else:
                last = self.noel_last_run(self.noel_session(name), env)
                assert last == {"runId": run, "requestId": message["id"], "status": "aborted"}, last
        # Children stop after their lead, so the worker's notification waits
        # in the stopped lead's inbox.
        worker = self.wait_message(held[prefix + "-noel"][0]["id"], ok=False)
        assert worker["notification"]["state"] == "undelivered", worker
        sources = {held[prefix + "-noel"][0]["id"]}
        for agent in agents[1:]:
            name = f"{prefix}-{agent}"
            assert self.interrupts_logged(name) == 0, name
            self.call("restart", self.environment, "--session", name)
            self.idle(name)
            assert self.wait_message(held[name][0]["id"], ok=False)["state"] == "unknown", name
            sources.add(held[name][0]["id"])
        # Restarted, the lead adopts each worker message's notification once.
        self.call("restart", self.environment, "--session", lead)
        inbox = self.until(lambda: self.inbox(lead), lambda v: {
            m["source"]["message_id"] for m in v["messages"] if m["action"] == "notification"
            and m["state"] in ("accepted", "running", "completed")} >= sources, timeout=120)
        notifications = [m for m in inbox["messages"] if m["action"] == "notification"]
        assert len(notifications) == len(sources), notifications
        self.call("stop", self.environment, "--session", lead, "--all", "--output", "json", data=True)
        return took

    def stop_mid_run(self, name, turn, verb="stop"):
        """Stop NAME while its HOLD message runs and restart it, or with VERB
        "restart" only restart it. Returns that message as Codewire recorded
        it, its run, and how long the stop or restart took. TURN waits for the
        native turn ID as well, which Claude does not report."""
        holding, run = self.hold(name, turn=turn)
        started = time.monotonic()
        if verb == "stop":
            stopped = self.call("stop", self.environment, "--session", name, "--output", "json", data=True)[0]
            assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        took = time.monotonic() - started
        self.call("restart", self.environment, "--session", name)
        if verb == "restart":
            took = time.monotonic() - started
        self.idle(name)
        return self.wait_message(holding["id"], ok=False), run, took

    def run_real_noel(self):
        """The noel journey with the real binary: faux/echo, private pi state."""
        created = self.call("create", "--local", "--type", "host", "--name", "proof",
                            "--path", str(self.workspace), "--output", "json", data=True)
        self.environment = env = created["id"]
        self.preserved = "noel-proof.txt"
        (self.workspace / self.preserved).write_text("workspace\n")
        home, agent = self.root / "noel-home", self.root / "noel-agent"
        home.mkdir(mode=0o700)
        agent.mkdir(mode=0o700)
        private = [f"HOME={home}", f"NOEL_DIR={agent}", "NOEL_OFFLINE=1"]
        self.check("create-host-environment")

        lead = self.launch("noel-lead", agent="noel", model="faux/echo", prompt="Hello", env=private)
        first = self.wait_message(lead["message"]["id"])
        assert first["state"] == "completed" and first["result"] == "[faux/echo] Hello", first
        inbox = self.call("inbox", env, "--session", "noel-lead").stdout
        assert "[faux/echo] Hello" in inbox, inbox
        session = self.inbox("noel-lead")["driver"]["native_thread_id"]
        journal = agent / "sessions" / f"{session}.jsonl"

        def said(role, journal=journal):
            """What noel saved in its session journal for ROLE. A reply an
            abort cut off answered nothing, so it is left out: noel from
            noeljackson/noel#95 keeps it in the journal marked aborted (noel
            spec section 4.2), and earlier builds did not save it at all."""
            entries = [json.loads(line) for line in journal.read_text().splitlines()]
            return [e["message"]["content"] for e in entries
                    if e.get("type") == "message" and e["message"]["role"] == role
                    and not e["message"].get("aborted")]

        print(f"cli-host: noel inbox: {inbox.splitlines()[-1]}", flush=True)
        self.check("real-noel-first-turn/inbox-shows-reply")

        again = self.call("msg", env, "--session", "noel-lead", "Again", "--output", "json", data=True)
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

        slow = private + ["NOEL_FAUX_STREAM_DELAY_MS=200", "NOEL_FAUX_STREAM_CHARS=1"]
        self.launch("noel-slow", agent="noel", model="faux/echo", parent="noel-lead", env=slow)
        self.until(lambda: self.inbox("noel-slow"), lambda v: v["driver"] and v["driver"]["phase"] == "idle")
        story_text = "Write a long story about a lighthouse keeper and the sea."
        story, run = self.held("noel-slow", story_text)
        refused = self.call("steer", env, "--session", "noel-slow", "Wrong run", "--turn-id",
                            "00000000-0000-4000-8000-000000000000", ok=False)
        assert "nothing was steered" in refused.stderr, refused.stderr
        steered, steer_time = self.timed("steer", env, "--session", "noel-slow", "Be brief.", "--turn-id", run,
                                         "--output", "json")
        steered = json.loads(steered.stdout)
        assert steered["native_acknowledged"] and steered["turn_id"] == run, steered
        interrupted, abort_time = self.timed("interrupt", env, "--session", "noel-slow", "--output", "json")
        interrupted = json.loads(interrupted.stdout)
        assert self.wait_message(interrupted["id"])["state"] == "completed"
        story = self.wait_message(story["id"], ok=False)
        assert story["state"] == "interrupted", story
        assert self.wait_message(steered["id"], ok=False)["state"] == "interrupted"
        print(f"cli-host: noel steer acknowledged in {steer_time:.2f}s, interrupt in {abort_time:.2f}s; "
              f"interrupted reply so far: {story['result']!r}", flush=True)
        self.check("real-noel-steer-fenced-and-acknowledged/interrupt-acknowledged")

        # An explicit stop mid-run interrupts noel's run first: noel aborts it
        # and records it aborted before the stop signals noel, the message
        # ends interrupted, and the lead hears about it.
        second_text = "Tell another long story, about the mountains."
        second, run = self.held("noel-slow", second_text)
        stopped, stop_time = self.timed("stop", env, "--session", "noel-slow", "--output", "json")
        stopped = json.loads(stopped.stdout)[0]
        assert stopped["state"] == "Stopped" and not stopped["cleanup_unknown"], stopped
        slow_session = self.noel_session("noel-slow")
        last = self.noel_last_run(slow_session, private)
        assert last == {"runId": run, "requestId": second["id"], "status": "aborted"}, last
        second = self.wait_message(second["id"], ok=False)
        assert second["state"] == "interrupted" and second["turn_id"] == run, second
        assert self.interrupts_logged("noel-slow") == 1
        self.call("restart", env, "--session", "noel-slow")
        self.idle("noel-slow")
        print(f"cli-host: noel stop mid-run in {stop_time:.2f}s: message {second['state']}, "
              f"noel's run {last['status']}", flush=True)
        self.check(f"real-noel-stop-interrupts-run-first-in-{stop_time:.2f}s/journal-aborted")

        short = self.call("msg", env, "--session", "noel-slow", "Short.", "--output", "json", data=True)
        assert self.wait_message(short["id"])["result"] == "[faux/echo] Short."
        assert self.inbox("noel-slow")["driver"]["native_thread_id"] == slow_session
        # noel saved both stories' prompts and no reply but the last: an
        # aborted reply is not saved, or is saved marked aborted, and nothing
        # resumed the stopped run. The steer the
        # interrupt left queued was cleared before that prompt, not joined.
        slow_journal = agent / "sessions" / f"{slow_session}.jsonl"
        assert said("user", slow_journal) == [story_text, second_text, "Short."], said("user", slow_journal)
        assert said("assistant", slow_journal) == ["[faux/echo] Short."], said("assistant", slow_journal)
        self.check("real-noel-restart-answers-next/stopped-run-not-resumed/queued-steer-not-replayed")

        # cw restart interrupts the same way. noel's journal records the run
        # aborted before the restart's signal; no prompt has followed it.
        third, run = self.held("noel-slow", "One more long story, about a river.")
        _, restart_time = self.timed("restart", env, "--session", "noel-slow")
        self.idle("noel-slow")
        third = self.wait_message(third["id"], ok=False)
        assert third["state"] == "interrupted" and third["turn_id"] == run, third
        assert self.interrupts_logged("noel-slow") == 2
        assert journal_runs(slow_journal)[run] == "aborted", journal_runs(slow_journal)
        self.check(f"real-noel-restart-interrupts-run-first-in-{restart_time:.2f}s/journal-aborted")

        # The lead heard once about each finished worker message, including
        # the ones the interrupt, the stop and the restart ended.
        finished = {worker["message"]["id"], story["id"], second["id"], short["id"], third["id"]}
        inbox = self.until(lambda: self.inbox("noel-lead"), lambda v: sum(
            m["action"] == "notification" and m["state"] == "completed" for m in v["messages"]) >= 5, timeout=60)
        notifications = [m for m in inbox["messages"] if m["action"] == "notification"]
        assert {m["source"]["message_id"] for m in notifications} == finished, notifications
        assert len(notifications) == 5, notifications
        wakes = [text for text in said("user") if "[Codewire] Managed worker" in text]
        assert len(wakes) == 5, wakes
        assert [sum(f"as {state}." in text for text in wakes) for state in ("interrupted", "unknown")] == [3, 0], wakes
        self.check("real-noel-lead-woken-once-per-worker-message")
        self.prove_real_resume(private)

        # Stopping a lead and its worker interrupts both runs first.
        long_story = "Write a long story about a lighthouse keeper and the sea."
        all_time = self.prove_cascade("rall", lambda lead: self.call(
            "stop", env, "--session", lead, "--all", "--output", "json", data=True), ("noel",), long_story, slow)
        self.check(f"real-noel-stop-all-interrupts-lead-and-worker-first-in-{all_time:.2f}s")
        asked = []

        def confirmed(lead):
            stopped, prompt = self.stop_confirmed(lead)
            asked.append(prompt)
            return stopped
        confirmed_time = self.prove_cascade("rasked", confirmed, ("noel",), long_story, slow)
        assert "Also stop 1 running child session (rasked-noel)" in asked[0], asked
        self.check(f"real-noel-confirmed-cascade-interrupts-lead-and-worker-first-in-{confirmed_time:.2f}s")

        # Taking the whole environment down pauses the run instead: noel's
        # journal keeps it interrupted, and the message is paused, not ended.
        # A conversation launched with inline --env values can never restart
        # after daemon recovery, so its paused message resolves once instead
        # of waiting for a start that cannot come.
        paused = self.pause(("noel",), "A long story about a bridge.", slow)
        self.call("stop", "--local", env)
        self.prove_paused(paused, slow)
        self.call("start", "--local", env)
        message = self.wait_message(paused["paused-noel"][0]["id"], ok=False)
        assert message["state"] == "unknown", message
        assert message["error"].startswith(
            "paused when its environment stopped; its conversation cannot start again"), message
        assert message["error"].endswith("outcome unknown; not replayed"), message
        self.check("real-noel-env-stop-pauses-run/journal-interrupted/"
                   "unrestartable-conversation-resolves-unknown-once")
        self.prove_real_pause(private)
        self.prove_real_delegation(private)

    def prove_real_resume(self, private):
        """A crash leaves a real noel run interrupted, and its message running.
        noel resumes the run once: a cut-off model request is sent again, a
        cut-off bash call never runs again, and the lead hears once, at the end."""
        env = self.environment
        lead = "resume-lead"
        self.launch(lead, agent="noel", model="faux/echo", env=private)
        self.idle(lead)
        lead_journal = self.root / "noel-agent" / "sessions" / f"{self.noel_session(lead)}.jsonl"

        def lead_said():
            entries = [json.loads(line) for line in lead_journal.read_text().splitlines()]
            return [e["message"]["content"] for e in entries
                    if e.get("type") == "message" and e["message"]["role"] == "user"]

        def scripted(name, responses):
            """A worker of the lead whose faux/script model answers with
            RESPONSES in order. Returns where noel logs its model requests."""
            script, log = self.root / f"{name}-script.json", self.root / f"{name}-requests.jsonl"
            script.write_text(json.dumps(responses))
            self.launch(name, agent="noel", model="faux/script", parent=lead,
                        env=private + [f"NOEL_FAUX_SCRIPT={script}", f"NOEL_FAUX_SCRIPT_LOG={log}", "SHELL=/bin/sh"])
            self.idle(name)
            return log

        def requests(log, count):
            """noel's logged model requests, once there are COUNT."""
            return self.until(lambda: [json.loads(line) for line in log.read_text().splitlines()]
                              if log.exists() else [], lambda sent: len(sent) >= count)

        def held(marker):
            return [{"wait_for_file": f"never-{marker}"}, {"text": "never sent"}]

        # noel is killed while its model request is cut off: the driver starts
        # it again, and the resumed run sends that request once more.
        log = scripted("noel-model", [held("model"), [{"text": "Answered after the resend."}]])
        message, run = self.held("noel-model", "Count the lighthouses.")
        requests(log, 1)
        os.kill(self.native_pid("noel-model", "noel"), signal.SIGKILL)
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "Answered after the resend.", done
        assert done["native_resumed"] == 1 and done["turn_id"] == run, done
        sent = requests(log, 2)
        assert len(sent) == 2 and sent[0]["messages"] == sent[1]["messages"] == [
            {"role": "user", "content": "Count the lighthouses."}], sent
        self.real_resumed("noel-model", message, run)
        self.heard_once(lead, message, lead_said)
        print(f"cli-host: noel resend logged: {json.dumps(sent[1]['messages'])}", flush=True)
        self.check("real-noel-killed-mid-model-request/request-sent-again-once/resumed-once/lead-woken-once")

        # noel is killed while its bash call sleeps after appending a line:
        # the resumed run never runs the call again.
        counter = self.root / "tool-counter.txt"
        command = (f"printf 'ran\\n' >> {counter}; n=0; "
                   "while [ $n -lt 600 ] && kill -0 $PPID 2>/dev/null; do sleep 0.1; n=$((n+1)); done")
        log = scripted("noel-tool", [[{"tool_call": {"name": "bash", "arguments": {"command": command}}}],
                                     [{"text": "The counter was written once."}]])
        message, run = self.held("noel-tool", "Append a line to the counter.")
        self.until(lambda: counter.read_text().splitlines() if counter.exists() else [],
                   lambda lines: lines == ["ran"])
        os.kill(self.native_pid("noel-tool", "noel"), signal.SIGKILL)
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "The counter was written once.", done
        assert done["native_resumed"] == 1 and done["turn_id"] == run, done
        time.sleep(1)  # a second run of the call would have appended by now
        assert counter.read_text().splitlines() == ["ran"], counter.read_text()
        sent = requests(log, 2)
        assert len(sent) == 2, sent
        results = [(m["tool_name"], m["content"]) for m in sent[1]["messages"] if m["role"] == "tool"]
        # The interrupted call is not run again. Its result says so: the
        # output saved before the kill (none: it printed to a file) and
        # Durable's interrupted block, from noeljackson/noel#95 on, or the
        # earlier placeholder.
        interrupted = (
            "<harness>\n[error] Tool bash was interrupted and may have partially run\n</harness>",
            "tool call bash did not complete before the session continued",
        )
        assert len(results) == 1 and results[0][0] == "bash" and results[0][1] in interrupted, sent
        assert "bash is reported interrupted, not run again" in self.call("logs", env, "--session", "noel-tool").stdout
        self.real_resumed("noel-tool", message, run)
        self.heard_once(lead, message, lead_said)
        print(f"cli-host: noel interrupted bash once; counter {counter.read_text().splitlines()}, "
              f"model told {results[0][1]!r}", flush=True)
        self.check("real-noel-killed-during-bash/bash-not-run-again/counter-has-one-line/lead-woken-once")

        # The driver is killed mid-turn: `cw restart` resumes the run.
        log = scripted("noel-driver", [held("driver"), [{"text": "Answered after the driver restarted."}]])
        message, run = self.held("noel-driver", "Map the coast.")
        requests(log, 1)
        os.kill(self.driver_pid("noel-driver"), signal.SIGKILL)
        self.ended("noel-driver")
        self.call("restart", env, "--session", "noel-driver")
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "Answered after the driver restarted.", done
        assert done["native_resumed"] == 1 and done["turn_id"] == run, done
        sent = requests(log, 2)
        assert len(sent) == 2 and sent[0]["messages"] == sent[1]["messages"], sent
        self.real_resumed("noel-driver", message, run)
        self.heard_once(lead, message, lead_said)
        self.check("real-noel-driver-killed-mid-turn/restart-resumes-once/lead-woken-once")

        # The driver dies after sending resume_run, before the run settles: the
        # next start resumes it again, counted, and the lead hears once.
        log = scripted("noel-twice", [held("first"), held("second"), [{"text": "Survived both crashes."}]])
        message, run = self.held("noel-twice", "Cross the bay.")
        requests(log, 1)
        os.kill(self.native_pid("noel-twice", "noel"), signal.SIGKILL)
        requests(log, 2)
        # Counted before resume_run was sent.
        assert self.message_record("noel-twice", message["id"])["native_resumed"] == 1
        os.kill(self.driver_pid("noel-twice"), signal.SIGKILL)
        self.ended("noel-twice")
        assert self.message_record("noel-twice", message["id"])["state"] == "running"
        self.call("restart", env, "--session", "noel-twice")
        done = self.wait_message(message["id"])
        assert done["state"] == "completed" and done["result"] == "Survived both crashes.", done
        assert done["native_resumed"] == 2 and done["turn_id"] == run, done
        sent = requests(log, 3)
        assert len(sent) == 3 and sent[0]["messages"] == sent[1]["messages"] == sent[2]["messages"], sent
        self.real_resumed("noel-twice", message, run, resumes=2)
        self.heard_once(lead, message, lead_said)
        self.check("real-noel-driver-killed-after-resume-run/resumed-again-counted-twice/lead-woken-once")

    def prove_real_pause(self, private):
        """The real noel resumes a run its environment's takedown paused, by
        itself when the environment starts: the cut-off model request is sent
        again once, the waiting `cw wait` returns its answer, and the lead
        hears of the pause once and then of the final state once. Codex and
        Claude end unknown and are not restarted. The environment's daemon
        carries noel's private settings, as a user's own environment does,
        so its conversations can restart."""
        main = self.environment
        script, log = self.root / "pause-script.json", self.root / "pause-requests.jsonl"
        script.write_text(json.dumps([[{"wait_for_file": "never-pause"}, {"text": "never sent"}],
                                      [{"text": "Answered after the environment came back."}],
                                      [{"wait_for_file": "never-stop"}, {"text": "never sent"}]]))
        daemon = dict(self.env)
        daemon.update(value.split("=", 1) for value in private + [
            f"NOEL_FAUX_SCRIPT={script}", f"NOEL_FAUX_SCRIPT_LOG={log}", "SHELL=/bin/sh"])
        created = self.call("create", "--local", "--type", "host", "--name", "paused",
                            "--path", str(self.workspace), "--output", "json", data=True, env=daemon)
        self.environment = env = created["id"]
        self.extra_environments.append(env)
        try:
            lead = "pause-lead"
            self.launch(lead, agent="noel", model="faux/echo")
            self.idle(lead)
            self.launch("pause-worker", agent="noel", model="faux/script", parent=lead)
            self.idle("pause-worker")
            others = {}
            for agent in ("codex", "claude"):
                self.launch("pause-" + agent, agent=agent)
                self.idle("pause-" + agent)
                others["pause-" + agent] = self.hold("pause-" + agent, turn=agent == "codex")[0]
            prompt = "Cross the strait."

            def requests():
                """noel's logged model requests for the worker's prompt."""
                sent = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                return [s for s in sent if s["messages"] and s["messages"][0].get("content") == prompt]
            message, run = self.held("pause-worker", prompt)
            self.until(requests, lambda sent: len(sent) >= 1)
            waiter = self.waiting(message["id"], env=daemon)
            session = self.noel_session("pause-worker")
            journal = self.root / "noel-agent" / "sessions" / f"{session}.jsonl"
            lead_journal = self.root / "noel-agent" / "sessions" / f"{self.noel_session(lead)}.jsonl"

            self.call("stop", "--local", env)
            record = self.record_file("pause-worker", message["id"])
            assert record["state"] == "paused" and record["pause"]["reason"] == "environment_stopped", record
            assert self.daemon_logged("pause-worker", PAUSE_LOGGED) == 1
            assert self.interrupts_logged("pause-worker") == 0
            # noel never ended the run: it stays resumable in its journal.
            assert journal_runs(journal).get(run) in (None, "interrupted"), journal_runs(journal)
            notes = self.notices(lead, message["id"])
            assert len(notes) == 1 and "paused message" in notes[0]["text"], notes

            self.call("start", "--local", env, env=daemon)
            done = self.wait_message(message["id"])
            assert done["state"] == "completed", done
            assert done["result"] == "Answered after the environment came back.", done
            assert done["turn_id"] == run and "native_resumed" not in done, done
            assert done["pause"]["reason"] == "environment_stopped", done
            self.waited(waiter, message, "Answered after the environment came back.")
            assert self.daemon_logged("pause-worker", RESUME_LOGGED) == 1
            sent = requests()
            assert len(sent) == 2 and sent[0]["messages"] == sent[1]["messages"] == [
                {"role": "user", "content": prompt}], sent
            assert journal_runs(journal) == {run: "completed"}, journal_runs(journal)
            inbox = self.call("inbox", env, "--session", "pause-worker").stdout
            line = next(line for line in inbox.splitlines() if line.startswith(message["id"]))
            assert line.endswith("(resumed after its environment stopped)"), inbox
            print(f"cli-host: noel inbox after its environment restarted: {line}", flush=True)
            views = {v["name"]: v for v in self.call("ls", env, "--output", "json", data=True)}
            for name in list(others) + [lead]:
                assert views[name]["state"] == "Stopped", views[name]
            for name, other in others.items():
                self.call("restart", env, "--session", name)
                self.idle(name)
                ended = self.wait_message(other["id"], ok=False)
                assert ended["state"] == "unknown" and "pause" not in ended, (name, ended)
            self.call("restart", env, "--session", lead)

            def lead_said():
                entries = [json.loads(line) for line in lead_journal.read_text().splitlines()]
                return [e["message"]["content"] for e in entries
                        if e.get("type") == "message" and e["message"]["role"] == "user"]
            self.told_pause_then_final(lead, message, lead_said)
            self.check("real-noel-env-stop-pauses-run/env-start-resumes-without-restart/"
                       "model-request-sent-again-once/wait-goes-on/lead-hears-pause-then-final/"
                       "codex-and-claude-unknown-and-not-restarted")

            # An explicit stop whose record helper fails and whose driver is
            # killed before it acts: only the host daemon's stop intent says
            # the stop was explicit. The next start never resumes the run:
            # its cut-off model request is not sent again.
            def sent():
                return [json.loads(line) for line in log.read_text().splitlines()]
            asked = len(sent())
            stopped, stopped_run = self.held("pause-worker", "Hold the harbour.")
            self.until(sent, lambda requests: len(requests) == asked + 1)
            self.stop_without_helper("pause-worker", killed_first=True)
            assert self.record_file("pause-worker", stopped["id"])["state"] == "running"
            self.call("restart", env, "--session", "pause-worker")
            self.idle("pause-worker")
            done = self.wait_message(stopped["id"], ok=False)
            assert done["state"] == "unknown" and done["error"] == STOPPED_IN_FLIGHT, done
            assert "pause" not in done and "native_resumed" not in done, done
            assert not self.stop_intent("pause-worker").exists()
            assert journal_runs(journal).get(stopped_run) != "completed", journal_runs(journal)
            self.heard_once(lead, stopped, lead_said)
            assert len(sent()) == asked + 1, sent()
            self.check("real-noel-explicit-stop-with-failed-record-helper/driver-killed-first/"
                       "never-resumed/model-request-not-sent-again/lead-hears-once")
            self.call("rm", "--local", env, "--yes")
            self.extra_environments.remove(env)
        finally:
            self.environment = main

    def prove_real_delegation(self, private):
        """A real noel lead is told how to delegate, and delegates. cw writes
        the delegation skill into the lead's driver directory and noel lists
        it in the lead's system prompt. The lead's scripted model reads it
        with noel's `read` tool and runs every command in it with noel's
        `bash` tool, exactly as the skill writes it. It launches a worker of
        each agent; launching the first again is refused and starts no second
        worker; each worker message that ends wakes the lead once with its
        result. It then reads a worker's state, follows up, steers, waits for
        one result, interrupts and stops. The environment's daemon carries
        noel's private settings and the lead's script. Its faux/echo is
        slowed, so a noel worker's task runs for seconds."""
        main = self.environment
        script, log = self.root / "delegate-script.json", self.root / "delegate-requests.jsonl"
        script.write_text("[]")
        daemon = dict(self.env)
        daemon.update(value.split("=", 1) for value in private + [
            f"NOEL_FAUX_SCRIPT={script}", f"NOEL_FAUX_SCRIPT_LOG={log}", "SHELL=/bin/sh",
            "NOEL_FAUX_STREAM_DELAY_MS=100", "NOEL_FAUX_STREAM_CHARS=1"])
        created = self.call("create", "--local", "--type", "host", "--name", "delegating",
                            "--path", str(self.workspace), "--output", "json", data=True, env=daemon)
        self.environment = env = created["id"]
        self.extra_environments.append(env)
        try:
            lead, worker = "delegating-lead", "count-lighthouses"
            self.launch(lead, agent="noel", model="faux/script")
            self.idle(lead)
            file, commands = self.delegation_skill(lead)
            responses, used = [], set()

            def skill(start, values):
                """The skill's one command that is `cw START`, or else that
                begins with it, with VALUES in place of its placeholders."""
                (command,) = ([c for c in commands if c == f"{self.cw} {start}"]
                              or [c for c in commands if c.startswith(f"{self.cw} {start} ")])
                used.add(command)
                words = command[len(self.cw):]
                for placeholder, value in values.items():
                    assert words.count(placeholder) == 1, (command, placeholder)
                    words = words.replace(placeholder, value)
                assert not any(left in words for left in ("NAME", "TASK", "TEXT", "MESSAGE_ID", "PROVIDER/ID")), words
                return self.cw + words

            def tool(name, after=None, **arguments):
                """A model response that calls noel's tool NAME, held until
                the file AFTER exists beside the script."""
                held = [{"wait_for_file": after}] if after else []
                return held + [{"tool_call": {"name": name, "arguments": arguments}}]

            def respond(*more):
                """Appends model responses to the script, which noel reads
                again for every request. Returns which request each answers,
                counted from 1."""
                answered = len(responses)
                responses.extend(more)
                fresh = script.with_suffix(".new")
                fresh.write_text(json.dumps(responses))
                fresh.replace(script)
                return range(answered + 1, len(responses) + 1)

            def sent(count):
                """The lead's logged model requests, once there are COUNT."""
                return self.until(lambda: [json.loads(line) for line in log.read_text().splitlines()]
                                  if log.exists() else [], lambda requests: len(requests) >= count, timeout=120)

            def ran(request):
                """What the tool call that answered REQUEST returned, as the
                next request tells the model."""
                messages = sent(request + 1)[request]["messages"]
                return [m["content"] for m in messages if m["role"] == "tool"][-1]

            def running(message):
                """Waits until the worker's noel runs MESSAGE."""
                self.until(lambda: self.inbox(worker)["driver"], lambda driver: driver["active_message_id"] == message
                           and driver["current_turn_id"] is not None)

            def notices():
                return [m for m in self.inbox(lead)["messages"] if m["action"] == "notification"]

            # The lead reads its skill, launches a worker of each agent and
            # then the first again, with the launch commands as written.
            said, task = [{"text": "Noted."}], "Count the lighthouses."
            launch = skill('run --in "$CW_ENVIRONMENT" --agent noel',
                           {"PROVIDER/ID": "faux/echo", "NAME": worker, "TASK": task})
            reviews = {agent: skill(f'run --in "$CW_ENVIRONMENT" --agent {agent}',
                                    {"NAME": f"review-{agent}", "TASK": f"Review the count as {agent}."})
                       for agent in ("codex", "claude")}
            read, launched, codex, claude, again, *_ = respond(
                tool("read", path=str(file)), tool("bash", command=launch), tool("bash", command=reviews["codex"]),
                tool("bash", command=reviews["claude"]), tool("bash", command=launch),
                [{"text": "Delegated."}], said, said, said)
            first = self.call("msg", env, "--session", lead, "Have the lighthouses counted and the count reviewed.",
                              "--output", "json", data=True)
            asked = sent(1)[0]
            # A noel without the skill listing sends no system prompt at all.
            prompt = asked["system_prompt"] or ""
            assert "<name>codewire-delegation</name>" in prompt and f"<location>{file}</location>" in prompt, (
                "noel did not list the delegation skill in its system prompt; this journey needs a noel built "
                f"from noeljackson/pi main at 08566af5 or later. Its system prompt: {prompt!r}")
            assert {"read", "bash"} <= set(asked["tools"]), asked["tools"]
            assert ran(read) == file.read_text(), ran(read)
            print(f"cli-host: noel system prompt lists codewire-delegation at {file}", flush=True)
            self.check("real-noel-lead-given-delegation-skill/owner-only-in-its-driver-directory/"
                       "system-prompt-lists-its-name-and-file/read-tool-returns-it")

            assert self.wait_message(first["id"])["result"] == "Delegated."
            ids = {worker: message_id(ran(launched)), "review-codex": message_id(ran(codex)),
                   "review-claude": message_id(ran(claude))}
            assert f"Launched managed noel conversation {worker} " in ran(launched), ran(launched)
            listed = self.call("ls", env, "--output", "json", data=True)
            views = {view["name"]: view for view in listed}
            assert all(views[name]["parent_session_id"] == self.session_ids[lead] for name in ids), listed
            results = {worker: f"[faux/echo] {task}", "review-codex": "RESULT:Review the count as codex.",
                       "review-claude": "RESULT:Review the count as claude."}
            for name, message in ids.items():
                done = self.wait_message(message)
                assert done["state"] == "completed" and done["result"] == results[name], done
                assert done["target_session_id"] == views[name]["session_id"], (done, views[name])
            self.check("real-noel-lead-bash-runs-the-skills-launch-command/"
                       "worker-of-each-agent-started-under-the-lead")

            refused = ran(again)
            assert f"session name is already retained: {worker}" in refused, refused
            assert "Command exited with code 1" in refused and "Launched" not in refused, refused
            assert sorted(views) == sorted([lead, *ids]) and len(listed) == 4, listed
            print(f"cli-host: noel repeated launch refused: {refused.splitlines()[0]}", flush=True)
            self.check("real-noel-repeated-launch-refused/session-name-already-retained/no-second-worker")

            self.until(notices, lambda notes: sum(m["state"] == "completed" for m in notes) >= 3)
            assert len(sent(len(responses))) == len(responses)
            woken = time.monotonic()

            # The lead reads the worker's state, gives it a long task, steers
            # it and waits for its result; then interrupts a second long task
            # and stops the worker, which has a worker of its own.
            self.launch("lamp-keeper", agent="noel", model="faux/echo", parent=worker)
            self.idle("lamp-keeper")
            long = "Write a long story about a lighthouse keeper, the sea and the lamp that never went out."
            named = {"NAME": worker}
            follow = skill("msg", {**named, "TEXT": long})
            looked, followed, steered = respond(
                tool("bash", command=skill("inbox", named)), tool("bash", command=follow),
                tool("bash", "delegate-steer", command=skill("steer", {**named, "TEXT": "Be brief."})))
            second = self.call("msg", env, "--session", lead, "Follow up with the worker, then stop it.",
                               "--output", "json", data=True)
            assert f"{ids[worker]}\tprompt\tcompleted\t" in ran(looked), ran(looked)
            follow_id = message_id(ran(followed))
            running(follow_id)
            waited, cut, interrupted, stopped, all_stopped, *_ = respond(
                tool("bash", command=skill("wait", {"MESSAGE_ID": follow_id})), tool("bash", command=follow),
                tool("bash", "delegate-interrupt", command=skill("interrupt", named)),
                tool("bash", command=skill('stop "$CW_ENVIRONMENT" --session NAME', named)),
                tool("bash", command=skill('stop "$CW_ENVIRONMENT" --session NAME --all', named)),
                [{"text": "Stopped."}], said, said)
            (self.root / "delegate-steer").write_text("")
            cut_id = message_id(ran(cut))
            running(cut_id)
            (self.root / "delegate-interrupt").write_text("")
            assert self.wait_message(second["id"])["result"] == "Stopped."
            assert ran(waited) == "[faux/echo] Be brief.\n", ran(waited)
            done = self.wait_message(follow_id)
            assert done["state"] == "completed" and done["result"] == "[faux/echo] Be brief.", done
            assert self.wait_message(message_id(ran(steered)))["state"] == "completed"
            assert self.wait_message(message_id(ran(interrupted)))["state"] == "completed"
            assert self.wait_message(cut_id, ok=False)["state"] == "interrupted"
            # Without a terminal `cw stop ENV --session NAME` leaves the
            # worker's own worker running and names it; `--all` stops it too.
            assert re.search(rf"^{worker} +Stopped ", ran(stopped), re.M), ran(stopped)
            assert "child session lamp-keeper is still running" in ran(stopped), ran(stopped)
            assert "Command exited" not in ran(stopped) + ran(all_stopped), (ran(stopped), ran(all_stopped))
            assert all(re.search(rf"^{name} +Stopped ", ran(all_stopped), re.M)
                       for name in (worker, "lamp-keeper")), ran(all_stopped)
            states = {view["name"]: view["state"] for view in self.call("ls", env, "--output", "json", data=True)}
            assert states == {lead: "Running", worker: "Stopped", "lamp-keeper": "Stopped",
                              "review-codex": "Running", "review-claude": "Running"}, states
            assert used == set(commands), set(commands) - used
            print(f"cli-host: noel lead ran all {len(commands)} commands of its delegation skill", flush=True)
            self.check("real-noel-lead-reads-state-follows-up-steers-waits-interrupts-and-stops-as-the-skill-writes/"
                       "every-skill-command-ran")

            # Each worker message that ended woke the lead once, with its
            # result. The first three did so more than one scan of the
            # lead's inbox ago, and no scan admitted one of them again.
            finished = set(ids.values()) | {follow_id, cut_id}
            self.until(notices, lambda notes: sum(m["state"] == "completed" for m in notes) >= 5)
            time.sleep(max(0, 11 - (time.monotonic() - woken)))
            notes = notices()
            assert len(notes) == 5 and {m["source"]["message_id"] for m in notes} == finished, notes
            requests = sent(len(responses))
            assert len(requests) == len(responses) == 20, len(requests)
            wakes = [m["content"] for m in requests[-1]["messages"]
                     if m["role"] == "user" and "[Codewire] Managed worker" in m["content"]]
            assert len(wakes) == 5 and all(sum(message in text for text in wakes) == 1 for message in finished), wakes
            counted = next(text for text in wakes if ids[worker] in text)
            assert counted.startswith(f"[Codewire] Managed worker {worker} (session {views[worker]['session_id']}) "
                                      f"finished message {ids[worker]} as completed.\n\n[faux/echo] {task}\n"), counted
            assert sum(f"finished message {cut_id} as interrupted." in text for text in wakes) == 1, wakes
            self.check("real-noel-lead-woken-once-per-worker-message-with-its-result")
            self.call("rm", "--local", env, "--yes")
            self.extra_environments.remove(env)
        finally:
            self.environment = main

    def real_resumed(self, name, message, run, resumes=1):
        """noel's journal for NAME holds MESSAGE's prompt once and its RUN
        completed; the inbox and the session log say noel resumed it."""
        journal = self.root / "noel-agent" / "sessions" / f"{self.noel_session(name)}.jsonl"
        entries = [json.loads(line) for line in journal.read_text().splitlines()]
        prompts = [e["message"]["content"] for e in entries
                   if e.get("type") == "message" and e["message"]["role"] == "user"]
        assert prompts == [message["text"]], prompts
        assert journal_runs(journal) == {run: "completed"}, journal_runs(journal)
        note = "(resumed by noel)" if resumes == 1 else f"(resumed by noel {resumes} times)"
        inbox = self.call("inbox", self.environment, "--session", name).stdout
        assert next(line for line in inbox.splitlines() if line.startswith(message["id"])).endswith(note), inbox
        logs = self.call("logs", self.environment, "--session", name).stdout
        assert f"message {message['id']} resumed by noel: run {run}, resume {resumes} of 3" in logs, logs
        print(f"cli-host: noel inbox: {next(l for l in inbox.splitlines() if l.startswith(message['id']))}",
              flush=True)

    def cleanup(self, preserve=False):
        try:
            try:
                # An environment a failed step left behind stops with the rest.
                for extra in self.extra_environments:
                    self.call("stop", "--local", extra, ok=None)
                if self.environment:
                    if preserve:
                        self.call("stop", "--local", self.environment)
                        print(f"cli-host: failed-journey evidence retained: {self.root}", file=sys.stderr)
                    else:
                        result = self.call("rm", "--local", self.environment, "--yes")
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


def skill_commands(text):
    """The command lines of a skill's `sh` blocks."""
    commands, fenced = [], False
    for line in text.splitlines():
        if line in ("```sh", "```"):
            fenced = line == "```sh"
        elif fenced:
            commands.append(line)
    return commands


def message_id(printed):
    """The message ID in what `cw run --detach --prompt`, `cw steer` or
    `cw interrupt` printed (a line `ID<tab>STATE`), or `cw msg` printed (a
    line `<mark> Message ID STATE`)."""
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    found = re.findall(rf"^({uuid})\t[a-z_]+$", printed, re.M)
    found += re.findall(rf"^\S+ Message ({uuid}) [a-z_]+", printed, re.M)
    assert len(found) == 1, printed
    return found[0]


def journal_runs(journal):
    """The runs a noel session journal records, by ID: how each ended, or
    None while it has no end."""
    runs = {}
    for line in journal.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("type") == "message" and entry.get("run"):
            runs[entry["run"]["id"]] = None
        elif entry.get("type") == "run_finished":
            runs[entry["run_id"]] = entry["status"]
    return runs


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
