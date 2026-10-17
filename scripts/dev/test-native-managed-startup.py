#!/usr/bin/env python3
"""Bounded proof that a guest managed driver cancels a stalled provider startup.

  scripts/dev/test-native-managed-startup.py --cw /abs/candidate/cw [--scratch DIR]

Runs one candidate binary's hidden `cw _agent-driver --guest-root` and
`cw _agent-control` directly on this Linux host, in a private temporary HOME,
config, guest state and PATH. The `codex` and `claude` on that PATH are
synthetic Python peers that never answer the startup handshake; each records
only its own process birth as a readiness marker and never reads
authentication or uses the network. --scratch must allow execution.

Scenarios: Codex and Claude startups each cancelled by a durable shutdown bound
to the captured peer identity, with no driver stdin hint; a Codex startup
stopped by SIGTERM; and shutdowns naming a wrong expected peer, refused before
any operation write. An unrelated synthetic process must survive. The startup
task stays queued and unissued; no completion, daemon session or VM parity is
claimed. The harness stops and reaps only its own exact processes, removes its
temporary tree on success (retains it on failure), and prints one bounded JSON
report. Prompts, launch environments and provider arguments are never printed.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

HARNESS = "scripts/dev/test-native-managed-startup.py"
OVERALL_SECONDS = 240
CLEANUP_RESERVE_SECONDS = 45
HELPER_SECONDS = 15
READY_SECONDS = 15
EXIT_BOUND_SECONDS = 15
GONE_SECONDS = 5
# The product's Claude control-probe timeout. A stalled Claude startup must be
# cancelled inside it; the driver log, not timing, proves the startup branch.
CLAUDE_PROBE_SECONDS = 20
CHILD_UMASK = 0o022
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Closed native schemas: any added or missing field fails the proof.
IDENTITY_KEYS = {"environment_id", "driver_id", "session_id", "instance_id", "driver_started_at",
                 "boot_id", "driver_pid", "driver_start_ticks"}
RECEIPT_KEYS = {"version", "identity", "guardian_pid", "guardian_start_ticks", "provider_pid",
                "cleanup_unknown", "finished_at", "exit_code", "error"}
SHUTDOWN_KEYS = {"version", "operation_id", "peer", "requested_at", "accepted_at", "finished_at",
                 "cleanup_unknown", "error"}
BINDING_KEYS = {"driver_id", "session_id", "bound_at"}
# Driver capability note persisted before initialization; it changes only when
# the native handshake completes.
STARTING_NOTE = "driver starting"
SCENARIOS = (
    # (label, agent, stop, wrong expected peer)
    ("codex-shutdown", "codex", "shutdown", True),
    ("claude-shutdown", "claude", "shutdown", False),
    ("codex-sigterm", "codex", "sigterm", False),
)

PEER_SOURCE = """#!@PYTHON@ -I
# Synthetic stalled provider for scripts/dev/test-native-managed-startup.py.
# It never answers or writes native output, never reads authentication and
# never uses the network. It records only its own process birth.
import json, os, signal, sys, time

MARKERS = @MARKERS@
# Bound even a blocked stdin read if the outer harness is interrupted.
signal.alarm(@PEER_LIFETIME@)
with open("/proc/self/stat") as handle:
    fields = handle.read().rsplit(") ", 1)[1].split()
name = os.path.basename(sys.argv[0])
pid = os.getpid()
path = os.path.join(MARKERS, f"{name}-{pid}.json")
fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump({"agent": name, "pid": pid, "ppid": int(fields[1]), "start_ticks": int(fields[19])}, handle)
os.rename(path + ".tmp", path)
# Drain native input unrecorded; stay stalled after EOF until signalled.
try:
    while os.read(0, 65536):
        pass
except OSError:
    pass
while True:
    time.sleep(3600)
"""


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def bounded(text, limit=300):
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()[:limit]


def is_uuid(value):
    return isinstance(value, str) and UUID_PATTERN.fullmatch(value) is not None


def rfc3339_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def birth(pid):
    """(ppid, start ticks, state) of a live or unreaped process, else None."""
    try:
        with open(f"/proc/{pid}/stat") as handle:
            fields = handle.read().rsplit(") ", 1)[1].split()
        return int(fields[1]), int(fields[19]), fields[0]
    except (OSError, IndexError, ValueError):
        return None


def birth_present(pid, ticks):
    found = birth(pid)
    return found is not None and found[1] == ticks


def wait_gone(pid, ticks, seconds):
    end = time.monotonic() + seconds
    while birth_present(pid, ticks):
        if time.monotonic() >= end:
            return False
        time.sleep(0.05)
    return True


def signal_birth(pid, ticks, signum):
    """Signals one exact process birth through a pidfd; False when it is gone."""
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        if not birth_present(pid, ticks):
            return False
        signal.pidfd_send_signal(fd, signum)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(fd)


def kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.communicate()


def private_dir(path):
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    return path


def read_text(path):
    with open(path, "rb") as handle:
        return handle.read().decode(errors="replace")


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def terminate(signum, _frame):
    raise Failure(f"harness received signal {signum}")


class Proof:
    def __init__(self, cw, scratch):
        self.cw = cw
        self.started = time.monotonic()
        self.deadline = self.started + OVERALL_SECONDS - CLEANUP_RESERVE_SECONDS
        self.stage = "init"
        self.checks = []
        self.scenarios = []
        self.limitations = []
        self.drivers = []
        self.births = {}
        self.helper_calls = 0
        self.owned = []
        self.sentinel = None
        self.sentinel_birth = None
        self.environment_id = str(uuid.uuid4())
        self.work = tempfile.mkdtemp(prefix="cw-startup-proof-", dir=scratch)
        os.chmod(self.work, 0o700)
        self.home = private_dir(os.path.join(self.work, "home"))
        self.config = private_dir(os.path.join(self.work, "config"))
        self.tmp = private_dir(os.path.join(self.work, "tmp"))
        self.bin = private_dir(os.path.join(self.work, "bin"))
        self.markers = private_dir(os.path.join(self.work, "markers"))
        self.workspace = private_dir(os.path.join(self.work, "workspace"))
        self.logs = private_dir(os.path.join(self.work, "logs"))
        self.guest_root = os.path.join(private_dir(os.path.join(self.work, "guest-state")), self.environment_id)
        private_dir(self.guest_root)
        # Built from nothing: no ambient provider, credential or config value
        # reaches cw or the peers. PATH names only the synthetic peers.
        self.env = {
            "HOME": self.home,
            "XDG_CONFIG_HOME": os.path.join(self.home, ".config"),
            "CW_CONFIG_DIR": self.config,
            "TMPDIR": self.tmp,
            "PATH": self.bin,
            "LANG": "C.UTF-8",
        }

    # -- Bounds and evidence ---------------------------------------------

    def budget(self, requested):
        remaining = self.deadline - time.monotonic()
        if remaining <= 1:
            raise Failure(f"overall proof deadline expired during {self.stage}")
        return max(0.5, min(float(requested), remaining))

    def check(self, name):
        self.checks.append(name)
        print(f"native-managed-startup: {name} PASS", file=sys.stderr, flush=True)

    # -- Synthetic peers -------------------------------------------------

    def install_peers(self):
        source = (PEER_SOURCE.replace("@PYTHON@", sys.executable)
                  .replace("@MARKERS@", repr(self.markers))
                  .replace("@PEER_LIFETIME@", str(OVERALL_SECONDS + CLEANUP_RESERVE_SECONDS)))
        for name in ("codex", "claude"):
            path = os.path.join(self.bin, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "w") as handle:
                handle.write(source)

    def marker(self, agent, pid):
        path = os.path.join(self.markers, f"{agent}-{pid}.json")
        try:
            with open(path) as handle:
                return json.load(handle)
        except FileNotFoundError:
            return None

    # -- Real hidden helpers ----------------------------------------------

    def control(self, request):
        """One `cw _agent-control` request: (exit code, JSON or None, stderr text)."""
        limit = self.budget(HELPER_SECONDS)
        process = subprocess.Popen(
            [self.cw, "_agent-control", "--environment", self.environment_id, "--guest-root", self.guest_root],
            cwd=self.workspace, env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, umask=CHILD_UMASK)
        try:
            stdout, stderr = process.communicate(json.dumps(request).encode(), timeout=limit)
        except subprocess.TimeoutExpired:
            kill_group(process)
            raise Failure(f"cw _agent-control {request['op']} did not finish within {limit:.0f}s; "
                          f"its effect is unknown") from None
        except BaseException:
            kill_group(process)
            raise
        self.helper_calls += 1
        if process.returncode != 0:
            require(not stdout.strip(), f"refused cw _agent-control {request['op']} still wrote a response")
            return process.returncode, None, stderr.decode(errors="replace")
        require(not stderr, f"cw _agent-control {request['op']} returned unexpected stderr")
        try:
            return 0, json.loads(stdout), ""
        except json.JSONDecodeError:
            raise Failure(f"cw _agent-control {request['op']} returned invalid JSON") from None

    def ok(self, request):
        code, value, error = self.control(request)
        require(code == 0, f"cw _agent-control {request['op']} exited {code}: {bounded(error)}")
        return value

    def refused(self, request):
        code, _, error = self.control(request)
        require(code != 0, f"cw _agent-control {request['op']} unexpectedly succeeded")
        return error

    def launch_driver(self, label, driver_id):
        def log(name):
            return os.open(os.path.join(self.logs, f"{label}.{name}"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        out, err = log("out"), log("err")
        try:
            # stdin stays an open pipe that is never written: no control hint.
            process = subprocess.Popen(
                [self.cw, "_agent-driver", "--environment", self.environment_id, "--driver-id", driver_id,
                 "--guest-root", self.guest_root],
                cwd=self.workspace, env=self.env, stdin=subprocess.PIPE, stdout=out, stderr=err,
                start_new_session=True, umask=CHILD_UMASK)
        finally:
            os.close(out)
            os.close(err)
        self.drivers.append({"label": label, "process": process})
        return process

    def wait_exit(self, process, seconds):
        try:
            return process.wait(timeout=self.budget(seconds))
        except subprocess.TimeoutExpired:
            return None

    # -- Records ---------------------------------------------------------

    def snapshot(self, root):
        """Every entry's type, mode, size and mtime, except append-only journals."""
        entries = {}
        for directory, dirs, files in os.walk(root):
            for name in dirs + files:
                path = os.path.join(directory, name)
                if name.endswith(".journal"):
                    continue
                meta = os.lstat(path)
                entries[os.path.relpath(path, root)] = (stat.S_IFMT(meta.st_mode), stat.S_IMODE(meta.st_mode),
                                                         meta.st_size, meta.st_mtime_ns)
        return entries

    def private_tree(self, root):
        """Owner-private records: 0700 directories, 0600 files, no links."""
        euid = os.geteuid()
        counts = {"directories": 0, "files": 0}
        for directory, dirs, files in os.walk(root):
            for name in [None] + dirs + files:
                path = directory if name is None else os.path.join(directory, name)
                if name is None and directory != root:
                    continue
                meta = os.lstat(path)
                mode = stat.S_IMODE(meta.st_mode)
                relative = os.path.relpath(path, self.guest_root)
                require(meta.st_uid == euid, f"guest record {relative} has another owner")
                if stat.S_ISDIR(meta.st_mode):
                    require(mode == 0o700, f"guest directory {relative} is {mode:o}, not 700")
                    counts["directories"] += 1
                else:
                    require(stat.S_ISREG(meta.st_mode), f"guest record {relative} is not a regular file")
                    require(mode == 0o600, f"guest record {relative} is {mode:o}, not 600")
                    counts["files"] += 1
        return counts

    # -- Proof -----------------------------------------------------------

    def run(self):
        self.stage = "preflight"
        self.install_peers()
        info = self.ok({"op": "protocol_info"})
        require(info == {"protocol_version": 1}, "the candidate does not speak guest agent protocol 1")
        require(sorted(os.listdir(self.bin)) == ["claude", "codex"], "the private PATH holds more than the peers")
        self.check("preflight/candidate-protocol-v1/synthetic-peers-only-on-private-path")

        self.stage = "sentinel"
        self.sentinel = subprocess.Popen(
            [os.path.join(self.bin, "codex"), "app-server"], cwd=self.workspace, env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, umask=CHILD_UMASK)
        end = time.monotonic() + self.budget(10)
        while (marker := self.marker("codex", self.sentinel.pid)) is None:
            require(self.sentinel.poll() is None and time.monotonic() < end,
                    "the unrelated synthetic process did not start")
            time.sleep(0.05)
        require(marker["ppid"] == os.getpid(), "the unrelated synthetic process is not this harness's child")
        self.sentinel_birth = (marker["pid"], marker["start_ticks"])
        self.check("sentinel/unrelated-synthetic-process-running")

        for label, agent, stop, wrong_peer in SCENARIOS:
            self.scenario(label, agent, stop, wrong_peer)

        self.stage = "sentinel-survival"
        require(self.sentinel.poll() is None and birth_present(*self.sentinel_birth),
                "the unrelated synthetic process did not survive startup cancellation")
        providers = {births["provider"][0] for births in self.births.values()}
        recorded = set()
        for name in os.listdir(self.markers):
            match = re.fullmatch(r"(codex|claude)-(\d+)\.json", name)
            require(match is not None, f"unexpected synthetic marker {bounded(name, 80)}")
            recorded.add(int(match.group(2)))
        require(recorded == providers | {self.sentinel_birth[0]},
                "synthetic process births do not match one provider per startup plus the sentinel")
        self.check("sentinel/unrelated-synthetic-process-survived/one-provider-birth-per-startup")

    def scenario(self, label, agent, stop, wrong_peer):
        self.stage = label
        driver_id, session_id, message_id = str(uuid.uuid4()), f"session-{uuid.uuid4()}", str(uuid.uuid4())
        observed = {"name": label, "agent": agent, "stop": stop, "driver_id": driver_id,
                    "session_id": session_id, "startup_task_id": message_id}
        self.scenarios.append(observed)
        conversation = {"driver_id": driver_id, "session_id": session_id}
        driver_dir = os.path.join(self.guest_root, "agents", driver_id)

        config = {"version": 1, "driver_id": driver_id, "environment_id": self.environment_id, "agent": agent,
                  "program": "", "model": "synthetic-startup-model", "effort": "max" if agent == "codex" else None,
                  "working_dir": self.workspace, "name": "", "parent": None,
                  "initial_message_id": message_id, "created_at": rfc3339_now()}
        prepared = self.ok({"op": "prepare", "config": config})["config"]
        # The guest records the file its shell runs, links followed.
        require(prepared["program"] == os.path.realpath(os.path.join(self.bin, agent)) and
                prepared["driver_id"] == driver_id,
                f"prepare did not resolve the synthetic {agent} on the private PATH")
        launched_at = time.monotonic()
        driver = self.launch_driver(label, driver_id)
        observed["driver_pid"] = driver.pid
        # Bind after launch, as the host does; the prompt is synthetic and never printed.
        bound = self.ok({"op": "bind", **conversation, "prompt": f"Synthetic startup task {secrets.token_hex(4)}"})
        binding, task = bound["binding"], bound["message"]
        require(set(binding) == BINDING_KEYS and binding["driver_id"] == driver_id and
                binding["session_id"] == session_id, "bind returned another binding")
        require(task and task["id"] == message_id and task["action"] == "prompt" and task["state"] == "requested",
                "bind did not create the requested startup task")

        status, marker = self.wait_ready(driver, conversation, agent)
        observed["ready_seconds"] = round(time.monotonic() - launched_at, 3)
        state, receipt = status["driver"], status["peer"]
        identity = receipt["identity"]
        require(set(receipt) == RECEIPT_KEYS and set(identity) == IDENTITY_KEYS,
                "peer custody is not the closed native receipt schema")
        require(identity["environment_id"] == self.environment_id and identity["driver_id"] == driver_id and
                identity["session_id"] == session_id and is_uuid(identity["instance_id"]) and
                identity["driver_pid"] == driver.pid and identity["driver_started_at"] == state["started_at"],
                "peer identity does not bind this driver, session and start")
        driver_birth = birth(driver.pid)
        require(driver_birth and driver_birth[1] == identity["driver_start_ticks"],
                "peer identity does not record the driver's exact birth")
        guardian = (receipt["guardian_pid"], receipt["guardian_start_ticks"])
        provider = (marker["pid"], marker["start_ticks"])
        self.births[label] = {"guardian": guardian, "provider": provider}
        guardian_birth = birth(guardian[0])
        require(guardian_birth and guardian_birth[0] == driver.pid and guardian_birth[1] == guardian[1],
                "the guardian is not the driver's exact direct child")
        require(receipt["provider_pid"] == provider[0] and marker["ppid"] == guardian[0] and
                birth_present(*provider), "the synthetic provider is not the guardian's exact direct child")
        require(receipt["cleanup_unknown"] is True and receipt["finished_at"] is None,
                "running custody was not recorded as unknown")
        require(state["phase"] == "starting" and state["capabilities"]["note"] == STARTING_NOTE and
                state["active_message_id"] is None and state["queued"] == 1 and status["shutdown"] is None,
                "the driver is not stalled in startup with one queued task")
        queued = self.ok({"op": "get_message", "driver_id": driver_id, "message_id": message_id})["record"]
        require(queued["state"] == "accepted" and queued["started_at"] is None,
                "the startup task was not adopted as accepted and unissued")
        observed.update(guardian_pid=guardian[0], provider_pid=provider[0], instance_id=identity["instance_id"])
        self.check(f"{label}/stalled-startup/peer-custody-bound/task-accepted-unissued")

        if wrong_peer:
            self.prove_wrong_peer(label, driver, driver_dir, conversation, identity)

        operation_id = None
        if stop == "shutdown":
            operation_id = str(uuid.uuid4())
            observed["operation_id"] = operation_id
            requested_at = time.monotonic()
            requested = self.ok({"op": "shutdown", **conversation, "operation_id": operation_id, "peer": identity})
            record = requested["shutdown"]
            require(set(record) == SHUTDOWN_KEYS and record["operation_id"] == operation_id and
                    record["peer"] == identity and record["accepted_at"] is None and
                    record["finished_at"] is None and record["cleanup_unknown"] is True,
                    "shutdown was not recorded as a pending operation for the captured peer")
            # Deliberately no driver stdin hint: the durable record alone must cancel startup.
        else:
            requested_at = time.monotonic()
            driver.send_signal(signal.SIGTERM)
        observed["launch_to_cancel_seconds"] = round(requested_at - launched_at, 3)
        if agent == "claude":
            require(requested_at - launched_at < CLAUDE_PROBE_SECONDS,
                    "Claude cancellation was requested after its control-probe window")
        code = self.wait_exit(driver, EXIT_BOUND_SECONDS)
        observed["driver_exit_code"] = code
        require(code is not None, f"the driver did not exit within {EXIT_BOUND_SECONDS}s of its {stop}")
        observed["cancel_to_exit_seconds"] = round(time.monotonic() - requested_at, 3)
        require(code == 0, f"the driver exited {code} after its {stop}; cleanup was not confirmed")
        log = read_text(os.path.join(self.logs, f"{label}.err"))
        expected = (f"managed startup shutdown {operation_id}" if stop == "shutdown"
                    else "startup stopped by SIGTERM")
        require(expected in log, "the driver log does not show cancellation in its startup branch")
        require("conversation ready" not in log and "cleanup is unknown" not in log,
                "the driver completed startup or left cleanup unknown")
        observed["forwarded_provider_stderr_lines"] = sum(
            line.startswith(f"[{agent}]") for line in log.splitlines())
        self.check(f"{label}/" + ("durable-shutdown-without-stdin-hint" if stop == "shutdown"
                                  else "sigterm-during-startup") +
                   f"/startup-branch/driver-exit-within-{EXIT_BOUND_SECONDS}s")

        self.prove_settled(label, agent, stop, driver_dir, conversation, identity, operation_id,
                           message_id, guardian, provider, observed)

    def wait_ready(self, driver, conversation, agent):
        end = time.monotonic() + self.budget(READY_SECONDS)
        last = "no peer status yet"
        while time.monotonic() < end:
            code = driver.poll()
            require(code is None, f"the {agent} driver exited {code} during stalled startup")
            result, status, error = self.control({"op": "peer_status", **conversation})
            if result == 0:
                phase, receipt = status["driver"]["phase"], status["peer"]
                require(phase == "starting", f"the {agent} driver left startup as {phase} without an answer")
                pid = receipt.get("provider_pid")
                marker = self.marker(agent, pid) if pid else None
                if receipt.get("guardian_pid") and marker:
                    return status, marker
                last = f"guardian={bool(receipt.get('guardian_pid'))} provider={bool(pid)} marker={bool(marker)}"
            else:
                last = bounded(error, 160)
            time.sleep(0.1)
        raise Failure(f"{agent} stalled startup custody was not observed within {READY_SECONDS}s: {last}")

    def prove_wrong_peer(self, label, driver, driver_dir, conversation, identity):
        before = self.snapshot(driver_dir)
        for field, value in (("instance_id", str(uuid.uuid4())),
                             ("driver_start_ticks", identity["driver_start_ticks"] + 1)):
            wrong = dict(identity, **{field: value})
            error = self.refused({"op": "shutdown", **conversation, "operation_id": str(uuid.uuid4()),
                                  "peer": wrong})
            require("no operation was created" in error,
                    f"a wrong expected peer ({field}) was refused for another reason: {bounded(error, 160)}")
        after = self.snapshot(driver_dir)
        changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
        require(not changed, f"a refused shutdown changed custody records: {', '.join(changed)[:200]}")
        require(not any(os.path.basename(name).startswith("shutdown-") for name in after),
                "a refused shutdown wrote an operation record")
        require(driver.poll() is None, "a refused shutdown ended the driver")
        status = self.ok({"op": "peer_status", **conversation})
        require(status["driver"]["phase"] == "starting" and status["peer"]["identity"] == identity and
                status["shutdown"] is None, "a refused shutdown changed the stalled startup")
        self.check(f"{label}/wrong-expected-peer-refused/no-operation-write/startup-unaffected")

    def prove_settled(self, label, agent, stop, driver_dir, conversation, identity, operation_id,
                      message_id, guardian, provider, observed):
        status = self.ok({"op": "status", **conversation, "limit": 100})
        state, receipt, binding = status["driver"], status["peer"], status["binding"]
        require(status["peer_error"] is None and set(receipt) == RECEIPT_KEYS and receipt["identity"] == identity,
                "settled custody does not name the captured peer")
        require(receipt["cleanup_unknown"] is False and receipt["finished_at"] and receipt["error"] is None and
                receipt["provider_pid"] == provider[0] and receipt["guardian_pid"] == guardian[0] and
                isinstance(receipt["exit_code"], int), "the peer receipt is not finished known-clean")
        observed["receipt_exit_code"] = receipt["exit_code"]
        require(state["phase"] == "stopped" and state["last_error"] is None and
                state["active_message_id"] is None and state["current_turn_id"] is None and
                state["queued"] == 1 and state["capabilities"]["note"] == STARTING_NOTE,
                "the driver did not stop known-clean with initialization incomplete and its task queued")
        if agent == "codex":
            require(state["native_thread_established"] is False, "a Codex thread was established")
        if stop == "shutdown":
            done = self.ok({"op": "get_shutdown", **conversation, "operation_id": operation_id,
                            "instance_id": identity["instance_id"]})["shutdown"]
            require(set(done) == SHUTDOWN_KEYS and done["peer"] == identity and done["accepted_at"] and
                    done["finished_at"] and done["cleanup_unknown"] is False and done["error"] is None and
                    done["requested_at"] <= done["accepted_at"] <= done["finished_at"],
                    "the shutdown was not accepted and finished known-clean")
            require(status["shutdown"] == done, "status reports another shutdown operation")
        else:
            require(status["shutdown"] is None and
                    not any(name.startswith("shutdown-") for name in os.listdir(driver_dir)),
                    "SIGTERM created a shutdown operation")
        journal = read_text(os.path.join(driver_dir, f"peer-{identity['instance_id']}.journal"))
        for needle in (f"claimed custody guardian_pid={guardian[0]} ", f"provider started pid={provider[0]} ",
                       "cleanup started: received SIGTERM",
                       "cleanup proven: waitpid reported no remaining children", "finished exit_code="):
            require(needle in journal, f"the guardian journal lacks {needle.split(':')[0].split('=')[0]!r}")
        for role, (pid, ticks) in (("provider", provider), ("guardian", guardian)):
            require(wait_gone(pid, ticks, GONE_SECONDS), f"the exact {role} birth outlived its driver")
        task = self.ok({"op": "get_message", "driver_id": conversation["driver_id"],
                        "message_id": message_id})["record"]
        require(task["state"] == "accepted" and task["started_at"] is None and task["finished_at"] is None and
                task["native_acknowledged"] is False and task["result"] is None and task["turn_id"] is None and
                task["error"] is None, "the startup task did not stay queued and unissued")
        require(status["total_messages"] == 1 and [m["id"] for m in status["messages"]] == [message_id],
                "the conversation holds records other than its startup task")
        require(set(binding) == BINDING_KEYS and binding["session_id"] == conversation["session_id"] and
                binding["session_id"].startswith("session-") and is_uuid(binding["session_id"][8:]),
                "the binding does not name the canonical session-UUID")
        observed["private_records"] = self.private_tree(self.guest_root)
        self.check(f"{label}/" + ("accepted-finished-known-clean" if stop == "shutdown" else "no-shutdown-operation") +
                   "/receipt-echild-clean/exact-births-gone/task-still-queued/private-closed-records")

    # -- Cleanup ---------------------------------------------------------

    def cleanup(self):
        """Stops and reaps only this run's exact processes. Any intervention is an error."""
        self.stage = "cleanup"
        errors = []
        for entry in self.drivers:
            process = entry["process"]
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=EXIT_BOUND_SECONDS)
                    errors.append(f"{entry['label']} driver was still running; stopped by SIGTERM in cleanup")
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=GONE_SECONDS)
                    errors.append(f"{entry['label']} driver ignored SIGTERM; its session was killed")
            if process.stdin:
                process.stdin.close()
        for label, births in self.births.items():
            for role, (pid, ticks) in births.items():
                if wait_gone(pid, ticks, 0.5):
                    continue
                signal_birth(pid, ticks, signal.SIGKILL)
                gone = wait_gone(pid, ticks, GONE_SECONDS)
                errors.append(f"{label} {role} birth was present at cleanup; " +
                              ("killed" if gone else "could not be stopped"))
        if self.sentinel is not None:
            if self.sentinel.poll() is None:
                self.sentinel.send_signal(signal.SIGTERM)
                try:
                    self.sentinel.wait(timeout=GONE_SECONDS)
                except subprocess.TimeoutExpired:
                    self.sentinel.kill()
                    self.sentinel.wait(timeout=GONE_SECONDS)
            if self.sentinel_birth and not wait_gone(*self.sentinel_birth, GONE_SECONDS):
                errors.append("the sentinel could not be reaped")
        # Any other synthetic birth that ever ran is also exactly owned here.
        known = {births["provider"][0] for births in self.births.values()}
        known |= {self.sentinel_birth[0]} if self.sentinel_birth else set()
        for name in os.listdir(self.markers):
            match = re.fullmatch(r"(codex|claude)-(\d+)\.json", name)
            if not match or int(match.group(2)) in known:
                continue
            marker = self.marker(match.group(1), match.group(2)) or {}
            if marker.get("start_ticks") is not None and birth_present(int(match.group(2)), marker["start_ticks"]):
                signal_birth(int(match.group(2)), marker["start_ticks"], signal.SIGKILL)
                errors.append("an unaccounted synthetic peer birth was killed in cleanup")
        self.owned = [{"role": f"{entry['label']} driver", "pid": entry["process"].pid,
                       "exit_code": entry["process"].returncode} for entry in self.drivers]
        self.owned += [{"role": f"{label} {role}", "pid": pid, "gone": not birth_present(pid, ticks)}
                       for label, births in self.births.items() for role, (pid, ticks) in births.items()]
        if self.sentinel_birth:
            self.owned.append({"role": "unrelated sentinel", "pid": self.sentinel_birth[0],
                               "exit_code": self.sentinel.returncode,
                               "gone": not birth_present(*self.sentinel_birth)})
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cw", required=True, help="absolute candidate cw binary")
    parser.add_argument("--scratch", default=os.environ.get("TMPDIR") or tempfile.gettempdir(),
                        help="existing executable-mount directory for the private temporary tree")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("guest managed startup custody requires Linux")
    if not (os.path.isabs(args.cw) and os.path.isfile(args.cw) and os.access(args.cw, os.X_OK)):
        parser.error("--cw must be an absolute executable file")
    scratch = os.path.realpath(args.scratch)
    if not (os.path.isabs(args.scratch) and os.path.isdir(scratch)):
        parser.error("--scratch must be an existing absolute directory")
    if os.statvfs(scratch).f_flag & os.ST_NOEXEC:
        parser.error("--scratch is on a noexec mount; synthetic peers must be executable")
    cw_sha256 = file_sha256(args.cw)
    proof = Proof(args.cw, scratch)
    failure = None
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        proof.run()
    except Exception as error:
        detail = str(error) if isinstance(error, Failure) else f"{type(error).__name__}: {error}"
        failure = {"stage": proof.stage, "detail": bounded(detail, 600)}
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_errors = proof.cleanup()
    required = ["preflight/candidate-protocol-v1/synthetic-peers-only-on-private-path",
                "sentinel/unrelated-synthetic-process-running"]
    for label, _, stop, wrong_peer in SCENARIOS:
        required.append(f"{label}/stalled-startup/peer-custody-bound/task-accepted-unissued")
        if wrong_peer:
            required.append(f"{label}/wrong-expected-peer-refused/no-operation-write/startup-unaffected")
        required.append(f"{label}/" + ("durable-shutdown-without-stdin-hint" if stop == "shutdown"
                                       else "sigterm-during-startup") +
                        f"/startup-branch/driver-exit-within-{EXIT_BOUND_SECONDS}s")
        required.append(f"{label}/" + ("accepted-finished-known-clean" if stop == "shutdown"
                                       else "no-shutdown-operation") +
                        "/receipt-echild-clean/exact-births-gone/task-still-queued/private-closed-records")
    required.append("sentinel/unrelated-synthetic-process-survived/one-provider-birth-per-startup")
    missing = [name for name in required if name not in proof.checks]
    passed = failure is None and not cleanup_errors and not missing
    artifacts = "removed"
    if passed:
        shutil.rmtree(proof.work)
    else:
        artifacts = f"retained for diagnosis at {proof.work}"
    proof.limitations += [
        "the real guest-mode driver, guardian and control helper run directly on this Linux host in private "
        "temporary state; no VM, guest daemon session, launch generation or host `cw stop` transport is used, "
        "so VM parity is not claimed",
        "synthetic peers stall the startup handshake and record only their process birth; no provider, "
        "authentication or protocol completion is exercised, and the startup task is never issued or completed",
        "network isolation is by construction (synthetic peers use no network and these cw paths make no "
        "connections); it is not enforced by a namespace",
        f"Claude must be cancelled inside the product's {CLAUDE_PROBE_SECONDS}s control-probe window; the driver "
        "log, not timing, proves the startup branch",
    ]
    print(json.dumps({
        "status": "passed" if passed else "failed",
        "harness": HARNESS,
        "cw": {"path": args.cw, "sha256": cw_sha256},
        "environment_id": proof.environment_id,
        "limits": {"overall_seconds": OVERALL_SECONDS, "helper_seconds": HELPER_SECONDS,
                   "ready_seconds": READY_SECONDS, "cancel_to_exit_seconds": EXIT_BOUND_SECONDS,
                   "birth_gone_seconds": GONE_SECONDS, "child_umask": f"{CHILD_UMASK:03o}",
                   "synthetic_peer_lifetime_seconds": OVERALL_SECONDS + CLEANUP_RESERVE_SECONDS},
        "checks": proof.checks,
        "missing": missing,
        "scenarios": proof.scenarios,
        "helper_calls": proof.helper_calls,
        "owned_processes": proof.owned,
        "limitations": proof.limitations,
        "cleanup_errors": [bounded(error) for error in cleanup_errors],
        "artifacts": artifacts,
        "failure": failure,
        "elapsed_seconds": round(time.monotonic() - proof.started, 1),
    }, indent=2))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
