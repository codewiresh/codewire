#!/usr/bin/env python3
"""Observe pinned cw A -> B -> A with retained Linux host conversations.

Both directories must contain a real built cw and its complete cw-runtime.json,
for a release target: `cw upgrade --from` admits only release targets. Build them
from this committed checkout with distinct versions, for example
`CODEWIRE_VERSION=0.1.0-journey.a scripts/dev/build-cw.py --target
x86_64-unknown-linux-musl --release-dir A`.
Both assets must contain this checkout's admitted compiler and mesh-path code.
This journey uses the existing synthetic agent peers and public CLI commands;
it never contacts a provider, replaces a user installation or restarts a daemon
or driver during selection. Use --mesh for the retained Mesh/DERP journey;
native VM qualification is separate.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import socket
import stat
import struct
import sys
import time


spec = importlib.util.spec_from_file_location(
    "cli_host_journey", Path(__file__).with_name("test-cli-host.py"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def release(directory, pin):
    directory = directory.resolve(strict=True)
    executable = directory / "cw"
    identity_path = directory / "cw-runtime.json"
    for path in (executable, identity_path):
        assert stat.S_ISREG(path.lstat().st_mode), f"not a regular release file: {path}"
    identity = json.loads(identity_path.read_text())
    assert len(pin) == 64 and all(c in "0123456789abcdef" for c in pin), "invalid SHA-256 pin"
    assert digest(executable) == pin == identity["sha256"], "release pin differs from bytes/identity"
    assert executable.stat().st_size == identity["size"], "release size differs from identity"
    assert identity["source_revision"] and identity["source_tree_sha256"], "source provenance missing"
    return directory, identity


def process_stat(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    assert fields[0] not in ("Z", "X"), f"process {pid} exited"
    return {"parent": int(fields[1]), "birth": int(fields[19])}


class Process:
    """A kernel handle plus birth and executable identity, never PID alone."""
    def __init__(self, pid):
        self.pid = pid
        self.fd = os.pidfd_open(pid)
        try:
            self.identity = self.observe()
            self.args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
            self.verify()
        except BaseException:
            self.close()
            raise

    def observe(self):
        assert not select.select([self.fd], [], [], 0)[0], f"process {self.pid} exited"
        before = process_stat(self.pid)
        executable = Path(f"/proc/{self.pid}/exe")
        metadata = executable.stat()
        result = {"pid": self.pid, **before, "executable": os.readlink(executable),
                  "device": metadata.st_dev, "inode": metadata.st_ino}
        assert process_stat(self.pid) == before, f"process {self.pid} changed during observation"
        return result

    def verify(self):
        assert self.observe() == self.identity, f"process {self.pid} was replaced or re-executed"

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def descendants(pid):
    result, pending = set(), [pid]
    while pending:
        parent = pending.pop()
        for task in Path(f"/proc/{parent}/task").iterdir():
            for value in (task / "children").read_text().split():
                child = int(value)
                if child not in result:
                    result.add(child)
                    pending.append(child)
    return result


class Journey(host.Journey):
    def __init__(self, a, b, mesh):
        self.mesh_arguments = []
        if mesh:
            # Match the retained-helper fixture: reserve both distinct loopback
            # endpoints together, then reuse them through selection and restart.
            with (
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mesh_listener,
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as derp_listener,
            ):
                mesh_listener.bind(("127.0.0.1", 0))
                derp_listener.bind(("127.0.0.1", 0))
                mesh_address = f"127.0.0.1:{mesh_listener.getsockname()[1]}"
                derp_address = f"127.0.0.1:{derp_listener.getsockname()[1]}"
            self.mesh_arguments = [
                "--base-url", f"http://{mesh_address}", "--listen", mesh_address,
                "--derp-url", f"http://{derp_address}", "--derp-listen", derp_address,
            ]
        super().__init__(a[0] / "cw", False)
        root_metadata = self.root.lstat()
        self.disposable_root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        # Synthetic peers must not inherit provider or other ambient secrets.
        self.env = {key: value for key, value in self.env.items() if key in (
            "HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "TERM", "TMPDIR",
            "CW_HOST_DATA_DIR", "CW_CONFIG_DIR")}
        self.env["CW_MESH_DATA_DIR"] = str(self.root / "mesh")
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + "/usr/bin:/bin"
        self.a, self.b = a, b
        self.store = self.root / "store"
        self.entry = self.root / "entry" / "cw"
        self.processes = []
        self.commands = []
        self.selections = []
        self.observations = []
        self.conversation_names = ["lead", "worker", "active"]
        self.mesh = mesh
        self.mesh_started = False
        self.mesh_processes = []
        self.mesh_original = None
        self.network_original = None

    def remove_files(self):
        # This hook runs after public rm and workspace-preservation checks.
        # Only a successful journey may make its immutable test store disposable.
        assert not self.mesh_started, "retained Mesh helpers have not been stopped"
        handles = [process.fd for process in [*self.processes, *self.mesh_processes]]
        assert all(handle is not None for handle in handles), "actor custody was closed before cleanup"
        ready, _, _ = select.select(handles, [], [], 0)
        assert set(ready) == set(handles), "owned actor cleanup is unknown; retain runtime evidence"
        assert self.store == self.root / "store", "store is outside the disposable journey"
        pins = {identity["sha256"] for _, identity in (self.a, self.b)}
        assert len(pins) == 2 and all(len(pin) == 64 and all(c in "0123456789abcdef" for c in pin)
                                     for pin in pins), "invalid disposable release identities"
        descriptors = []

        def directory(name, parent=None, mode=None):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
            descriptors.append(fd)
            metadata = os.fstat(fd)
            permissions = stat.S_IMODE(metadata.st_mode)
            assert metadata.st_uid == os.geteuid(), "unowned disposable directory"
            assert permissions == mode if mode is not None else (
                permissions & 0o700 == 0o700 and permissions & 0o7022 == 0), "unsafe disposable directory mode"
            return fd

        try:
            root = directory(self.root, mode=0o700)
            metadata = os.fstat(root)
            assert (metadata.st_dev, metadata.st_ino) == self.disposable_root_identity, "journey root replaced"
            store = directory("store", root)
            versions = directory("versions", store)
            assert set(os.listdir(versions)) == pins, "unknown release member; retain store evidence"
            members = [directory(pin, versions, 0o555) for pin in sorted(pins)]
            # Validate both members before changing either; never chmod a path or file.
            for member in members:
                os.fchmod(member, 0o700)
            current = self.root.lstat()
            assert (current.st_dev, current.st_ino) == self.disposable_root_identity, "journey root moved"
            super().remove_files()
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def call(self, *args, **kwargs):
        started = time.monotonic()
        result = super().call(*args, **kwargs)
        self.commands.append({"executable": self.cw, "args": list(args),
                              "exit": 0 if isinstance(result, (list, dict)) else result.returncode,
                              "seconds": round(time.monotonic() - started, 3)})
        return result

    def status(self):
        return self.call("upgrade", "status", "--json", data=True)

    def update(self, generation, **kwargs):
        return self.call("upgrade", "--from", str(self.b[0]), "--sha256", self.b[1]["sha256"],
                         "--expect-generation", str(generation), "--json", **kwargs)

    def selection(self, identity, generation, previous):
        current = self.status()
        assert current["consistent"] and current["pending"] is None, current
        assert current["current"] == identity["sha256"] and current["generation"] == generation, current
        assert current["previous"] == previous, current
        canonical = self.store / "versions" / identity["sha256"] / "cw"
        assert self.entry.resolve() == canonical and digest(canonical) == identity["sha256"]
        assert self.call("--version").stdout.strip().split() == ["cw", identity["package_version"]]
        self.selections.append(current)
        return current

    def refusals(self, generation):
        before = self.status()
        before_bytes = self.store_bytes()
        result = self.update(generation + 1, ok=False)
        assert "not the expected" in result.stderr, result.stderr
        assert self.status() == before, "stale request changed selection or membership"
        assert self.store_bytes() == before_bytes, "stale request changed store files"
        self.entry.parent.chmod(0o500)
        try:
            result = self.update(generation, ok=False)
            assert "not writable" in result.stderr, result.stderr
            assert self.status() == before, "readonly entry admitted a candidate"
            assert self.store_bytes() == before_bytes, "readonly refusal changed store files"
        finally:
            self.entry.parent.chmod(0o700)

        negative = self.root / "negative-release"
        negative.mkdir(mode=0o700)
        shutil.copyfile(self.b[0] / "cw", negative / "cw")
        shutil.copyfile(self.b[0] / "cw-runtime.json", negative / "cw-runtime.json")
        with (negative / "cw").open("r+b") as file:
            file.seek(-1, os.SEEK_END)
            byte = file.read(1)
            file.seek(-1, os.SEEK_END)
            file.write(bytes([byte[0] ^ 1]))
        result = self.call("upgrade", "--from", str(negative), "--sha256", self.b[1]["sha256"],
                           "--expect-generation", str(generation), ok=False)
        assert "digest differs from the pin" in result.stderr, result.stderr
        assert self.status() == before, "corrupt release changed the store"
        assert self.store_bytes() == before_bytes, "corrupt release left store changes"
        shutil.copyfile(self.b[0] / "cw", negative / "cw")
        incompatible = dict(self.b[1], protocol_version=self.b[1]["protocol_version"] + 1)
        (negative / "cw-runtime.json").write_text(json.dumps(incompatible))
        result = self.call("upgrade", "--from", str(negative), "--sha256", self.b[1]["sha256"],
                           "--expect-generation", str(generation), ok=False)
        assert "unsupported cw identity: protocol_version" in result.stderr, result.stderr
        assert self.status() == before, "unsupported release changed the store"
        assert self.store_bytes() == before_bytes, "unsupported release left store changes"

        unmanaged = self.root / "unmanaged"
        unmanaged.mkdir(mode=0o700)
        shutil.copyfile(self.a[0] / "cw", unmanaged / "cw")
        unmanaged_identity = digest(unmanaged / "cw"), (unmanaged / "cw").stat().st_ino
        result = self.call("install", "--managed", "--bin-dir", str(unmanaged),
                           "--store", str(self.root / "unmanaged-store"), ok=False)
        assert "unmanaged" in result.stderr, result.stderr
        assert (digest(unmanaged / "cw"), (unmanaged / "cw").stat().st_ino) == unmanaged_identity
        self.check("stale/readonly/corrupt/unsupported/unmanaged-refusals")

    def store_bytes(self):
        result = {"entry": os.readlink(self.entry)}
        for path in sorted(self.store.rglob("*")):
            metadata = path.lstat()
            value = [metadata.st_ino, metadata.st_mode]
            if stat.S_ISREG(metadata.st_mode):
                value.extend([metadata.st_size, digest(path)])
            elif stat.S_ISLNK(metadata.st_mode):
                value.append(os.readlink(path))
            result[str(path.relative_to(self.store))] = value
        return result

    def daemon(self):
        path = self.root / "hosts" / self.environment / "daemon.sock"
        before = path.stat()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(path))
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        after = path.stat()
        assert uid == os.geteuid() and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        return pid, (before.st_dev, before.st_ino)

    def retain_processes(self):
        pid, self.socket_identity = self.daemon()
        self.processes.append(Process(pid))
        for child in sorted(descendants(pid)):
            self.processes.append(Process(child))
        assert b"_host-daemon" in self.processes[0].args
        drivers = [p for p in self.processes if b"_agent-driver" in p.args]
        assert len(drivers) == 3, f"expected three original managed drivers, got {len(drivers)}"
        expected = str(self.store / "versions" / self.a[1]["sha256"] / "cw")
        for process in [self.processes[0], *drivers]:
            assert process.identity["executable"] == expected, process.identity

    def verify_processes(self):
        assert self.daemon() == (self.processes[0].pid, self.socket_identity), "host daemon replaced"
        for process in self.processes:
            process.verify()

    def stop_owned(self):
        self.call("stop", "--local", self.environment)
        self.wait_death(self.processes)
        if self.mesh_started:
            self.mesh_down()
        self.check("explicit-owned-stop/kernel-death-of-original-and-B-actors/unrelated-sentinel")

    def wait_death(self, processes):
        pending = {process.fd for process in processes}
        deadline = time.monotonic() + 10
        while pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "owned actor cleanup is unknown; retain runtime evidence"
            ready, _, _ = select.select(list(pending), [], [], remaining)
            pending.difference_update(ready)

    def mesh_up(self, identity):
        report = self.call("mesh", "up", *self.mesh_arguments, "--output", "json", data=True)
        assert report["started"], report
        self.mesh_started = True
        runtime = json.loads((self.root / "mesh" / "mesh_runtime.json").read_text())
        expected = str(self.store / "versions" / identity["sha256"] / "cw")
        for record, role in ((runtime, "embedded_mesh"), (runtime["derp"], "embedded_derp")):
            process = Process(record["pid"])
            self.mesh_processes.append(process)
            custody = record["custody"]
            assert custody["schema_version"] == 1 and custody["role"] == role
            assert custody["pid"] == process.pid and custody["uid"] == os.geteuid()
            assert custody["start_ticks"] == process.identity["birth"]
            assert custody["executable"]["path"] == process.identity["executable"] == expected
            assert custody["executable"]["sha256"] == identity["sha256"]
        return runtime

    def mesh_down(self):
        self.call("mesh", "down", "--output", "json", data=True)
        self.wait_death(self.mesh_processes)
        self.mesh_started = False
        assert not (self.root / "mesh" / "mesh_runtime.json").exists()

    def verify_mesh(self):
        if not self.mesh:
            return
        report = self.call("mesh", "up", *self.mesh_arguments, "--output", "json", data=True)
        assert not report["started"], "selection restarted a retained helper"
        runtime = json.loads((self.root / "mesh" / "mesh_runtime.json").read_text())
        assert runtime == self.mesh_original, "selection changed helper custody/configuration"
        for process in self.mesh_processes:
            process.verify()
        status = self.call("mesh", "status", "--output", "json", data=True)
        assert status["local"]["pid"] == runtime["pid"]
        assert status["local"]["derp"]["pid"] == runtime["derp"]["pid"]
        assert self.network_state() == self.network_original, "network catalog/selection changed"

    def network_state(self):
        # Only public organization identity is used from this synthetic owner
        # projection. Never inspect config.toml or helper TLS/key material.
        owner = json.loads((self.root / "mesh" / "mesh_owner.json").read_text())
        catalog = self.call("network", "list", "--org", owner["organization_id"],
                            "--output", "json", data=True)
        assert any(network["id"] == "update-proof" for network in catalog), "owned network disappeared"
        return {"catalog": catalog, "current": self.call("network", "current").stdout,
                "nodes": self.call("network", "nodes", "--org", owner["organization_id"],
                                   "--output", "json", data=True)}

    def conversations(self):
        result = {}
        for name in self.conversation_names:
            inbox = self.inbox(name)
            driver = inbox["driver"]
            assert driver, inbox
            trace = self.workspace / ("peer-" + driver["native_thread_id"] + ".jsonl")
            result[name] = {"session": inbox["session_id"],
                            "driver": {key: driver[key] for key in (
                                "driver_id", "native_thread_id", "started_at", "phase", "current_turn_id",
                                "active_message_id", "native_thread_established")},
                            "messages": inbox["messages"], "trace": trace.read_text()}
        return result

    def run(self):
        installed = self.call("install", "--managed", "--bin-dir", str(self.entry.parent),
                              "--store", str(self.store), "--json", data=True)
        assert installed["identity"] == self.a[1], "self-install did not report the compiled complete identity"
        self.cw = str(self.entry)  # Follow selection on every public invocation.
        generation = installed["generation"]
        self.selection(self.a[1], generation, None)
        self.refusals(generation)
        if self.mesh:
            self.mesh_original = self.mesh_up(self.a[1])
            owner = json.loads((self.root / "mesh" / "mesh_owner.json").read_text())
            self.call("network", "create", "update-proof", "--org", owner["organization_id"])
            self.network_original = self.network_state()
            assert "update-proof" in self.network_original["current"]
            self.verify_mesh()

        created = self.call("create", "--local", "--type", "host", "--name", "update-proof",
                            "--path", str(self.workspace), "--output", "json", data=True)
        self.environment = created["id"]
        self.launch("terminal", ["sh", "-c", 'echo $$ > "$1"; echo TERMINAL_READY; '
                    'while IFS= read -r line; do printf "TERMINAL:%s\\n" "$line"; '
                    '[ "$line" = finish ] && break; done', "sh", str(self.workspace / "child.pid")])
        self.until(lambda: self.call("logs", self.environment, "--session", "terminal").stdout,
                   lambda value: value == "TERMINAL_READY\n")
        marker = self.workspace / "retained-workspace.txt"
        marker.write_text("workspace belongs to this journey\n")
        lead = self.launch("lead", agent="codex", prompt="FIRST")
        assert self.wait_message(lead["message"]["id"])["state"] == "completed"
        self.until(lambda: self.inbox("lead"), lambda value: value["driver"] and value["driver"]["phase"] == "idle")
        worker = self.launch("worker", agent="claude", parent="lead", prompt="WORKER")
        assert self.wait_message(worker["message"]["id"])["state"] == "completed"
        self.until(lambda: self.inbox("lead"), lambda value: any(
            m["action"] == "notification" and m["state"] == "completed" for m in value["messages"]))
        active = self.launch("active", agent="codex", prompt="HOLD")
        self.until(lambda: self.inbox("active"), lambda value: value["driver"] and
                   value["driver"]["phase"] == "busy" and value["driver"]["current_turn_id"] is not None)
        original = self.conversations()
        self.observations.append({"default": "A", "conversations": original})
        self.retain_processes()
        self.check("actual-A-install/active-idle-completed-conversations/kernel-process-handles")

        selected = self.update(generation, data=True)
        assert selected["changed"] and selected["sha256"] == self.b[1]["sha256"]
        self.selection(self.b[1], generation + 1, self.a[1]["sha256"])
        self.verify_processes()
        self.verify_mesh()
        unchanged = self.conversations()
        assert unchanged == original, "update changed a conversation or replayed a turn"
        self.observations.append({"default": "B", "conversations": unchanged})
        assert marker.read_text() == "workspace belongs to this journey\n"
        self.call("send", self.environment, "--session", "terminal", "from-B")
        self.until(lambda: self.call("logs", self.environment, "--session", "terminal").stdout,
                   lambda value: value == "TERMINAL_READY\nTERMINAL:from-B\n")
        message = self.call("msg", self.environment, "lead", "FROM_B", "--output", "json", data=True)
        assert self.wait_message(message["id"])["result"] == "RESULT:FROM_B"
        self.until(lambda: self.inbox("lead"), lambda value: value["driver"]["phase"] == "idle")
        self.call("steer", self.environment, "active", "finish", "--turn-id", "wrong-turn", ok=False)
        fresh = self.launch("selected-B", agent="codex", prompt="NEW_B")
        assert fresh["session"]["command"][0] == str(self.entry.resolve()), fresh
        assert self.wait_message(fresh["message"]["id"])["state"] == "completed"
        self.until(lambda: self.inbox("selected-B"), lambda value: value["driver"]["phase"] == "idle")
        self.conversation_names.append("selected-B")
        for pid in descendants(self.processes[0].pid):
            process = Process(pid)
            if fresh["driver_id"].encode() in process.args:
                assert process.identity["executable"] == str(self.entry.resolve())
                self.processes.append(process)
                for child in sorted(descendants(pid)):
                    self.processes.append(Process(child))
                break
            process.close()
        else:
            raise AssertionError("selected B did not launch its own retained driver")
        at_b = self.conversations()
        self.observations.append({"default": "B-after-new-work", "conversations": at_b})
        self.check("B-default/original-processes/no-replay/terminal-message/new-B-driver")

        rolled = self.call("upgrade", "rollback", "--expect-generation", str(generation + 1), "--json", data=True)
        assert rolled["changed"] and rolled["sha256"] == self.a[1]["sha256"]
        self.selection(self.a[1], generation + 2, self.b[1]["sha256"])
        self.verify_processes()
        self.verify_mesh()
        unchanged = self.conversations()
        assert unchanged == at_b, "rollback changed a conversation or replayed a turn"
        self.observations.append({"default": "A-after-rollback", "conversations": unchanged})
        assert marker.read_text() == "workspace belongs to this journey\n"
        for identity in (self.a[1], self.b[1]):
            assert digest(self.store / "versions" / identity["sha256"] / "cw") == identity["sha256"]
        self.call("send", self.environment, "--session", "terminal", "from-A")
        self.until(lambda: self.call("logs", self.environment, "--session", "terminal").stdout,
                   lambda value: value == "TERMINAL_READY\nTERMINAL:from-B\nTERMINAL:from-A\n")
        steered = self.call("steer", self.environment, "active", "finish", "--output", "json", data=True)
        assert self.wait_message(steered["id"])["state"] == "completed"
        assert self.wait_message(active["message"]["id"])["result"] == "STEERED"
        notifications = [m for m in self.inbox("lead")["messages"] if m["action"] == "notification"]
        assert len(notifications) == 1, "completed worker emitted a duplicate parent notification"
        self.verify_processes()
        self.check("rollback/original-A-and-B-drivers/workspace-history/held-turn-steer/parent-once")
        if self.mesh:
            self.mesh_down()
            self.update(generation + 2, data=True)
            self.selection(self.b[1], generation + 3, self.a[1]["sha256"])
            fresh = self.mesh_up(self.b[1])
            assert fresh["custody"]["launch_nonce"] != self.mesh_original["custody"]["launch_nonce"]
            self.mesh_down()
            self.call("upgrade", "rollback", "--expect-generation", str(generation + 3), "--json", data=True)
            self.selection(self.a[1], generation + 4, self.b[1]["sha256"])
            self.verify_processes()
            self.check("retained-Mesh-DERP/A-B-A/no-PATH-helpers/explicit-stop/new-selected-B-roles")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("a", "b"):
        parser.add_argument(f"--release-{label}", type=Path, required=True)
        parser.add_argument(f"--sha256-{label}", required=True)
    parser.add_argument("--proof", type=Path, required=True, help="new proof file; never overwrite an existing receipt")
    parser.add_argument("--mesh", action="store_true", help="also require retained Mesh/DERP and new-selected-version roles")
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"):
        parser.error("the retained process journey requires Linux pidfd support")
    a, b = release(args.release_a, args.sha256_a), release(args.release_b, args.sha256_b)
    assert a[1]["sha256"] != b[1]["sha256"], "A and B must have different executable bytes"
    assert not args.proof.exists(), "proof file already exists"
    # Bind execution to the source containing the checked path override and
    # retained protocols. This is the shared producer's dependency digest;
    # a different admitted build/version may still use identical source.
    source_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(source_root / "scripts/ci/release"))
    import cw_release
    source = cw_release.source_tree_sha256(source_root)
    for directory, identity in (a, b):
        executable = cw_release.read_regular(directory / "cw", cw_release.MAX_EXECUTABLE)
        admitted = cw_release.make_identity(
            executable, identity["target"], identity["package_version"],
            identity["source_revision"], source, identity["rustc"])
        assert admitted == identity, "executable build record differs from its complete source identity"
        cw_release.toolchain_rustc(source_root, identity["rustc"])
    host.arm_owned_family()
    journey = Journey(a, b, args.mesh)
    passed = False
    try:
        journey.run()
        journey.stop_owned()
        passed = True
    finally:
        try:
            if not passed and journey.mesh_started:
                try:
                    journey.mesh_down()
                except Exception as error:
                    print(f"cli-update: helper cleanup unknown; evidence retained: {journey.root}: {error}",
                          file=sys.stderr)
            if not passed and not journey.environment:
                print(f"cli-update: pre-environment evidence retained: {journey.root}", file=sys.stderr)
                journey.sentinel.terminate()
                journey.sentinel.wait(timeout=5)
                host.reap_owned_family()
            else:
                journey.cleanup(preserve=not passed)
        finally:
            for process in [*journey.processes, *journey.mesh_processes]:
                process.close()
    proof = {"status": "passed", "placement": "host", "provider_peers": "synthetic",
             "identities": {"a": a[1], "b": b[1]}, "checks": journey.checks,
             "selections": journey.selections, "processes": [p.identity for p in journey.processes],
             "observations": journey.observations,
             "mesh_checked": args.mesh, "original_mesh_runtime": journey.mesh_original,
             "network_catalog": journey.network_original,
             "helper_processes": [p.identity for p in journey.mesh_processes],
             "retained_actors_exited": True,
             "commands": journey.commands}
    with os.fdopen(os.open(args.proof, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(proof, file, indent=2)
        file.write("\n")
    print(json.dumps({"status": "passed", "checks": journey.checks, "proof": str(args.proof)}))


if __name__ == "__main__":
    main()
