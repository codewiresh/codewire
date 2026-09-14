#!/usr/bin/env python3
"""Strict production-workload/service-VM developer fixture, not CLI parity.

Only the Linux service parses network packets. The Rust verifier authenticates
the actual production progress/daemon/session protocols. This parent joins the
independent evidence and owns the native helper and verifier lifetimes.
"""

from __future__ import annotations

import importlib.util
import array
import fcntl
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import struct
import sys
import time
import uuid


def load_sibling(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


product = load_sibling("workload_network_product", "macos-vz-product-network.py")
common = product.common
production = load_sibling("workload_network_production", "macos-vz-production-boot.py")
FixtureFailure = common.FixtureFailure
SCHEMA = 4
FIXTURE = "macos-vz-workload-network"
SERVICE = common.ROLE_SERVICE
EXPECTED_WAITS = (9472, 0, 18432, 0)
NATIVE_MARKERS = frozenset({
    "workload-network-admitted", "workload-network-started", "packet-attached",
    "progress-connected", "daemon-connected", "progress-closed",
})
SERVICE_STATUSES = (
    *product.PREPARATION, common.STATUS_WORKER_READY, product.STATUS_ENDPOINT_COMPLETED,
    common.STATUS_EOF_ARMED, common.STATUS_NO_EOF_OBSERVED,
    common.STATUS_CHILDREN_REAPED, common.STATUS_CANCELLED,
)


class ServiceCodec(common.RoleFrameCodec):
    """Reuse the existing codec, not its synthetic two-guest state machine."""

    status_magic = product.ProductNetworkCoordinator.status_magic
    control_magic = product.ProductNetworkCoordinator.control_magic
    status_domain = product.ProductNetworkCoordinator.status_domain
    control_domain = product.ProductNetworkCoordinator.control_domain
    wait_keys = product.ProductNetworkCoordinator.wait_keys

    def __init__(self, vm_id: uuid.UUID, generation: int, nonce: bytes, key: bytes):
        if (vm_id.int == 0 or type(generation) is not int or not 0 < generation < 2**64
                or len(nonce) != 32 or not any(nonce) or len(key) != 32 or not any(key)):
            raise FixtureFailure()
        self.vm_id = vm_id
        self.generation = generation
        self.nonce = nonce
        self.keys = {SERVICE: key}
        self.status_sequence = {SERVICE: 1}
        self.control_sequence = {SERVICE: 1}


class Coordinator:
    """Join real independent facts; writes become facts only after completion."""

    def __init__(self, codec: ServiceCodec):
        self.codec = codec
        self.native: set[str] = set()
        self.service: list[int] = []
        self.verifier: set[int] = set()
        self.sent: set[str] = set()
        self.vm_stops: set[int] = set()
        self.vm_events: list[list[int]] = []
        self.waits: tuple[int, ...] | None = None
        self.native_buffer = bytearray()
        self.native_records = 0
        self.helper_reaped = False
        self.verifier_reaped = False
        self.write_failed = False

    def feed_native(self, data: bytes) -> None:
        self.native_buffer.extend(data)
        if len(self.native_buffer) > 8192:
            raise FixtureFailure()
        while len(self.native_buffer) >= 4:
            size = struct.unpack(">I", self.native_buffer[:4])[0]
            if not 0 < size <= 256:
                raise FixtureFailure()
            if len(self.native_buffer) < size + 4:
                return
            payload = bytes(self.native_buffer[4:size + 4])
            del self.native_buffer[:size + 4]
            self.native_records += 1
            if self.native_records > 64:
                raise FixtureFailure()
            self.native_record(payload)

    def native_record(self, payload: bytes) -> None:
        for marker in NATIVE_MARKERS:
            if payload == common.canonical({"result": marker, "schemaVersion": SCHEMA}):
                if marker in self.native:
                    raise FixtureFailure()
                if marker != "workload-network-admitted" and "boot" not in self.sent:
                    raise FixtureFailure()
                if marker == "workload-network-admitted" and self.native:
                    raise FixtureFailure()
                if marker == "packet-attached" and "attach" not in self.sent:
                    raise FixtureFailure()
                if marker == "progress-closed" and "progress-connected" not in self.native:
                    raise FixtureFailure()
                self.native.add(marker)
                return
        if "boot" not in self.sent:
            raise FixtureFailure()
        if len(payload) == 130 and payload[:2] == b"R\x02":
            _, code, *waits = self.codec.decode_status(SERVICE, payload[2:])
            self.service_status(code, tuple(waits))
        elif len(payload) == 3 and payload[0] == ord("V"):
            role, state = payload[1:]
            if role in common.ROLES and state in (0, 1, 2) and len(self.vm_events) < 4:
                # Preserve the closed lifecycle enum even when it rejects the
                # trial. A forced stop is evidence, never an actual stop.
                self.vm_events.append([role, state])
            if role not in common.ROLES or role in self.vm_stops or state != common.VM_STOPPED:
                raise FixtureFailure()
            if ("guest-poweroff" if role == 1 else "service-poweroff") not in self.sent:
                raise FixtureFailure()
            # Independent native/Rust streams may deliver actual VM stop before A.
            # Record it, but never complete without authenticated acceptance too.
            self.vm_stops.add(role)
        else:
            raise FixtureFailure()

    def service_status(self, code: int, waits: tuple[int | None, ...]) -> None:
        index = len(self.service)
        if index >= len(SERVICE_STATUSES) or code != SERVICE_STATUSES[index]:
            raise FixtureFailure()
        required = {
            common.STATUS_WORKER_READY: "attach",
            common.STATUS_EOF_ARMED: "observe",
            common.STATUS_NO_EOF_OBSERVED: "observe",
            common.STATUS_CHILDREN_REAPED: "cancel",
            common.STATUS_CANCELLED: "cancel",
        }.get(code)
        if required and required not in self.sent:
            raise FixtureFailure()
        if code == common.STATUS_CHILDREN_REAPED:
            if waits != EXPECTED_WAITS:
                raise FixtureFailure()
            self.waits = waits
        elif waits != (None,) * 4:
            raise FixtureFailure()
        self.service.append(code)

    def feed_verifier(self, data: bytes) -> None:
        # Validate a whole coalesced read before the caller advances side effects.
        for marker in data:
            if marker in self.verifier:
                raise FixtureFailure()
            if marker == ord("R"):
                valid = {"progress", "daemon", "service"}.issubset(self.sent)
            elif marker == ord("W"):
                valid = ord("R") in self.verifier and "endpoint" in self.sent
            elif marker == ord("A"):
                valid = (ord("W") in self.verifier
                         and {"guest-poweroff", "service-poweroff"}.issubset(self.sent))
            elif marker == ord("C"):
                valid = ord("A") in self.verifier and "finish" in self.sent
            else:
                valid = False
            if not valid:
                raise FixtureFailure()
            self.verifier.add(marker)

    def advance(self, send_native, send_verifier) -> None:
        if self.write_failed:
            raise FixtureFailure()

        def completed_write(sender, payload: bytes) -> None:
            try:
                sender(payload)
            except BaseException:
                # A partial stream write has unknown delivery, so no retry of
                # either stream is admitted. Retain earlier completed facts.
                self.write_failed = True
                raise

        def native_once(name: str, payload: bytes) -> None:
            completed_write(send_native, common.framed(payload))
            self.sent.add(name)

        def verifier_once(name: str, payload: bytes) -> None:
            completed_write(send_verifier, payload)
            self.sent.add(name)

        if "workload-network-admitted" in self.native and "boot" not in self.sent:
            native_once("boot", b"\x01")
        for marker, name, value in (
            ("progress-connected", "progress", b"P"),
            ("daemon-connected", "daemon", b"D"),
        ):
            if marker in self.native and name not in self.sent:
                verifier_once(name, value)
        if ("workload-network-started" in self.native
                and self.service == list(product.PREPARATION) and "attach" not in self.sent):
            frame = self.codec.control_frame(SERVICE, common.CONTROL_START)
            native_once("attach", b"A" + frame[1:])
        if ("packet-attached" in self.native and common.STATUS_WORKER_READY in self.service
                and "service" not in self.sent):
            verifier_once("service", b"S")
        if (product.STATUS_ENDPOINT_COMPLETED in self.service and "service" in self.sent
                and "endpoint" not in self.sent):
            verifier_once("endpoint", b"E")
        if ord("W") in self.verifier and "observe" not in self.sent:
            native_once("observe", self.codec.control_frame(SERVICE, common.CONTROL_OBSERVE_EOF))
        if common.STATUS_NO_EOF_OBSERVED in self.service and "cancel" not in self.sent:
            native_once("cancel", self.codec.control_frame(SERVICE, common.CONTROL_CANCEL))
        if (common.STATUS_CANCELLED in self.service and self.waits == EXPECTED_WAITS
                and ord("W") in self.verifier):
            # Both operations follow successful service cancellation. Preserve
            # partial-write failure as failure, never as both completed writes.
            if "guest-poweroff" not in self.sent:
                verifier_once("guest-poweroff", b"Q")
            if "service-poweroff" not in self.sent:
                native_once("service-poweroff", self.codec.control_frame(SERVICE, common.CONTROL_POWER_OFF))
        if (ord("A") in self.verifier and self.vm_stops == set(common.ROLES)
                and self.helper_reaped and "finish" not in self.sent):
            verifier_once("finish", b"F")

    def complete(self) -> bool:
        return (
            self.native == set(NATIVE_MARKERS)
            and self.service == list(SERVICE_STATUSES)
            and self.waits == EXPECTED_WAITS
            and self.verifier == set(b"RWAC")
            and self.vm_stops == set(common.ROLES)
            and self.helper_reaped and self.verifier_reaped
            and not self.native_buffer
            and {"guest-poweroff", "service-poweroff"}.issubset(self.sent)
            and not self.write_failed
        )

    def diagnostic_state(self) -> dict[str, object]:
        # Never include identities, nonces, keys, authenticated frames, guest
        # output or arbitrary exception strings in public/persisted diagnostics.
        return {
            "nativeFacts": sorted(self.native), "serviceStatuses": list(self.service),
            "verifierFacts": [chr(value) for value in sorted(self.verifier)],
            "completedWrites": sorted(self.sent), "actualVMStops": sorted(self.vm_stops),
            "observedVMEvents": list(self.vm_events),
            "serviceWaits": self.waits, "helperReaped": self.helper_reaped,
            "verifierReaped": self.verifier_reaped,
            "writeFailed": self.write_failed,
        }


class Run(production.Run):
    """Reuse exact child ownership without deleting this trial's evidence."""

    def __init__(self):
        super().__init__()
        self.quiescent = False
        self.coordinator: Coordinator | None = None
        self.helper_eof = False
        self.verifier_eof = False
        self.observation = "admission"
        self.proof_children = {}
        self.pre_cleanup_child_exit = {}

    def seed(self, paths: dict[str, Path], vm_id: str) -> Path:
        assert self.directory is not None
        seed = self.directory / "seed"
        key = self.directory / "network-key"
        setup_fd = self.open(paths["setup"], os.O_RDONLY)
        seed_fd = self.open(seed, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        key_fd = self.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        self.wait(self.spawn([
            str(paths["fixture"]), "seed", "--setup-fd", str(setup_fd),
            "--output-fd", str(seed_fd), "--network-key-fd", str(key_fd),
            "--vm-id", vm_id, "--generation", "1",
        ], (setup_fd, seed_fd, key_fd)))
        for descriptor in (key_fd, seed_fd, setup_fd):
            self.close_fd(descriptor)
        if key.stat().st_size != 32:
            raise FixtureFailure()
        return seed

    def cleanup(self) -> bool:
        # No synthesized VM-stop or protocol-success facts here. Killing an
        # owned native process on failure is cleanup, never a passing trial.
        diagnostics_ok = True
        try:
            self.retain_diagnostics()
        except Exception:
            diagnostics_ok = False
        finally:
            self.quiescent = self.stop_and_close()
        return self.quiescent and diagnostics_ok

    def retain_diagnostics(self) -> None:
        if not self.pre_cleanup_child_exit:
            self.pre_cleanup_child_exit = {
                role: process.poll() for role, process in self.proof_children.items()
            }
        # The inherited cleanup discards output to keep teardown bounded. Save
        # one already-available bounded chunk first, before TERM can erase the
        # helper's fixed rejection diagnostic. This is not a final-log/EOF claim.
        for process, (pipe, output) in list(self.logs.items()):
            available = min(4096, production.MAX_LOG_BYTES - self.log_bytes[process])
            if available <= 0:
                continue
            try:
                chunk = os.read(pipe, available)
                view = memoryview(chunk)
                while view:
                    count = os.write(output, view)
                    if count <= 0:
                        break
                    self.log_bytes[process] += count
                    view = view[count:]
            except OSError:
                # Diagnostic capture cannot skip owned teardown or create PASS.
                pass


def prepare(run: Run, args) -> tuple[dict, dict[str, Path], Coordinator]:
    root = common.private_artifact_root(args.artifact_root)
    config, paths = production.prepare(
        run, args, extra_initramfs=("service_initramfs",), artifact_root=root,
    )
    assert run.directory is not None
    descriptor = run.open(run.directory / "network-key", os.O_RDONLY)
    try:
        key = os.read(descriptor, 33)
    finally:
        run.close_fd(descriptor)
    if len(key) != 32 or not any(key):
        raise FixtureFailure()
    nonce, status_key = secrets.token_bytes(32), secrets.token_bytes(32)
    codec = ServiceCodec(uuid.UUID(config["vmID"]), 1, nonce, status_key)
    binding = product.PRODUCT_SPEC.binding_image(
        "service", config["vmID"], 1, nonce, key, status_key,
    )
    paths["service_binding"] = run.directory / "service-binding"
    common.write_private(paths["service_binding"], binding)
    config.update(
        schemaVersion=SCHEMA, runNonce=nonce.hex(),
        serviceInitialRamdisk={
            "size": paths["service_initramfs"].stat().st_size,
            "sha256": run.digest(paths["service_initramfs"]),
        },
        serviceBinding={"size": len(binding), "sha256": run.digest(paths["service_binding"])},
    )
    run.coordinator = Coordinator(codec)
    return config, paths, run.coordinator


def send_all(run: Run, stream: socket.socket, payload: bytes, *, remaining=None) -> None:
    """A bounded complete write or terminal exception; never partial success."""
    available = remaining or run.remaining
    stop = time.monotonic() + min(1.0, available())
    view = memoryview(payload)
    while view:
        seconds = min(available(), stop - time.monotonic())
        if seconds <= 0:
            raise FixtureFailure()
        _, writable, _ = select.select([], [stream], [], min(0.05, seconds))
        run.drain_logs()
        if not writable:
            continue
        try:
            count = stream.send(view)
        except BlockingIOError:
            continue
        if count <= 0:
            raise FixtureFailure()
        view = view[count:]
    # Completion after phase expiry is unknown delivery, not a transition that
    # may refresh an already-expired budget. The coordinator latches failure.
    available()
    if time.monotonic() > stop:
        raise FixtureFailure()


def send_request(run: Run, stream: socket.socket, config: dict, descriptors: list[int], *, remaining=None) -> None:
    request = common.framed(common.canonical(config))
    rights = array.array("i", descriptors)
    # An EAGAIN transferred nothing. After the first positive sendmsg, never
    # repeat SCM_RIGHTS, even when the frame itself was only partially written.
    available = remaining or run.remaining
    stop = time.monotonic() + min(1.0, available())
    while True:
        seconds = min(available(), stop - time.monotonic())
        if seconds <= 0:
            raise FixtureFailure()
        _, writable, _ = select.select([], [stream], [], min(0.05, seconds))
        if not writable:
            continue
        try:
            count = stream.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        except BlockingIOError:
            continue
        if count <= 0:
            raise FixtureFailure()
        send_all(run, stream, request[count:], remaining=available)
        return


def observe_processes(run: Run, state: Coordinator, helper, verifier) -> None:
    helper_status, verifier_status = helper.poll(), verifier.poll()
    if helper_status not in (None, 0) or verifier_status not in (None, 0):
        raise FixtureFailure()
    # Exit can precede delivery of already queued V/A/C bytes. Drain each
    # control stream to real EOF before judging a successful leader exit.
    if helper_status == 0 and run.helper_eof and helper not in run.logs:
        if (state.vm_stops != set(common.ROLES) or state.native_buffer
                or not production.group_absent(helper)):
            raise FixtureFailure()
        state.helper_reaped = True
    if verifier_status == 0 and run.verifier_eof and verifier not in run.logs:
        if ord("C") not in state.verifier or not production.group_absent(verifier):
            raise FixtureFailure()
        state.verifier_reaped = True


class PhaseBudget:
    """Phase bounds only tighten the inherited whole-run deadline."""

    def __init__(self, run: Run):
        self.run = run
        self.name = "descriptor-admission"
        self.run.phase = self.name
        self.stop = min(run.deadline, time.monotonic() + 15)

    def update(self, state: Coordinator) -> None:
        self.remaining()
        if state.vm_stops == set(common.ROLES) and ord("A") in state.verifier:
            name, seconds = "owned-reap", 5
        elif "guest-poweroff" in state.sent:
            name, seconds = "poweroff", 20
        elif ord("R") in state.verifier:
            name, seconds = "workload", 30
        elif "attach" in state.sent:
            name, seconds = "transport-readiness", 120
        elif "boot" in state.sent:
            name, seconds = "service-preparation", 120
        else:
            return
        if name != self.name:
            self.name = name
            self.stop = min(self.run.deadline, time.monotonic() + seconds)
        self.run.phase = self.name

    def remaining(self) -> float:
        remaining = min(self.run.remaining(), self.stop - time.monotonic())
        if remaining <= 0:
            raise FixtureFailure()
        return remaining


def boot(run: Run, config: dict, paths: dict[str, Path], state: Coordinator) -> None:
    run.phase = "boot"
    budget = PhaseBudget(run)
    native, native_child = run.pair()
    control, control_child = run.pair()
    channels = [run.pair() for _ in range(2)]  # progress, daemon; no network FD
    seed_fd = run.open(paths["seed"], os.O_RDONLY)
    verifier_fds = tuple(pair[0].fileno() for pair in channels) + (control_child.fileno(), seed_fd)
    argv = [str(paths["fixture"]), "verify"]
    for name, descriptor in zip(("progress", "daemon", "control", "seed"), verifier_fds):
        argv.extend([f"--{name}-fd", str(descriptor)])
    verifier = run.spawn(argv, verifier_fds)
    run.proof_children["verifier"] = verifier
    control_child.close()
    run.close_fd(seed_fd)
    for pair in channels:
        pair[0].close()
    helper = run.spawn([
        str(paths["helper"]), "workload-network-fixture", "--control-fd", str(native_child.fileno()),
    ], (native_child.fileno(),))
    run.proof_children["helper"] = helper
    native_child.close()
    file_fds = [
        run.open(paths[name], os.O_RDWR if name in {"state", "root"} else os.O_RDONLY)
        for name in ("kernel", "initramfs", "seed", "state", "root", "setup", "service_initramfs", "service_binding")
    ]
    native.setblocking(False)
    control.setblocking(False)
    send_request(run, native, config, file_fds + [pair[1].fileno() for pair in channels], remaining=budget.remaining)
    aliases_closed = False
    while True:
        run.observation = "drain-logs"
        run.drain_logs()
        active = ([native] if not run.helper_eof else []) + ([control] if not run.verifier_eof else [])
        run.observation = "wait-control"
        readable, _, _ = select.select(active, [], [], min(0.05, budget.remaining()))
        # Validate all streams returned by this select before any state-machine
        # side effect. A coalesced bad suffix cannot authorize a partial prefix.
        for stream in readable:
            run.observation = "native-read" if stream is native else "verifier-read"
            data = stream.recv(4096)
            if stream is native:
                if data:
                    run.observation = "native-record"
                    state.feed_native(data)
                else:
                    run.observation = "helper-control-eof"
                    if (state.native_buffer or state.vm_stops != set(common.ROLES)
                            or state.native != set(NATIVE_MARKERS)):
                        raise FixtureFailure()
                    run.helper_eof = True
            elif data:
                run.observation = "verifier-record"
                state.feed_verifier(data)
            else:
                run.observation = "verifier-control-eof"
                if ord("C") not in state.verifier:
                    raise FixtureFailure()
                run.verifier_eof = True
        run.observation = "child-status"
        observe_processes(run, state, helper, verifier)
        if "workload-network-admitted" in state.native and not aliases_closed:
            run.observation = "close-admitted-aliases"
            for descriptor in file_fds:
                run.close_fd(descriptor)
            for pair in channels:
                pair[1].close()
            aliases_closed = True
        run.observation = "phase-deadline"
        budget.remaining()
        run.observation = "advance"
        state.advance(
            lambda data: send_all(run, native, data, remaining=budget.remaining),
            lambda data: send_all(run, control, data, remaining=budget.remaining),
        )
        run.observation = "phase-update"
        budget.update(state)
        if state.complete() and run.helper_eof and run.verifier_eof:
            run.phase = "proof-complete"
            run.observation = "proof-complete"
            return


def result_document(run: Run, status: int) -> dict:
    state = run.coordinator
    passed = (status == 0 and state is not None and state.complete()
              and run.helper_eof and run.verifier_eof and run.quiescent)
    return {
        "schemaVersion": SCHEMA, "fixture": FIXTURE,
        "outcome": "pass" if passed else "unknown",
        "artifacts": "retained" if run.directory is not None else "not-created",
        "phase": run.phase, "ownedGroupsAbsent": run.quiescent,
        "lastObservationBoundary": run.observation,
        "preCleanupChildExit": dict(run.pre_cleanup_child_exit),
        "helperControlEOF": run.helper_eof, "verifierControlEOF": run.verifier_eof,
        "eofObservation": (
            "not-observed-within-bound"
            if state and common.STATUS_NO_EOF_OBSERVED in state.service else "unknown"
        ),
        "facts": state.diagnostic_state() if state else None,
        "confinement": False, "internetEgress": False, "providerDelivery": False, "parity": False,
    }


def parser():
    result = production.parser()
    result.description = __doc__
    result.add_argument("--service-initramfs", required=True)
    result.add_argument("--service-initramfs-sha256", required=True)
    result.add_argument("--artifact-root", required=True)
    return result


def persist_result(run: Run, document: dict) -> None:
    assert run.directory is not None
    target = run.directory / "result.json"
    if document["outcome"] != "pass":
        common.write_private(target, common.canonical(document) + b"\n")
        return
    # Canonical evidence remains unknown until the entire passing candidate is
    # written, fsynced and closed. A short write/close/fsync failure must never
    # expose PASS at result.json. Retain incomplete candidates for diagnosis.
    unknown = {**document, "outcome": "unknown"}
    common.write_private(target, common.canonical(unknown) + b"\n")
    candidate = run.directory / "result-candidate.json"
    common.write_private(candidate, common.canonical(document) + b"\n")
    # Atomic rename is the publication commit. There is deliberately no later
    # directory-fsync/cleanup operation that could retroactively call this a
    # failed commit. This proves atomic visibility, not power-loss durability.
    os.replace(candidate, target)


def main(argv: list[str] | None = None) -> int:
    run = Run()
    # Standalone signal ownership follows the existing production parent. No
    # embedding into a process with a pre-existing timer or blocked signals.
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        print(common.canonical(result_document(run, 1)).decode(), flush=True)
        return 1
    admission_mask = signal.pthread_sigmask(signal.SIG_BLOCK, production.OWNED_SIGNALS)
    if set(admission_mask).intersection(production.OWNED_SIGNALS):
        signal.pthread_sigmask(signal.SIG_SETMASK, admission_mask)
        print(common.canonical(result_document(run, 1)).decode(), flush=True)
        return 1
    prior_umask = os.umask(0o077)
    status = 1
    try:
        try:
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            for signum in production.OWNED_SIGNALS:
                signal.signal(signum, run.signal)
            signal.setitimer(signal.ITIMER_REAL, run.remaining())
            signal.pthread_sigmask(signal.SIG_SETMASK, admission_mask)
            args = parser().parse_args(argv)
            production.require_host()
            config, paths, state = prepare(run, args)
            boot(run, config, paths, state)
            status = 0
        except production.Interrupted as error:
            status = 128 + error.signum
        except (Exception, KeyboardInterrupt):
            status = 1
        finally:
            status = production.finalize(run, status, prior_umask)
    except production.FixtureFailure:
        status = production.finalize(run, 1, prior_umask)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, production.OWNED_SIGNALS)
    try:
        for signum in signal.sigpending().intersection(production.OWNED_SIGNALS):
            run.signal(signum, None)
        if run.cancelled:
            status = 128 + run.cancelled
        elif run.expired:
            status = status or 1
        run.committed = True
        document = result_document(run, status)
        if document["outcome"] != "pass":
            status = status or 1
        if run.directory is not None:
            try:
                persist_result(run, document)
            except Exception:
                status = status or 1
                document["outcome"] = "unknown"
        if document["outcome"] == "pass":
            # All owned children/channels are already quiescent and closed.
            # The committed file is authoritative; stdout is notification.
            # A broken viewer pipe or interpreter teardown must not turn a
            # committed PASS into a contradictory nonzero exit. This standalone
            # program deliberately has no postcommit cleanup or mask restore.
            descriptor = flags = None
            try:
                descriptor = sys.stdout.fileno()
                flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                os.write(descriptor, common.canonical(document) + b"\n")
            except (OSError, ValueError):
                pass
            finally:
                # Inherited stdout may share its open-file description with
                # the caller. Do not leave that caller's pipe/TTY nonblocking.
                if descriptor is not None and flags is not None:
                    try:
                        fcntl.fcntl(descriptor, fcntl.F_SETFL, flags)
                    except OSError:
                        pass
                os._exit(0)
        print(common.canonical(document).decode(), flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
