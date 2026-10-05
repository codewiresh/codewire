#!/usr/bin/env python3
"""Synthetic tests for the bounded macOS VZ console-pair parent."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid


SCRIPT = Path(__file__).with_name("macos-vz-console-pair.py")
SPEC = importlib.util.spec_from_file_location("macos_vz_console_pair", SCRIPT)
assert SPEC and SPEC.loader
fixture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixture
SPEC.loader.exec_module(fixture)


class FakeRun:
    def __init__(self) -> None:
        self.spec = fixture.CONSOLE_SPEC
        self.result = fixture.base_result()
        self.deadline = float("inf")
        self.phase = "test"
        self.force_stop_requested = False
        self.sent: list[bytes] = []
        self.persisted: list[tuple[str, dict[str, object]]] = []
        self.coordinator = None

    def send(self, value: bytes) -> None:
        self.sent.append(value)

    def persist(self, status: str) -> None:
        self.persisted.append((status, dict(self.result)))


def status_frame(
    role: int,
    code: int,
    sequence: int,
    vm_id: uuid.UUID,
    generation: int,
    nonce: bytes,
    key: bytes,
    *,
    worker: int = 0,
    adapter: int = 0,
) -> bytes:
    value = bytearray(fixture.ROLE_FRAME_BYTES)
    value[:8] = fixture.STATUS_MAGIC
    value[8] = role
    value[9] = code
    value[16:32] = vm_id.bytes
    value[32:40] = generation.to_bytes(8, "little")
    value[40:72] = nonce
    value[72:80] = sequence.to_bytes(8, "little")
    if code == fixture.STATUS_CHILDREN_REAPED:
        value[80:84] = worker.to_bytes(4, "little", signed=True)
        value[84:88] = adapter.to_bytes(4, "little", signed=True)
    value[96:] = hmac.new(
        key, fixture.STATUS_DOMAIN + value[:96], hashlib.sha256
    ).digest()
    return bytes(value)


class CoordinatorCase(unittest.TestCase):
    def setUp(self) -> None:
        self.run = FakeRun()
        self.vm_id = uuid.UUID("12345678-1234-4234-9234-123456789abc")
        self.generation = 17
        self.nonce = bytes(range(32))
        self.keys = {fixture.ROLE_GUEST: b"g" * 32, fixture.ROLE_SERVICE: b"s" * 32}
        self.coordinator = fixture.Coordinator(
            self.run, self.vm_id, self.generation, self.nonce, self.keys
        )

    def emit(
        self,
        role: int,
        code: int,
        sequence: int,
        *,
        worker: int = 0,
        adapter: int = 0,
    ) -> None:
        frame = status_frame(
            role,
            code,
            sequence,
            self.vm_id,
            self.generation,
            self.nonce,
            self.keys[role],
            worker=worker,
            adapter=adapter,
        )
        self.coordinator.feed(fixture.framed(b"R" + bytes([role]) + frame))

    def start(self) -> None:
        self.coordinator.started = True
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PORTS_READY, 1)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_PREPARED, 1)

    def through_packet(self) -> None:
        self.start()
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_GUEST_ARMED, 2)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_WORKER_READY, 2)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_HOST_READY, 3)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PACKET_COMPLETED, 4)

    def finish(self, eof_code: int = fixture.STATUS_NO_EOF_OBSERVED) -> None:
        self.through_packet()
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_EOF_ARMED, 3)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PACKET_CLOSED, 5)
        self.emit(fixture.ROLE_SERVICE, eof_code, 4)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_CANCELLED, 6)
        self.emit(
            fixture.ROLE_SERVICE,
            fixture.STATUS_CHILDREN_REAPED,
            5,
            worker=9472,
            adapter=0,
        )
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_CANCELLED, 6)

    def control_codes(self) -> list[tuple[int, int, int]]:
        result = []
        for value in self.run.sent:
            size = struct.unpack(">I", value[:4])[0]
            payload = value[4:]
            self.assertEqual(size, len(payload))
            self.assertEqual(len(payload), 2 + fixture.ROLE_FRAME_BYTES)
            result.append(
                (payload[1], payload[11], int.from_bytes(payload[74:82], "little"))
            )
        return result

    def test_complete_authenticated_flow_and_poweroff_order(self) -> None:
        self.finish()
        self.assertEqual(
            self.control_codes(),
            [
                (fixture.ROLE_GUEST, fixture.CONTROL_START, 1),
                (fixture.ROLE_SERVICE, fixture.CONTROL_START, 1),
                (fixture.ROLE_SERVICE, fixture.CONTROL_OBSERVE_EOF, 2),
                (fixture.ROLE_GUEST, fixture.CONTROL_CLOSE_PACKET, 2),
                (fixture.ROLE_GUEST, fixture.CONTROL_CANCEL, 3),
                (fixture.ROLE_SERVICE, fixture.CONTROL_CANCEL, 3),
                (fixture.ROLE_GUEST, fixture.CONTROL_POWER_OFF, 4),
                (fixture.ROLE_SERVICE, fixture.CONTROL_POWER_OFF, 4),
            ],
        )
        self.assertEqual(self.run.persisted[0][0], "packet-completed")
        self.assertTrue(self.run.persisted[0][1]["packetCompleted"])
        self.assertEqual(self.run.persisted[0][1]["eofObservation"], "unknown")
        self.coordinator.feed(
            fixture.framed(bytes([ord("V"), fixture.ROLE_GUEST, fixture.VM_STOPPED]))
        )
        self.coordinator.feed(
            fixture.framed(bytes([ord("V"), fixture.ROLE_SERVICE, fixture.VM_STOPPED]))
        )
        self.run.result["helperReaped"] = True
        self.assertTrue(self.coordinator.complete())
        self.assertTrue(fixture.result_is_pass(self.run.result))

    def test_actual_eof_is_a_separate_valid_subclaim(self) -> None:
        self.finish(fixture.STATUS_EOF_OBSERVED)
        self.assertTrue(self.run.result["packetCompleted"])
        self.assertEqual(self.run.result["eofObservation"], "observed")

    def test_diagnostics_retain_only_fixed_authenticated_observations(self) -> None:
        self.through_packet()
        with tempfile.TemporaryDirectory() as temporary:
            run = fixture.Run(Path(temporary))
            run.coordinator = self.coordinator
            run.persist("prepared")
            receipt = json.loads(run.receipt_path.read_bytes())
        self.assertEqual(receipt["observations"], {
            "nativeStarted": True,
            "authenticatedStatuses": {"guest": [1, 3, 4, 6], "service": [2, 5]},
            "guestStartWriteCompleted": True,
            "serviceStartWriteCompleted": True,
            "observeEOFWriteCompleted": True,
            "closePacketWriteCompleted": False,
            "cancelWritesCompleted": False,
            "powerOffWritesCompleted": [],
        })

    def test_packet_waits_for_both_independently_delivered_role_facts(self) -> None:
        self.start()
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_GUEST_ARMED, 2)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_HOST_READY, 3)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PACKET_COMPLETED, 4)
        self.assertFalse(self.run.result["packetCompleted"])
        self.assertEqual(self.run.persisted, [])
        self.assertFalse(self.coordinator.sent_eof_observe)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_WORKER_READY, 2)
        self.assertTrue(self.run.result["packetCompleted"])
        self.assertEqual(len(self.run.persisted), 1)
        self.assertTrue(self.coordinator.sent_eof_observe)

    def test_service_reap_precedes_cancelled_in_actual_guest_protocol(self) -> None:
        self.through_packet()
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_EOF_ARMED, 3)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PACKET_CLOSED, 5)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_NO_EOF_OBSERVED, 4)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_CHILDREN_REAPED, 5,
                  worker=9472, adapter=0)
        self.assertNotIn(fixture.ROLE_SERVICE, self.coordinator.sent_poweroff)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_CANCELLED, 6)
        self.assertIn(fixture.ROLE_SERVICE, self.coordinator.sent_poweroff)

    def test_partial_trailing_record_after_vm_stop_prevents_pass(self) -> None:
        self.finish()
        for role in fixture.ROLES:
            self.coordinator.feed(fixture.framed(bytes([ord("V"), role, fixture.VM_STOPPED])))
        self.run.control_eof = False
        self.run.control = mock.Mock()
        self.run.control.recv.side_effect = [b"\x00", b""]
        self.run.helper = mock.Mock(returncode=0)
        self.run.helper.poll.return_value = 0
        self.run.wait_readable = mock.Mock()
        with self.assertRaises(fixture.FixtureFailure):
            fixture.run_coordinator(self.run, self.coordinator)

    def test_eof_observation_is_armed_before_packet_close(self) -> None:
        self.through_packet()
        self.assertEqual(self.control_codes()[-1][1], fixture.CONTROL_OBSERVE_EOF)
        self.assertNotIn(fixture.CONTROL_CLOSE_PACKET, [code for _, code, _ in self.control_codes()])
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_EOF_ARMED, 3)
        self.assertEqual(self.control_codes()[-1][1], fixture.CONTROL_CLOSE_PACKET)

    def test_completed_proof_rechecks_absolute_deadline(self) -> None:
        self.finish()
        for role in fixture.ROLES:
            self.coordinator.feed(fixture.framed(bytes([ord("V"), role, fixture.VM_STOPPED])))
        self.run.control_eof = True
        self.run.helper = mock.Mock(returncode=0)
        self.run.helper.poll.return_value = 0
        self.run.remaining = mock.Mock(side_effect=fixture.FixtureFailure())
        with self.assertRaises(fixture.FixtureFailure):
            fixture.run_coordinator(self.run, self.coordinator)

    def test_packet_proof_survives_later_authenticated_failure(self) -> None:
        self.through_packet()
        self.assertTrue(self.run.result["packetCompleted"])
        self.assertEqual(len(self.run.persisted), 1)
        with self.assertRaises(fixture.FixtureFailure):
            self.emit(fixture.ROLE_SERVICE, fixture.STATUS_FAILED, 3)
        self.assertTrue(self.run.persisted[0][1]["packetCompleted"])

    def test_statuses_may_precede_native_started_but_not_start_controls(self) -> None:
        first = status_frame(
            fixture.ROLE_GUEST,
            fixture.STATUS_PORTS_READY,
            1,
            self.vm_id,
            self.generation,
            self.nonce,
            self.keys[fixture.ROLE_GUEST],
        )
        self.coordinator.feed(
            fixture.framed(b"R" + bytes([fixture.ROLE_GUEST]) + first),
            awaiting_started=True,
        )
        self.assertEqual(self.run.sent, [])
        started = fixture.framed(
            fixture.canonical(
                {"result": "console-pair-started", "schemaVersion": 3}
            )
        )
        second = status_frame(
            fixture.ROLE_SERVICE,
            fixture.STATUS_PREPARED,
            1,
            self.vm_id,
            self.generation,
            self.nonce,
            self.keys[fixture.ROLE_SERVICE],
        )
        self.coordinator.feed(
            started + fixture.framed(b"R" + bytes([fixture.ROLE_SERVICE]) + second),
            awaiting_started=True,
        )
        self.assertEqual(self.control_codes(), [(fixture.ROLE_GUEST, fixture.CONTROL_START, 1)])

    def test_fragmented_authenticated_record(self) -> None:
        frame = status_frame(
            fixture.ROLE_GUEST,
            fixture.STATUS_PORTS_READY,
            1,
            self.vm_id,
            self.generation,
            self.nonce,
            self.keys[fixture.ROLE_GUEST],
        )
        record = fixture.framed(b"R" + bytes([fixture.ROLE_GUEST]) + frame)
        for byte in record:
            self.coordinator.feed(bytes([byte]))
        self.assertEqual(self.coordinator.seen[fixture.ROLE_GUEST], [fixture.STATUS_PORTS_READY])

    def test_wrong_hmac_role_reserved_and_sequence_are_rejected(self) -> None:
        cases = []
        valid = bytearray(
            status_frame(
                fixture.ROLE_GUEST,
                fixture.STATUS_PORTS_READY,
                1,
                self.vm_id,
                self.generation,
                self.nonce,
                self.keys[fixture.ROLE_GUEST],
            )
        )
        bad_tag = bytearray(valid)
        bad_tag[-1] ^= 1
        cases.append((fixture.ROLE_GUEST, bytes(bad_tag)))
        cases.append((fixture.ROLE_SERVICE, bytes(valid)))
        bad_reserved = bytearray(valid)
        bad_reserved[10] = 1
        bad_reserved[96:] = hmac.new(
            self.keys[fixture.ROLE_GUEST],
            fixture.STATUS_DOMAIN + bad_reserved[:96],
            hashlib.sha256,
        ).digest()
        cases.append((fixture.ROLE_GUEST, bytes(bad_reserved)))
        wrong_sequence = status_frame(
            fixture.ROLE_GUEST,
            fixture.STATUS_PORTS_READY,
            2,
            self.vm_id,
            self.generation,
            self.nonce,
            self.keys[fixture.ROLE_GUEST],
        )
        cases.append((fixture.ROLE_GUEST, wrong_sequence))
        for role, frame in cases:
            with self.subTest(role=role, marker=frame[-1]):
                coordinator = fixture.Coordinator(
                    FakeRun(), self.vm_id, self.generation, self.nonce, self.keys
                )
                with self.assertRaises(fixture.FixtureFailure):
                    coordinator.feed(fixture.framed(b"R" + bytes([role]) + frame))

    def test_duplicate_and_out_of_order_statuses_are_rejected(self) -> None:
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PORTS_READY, 1)
        with self.assertRaises(fixture.FixtureFailure):
            self.emit(fixture.ROLE_GUEST, fixture.STATUS_PORTS_READY, 2)
        fresh = CoordinatorCase(methodName="runTest")
        fresh.setUp()
        with self.assertRaises(fixture.FixtureFailure):
            fresh.emit(fixture.ROLE_GUEST, fixture.STATUS_GUEST_ARMED, 1)

    def test_children_reaped_payload_is_service_only_and_authenticated(self) -> None:
        self.finish()
        self.assertEqual(self.run.result["workerWaitStatus"], 9472)
        self.assertEqual(self.run.result["adapterWaitStatus"], 0)
        bad = bytearray(
            status_frame(
                fixture.ROLE_GUEST,
                fixture.STATUS_CHILDREN_REAPED,
                1,
                self.vm_id,
                self.generation,
                self.nonce,
                self.keys[fixture.ROLE_GUEST],
                worker=9472,
            )
        )
        coordinator = fixture.Coordinator(
            FakeRun(), self.vm_id, self.generation, self.nonce, self.keys
        )
        with self.assertRaises(fixture.FixtureFailure):
            coordinator.feed(
                fixture.framed(b"R" + bytes([fixture.ROLE_GUEST]) + bad)
            )

    def test_forced_wait_status_cannot_pass(self) -> None:
        self.through_packet()
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_EOF_ARMED, 3)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_PACKET_CLOSED, 5)
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_EOF_OBSERVED, 4)
        self.emit(fixture.ROLE_GUEST, fixture.STATUS_CANCELLED, 6)
        self.emit(
            fixture.ROLE_SERVICE,
            fixture.STATUS_CHILDREN_REAPED,
            5,
            worker=9,
            adapter=9,
        )
        self.emit(fixture.ROLE_SERVICE, fixture.STATUS_CANCELLED, 6)
        self.run.result["guestVMTermination"] = "actual"
        self.run.result["serviceVMTermination"] = "actual"
        self.run.result["helperReaped"] = True
        self.assertFalse(fixture.result_is_pass(self.run.result))

    def test_vm_stop_never_fabricates_eof(self) -> None:
        self.finish()
        self.coordinator.feed(
            fixture.framed(bytes([ord("V"), fixture.ROLE_GUEST, fixture.VM_STOPPED]))
        )
        self.assertEqual(
            self.run.result["eofObservation"], "not-observed-within-bound"
        )

    def test_early_vm_failure_is_immediate(self) -> None:
        with self.assertRaises(fixture.FixtureFailure):
            self.coordinator.feed(
                fixture.framed(
                    bytes([ord("V"), fixture.ROLE_GUEST, fixture.VM_FAILED])
                ),
                awaiting_started=True,
            )
        self.assertEqual(self.run.result["guestVMTermination"], "failure")

    def test_force_stop_event_requires_parent_request(self) -> None:
        with self.assertRaises(fixture.FixtureFailure):
            self.coordinator.feed(
                fixture.framed(
                    bytes([ord("V"), fixture.ROLE_GUEST, fixture.VM_FORCE_STOPPED])
                )
            )

    def test_malformed_outer_record_and_trailing_frame_are_rejected(self) -> None:
        with self.assertRaises(fixture.FixtureFailure):
            self.coordinator.feed(struct.pack(">I", 1) + b"X")
        coordinator = fixture.Coordinator(
            FakeRun(), self.vm_id, self.generation, self.nonce, self.keys
        )
        started = fixture.framed(
            fixture.canonical({"result": "console-pair-started", "schemaVersion": 3})
        )
        with self.assertRaises(fixture.FixtureFailure):
            coordinator.feed(started + struct.pack(">I", 1) + b"x", awaiting_started=True)

    def test_outer_framing_exact_partial_and_coalesced(self) -> None:
        frame = status_frame(
            fixture.ROLE_GUEST,
            fixture.STATUS_PORTS_READY,
            1,
            self.vm_id,
            self.generation,
            self.nonce,
            self.keys[fixture.ROLE_GUEST],
        )
        status = fixture.framed(b"R" + bytes([fixture.ROLE_GUEST]) + frame)
        self.assertEqual(status[:4], struct.pack(">I", 130))
        self.assertEqual(len(status), 134)
        started = fixture.framed(
            fixture.canonical({"result": "console-pair-started", "schemaVersion": 3})
        )
        for part in (started[:2], started[2:] + status[:3], status[3:]):
            self.coordinator.feed(part, awaiting_started=True)
        self.assertTrue(self.coordinator.started)
        self.assertEqual(self.coordinator.seen[fixture.ROLE_GUEST], [fixture.STATUS_PORTS_READY])
        control = self.coordinator.control_frame(fixture.ROLE_GUEST, fixture.CONTROL_START)
        self.assertEqual(fixture.framed(control)[:4], struct.pack(">I", 130))
        self.assertEqual(control[:2], b"C\x01")
        role_frame = control[2:]
        self.assertEqual(role_frame[:8], fixture.CONTROL_MAGIC)
        self.assertEqual(role_frame[80:96], bytes(16))
        self.assertEqual(
            role_frame[96:],
            hmac.new(
                self.keys[fixture.ROLE_GUEST],
                fixture.CONTROL_DOMAIN + role_frame[:96],
                hashlib.sha256,
            ).digest(),
        )
        self.assertEqual(fixture.framed(b"Q"), b"\0\0\0\x01Q")
        self.assertEqual(fixture.framed(b"\x01"), b"\0\0\0\x01\x01")

    def test_oversize_outer_frame_is_rejected_before_allocation(self) -> None:
        with self.assertRaises(fixture.FixtureFailure):
            self.coordinator.feed(
                struct.pack(">I", fixture.artifact.MAX_FRAME_BYTES + 1)
            )


class BindingAndArtifactCase(unittest.TestCase):
    def test_start_effect_retains_coordinator_before_sender_raises(self) -> None:
        run = FakeRun()

        def effect_then_raise(value: bytes) -> None:
            run.sent.append(value)
            raise fixture.FixtureFailure()

        run.send = effect_then_raise
        with self.assertRaises(fixture.FixtureFailure):
            fixture.attach_and_start_coordinator(
                run,
                uuid.UUID("12345678-1234-4234-9234-123456789abc"),
                17,
                bytes(range(32)),
                {fixture.ROLE_GUEST: b"g" * 32, fixture.ROLE_SERVICE: b"s" * 32},
            )
        self.assertIsInstance(run.coordinator, fixture.Coordinator)
        self.assertEqual(run.sent, [fixture.framed(b"\x01")])

    def test_request_descriptors_close_even_when_socket_reset_fails(self) -> None:
        for operation in ("settimeout", "setblocking"):
            with self.subTest(operation=operation):
                descriptors = [os.open("/dev/null", os.O_RDONLY) for _ in range(4)]
                control = mock.Mock()
                getattr(control, operation).side_effect = OSError(
                    "synthetic reset failure"
                )
                with self.assertRaises(OSError):
                    fixture.close_request_descriptors(control, descriptors)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_later_admission_failure_closes_prior_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = fixture.Run(Path(temporary))
            admitted = mock.Mock()
            with mock.patch.object(fixture, "admit_input", side_effect=[admitted, fixture.FixtureFailure()]):
                with self.assertRaises(fixture.FixtureFailure):
                    fixture.prepare_and_run(mock.Mock(), run)
            admitted.close.assert_called_once_with()

    def test_binding_is_exact_canonical_zero_padded_and_role_bound(self) -> None:
        vm_id = "12345678-1234-4234-9234-123456789abc"
        nonce = bytes(range(32))
        guest = fixture.binding_image("guest", vm_id, 7, nonce, b"n" * 32, b"g" * 32)
        service = fixture.binding_image("service", vm_id, 7, nonce, b"n" * 32, b"s" * 32)
        self.assertEqual(len(guest), fixture.BINDING_BYTES)
        self.assertNotEqual(hashlib.sha256(guest).digest(), hashlib.sha256(service).digest())
        end = guest.index(0)
        document = json.loads(guest[:end])
        self.assertEqual(guest[:end], fixture.canonical(document))
        self.assertEqual(document["role"], "guest")
        self.assertEqual(guest[end:], bytes(fixture.BINDING_BYTES - end))

    def test_private_root_requires_absent_child_of_private_canonical_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            expected = parent / "evidence"
            self.assertEqual(fixture.private_artifact_root(str(expected)), expected)
            parent.chmod(0o755)
            with self.assertRaises(fixture.FixtureFailure):
                fixture.private_artifact_root(str(expected))

    def test_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "input"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(fixture.FixtureFailure):
                fixture.admit_input(str(fifo), "0" * 64, "kernel", executable=False)

    def test_path_replacement_during_fd_copy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            content = b"immutable source"
            source.write_bytes(content)
            source.chmod(0o600)
            admitted = fixture.admit_input(
                str(source), hashlib.sha256(content).hexdigest(), "kernel", executable=False
            )
            original_pread = os.pread
            changed = False

            def replacing_pread(descriptor: int, count: int, offset: int) -> bytes:
                nonlocal changed
                value = original_pread(descriptor, count, offset)
                if not changed:
                    changed = True
                    source.rename(root / "original")
                    source.write_bytes(content)
                    source.chmod(0o600)
                return value

            try:
                with mock.patch.object(fixture.os, "pread", side_effect=replacing_pread):
                    with self.assertRaises(fixture.FixtureFailure):
                        fixture.copy_admitted(admitted, destination, executable=False)
            finally:
                admitted.close()

    def test_source_mutation_after_admission_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.write_bytes(b"one")
            source.chmod(0o600)
            admitted = fixture.admit_input(
                str(source), hashlib.sha256(b"one").hexdigest(), "kernel", executable=False
            )
            try:
                with source.open("ab") as stream:
                    stream.write(b"two")
                with self.assertRaises(fixture.FixtureFailure):
                    admitted.revalidate()
            finally:
                admitted.close()

    def test_result_requires_exact_normal_cleanup(self) -> None:
        result = fixture.base_result()
        result.update(
            {
                "packetCompleted": True,
                "eofObservation": "observed",
                "cancellationRequested": True,
                "guestCancelled": True,
                "serviceCancelled": True,
                "serviceChildrenReaped": True,
                "workerWaitStatus": 9472,
                "adapterWaitStatus": 0,
                "guestVMTermination": "actual",
                "serviceVMTermination": "actual",
                "helperReaped": True,
            }
        )
        self.assertTrue(fixture.result_is_pass(result))
        for key, value in (
            ("eofObservation", "unknown"),
            ("workerWaitStatus", 9),
            ("adapterWaitStatus", 9),
            ("guestVMTermination", "owned-force-stop"),
            ("serviceVMTermination", "owned-force-stop"),
        ):
            changed = dict(result)
            changed[key] = value
            self.assertFalse(fixture.result_is_pass(changed), key)


class OwnedHelperCase(unittest.TestCase):
    def test_lowered_soft_limit_cannot_leak_an_inheritable_high_fd(self) -> None:
        # Limit changes and fd256 exist only in this fixed disposable process.
        program = r'''
import importlib.util, os, pathlib, resource, socket, sys, tempfile, time
spec = importlib.util.spec_from_file_location("console_pair_fd_limit", sys.argv[1])
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (512, hard))
fd = os.open("/dev/null", os.O_RDONLY)
os.dup2(fd, 256, inheritable=True)
os.close(fd)
resource.setrlimit(resource.RLIMIT_NOFILE, (128, hard))
child_code = """import errno, os
try:
    os.fstat(256)
except OSError as error:
    if error.errno != errno.EBADF:
        raise
    os.write(1, b'high-fd-closed\\n')
else:
    raise SystemExit(71)
"""
def exec_probe(_executable, _arguments, environment):
    os.execve(sys.executable, [sys.executable, "-c", child_code], environment)
fixture._exec_fixed_helper = exec_probe
with tempfile.TemporaryDirectory() as temporary:
    run = fixture.Run(pathlib.Path(temporary))
    parent, child = socket.socketpair()
    helper = None
    try:
        helper = run.spawn_helper(pathlib.Path(sys.executable), child.fileno())
        child.close()
        deadline = time.monotonic() + 5
        while helper.poll() is None and time.monotonic() < deadline:
            helper.drain()
            time.sleep(0.01)
        if helper.returncode != 0:
            raise SystemExit(72)
        helper.finish_log()
        if helper.log != b"high-fd-closed\n":
            raise SystemExit(73)
    finally:
        if helper is not None and not helper.reaped:
            helper.terminate(1)
        if helper is not None:
            helper.finish_log()
        parent.close()
        child.close()
'''
        result = subprocess.run(
            [sys.executable, "-c", program, str(SCRIPT)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_partial_source_duplication_closes_prior_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = fixture.Run(Path(temporary))
            parent, child = socket.socketpair()
            duplicated: list[int] = []
            original_fcntl = fixture.fcntl.fcntl

            def fail_second_duplicate(fd: int, operation: int, value: int) -> int:
                if duplicated:
                    raise OSError("synthetic second duplicate failure")
                result = original_fcntl(fd, operation, value)
                duplicated.append(result)
                return result

            try:
                with mock.patch.object(fixture.fcntl, "fcntl", side_effect=fail_second_duplicate):
                    with self.assertRaises(OSError):
                        run.spawn_helper(Path("/usr/bin/true"), child.fileno())
                self.assertEqual(len(duplicated), 1)
                with self.assertRaises(OSError):
                    os.fstat(duplicated[0])
                self.assertIsNone(run.helper)
            finally:
                for descriptor in duplicated:
                    fixture._close_quietly(descriptor)
                parent.close()
                child.close()

    def test_helper_bookkeeping_allocation_precedes_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = fixture.Run(Path(temporary))
            parent, child = socket.socketpair()
            try:
                # No real child is created in this allocation-failure case.
                with mock.patch.object(fixture, "OwnedHelper", side_effect=MemoryError), mock.patch.object(
                    fixture.os, "fork", return_value=4242
                ) as fork:
                    with self.assertRaises(MemoryError):
                        run.spawn_helper(Path("/usr/bin/true"), child.fileno())
                fork.assert_not_called()
                self.assertIsNone(run.helper)
            finally:
                parent.close()
                child.close()

    def test_nonblocking_pipe_setup_failure_precedes_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = fixture.Run(Path(temporary))
            parent, child = socket.socketpair()
            try:
                with mock.patch.object(fixture.os, "set_blocking", side_effect=OSError), mock.patch.object(
                    fixture.os, "fork", side_effect=AssertionError("fork before pipe is ready")
                ) as fork:
                    with self.assertRaises(OSError):
                        run.spawn_helper(Path("/usr/bin/true"), child.fileno())
                fork.assert_not_called()
                self.assertIsNone(run.helper)
            finally:
                parent.close()
                child.close()

    def spawn_pre_exec_blocked_helper(
        self, root: Path
    ) -> tuple[fixture.Run, fixture.OwnedHelper, socket.socket]:
        run = fixture.Run(root)
        parent, child = socket.socketpair()

        def blocked_exec(
            _executable: str, _arguments: list[str], _environment: dict[str, str]
        ) -> None:
            os.read(3, 1)
            os._exit(70)

        original_exec = fixture._exec_fixed_helper
        fixture._exec_fixed_helper = blocked_exec
        try:
            helper = run.spawn_helper(Path("/usr/bin/true"), child.fileno())
        finally:
            fixture._exec_fixed_helper = original_exec
            child.close()
        self.assertIsNone(helper.poll())
        return run, helper, parent

    def test_reaped_child_is_never_signalled(self) -> None:
        helper = fixture.OwnedHelper(4242, -1, -1)
        with mock.patch.object(fixture.os, "waitpid", return_value=(4242, 0)), mock.patch.object(
            fixture.os, "kill"
        ) as kill:
            self.assertTrue(helper.terminate(0.1))
        kill.assert_not_called()
        self.assertTrue(helper.reaped)

    def test_live_retained_child_is_signalled_before_reap(self) -> None:
        helper = fixture.OwnedHelper(4242, -1, -1)
        with mock.patch.object(
            fixture.os, "waitpid", side_effect=[(0, 0), (4242, signal.SIGTERM)]
        ), mock.patch.object(fixture.os, "kill") as kill:
            self.assertTrue(helper.terminate(0.1))
        kill.assert_called_once_with(4242, signal.SIGTERM)
        self.assertTrue(helper.reaped)

    def test_wait_error_makes_ownership_unknown_without_signal(self) -> None:
        helper = fixture.OwnedHelper(4242, -1, -1)
        with mock.patch.object(
            fixture.os, "waitpid", side_effect=ChildProcessError("synthetic ECHILD")
        ), mock.patch.object(fixture.os, "kill") as kill:
            with self.assertRaises(fixture.FixtureFailure):
                helper.terminate(0.1)
        kill.assert_not_called()
        self.assertTrue(helper.uncertain)

    def test_signal_error_makes_ownership_unknown_without_retry(self) -> None:
        helper = fixture.OwnedHelper(4242, -1, -1)
        with mock.patch.object(fixture.os, "waitpid", return_value=(0, 0)), mock.patch.object(
            fixture.os, "kill", side_effect=PermissionError("synthetic signal failure")
        ) as kill:
            with self.assertRaises(fixture.FixtureFailure):
                helper.terminate(0.1)
            with self.assertRaises(fixture.FixtureFailure):
                helper.terminate(0.1)
        kill.assert_called_once_with(4242, signal.SIGTERM)
        self.assertTrue(helper.uncertain)

    def test_cleanup_buffers_log_until_after_reap_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log_path = root / "helper.log"
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            output_read, output_write = os.pipe()
            os.write(output_write, b"bounded diagnostic")
            os.close(output_write)
            os.set_blocking(output_read, False)
            helper = fixture.OwnedHelper(4242, output_read, log_fd)
            run = fixture.Run(root)
            run.helper = helper
            run.control_eof = True
            with mock.patch.object(fixture.os, "waitpid", return_value=(4242, 0)):
                run.teardown(None)
            self.assertEqual(log_path.read_bytes(), b"")
            helper.finish_log()
            self.assertEqual(log_path.read_bytes(), b"bounded diagnostic")

    @unittest.skipUnless(hasattr(signal, "SIGCHLD"), "requires POSIX SIGCHLD")
    def test_spawn_normalizes_inherited_autoreap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            run = fixture.Run(root)
            parent, child = socket.socketpair()
            previous = signal.getsignal(signal.SIGCHLD)
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            helper = None
            try:
                helper = run.spawn_helper(Path("/usr/bin/true"), child.fileno())
                native_tmp = root / "native-tmp"
                self.assertEqual(stat.S_IMODE(native_tmp.stat().st_mode), 0o700)
                child.close()
                self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
                deadline = time.monotonic() + 5
                while helper.poll() is None and time.monotonic() < deadline:
                    helper.drain()
                    time.sleep(0.01)
                self.assertTrue(helper.reaped)
                self.assertEqual(helper.returncode, 0)
            finally:
                if helper is not None:
                    if not helper.reaped:
                        helper.terminate(1)
                    helper.finish_log()
                parent.close()
                child.close()
                signal.signal(signal.SIGCHLD, previous)

    def test_delayed_pre_exec_child_does_not_hide_real_parent_alarm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            previous_alarm = signal.getsignal(signal.SIGALRM)
            previous_child = signal.getsignal(signal.SIGCHLD)
            prior_timer = signal.getitimer(signal.ITIMER_REAL)
            run, helper, parent = self.spawn_pre_exec_blocked_helper(root)
            signal.signal(signal.SIGALRM, run.signal)
            try:
                with self.assertRaises(fixture.FixtureFailure):
                    signal.setitimer(signal.ITIMER_REAL, 0.05)
                    time.sleep(1)
            finally:
                signal.setitimer(signal.ITIMER_REAL, *prior_timer)
                self.assertTrue(helper.terminate(1))
                helper.finish_log()
                parent.close()
                signal.signal(signal.SIGALRM, previous_alarm)
                signal.signal(signal.SIGCHLD, previous_child)
            self.assertTrue(run.expired)
            self.assertTrue(helper.reaped)

    def test_delayed_pre_exec_child_preserves_cancel_and_exact_reap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            previous_term = signal.getsignal(signal.SIGTERM)
            previous_child = signal.getsignal(signal.SIGCHLD)
            run, helper, parent = self.spawn_pre_exec_blocked_helper(root)
            signal.signal(signal.SIGTERM, run.signal)
            try:
                os.kill(os.getpid(), signal.SIGTERM)
                with self.assertRaises(fixture.FixtureInterrupted):
                    run.remaining()
            finally:
                self.assertTrue(helper.terminate(1))
                helper.finish_log()
                parent.close()
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGCHLD, previous_child)
            self.assertEqual(run.cancelled, signal.SIGTERM)
            self.assertTrue(helper.reaped)


class MainFinalizationCase(unittest.TestCase):
    def arguments(self, root: Path) -> list[str]:
        return [
            "--helper",
            "/synthetic/helper",
            "--helper-sha256",
            "0" * 64,
            "--kernel",
            "/synthetic/kernel",
            "--kernel-sha256",
            "1" * 64,
            "--initramfs",
            "/synthetic/initramfs",
            "--initramfs-sha256",
            "2" * 64,
            "--artifact-root",
            str(root),
        ]

    def test_early_exception_tears_down_with_retained_coordinator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            root = parent / "evidence"
            coordinator = mock.Mock()
            coordinator.diagnostic_state.return_value = {"nativeStarted": False}
            observed: list[object] = []
            output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")

            def fail_after_attachment(_arguments: object, run: fixture.Run) -> None:
                run.coordinator = coordinator
                run.phase = "native-start"
                raise fixture.FixtureFailure()

            def teardown(run: fixture.Run, retained: object) -> None:
                observed.append(retained)
                run.control = None

            with mock.patch.object(fixture, "require_host"), mock.patch.object(
                fixture, "prepare_and_run", side_effect=fail_after_attachment
            ), mock.patch.object(fixture.Run, "teardown", teardown), mock.patch.object(
                fixture.sys, "stdout", output
            ):
                self.assertEqual(fixture.main(self.arguments(root)), 1)
            self.assertEqual(observed, [coordinator])
            receipt = json.loads((root / "receipt.json").read_bytes())
            self.assertEqual(receipt["result"]["outcome"], "unknown")
            self.assertEqual(receipt["failurePhase"], "native-start")
            self.assertEqual(receipt["phase"], "cleanup")
            self.assertEqual(receipt["observations"], {"nativeStarted": False})

    def test_pending_signal_prevents_success_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            root = parent / "evidence"
            output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")

            def succeed(_arguments: object, run: fixture.Run) -> None:
                run.result.update(
                    {
                        "outcome": "pass",
                        "packetCompleted": True,
                        "eofObservation": "observed",
                        "cancellationRequested": True,
                        "guestCancelled": True,
                        "serviceCancelled": True,
                        "serviceChildrenReaped": True,
                        "workerWaitStatus": 9472,
                        "adapterWaitStatus": 0,
                        "guestVMTermination": "actual",
                        "serviceVMTermination": "actual",
                        "helperReaped": True,
                    }
                )

            with mock.patch.object(fixture, "require_host"), mock.patch.object(
                fixture, "prepare_and_run", side_effect=succeed
            ), mock.patch.object(
                fixture.signal, "sigpending", return_value={signal.SIGTERM}
            ), mock.patch.object(fixture.sys, "stdout", output):
                self.assertEqual(
                    fixture.main(self.arguments(root)), 128 + signal.SIGTERM
                )
            public = json.loads(output.buffer.getvalue())
            receipt = json.loads((root / "receipt.json").read_bytes())
            self.assertEqual(public["outcome"], "unknown")
            self.assertEqual(receipt["result"]["outcome"], "unknown")


if __name__ == "__main__":
    unittest.main()
