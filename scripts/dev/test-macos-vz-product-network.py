#!/usr/bin/env python3
"""Synthetic strict-profile tests; never configure topology or start a VM."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import uuid


SPEC = importlib.util.spec_from_file_location(
    "macos_vz_product_network", Path(__file__).with_name("macos-vz-product-network.py")
)
assert SPEC and SPEC.loader
fixture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixture
SPEC.loader.exec_module(fixture)
common = fixture.common


class FakeRun:
    def __init__(self) -> None:
        self.spec = fixture.PRODUCT_SPEC
        self.result = self.spec.base_result()
        self.deadline = float("inf")
        self.phase = "test"
        self.force_stop_requested = False
        self.sent: list[bytes] = []
        self.persisted: list[tuple[str, dict[str, object]]] = []
        self.coordinator = None

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def persist(self, status: str) -> None:
        self.spec.validate_result(self.result)
        self.persisted.append((status, dict(self.result)))


class ProfileCase(unittest.TestCase):
    def setUp(self) -> None:
        self.run = FakeRun()
        self.vm_id = uuid.UUID("12345678-1234-4234-9234-123456789abc")
        self.generation = 17
        self.nonce = bytes(range(32))
        self.keys = {common.ROLE_GUEST: b"g" * 32, common.ROLE_SERVICE: b"s" * 32}
        self.coordinator = fixture.PRODUCT_SPEC.coordinator(
            self.run, self.vm_id, self.generation, self.nonce, self.keys
        )
        self.coordinator.started = True

    def frame(
        self, role: int, code: int, *, sequence: int | None = None,
        waits: tuple[int, ...] = (9472, 0, 18432, 0),
        profile: type = fixture.ProductNetworkCoordinator,
    ) -> bytes:
        value = bytearray(common.ROLE_FRAME_BYTES)
        value[:8] = profile.status_magic
        value[8:10] = bytes((role, code))
        value[16:32] = self.vm_id.bytes
        value[32:40] = self.generation.to_bytes(8, "little")
        value[40:72] = self.nonce
        value[72:80] = (
            sequence if sequence is not None else self.coordinator.status_sequence[role]
        ).to_bytes(8, "little")
        if code == common.STATUS_CHILDREN_REAPED:
            for index, wait in enumerate(waits):
                value[80 + index * 4:84 + index * 4] = wait.to_bytes(4, "little", signed=True)
        return self.authenticate(value, role, profile=profile)

    def authenticate(
        self, value: bytes, role: int,
        *, profile: type = fixture.ProductNetworkCoordinator,
    ) -> bytes:
        return value[:96] + hmac.new(
            self.keys[role], profile.status_domain + value[:96], hashlib.sha256
        ).digest()

    def emit(self, role: int, code: int, **options: object) -> None:
        self.coordinator.feed(common.framed(b"R" + bytes([role]) + self.frame(role, code, **options)))

    def start(self) -> None:
        self.emit(common.ROLE_GUEST, common.STATUS_PORTS_READY)
        for code in fixture.PREPARATION:
            self.emit(common.ROLE_SERVICE, code)
        self.emit(common.ROLE_GUEST, common.STATUS_GUEST_ARMED)

    def packet(self, *, endpoint_first: bool = True) -> None:
        self.start()
        self.emit(common.ROLE_SERVICE, common.STATUS_WORKER_READY)
        self.emit(common.ROLE_GUEST, common.STATUS_HOST_READY)
        if endpoint_first:
            self.emit(common.ROLE_SERVICE, fixture.STATUS_ENDPOINT_COMPLETED)
        self.emit(common.ROLE_GUEST, common.STATUS_PACKET_COMPLETED)
        if not endpoint_first:
            self.emit(common.ROLE_SERVICE, fixture.STATUS_ENDPOINT_COMPLETED)

    def cancellation(self, eof: int = common.STATUS_NO_EOF_OBSERVED) -> None:
        self.packet()
        self.emit(common.ROLE_SERVICE, common.STATUS_EOF_ARMED)
        self.emit(common.ROLE_GUEST, common.STATUS_PACKET_CLOSED)
        self.emit(common.ROLE_SERVICE, eof)

    def finish(self) -> None:
        self.cancellation()
        self.emit(common.ROLE_GUEST, common.STATUS_CANCELLED)
        self.emit(common.ROLE_SERVICE, common.STATUS_CHILDREN_REAPED)
        self.emit(common.ROLE_SERVICE, common.STATUS_CANCELLED)
        for role in common.ROLES:
            self.coordinator.feed(common.framed(bytes((ord("V"), role, common.VM_STOPPED))))
        self.run.result["helperReaped"] = True
        self.run.result["outcome"] = "pass"

    def controls(self) -> list[tuple[int, int]]:
        result = []
        for value in self.run.sent:
            self.assertEqual(struct.unpack(">I", value[:4])[0], len(value) - 4)
            self.assertEqual(value[4], ord("C"))
            role, frame = value[5], value[6:]
            self.assertEqual(frame[:8], self.coordinator.control_magic)
            self.assertEqual(frame[96:], hmac.new(
                self.keys[role], self.coordinator.control_domain + frame[:96], hashlib.sha256
            ).digest())
            self.assertNotEqual(frame[96:], hmac.new(
                self.keys[role], common.CONTROL_DOMAIN + frame[:96], hashlib.sha256
            ).digest())
            result.append((role, frame[9]))
        return result

    def test_complete_four_child_flow_and_domain_separated_controls(self) -> None:
        self.finish()
        self.assertTrue(self.coordinator.complete())
        fixture.PRODUCT_SPEC.validate_result(self.run.result)
        self.assertTrue(fixture.PRODUCT_SPEC.result_is_pass(self.run.result))
        self.assertEqual(self.controls(), [(1, 1), (2, 1), (2, 4), (1, 3),
                                           (1, 2), (2, 2), (1, 5), (2, 5)])
        self.assertEqual(len(self.run.persisted), 1)
        checkpoint = self.run.persisted[0]
        self.assertEqual(checkpoint[0], "packet-completed")
        self.assertTrue(all(checkpoint[1][key] for key in fixture.FACT_KEYS.values()))
        self.assertEqual(checkpoint[1]["eofObservation"], "unknown")

    def test_endpoint_and_guest_completion_can_arrive_in_either_order(self) -> None:
        for endpoint_first in (True, False):
            with self.subTest(endpoint_first=endpoint_first):
                self.setUp()
                self.packet(endpoint_first=endpoint_first)
                self.assertTrue(self.run.result["packetCompleted"])
                self.assertEqual(len(self.run.persisted), 1)
                self.assertTrue(self.coordinator.sent_eof_observe)

    def test_packet_checkpoint_waits_for_completed_endpoint(self) -> None:
        self.start()
        self.emit(2, common.STATUS_WORKER_READY)
        self.emit(1, common.STATUS_HOST_READY)
        self.emit(1, common.STATUS_PACKET_COMPLETED)
        self.assertFalse(self.run.result["packetCompleted"])
        self.assertFalse(self.coordinator.sent_eof_observe)
        self.assertEqual(self.run.persisted, [])
        self.emit(2, fixture.STATUS_ENDPOINT_COMPLETED)
        self.assertTrue(self.run.result["packetCompleted"])

    def test_start_waits_for_every_preparation_fact(self) -> None:
        self.emit(1, common.STATUS_PORTS_READY)
        for code in fixture.PREPARATION[:-1]:
            self.emit(2, code)
            self.assertEqual(self.run.sent, [])
        self.emit(2, fixture.PREPARATION[-1])
        self.assertEqual(self.controls(), [(1, 1)])

    def test_missing_or_reordered_preparation_rejected(self) -> None:
        for index in range(len(fixture.PREPARATION)):
            with self.subTest(index=index):
                self.setUp()
                for code in fixture.PREPARATION[:index]:
                    self.emit(2, code)
                wrong = (list(fixture.PREPARATION) + [common.STATUS_WORKER_READY])[index + 1]
                with self.assertRaises(common.FixtureFailure):
                    self.emit(2, wrong)
                self.assertEqual(self.run.sent, [])

    def test_premature_armed_does_not_become_observation(self) -> None:
        self.emit(1, common.STATUS_PORTS_READY)
        with self.assertRaises(common.FixtureFailure):
            self.emit(1, common.STATUS_GUEST_ARMED)
        self.assertEqual(self.coordinator.seen[1], [common.STATUS_PORTS_READY])

    def test_endpoint_completed_before_worker_ready_rejected(self) -> None:
        self.start()
        with self.assertRaises(common.FixtureFailure):
            self.emit(2, fixture.STATUS_ENDPOINT_COMPLETED)
        self.assertFalse(self.run.result["endpointCompleted"])

    def test_poweroff_waits_for_both_cancelled_and_all_reaped(self) -> None:
        self.cancellation()
        self.emit(1, common.STATUS_CANCELLED)
        self.assertEqual(self.coordinator.sent_poweroff, set())
        self.emit(2, common.STATUS_CHILDREN_REAPED)
        self.assertEqual(self.coordinator.sent_poweroff, set())
        self.emit(2, common.STATUS_CANCELLED)
        self.assertEqual(self.coordinator.sent_poweroff, {1, 2})

    def test_service_cancelled_first_also_waits_for_guest(self) -> None:
        self.cancellation()
        self.emit(2, common.STATUS_CHILDREN_REAPED)
        self.emit(2, common.STATUS_CANCELLED)
        self.assertEqual(self.coordinator.sent_poweroff, set())
        self.emit(1, common.STATUS_CANCELLED)
        self.assertEqual(self.coordinator.sent_poweroff, {1, 2})

    def test_wrong_four_child_waits_fail_before_poweroff(self) -> None:
        for waits in ((9472, 0), (9472, 0, 0, 0), (9472, 0, 18432, 9),
                      (9, 0, 18432, 0), (9472, 9, 18432, 0)):
            with self.subTest(waits=waits):
                self.setUp()
                self.cancellation()
                with self.assertRaises(common.FixtureFailure):
                    self.emit(2, common.STATUS_CHILDREN_REAPED, waits=waits)
                self.assertFalse(self.run.result["serviceChildrenReaped"])
                self.assertEqual(self.coordinator.sent_poweroff, set())

    def test_eof_observed_is_distinct_from_bounded_absence(self) -> None:
        self.cancellation(common.STATUS_EOF_OBSERVED)
        self.assertEqual(self.run.result["eofObservation"], "observed")

    def test_early_vm_stop_or_forced_stop_cannot_pass(self) -> None:
        self.packet()
        for state in (common.VM_STOPPED, common.VM_FORCE_STOPPED):
            with self.subTest(state=state), self.assertRaises(common.FixtureFailure):
                self.coordinator.handle_vm(1, state)

    def test_mode_cross_rejects_authenticated_status_frames(self) -> None:
        old = common.Coordinator(self.run, self.vm_id, self.generation, self.nonce, self.keys)
        new_frame = self.frame(1, common.STATUS_PORTS_READY)
        old_frame = self.frame(1, common.STATUS_PORTS_READY, profile=common.Coordinator)
        with self.assertRaises(common.FixtureFailure):
            old.decode_status(1, new_frame)
        with self.assertRaises(common.FixtureFailure):
            self.coordinator.decode_status(1, old_frame)
        # Changing only magic cannot turn an old HMAC into a new-profile frame.
        with self.assertRaises(common.FixtureFailure):
            self.coordinator.decode_status(1, self.coordinator.status_magic + old_frame[8:])

    def test_authenticated_metadata_and_replay_are_strict(self) -> None:
        original = self.frame(1, common.STATUS_PORTS_READY)
        for offset in (8, 10, 16, 32, 40, 72, 80):
            with self.subTest(offset=offset):
                changed = bytearray(original)
                changed[offset] ^= 1
                with self.assertRaises(common.FixtureFailure):
                    self.coordinator.decode_status(1, self.authenticate(changed, 1))
        with self.assertRaises(common.FixtureFailure):
            self.coordinator.decode_status(1, original[:-1] + bytes([original[-1] ^ 1]))
        self.coordinator.decode_status(1, original)
        with self.assertRaises(common.FixtureFailure):
            self.coordinator.decode_status(1, original)

    def test_reaped_metadata_is_service_only(self) -> None:
        with self.assertRaises(common.FixtureFailure):
            self.coordinator.decode_status(1, self.frame(1, common.STATUS_CHILDREN_REAPED))

    def test_result_exact_schema_facts_and_waits(self) -> None:
        self.finish()
        for key in fixture.RESULT_KEYS:
            with self.subTest(missing=key):
                invalid = dict(self.run.result)
                del invalid[key]
                with self.assertRaises(common.FixtureFailure):
                    fixture.PRODUCT_SPEC.validate_result(invalid)
        for key in fixture.FACT_KEYS.values():
            for value in (False, 1, None, "true"):
                with self.subTest(key=key, value=value), self.assertRaises(common.FixtureFailure):
                    fixture.PRODUCT_SPEC.validate_result(dict(self.run.result, **{key: value}))
        for key in fixture.EXTRA_WAIT_KEYS:
            for value in (None, False, "0", -1):
                with self.subTest(key=key, value=value), self.assertRaises(common.FixtureFailure):
                    fixture.PRODUCT_SPEC.validate_result(dict(self.run.result, **{key: value}))
        for additions in ({"unknown": 1}, {"schemaVersion": True},
                          {"schemaVersion": 1}, {"fixture": common.FIXTURE}):
            with self.assertRaises(common.FixtureFailure):
                fixture.PRODUCT_SPEC.validate_result(dict(self.run.result, **additions))

    def test_old_and_new_result_modes_cross_reject(self) -> None:
        self.finish()
        with self.assertRaises(common.FixtureFailure):
            common.validate_result(self.run.result)
        with self.assertRaises(common.FixtureFailure):
            fixture.PRODUCT_SPEC.validate_result(common.base_result())

    def test_binding_is_fixed_new_schema_and_zero_padded(self) -> None:
        args = ("service", str(self.vm_id), self.generation, self.nonce, b"n" * 32, self.keys[2])
        old = common.binding_image(*args)
        new = fixture.PRODUCT_SPEC.binding_image(*args)
        document = json.loads(new.rstrip(b"\0"))
        self.assertEqual(len(new), common.BINDING_BYTES)
        self.assertEqual(document.pop("schemaVersion"), 2)
        self.assertEqual(document.pop("kind"), "product-network")
        old_document = json.loads(old.rstrip(b"\0"))
        self.assertEqual(old_document.pop("schemaVersion"), 1)
        self.assertEqual(document, old_document)
        self.assertTrue(new.endswith(b"\0"))

    def test_shared_owner_retains_variant_before_start_write(self) -> None:
        def fail_send(_: bytes) -> None:
            self.assertIsInstance(self.run.coordinator, fixture.ProductNetworkCoordinator)
            raise common.FixtureFailure()
        self.run.send = fail_send
        with self.assertRaises(common.FixtureFailure):
            common.attach_and_start_coordinator(
                self.run, self.vm_id, self.generation, self.nonce, self.keys
            )

    def test_shared_receipt_uses_new_spec_and_strict_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = common.Run(Path(temporary), spec=fixture.PRODUCT_SPEC)
            run.persist("prepared")
            receipt = json.loads(run.receipt_path.read_bytes())
            self.assertEqual(receipt["schemaVersion"], 2)
            self.assertEqual(receipt["fixture"], "macos-vz-product-network")
            self.assertEqual(set(receipt["result"]), fixture.RESULT_KEYS)
            run.result = common.base_result()
            with self.assertRaises(common.FixtureFailure):
                run.persist("prepared")

    def test_entrypoint_binds_product_spec_without_user_profile_switch(self) -> None:
        with mock.patch.object(common, "main", return_value=7) as entry:
            self.assertEqual(fixture.main(["--help"]), 7)
        entry.assert_called_once_with(["--help"], spec=fixture.PRODUCT_SPEC)


if __name__ == "__main__":
    unittest.main()
