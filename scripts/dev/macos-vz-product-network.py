#!/usr/bin/env python3
"""Prove fixed numeric TCP through the product broker inside a no-NIC service VM.

This is a developer fixture, not Internet egress, provider delivery or CLI parity.
The native opaque console transport and exact process ownership are shared with
the original console fixture; bindings, authenticated frames and results are not.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import uuid


_spec = importlib.util.spec_from_file_location(
    "macos_vz_console_pair_shared", Path(__file__).with_name("macos-vz-console-pair.py")
)
assert _spec and _spec.loader
common = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = common
_spec.loader.exec_module(common)

STATUS_TOPOLOGY_READY = 14
STATUS_ENDPOINT_READY = 15
STATUS_BROKER_PREPARED = 16
STATUS_BROKER_READY = 17
STATUS_WORKER_BROKER_READY = 18
STATUS_ENDPOINT_COMPLETED = 19

PREPARATION = (
    STATUS_TOPOLOGY_READY,
    STATUS_ENDPOINT_READY,
    STATUS_BROKER_PREPARED,
    STATUS_BROKER_READY,
    STATUS_WORKER_BROKER_READY,
    common.STATUS_PREPARED,
)
FACT_KEYS = {
    STATUS_TOPOLOGY_READY: "topologyVerified",
    STATUS_ENDPOINT_READY: "endpointReady",
    STATUS_BROKER_PREPARED: "brokerPrepared",
    STATUS_BROKER_READY: "brokerReady",
    STATUS_WORKER_BROKER_READY: "workerBrokerReady",
    STATUS_ENDPOINT_COMPLETED: "endpointCompleted",
}
EXTRA_WAIT_KEYS = ("brokerWaitStatus", "endpointWaitStatus")
RESULT_KEYS = common.RESULT_KEYS | frozenset(FACT_KEYS.values()) | frozenset(EXTRA_WAIT_KEYS)


class ProductNetworkSpec(common.ConsolePairSpec):
    __slots__ = ()
    fixture = "macos-vz-product-network"
    schema_version = 2

    def base_result(self) -> dict[str, object]:
        result = common.base_result()
        result.update(schemaVersion=self.schema_version, fixture=self.fixture)
        result.update({key: False for key in FACT_KEYS.values()})
        result.update({key: None for key in EXTRA_WAIT_KEYS})
        return result

    def validate_result(self, result: dict[str, object]) -> None:
        if (
            set(result) != RESULT_KEYS
            or type(result["schemaVersion"]) is not int
            or result["schemaVersion"] != self.schema_version
            or result["fixture"] != self.fixture
        ):
            raise common.FixtureFailure()
        # Validate the unchanged shared fields without representing a four-child
        # result as an old two-child PASS. The variant's full predicate is below.
        shared = {key: result[key] for key in common.RESULT_KEYS}
        shared.update(schemaVersion=common.SCHEMA_VERSION, fixture=common.FIXTURE)
        if shared["outcome"] == "pass":
            shared["outcome"] = "unknown"
        common.validate_result(shared)
        for key in FACT_KEYS.values():
            if type(result[key]) is not bool:
                raise common.FixtureFailure()
        for key in EXTRA_WAIT_KEYS:
            if result[key] is not None and type(result[key]) is not int:
                raise common.FixtureFailure()
        if result["outcome"] == "pass" and not self.result_is_pass(result):
            raise common.FixtureFailure()

    def result_is_pass(self, result: dict[str, object]) -> bool:
        return (
            common.result_is_pass(result)
            and all(result[key] is True for key in FACT_KEYS.values())
            and result["brokerWaitStatus"] == 18432
            and result["endpointWaitStatus"] == 0
        )

    def binding_image(
        self,
        role: str,
        vm_id: str,
        generation: int,
        run_nonce: bytes,
        network_key: bytes,
        status_key: bytes,
    ) -> bytes:
        original = common.binding_image(
            role, vm_id, generation, run_nonce, network_key, status_key
        )
        document = json.loads(original.rstrip(b"\0"))
        document.update(schemaVersion=2, kind="product-network")
        encoded = common.canonical(document)
        if not encoded or len(encoded) > common.MAX_BINDING_JSON_BYTES:
            raise common.FixtureFailure()
        return encoded + bytes(common.BINDING_BYTES - len(encoded))

    def coordinator(
        self, run: common.Run, vm_id: uuid.UUID, generation: int, nonce: bytes,
        status_keys: dict[int, bytes],
    ) -> ProductNetworkCoordinator:
        return ProductNetworkCoordinator(run, vm_id, generation, nonce, status_keys)


class ProductNetworkCoordinator(common.Coordinator):
    status_magic = b"CWPNST1\0"
    control_magic = b"CWPNCT1\0"
    status_domain = b"codewire-product-network-status-v1\0"
    control_domain = b"codewire-product-network-control-v1\0"
    wait_keys = common.Coordinator.wait_keys + EXTRA_WAIT_KEYS

    def expected_statuses(self, role: int) -> list[int | tuple[int, ...]]:
        if role == common.ROLE_GUEST:
            return super().expected_statuses(role)
        if role != common.ROLE_SERVICE:
            raise common.FixtureFailure()
        return [
            *PREPARATION,
            common.STATUS_WORKER_READY,
            STATUS_ENDPOINT_COMPLETED,
            common.STATUS_EOF_ARMED,
            (common.STATUS_EOF_OBSERVED, common.STATUS_NO_EOF_OBSERVED),
            common.STATUS_CHILDREN_REAPED,
            common.STATUS_CANCELLED,
        ]

    def initial_ready(self) -> bool:
        return (
            self.seen[common.ROLE_GUEST] == [common.STATUS_PORTS_READY]
            and self.seen[common.ROLE_SERVICE] == list(PREPARATION)
        )

    def packet_ready(self) -> bool:
        return (
            super().packet_ready()
            and STATUS_ENDPOINT_COMPLETED in self.seen[common.ROLE_SERVICE]
        )

    def poweroff_ready(self) -> bool:
        return (
            all(common.STATUS_CANCELLED in self.seen[role] for role in common.ROLES)
            and common.STATUS_CHILDREN_REAPED in self.seen[common.ROLE_SERVICE]
        )

    def handle_status(
        self, role: int, code: int, *waits: int | None,
        persist_packet: bool = True,
    ) -> None:
        if code == common.STATUS_CHILDREN_REAPED and waits != (9472, 0, 18432, 0):
            raise common.FixtureFailure()
        super().handle_status(role, code, *waits, persist_packet=persist_packet)

    def accepted_status(self, role: int, code: int) -> None:
        if role == common.ROLE_SERVICE:
            if code in FACT_KEYS:
                self.run.result[FACT_KEYS[code]] = True
            if code == common.STATUS_WORKER_READY and not self.sent_service_start:
                raise common.FixtureFailure()
            if code == common.STATUS_EOF_ARMED and not self.sent_eof_observe:
                raise common.FixtureFailure()
            if code in (common.STATUS_EOF_OBSERVED, common.STATUS_NO_EOF_OBSERVED) and not self.sent_close:
                raise common.FixtureFailure()
            if code == common.STATUS_CHILDREN_REAPED and not self.sent_cancel:
                raise common.FixtureFailure()
        else:
            if code == common.STATUS_GUEST_ARMED and not self.sent_guest_start:
                raise common.FixtureFailure()
            if code in (common.STATUS_HOST_READY, common.STATUS_PACKET_COMPLETED) and not self.sent_service_start:
                raise common.FixtureFailure()
            if code == common.STATUS_PACKET_CLOSED and not self.sent_close:
                raise common.FixtureFailure()
        if code == common.STATUS_CANCELLED and not self.sent_cancel:
            raise common.FixtureFailure()


PRODUCT_SPEC = ProductNetworkSpec()


def main(argv: list[str] | None = None) -> int:
    return common.main(argv, spec=PRODUCT_SPEC)


if __name__ == "__main__":
    raise SystemExit(main())
