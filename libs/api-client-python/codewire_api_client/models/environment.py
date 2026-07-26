from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.environment_port import EnvironmentPort


T = TypeVar("T", bound="Environment")


@_attrs_define
class Environment:
    """
    Attributes:
        cpu_millicores (int):
        created_at (str):
        created_by (str):
        desired_state (str):
        disk_gb (int):
        id (str):
        memory_mb (int):
        org_id (str):
        protected (bool):
        recoverable (bool):
        retry_count (int):
        setup_complete (bool):
        setup_phase (int):
        state (str):
        state_changed_at (str):
        total_running_seconds (int):
        type_ (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        deletion_grace_until (str | Unset):
        deletion_requested_at (str | Unset):
        destroyed_at (str | Unset):
        error_reason (str | Unset):
        name (str | Unset):
        network (str | Unset):
        ports (list[EnvironmentPort] | None | Unset):
        preset_id (str | Unset):
        preset_name (str | Unset):
        setup_error (str | Unset):
        shutdown_at (str | Unset):
        started_at (str | Unset):
        stopped_at (str | Unset):
        ttl_seconds (int | Unset):
    """

    cpu_millicores: int
    created_at: str
    created_by: str
    desired_state: str
    disk_gb: int
    id: str
    memory_mb: int
    org_id: str
    protected: bool
    recoverable: bool
    retry_count: int
    setup_complete: bool
    setup_phase: int
    state: str
    state_changed_at: str
    total_running_seconds: int
    type_: str
    schema: str | Unset = UNSET
    deletion_grace_until: str | Unset = UNSET
    deletion_requested_at: str | Unset = UNSET
    destroyed_at: str | Unset = UNSET
    error_reason: str | Unset = UNSET
    name: str | Unset = UNSET
    network: str | Unset = UNSET
    ports: list[EnvironmentPort] | None | Unset = UNSET
    preset_id: str | Unset = UNSET
    preset_name: str | Unset = UNSET
    setup_error: str | Unset = UNSET
    shutdown_at: str | Unset = UNSET
    started_at: str | Unset = UNSET
    stopped_at: str | Unset = UNSET
    ttl_seconds: int | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        cpu_millicores = self.cpu_millicores

        created_at = self.created_at

        created_by = self.created_by

        desired_state = self.desired_state

        disk_gb = self.disk_gb

        id = self.id

        memory_mb = self.memory_mb

        org_id = self.org_id

        protected = self.protected

        recoverable = self.recoverable

        retry_count = self.retry_count

        setup_complete = self.setup_complete

        setup_phase = self.setup_phase

        state = self.state

        state_changed_at = self.state_changed_at

        total_running_seconds = self.total_running_seconds

        type_ = self.type_

        schema = self.schema

        deletion_grace_until = self.deletion_grace_until

        deletion_requested_at = self.deletion_requested_at

        destroyed_at = self.destroyed_at

        error_reason = self.error_reason

        name = self.name

        network = self.network

        ports: list[dict[str, Any]] | None | Unset
        if isinstance(self.ports, Unset):
            ports = UNSET
        elif isinstance(self.ports, list):
            ports = []
            for ports_type_0_item_data in self.ports:
                ports_type_0_item = ports_type_0_item_data.to_dict()
                ports.append(ports_type_0_item)

        else:
            ports = self.ports

        preset_id = self.preset_id

        preset_name = self.preset_name

        setup_error = self.setup_error

        shutdown_at = self.shutdown_at

        started_at = self.started_at

        stopped_at = self.stopped_at

        ttl_seconds = self.ttl_seconds

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cpu_millicores": cpu_millicores,
                "created_at": created_at,
                "created_by": created_by,
                "desired_state": desired_state,
                "disk_gb": disk_gb,
                "id": id,
                "memory_mb": memory_mb,
                "org_id": org_id,
                "protected": protected,
                "recoverable": recoverable,
                "retry_count": retry_count,
                "setup_complete": setup_complete,
                "setup_phase": setup_phase,
                "state": state,
                "state_changed_at": state_changed_at,
                "total_running_seconds": total_running_seconds,
                "type": type_,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if deletion_grace_until is not UNSET:
            field_dict["deletion_grace_until"] = deletion_grace_until
        if deletion_requested_at is not UNSET:
            field_dict["deletion_requested_at"] = deletion_requested_at
        if destroyed_at is not UNSET:
            field_dict["destroyed_at"] = destroyed_at
        if error_reason is not UNSET:
            field_dict["error_reason"] = error_reason
        if name is not UNSET:
            field_dict["name"] = name
        if network is not UNSET:
            field_dict["network"] = network
        if ports is not UNSET:
            field_dict["ports"] = ports
        if preset_id is not UNSET:
            field_dict["preset_id"] = preset_id
        if preset_name is not UNSET:
            field_dict["preset_name"] = preset_name
        if setup_error is not UNSET:
            field_dict["setup_error"] = setup_error
        if shutdown_at is not UNSET:
            field_dict["shutdown_at"] = shutdown_at
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if stopped_at is not UNSET:
            field_dict["stopped_at"] = stopped_at
        if ttl_seconds is not UNSET:
            field_dict["ttl_seconds"] = ttl_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.environment_port import EnvironmentPort

        d = dict(src_dict)
        cpu_millicores = d.pop("cpu_millicores")

        created_at = d.pop("created_at")

        created_by = d.pop("created_by")

        desired_state = d.pop("desired_state")

        disk_gb = d.pop("disk_gb")

        id = d.pop("id")

        memory_mb = d.pop("memory_mb")

        org_id = d.pop("org_id")

        protected = d.pop("protected")

        recoverable = d.pop("recoverable")

        retry_count = d.pop("retry_count")

        setup_complete = d.pop("setup_complete")

        setup_phase = d.pop("setup_phase")

        state = d.pop("state")

        state_changed_at = d.pop("state_changed_at")

        total_running_seconds = d.pop("total_running_seconds")

        type_ = d.pop("type")

        schema = d.pop("$schema", UNSET)

        deletion_grace_until = d.pop("deletion_grace_until", UNSET)

        deletion_requested_at = d.pop("deletion_requested_at", UNSET)

        destroyed_at = d.pop("destroyed_at", UNSET)

        error_reason = d.pop("error_reason", UNSET)

        name = d.pop("name", UNSET)

        network = d.pop("network", UNSET)

        def _parse_ports(data: object) -> list[EnvironmentPort] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                ports_type_0 = []
                _ports_type_0 = data
                for ports_type_0_item_data in _ports_type_0:
                    ports_type_0_item = EnvironmentPort.from_dict(ports_type_0_item_data)

                    ports_type_0.append(ports_type_0_item)

                return ports_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[EnvironmentPort] | None | Unset, data)

        ports = _parse_ports(d.pop("ports", UNSET))

        preset_id = d.pop("preset_id", UNSET)

        preset_name = d.pop("preset_name", UNSET)

        setup_error = d.pop("setup_error", UNSET)

        shutdown_at = d.pop("shutdown_at", UNSET)

        started_at = d.pop("started_at", UNSET)

        stopped_at = d.pop("stopped_at", UNSET)

        ttl_seconds = d.pop("ttl_seconds", UNSET)

        environment = cls(
            cpu_millicores=cpu_millicores,
            created_at=created_at,
            created_by=created_by,
            desired_state=desired_state,
            disk_gb=disk_gb,
            id=id,
            memory_mb=memory_mb,
            org_id=org_id,
            protected=protected,
            recoverable=recoverable,
            retry_count=retry_count,
            setup_complete=setup_complete,
            setup_phase=setup_phase,
            state=state,
            state_changed_at=state_changed_at,
            total_running_seconds=total_running_seconds,
            type_=type_,
            schema=schema,
            deletion_grace_until=deletion_grace_until,
            deletion_requested_at=deletion_requested_at,
            destroyed_at=destroyed_at,
            error_reason=error_reason,
            name=name,
            network=network,
            ports=ports,
            preset_id=preset_id,
            preset_name=preset_name,
            setup_error=setup_error,
            shutdown_at=shutdown_at,
            started_at=started_at,
            stopped_at=stopped_at,
            ttl_seconds=ttl_seconds,
        )

        return environment
