from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdminEnvironmentLifecycleJournalEntry")


@_attrs_define
class AdminEnvironmentLifecycleJournalEntry:
    """
    Attributes:
        actor (str):
        created_at (str):
        environment_id (str):
        id (str):
        kind (str):
        checkpoint (str | Unset):
        from_state (str | Unset):
        metadata (Any | Unset):
        phase (str | Unset):
        reason (str | Unset):
        status (str | Unset):
        to_state (str | Unset):
    """

    actor: str
    created_at: str
    environment_id: str
    id: str
    kind: str
    checkpoint: str | Unset = UNSET
    from_state: str | Unset = UNSET
    metadata: Any | Unset = UNSET
    phase: str | Unset = UNSET
    reason: str | Unset = UNSET
    status: str | Unset = UNSET
    to_state: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        actor = self.actor

        created_at = self.created_at

        environment_id = self.environment_id

        id = self.id

        kind = self.kind

        checkpoint = self.checkpoint

        from_state = self.from_state

        metadata = self.metadata

        phase = self.phase

        reason = self.reason

        status = self.status

        to_state = self.to_state

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "actor": actor,
                "created_at": created_at,
                "environment_id": environment_id,
                "id": id,
                "kind": kind,
            }
        )
        if checkpoint is not UNSET:
            field_dict["checkpoint"] = checkpoint
        if from_state is not UNSET:
            field_dict["from_state"] = from_state
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if phase is not UNSET:
            field_dict["phase"] = phase
        if reason is not UNSET:
            field_dict["reason"] = reason
        if status is not UNSET:
            field_dict["status"] = status
        if to_state is not UNSET:
            field_dict["to_state"] = to_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actor = d.pop("actor")

        created_at = d.pop("created_at")

        environment_id = d.pop("environment_id")

        id = d.pop("id")

        kind = d.pop("kind")

        checkpoint = d.pop("checkpoint", UNSET)

        from_state = d.pop("from_state", UNSET)

        metadata = d.pop("metadata", UNSET)

        phase = d.pop("phase", UNSET)

        reason = d.pop("reason", UNSET)

        status = d.pop("status", UNSET)

        to_state = d.pop("to_state", UNSET)

        admin_environment_lifecycle_journal_entry = cls(
            actor=actor,
            created_at=created_at,
            environment_id=environment_id,
            id=id,
            kind=kind,
            checkpoint=checkpoint,
            from_state=from_state,
            metadata=metadata,
            phase=phase,
            reason=reason,
            status=status,
            to_state=to_state,
        )

        return admin_environment_lifecycle_journal_entry
