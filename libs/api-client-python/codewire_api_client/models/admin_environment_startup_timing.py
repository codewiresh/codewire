from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdminEnvironmentStartupTiming")


@_attrs_define
class AdminEnvironmentStartupTiming:
    """
    Attributes:
        created_at (str):
        phase (str):
        status (str):
        duration_ms (int | Unset):
        message (str | Unset):
        metadata (Any | Unset):
    """

    created_at: str
    phase: str
    status: str
    duration_ms: int | Unset = UNSET
    message: str | Unset = UNSET
    metadata: Any | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        phase = self.phase

        status = self.status

        duration_ms = self.duration_ms

        message = self.message

        metadata = self.metadata

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "phase": phase,
                "status": status,
            }
        )
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if message is not UNSET:
            field_dict["message"] = message
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        phase = d.pop("phase")

        status = d.pop("status")

        duration_ms = d.pop("duration_ms", UNSET)

        message = d.pop("message", UNSET)

        metadata = d.pop("metadata", UNSET)

        admin_environment_startup_timing = cls(
            created_at=created_at,
            phase=phase,
            status=status,
            duration_ms=duration_ms,
            message=message,
            metadata=metadata,
        )

        return admin_environment_startup_timing
