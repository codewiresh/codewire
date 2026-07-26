from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="UsageSummary")


@_attrs_define
class UsageSummary:
    """
    Attributes:
        cpu_hours (float):
        memory_gb_hours (float):
        storage_gb_hours (float):
    """

    cpu_hours: float
    memory_gb_hours: float
    storage_gb_hours: float

    def to_dict(self) -> dict[str, Any]:
        cpu_hours = self.cpu_hours

        memory_gb_hours = self.memory_gb_hours

        storage_gb_hours = self.storage_gb_hours

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cpu_hours": cpu_hours,
                "memory_gb_hours": memory_gb_hours,
                "storage_gb_hours": storage_gb_hours,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cpu_hours = d.pop("cpu_hours")

        memory_gb_hours = d.pop("memory_gb_hours")

        storage_gb_hours = d.pop("storage_gb_hours")

        usage_summary = cls(
            cpu_hours=cpu_hours,
            memory_gb_hours=memory_gb_hours,
            storage_gb_hours=storage_gb_hours,
        )

        return usage_summary
