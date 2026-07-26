from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="EnvironmentUsageEntry")


@_attrs_define
class EnvironmentUsageEntry:
    """
    Attributes:
        cost_cents (int):
        cpu_millicores (int):
        hourly_cents (int):
        id (str):
        memory_mb (int):
        name (str):
        running_seconds (int):
    """

    cost_cents: int
    cpu_millicores: int
    hourly_cents: int
    id: str
    memory_mb: int
    name: str
    running_seconds: int

    def to_dict(self) -> dict[str, Any]:
        cost_cents = self.cost_cents

        cpu_millicores = self.cpu_millicores

        hourly_cents = self.hourly_cents

        id = self.id

        memory_mb = self.memory_mb

        name = self.name

        running_seconds = self.running_seconds

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cost_cents": cost_cents,
                "cpu_millicores": cpu_millicores,
                "hourly_cents": hourly_cents,
                "id": id,
                "memory_mb": memory_mb,
                "name": name,
                "running_seconds": running_seconds,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cost_cents = d.pop("cost_cents")

        cpu_millicores = d.pop("cpu_millicores")

        hourly_cents = d.pop("hourly_cents")

        id = d.pop("id")

        memory_mb = d.pop("memory_mb")

        name = d.pop("name")

        running_seconds = d.pop("running_seconds")

        environment_usage_entry = cls(
            cost_cents=cost_cents,
            cpu_millicores=cpu_millicores,
            hourly_cents=hourly_cents,
            id=id,
            memory_mb=memory_mb,
            name=name,
            running_seconds=running_seconds,
        )

        return environment_usage_entry
