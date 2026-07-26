from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="EnvironmentUsageHour")


@_attrs_define
class EnvironmentUsageHour:
    """
    Attributes:
        cost_cents (int):
        cpu_hours (float):
        hour (str):
        mem_gb_hours (float):
    """

    cost_cents: int
    cpu_hours: float
    hour: str
    mem_gb_hours: float

    def to_dict(self) -> dict[str, Any]:
        cost_cents = self.cost_cents

        cpu_hours = self.cpu_hours

        hour = self.hour

        mem_gb_hours = self.mem_gb_hours

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cost_cents": cost_cents,
                "cpu_hours": cpu_hours,
                "hour": hour,
                "mem_gb_hours": mem_gb_hours,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cost_cents = d.pop("cost_cents")

        cpu_hours = d.pop("cpu_hours")

        hour = d.pop("hour")

        mem_gb_hours = d.pop("mem_gb_hours")

        environment_usage_hour = cls(
            cost_cents=cost_cents,
            cpu_hours=cpu_hours,
            hour=hour,
            mem_gb_hours=mem_gb_hours,
        )

        return environment_usage_hour
