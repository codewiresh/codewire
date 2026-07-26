from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="EnvironmentUsageMonth")


@_attrs_define
class EnvironmentUsageMonth:
    """
    Attributes:
        cost_cents (int):
        cpu_hours (float):
        disk_gb_hours (float):
        included_cpu_hours (int):
        included_mem_gb_hours (int):
        mem_gb_hours (float):
    """

    cost_cents: int
    cpu_hours: float
    disk_gb_hours: float
    included_cpu_hours: int
    included_mem_gb_hours: int
    mem_gb_hours: float

    def to_dict(self) -> dict[str, Any]:
        cost_cents = self.cost_cents

        cpu_hours = self.cpu_hours

        disk_gb_hours = self.disk_gb_hours

        included_cpu_hours = self.included_cpu_hours

        included_mem_gb_hours = self.included_mem_gb_hours

        mem_gb_hours = self.mem_gb_hours

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cost_cents": cost_cents,
                "cpu_hours": cpu_hours,
                "disk_gb_hours": disk_gb_hours,
                "included_cpu_hours": included_cpu_hours,
                "included_mem_gb_hours": included_mem_gb_hours,
                "mem_gb_hours": mem_gb_hours,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cost_cents = d.pop("cost_cents")

        cpu_hours = d.pop("cpu_hours")

        disk_gb_hours = d.pop("disk_gb_hours")

        included_cpu_hours = d.pop("included_cpu_hours")

        included_mem_gb_hours = d.pop("included_mem_gb_hours")

        mem_gb_hours = d.pop("mem_gb_hours")

        environment_usage_month = cls(
            cost_cents=cost_cents,
            cpu_hours=cpu_hours,
            disk_gb_hours=disk_gb_hours,
            included_cpu_hours=included_cpu_hours,
            included_mem_gb_hours=included_mem_gb_hours,
            mem_gb_hours=mem_gb_hours,
        )

        return environment_usage_month
