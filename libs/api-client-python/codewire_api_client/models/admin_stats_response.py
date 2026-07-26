from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdminStatsResponse")


@_attrs_define
class AdminStatsResponse:
    """
    Attributes:
        active_environments (int):
        monthly_cost (int):
        monthly_cpu_hours (float):
        monthly_memory_gb_hours (float):
        total_environments (int):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    active_environments: int
    monthly_cost: int
    monthly_cpu_hours: float
    monthly_memory_gb_hours: float
    total_environments: int
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        active_environments = self.active_environments

        monthly_cost = self.monthly_cost

        monthly_cpu_hours = self.monthly_cpu_hours

        monthly_memory_gb_hours = self.monthly_memory_gb_hours

        total_environments = self.total_environments

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "active_environments": active_environments,
                "monthly_cost": monthly_cost,
                "monthly_cpu_hours": monthly_cpu_hours,
                "monthly_memory_gb_hours": monthly_memory_gb_hours,
                "total_environments": total_environments,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        active_environments = d.pop("active_environments")

        monthly_cost = d.pop("monthly_cost")

        monthly_cpu_hours = d.pop("monthly_cpu_hours")

        monthly_memory_gb_hours = d.pop("monthly_memory_gb_hours")

        total_environments = d.pop("total_environments")

        schema = d.pop("$schema", UNSET)

        admin_stats_response = cls(
            active_environments=active_environments,
            monthly_cost=monthly_cost,
            monthly_cpu_hours=monthly_cpu_hours,
            monthly_memory_gb_hours=monthly_memory_gb_hours,
            total_environments=total_environments,
            schema=schema,
        )

        return admin_stats_response
