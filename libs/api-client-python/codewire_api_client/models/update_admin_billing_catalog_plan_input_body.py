from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateAdminBillingCatalogPlanInputBody")


@_attrs_define
class UpdateAdminBillingCatalogPlanInputBody:
    """
    Attributes:
        cpu_overage_cents (float):
        disk_overage_cents (float):
        display_name (str):
        included_cpu_hours (int):
        included_devs (int):
        included_disk_gb_hours (int):
        included_mem_gb_hours (int):
        is_admin_only (bool):
        is_contact_us (bool):
        max_concurrent_ws (int):
        max_team_members (int):
        mem_overage_cents (float):
        price_cents (int):
        storage_gb (int):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    cpu_overage_cents: float
    disk_overage_cents: float
    display_name: str
    included_cpu_hours: int
    included_devs: int
    included_disk_gb_hours: int
    included_mem_gb_hours: int
    is_admin_only: bool
    is_contact_us: bool
    max_concurrent_ws: int
    max_team_members: int
    mem_overage_cents: float
    price_cents: int
    storage_gb: int
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        cpu_overage_cents = self.cpu_overage_cents

        disk_overage_cents = self.disk_overage_cents

        display_name = self.display_name

        included_cpu_hours = self.included_cpu_hours

        included_devs = self.included_devs

        included_disk_gb_hours = self.included_disk_gb_hours

        included_mem_gb_hours = self.included_mem_gb_hours

        is_admin_only = self.is_admin_only

        is_contact_us = self.is_contact_us

        max_concurrent_ws = self.max_concurrent_ws

        max_team_members = self.max_team_members

        mem_overage_cents = self.mem_overage_cents

        price_cents = self.price_cents

        storage_gb = self.storage_gb

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cpu_overage_cents": cpu_overage_cents,
                "disk_overage_cents": disk_overage_cents,
                "display_name": display_name,
                "included_cpu_hours": included_cpu_hours,
                "included_devs": included_devs,
                "included_disk_gb_hours": included_disk_gb_hours,
                "included_mem_gb_hours": included_mem_gb_hours,
                "is_admin_only": is_admin_only,
                "is_contact_us": is_contact_us,
                "max_concurrent_ws": max_concurrent_ws,
                "max_team_members": max_team_members,
                "mem_overage_cents": mem_overage_cents,
                "price_cents": price_cents,
                "storage_gb": storage_gb,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cpu_overage_cents = d.pop("cpu_overage_cents")

        disk_overage_cents = d.pop("disk_overage_cents")

        display_name = d.pop("display_name")

        included_cpu_hours = d.pop("included_cpu_hours")

        included_devs = d.pop("included_devs")

        included_disk_gb_hours = d.pop("included_disk_gb_hours")

        included_mem_gb_hours = d.pop("included_mem_gb_hours")

        is_admin_only = d.pop("is_admin_only")

        is_contact_us = d.pop("is_contact_us")

        max_concurrent_ws = d.pop("max_concurrent_ws")

        max_team_members = d.pop("max_team_members")

        mem_overage_cents = d.pop("mem_overage_cents")

        price_cents = d.pop("price_cents")

        storage_gb = d.pop("storage_gb")

        schema = d.pop("$schema", UNSET)

        update_admin_billing_catalog_plan_input_body = cls(
            cpu_overage_cents=cpu_overage_cents,
            disk_overage_cents=disk_overage_cents,
            display_name=display_name,
            included_cpu_hours=included_cpu_hours,
            included_devs=included_devs,
            included_disk_gb_hours=included_disk_gb_hours,
            included_mem_gb_hours=included_mem_gb_hours,
            is_admin_only=is_admin_only,
            is_contact_us=is_contact_us,
            max_concurrent_ws=max_concurrent_ws,
            max_team_members=max_team_members,
            mem_overage_cents=mem_overage_cents,
            price_cents=price_cents,
            storage_gb=storage_gb,
            schema=schema,
        )

        return update_admin_billing_catalog_plan_input_body
