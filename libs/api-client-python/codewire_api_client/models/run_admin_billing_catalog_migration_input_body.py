from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="RunAdminBillingCatalogMigrationInputBody")


@_attrs_define
class RunAdminBillingCatalogMigrationInputBody:
    """
    Attributes:
        resource_type (str):
        source_plan_key (str):
        target_plan_key (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        proration_behavior (str | Unset):
    """

    resource_type: str
    source_plan_key: str
    target_plan_key: str
    schema: str | Unset = UNSET
    proration_behavior: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        resource_type = self.resource_type

        source_plan_key = self.source_plan_key

        target_plan_key = self.target_plan_key

        schema = self.schema

        proration_behavior = self.proration_behavior

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "resource_type": resource_type,
                "source_plan_key": source_plan_key,
                "target_plan_key": target_plan_key,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if proration_behavior is not UNSET:
            field_dict["proration_behavior"] = proration_behavior

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resource_type = d.pop("resource_type")

        source_plan_key = d.pop("source_plan_key")

        target_plan_key = d.pop("target_plan_key")

        schema = d.pop("$schema", UNSET)

        proration_behavior = d.pop("proration_behavior", UNSET)

        run_admin_billing_catalog_migration_input_body = cls(
            resource_type=resource_type,
            source_plan_key=source_plan_key,
            target_plan_key=target_plan_key,
            schema=schema,
            proration_behavior=proration_behavior,
        )

        return run_admin_billing_catalog_migration_input_body
