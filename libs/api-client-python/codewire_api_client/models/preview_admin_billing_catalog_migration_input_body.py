from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="PreviewAdminBillingCatalogMigrationInputBody")


@_attrs_define
class PreviewAdminBillingCatalogMigrationInputBody:
    """
    Attributes:
        resource_type (str):
        source_plan_key (str):
        target_plan_key (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        sample_limit (int | Unset):
    """

    resource_type: str
    source_plan_key: str
    target_plan_key: str
    schema: str | Unset = UNSET
    sample_limit: int | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        resource_type = self.resource_type

        source_plan_key = self.source_plan_key

        target_plan_key = self.target_plan_key

        schema = self.schema

        sample_limit = self.sample_limit

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
        if sample_limit is not UNSET:
            field_dict["sample_limit"] = sample_limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resource_type = d.pop("resource_type")

        source_plan_key = d.pop("source_plan_key")

        target_plan_key = d.pop("target_plan_key")

        schema = d.pop("$schema", UNSET)

        sample_limit = d.pop("sample_limit", UNSET)

        preview_admin_billing_catalog_migration_input_body = cls(
            resource_type=resource_type,
            source_plan_key=source_plan_key,
            target_plan_key=target_plan_key,
            schema=schema,
            sample_limit=sample_limit,
        )

        return preview_admin_billing_catalog_migration_input_body
