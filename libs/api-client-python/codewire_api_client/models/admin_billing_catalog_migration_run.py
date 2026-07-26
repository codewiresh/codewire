from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdminBillingCatalogMigrationRun")


@_attrs_define
class AdminBillingCatalogMigrationRun:
    """
    Attributes:
        created_at (str):
        failed_count (int):
        id (str):
        migrated_count (int):
        proration_behavior (str):
        resource_type (str):
        skipped_count (int):
        source_plan_key (str):
        target_plan_key (str):
        target_stripe_price_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        created_by (str | Unset):
        metadata (Any | Unset):
    """

    created_at: str
    failed_count: int
    id: str
    migrated_count: int
    proration_behavior: str
    resource_type: str
    skipped_count: int
    source_plan_key: str
    target_plan_key: str
    target_stripe_price_id: str
    schema: str | Unset = UNSET
    created_by: str | Unset = UNSET
    metadata: Any | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        failed_count = self.failed_count

        id = self.id

        migrated_count = self.migrated_count

        proration_behavior = self.proration_behavior

        resource_type = self.resource_type

        skipped_count = self.skipped_count

        source_plan_key = self.source_plan_key

        target_plan_key = self.target_plan_key

        target_stripe_price_id = self.target_stripe_price_id

        schema = self.schema

        created_by = self.created_by

        metadata = self.metadata

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "failed_count": failed_count,
                "id": id,
                "migrated_count": migrated_count,
                "proration_behavior": proration_behavior,
                "resource_type": resource_type,
                "skipped_count": skipped_count,
                "source_plan_key": source_plan_key,
                "target_plan_key": target_plan_key,
                "target_stripe_price_id": target_stripe_price_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        failed_count = d.pop("failed_count")

        id = d.pop("id")

        migrated_count = d.pop("migrated_count")

        proration_behavior = d.pop("proration_behavior")

        resource_type = d.pop("resource_type")

        skipped_count = d.pop("skipped_count")

        source_plan_key = d.pop("source_plan_key")

        target_plan_key = d.pop("target_plan_key")

        target_stripe_price_id = d.pop("target_stripe_price_id")

        schema = d.pop("$schema", UNSET)

        created_by = d.pop("created_by", UNSET)

        metadata = d.pop("metadata", UNSET)

        admin_billing_catalog_migration_run = cls(
            created_at=created_at,
            failed_count=failed_count,
            id=id,
            migrated_count=migrated_count,
            proration_behavior=proration_behavior,
            resource_type=resource_type,
            skipped_count=skipped_count,
            source_plan_key=source_plan_key,
            target_plan_key=target_plan_key,
            target_stripe_price_id=target_stripe_price_id,
            schema=schema,
            created_by=created_by,
            metadata=metadata,
        )

        return admin_billing_catalog_migration_run
