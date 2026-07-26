from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.admin_billing_catalog_migration_sample import AdminBillingCatalogMigrationSample


T = TypeVar("T", bound="AdminBillingCatalogMigrationPreview")


@_attrs_define
class AdminBillingCatalogMigrationPreview:
    """
    Attributes:
        already_on_target (int):
        candidate_count (int):
        matching_count (int):
        resource_type (str):
        samples (list[AdminBillingCatalogMigrationSample] | None):
        source_plan_key (str):
        target_plan_key (str):
        target_stripe_price_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    already_on_target: int
    candidate_count: int
    matching_count: int
    resource_type: str
    samples: list[AdminBillingCatalogMigrationSample] | None
    source_plan_key: str
    target_plan_key: str
    target_stripe_price_id: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        already_on_target = self.already_on_target

        candidate_count = self.candidate_count

        matching_count = self.matching_count

        resource_type = self.resource_type

        samples: list[dict[str, Any]] | None
        if isinstance(self.samples, list):
            samples = []
            for samples_type_0_item_data in self.samples:
                samples_type_0_item = samples_type_0_item_data.to_dict()
                samples.append(samples_type_0_item)

        else:
            samples = self.samples

        source_plan_key = self.source_plan_key

        target_plan_key = self.target_plan_key

        target_stripe_price_id = self.target_stripe_price_id

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "already_on_target": already_on_target,
                "candidate_count": candidate_count,
                "matching_count": matching_count,
                "resource_type": resource_type,
                "samples": samples,
                "source_plan_key": source_plan_key,
                "target_plan_key": target_plan_key,
                "target_stripe_price_id": target_stripe_price_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_billing_catalog_migration_sample import AdminBillingCatalogMigrationSample

        d = dict(src_dict)
        already_on_target = d.pop("already_on_target")

        candidate_count = d.pop("candidate_count")

        matching_count = d.pop("matching_count")

        resource_type = d.pop("resource_type")

        def _parse_samples(data: object) -> list[AdminBillingCatalogMigrationSample] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                samples_type_0 = []
                _samples_type_0 = data
                for samples_type_0_item_data in _samples_type_0:
                    samples_type_0_item = AdminBillingCatalogMigrationSample.from_dict(samples_type_0_item_data)

                    samples_type_0.append(samples_type_0_item)

                return samples_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminBillingCatalogMigrationSample] | None, data)

        samples = _parse_samples(d.pop("samples"))

        source_plan_key = d.pop("source_plan_key")

        target_plan_key = d.pop("target_plan_key")

        target_stripe_price_id = d.pop("target_stripe_price_id")

        schema = d.pop("$schema", UNSET)

        admin_billing_catalog_migration_preview = cls(
            already_on_target=already_on_target,
            candidate_count=candidate_count,
            matching_count=matching_count,
            resource_type=resource_type,
            samples=samples,
            source_plan_key=source_plan_key,
            target_plan_key=target_plan_key,
            target_stripe_price_id=target_stripe_price_id,
            schema=schema,
        )

        return admin_billing_catalog_migration_preview
