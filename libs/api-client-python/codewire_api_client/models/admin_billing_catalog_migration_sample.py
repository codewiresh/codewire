from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdminBillingCatalogMigrationSample")


@_attrs_define
class AdminBillingCatalogMigrationSample:
    """
    Attributes:
        current_plan_key (str):
        org_id (str):
        org_slug (str):
        scope (str):
        status (str):
        stripe_subscription_id (str):
        current_stripe_price_id (str | Unset):
    """

    current_plan_key: str
    org_id: str
    org_slug: str
    scope: str
    status: str
    stripe_subscription_id: str
    current_stripe_price_id: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        current_plan_key = self.current_plan_key

        org_id = self.org_id

        org_slug = self.org_slug

        scope = self.scope

        status = self.status

        stripe_subscription_id = self.stripe_subscription_id

        current_stripe_price_id = self.current_stripe_price_id

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "current_plan_key": current_plan_key,
                "org_id": org_id,
                "org_slug": org_slug,
                "scope": scope,
                "status": status,
                "stripe_subscription_id": stripe_subscription_id,
            }
        )
        if current_stripe_price_id is not UNSET:
            field_dict["current_stripe_price_id"] = current_stripe_price_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        current_plan_key = d.pop("current_plan_key")

        org_id = d.pop("org_id")

        org_slug = d.pop("org_slug")

        scope = d.pop("scope")

        status = d.pop("status")

        stripe_subscription_id = d.pop("stripe_subscription_id")

        current_stripe_price_id = d.pop("current_stripe_price_id", UNSET)

        admin_billing_catalog_migration_sample = cls(
            current_plan_key=current_plan_key,
            org_id=org_id,
            org_slug=org_slug,
            scope=scope,
            status=status,
            stripe_subscription_id=stripe_subscription_id,
            current_stripe_price_id=current_stripe_price_id,
        )

        return admin_billing_catalog_migration_sample
