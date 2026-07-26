from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="AdminBillingCatalogPrice")


@_attrs_define
class AdminBillingCatalogPrice:
    """
    Attributes:
        archived (bool):
        plan_key (str):
        price_kind (str):
        resource_type (str):
        stripe_mode (str):
        stripe_price_id (str):
    """

    archived: bool
    plan_key: str
    price_kind: str
    resource_type: str
    stripe_mode: str
    stripe_price_id: str

    def to_dict(self) -> dict[str, Any]:
        archived = self.archived

        plan_key = self.plan_key

        price_kind = self.price_kind

        resource_type = self.resource_type

        stripe_mode = self.stripe_mode

        stripe_price_id = self.stripe_price_id

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "archived": archived,
                "plan_key": plan_key,
                "price_kind": price_kind,
                "resource_type": resource_type,
                "stripe_mode": stripe_mode,
                "stripe_price_id": stripe_price_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        archived = d.pop("archived")

        plan_key = d.pop("plan_key")

        price_kind = d.pop("price_kind")

        resource_type = d.pop("resource_type")

        stripe_mode = d.pop("stripe_mode")

        stripe_price_id = d.pop("stripe_price_id")

        admin_billing_catalog_price = cls(
            archived=archived,
            plan_key=plan_key,
            price_kind=price_kind,
            resource_type=resource_type,
            stripe_mode=stripe_mode,
            stripe_price_id=stripe_price_id,
        )

        return admin_billing_catalog_price
