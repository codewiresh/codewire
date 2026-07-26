from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAdminBillingCatalogPriceInputBody")


@_attrs_define
class CreateAdminBillingCatalogPriceInputBody:
    """
    Attributes:
        plan_key (str):
        price_kind (str):
        resource_type (str):
        stripe_mode (str):
        stripe_price_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    plan_key: str
    price_kind: str
    resource_type: str
    stripe_mode: str
    stripe_price_id: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        plan_key = self.plan_key

        price_kind = self.price_kind

        resource_type = self.resource_type

        stripe_mode = self.stripe_mode

        stripe_price_id = self.stripe_price_id

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "plan_key": plan_key,
                "price_kind": price_kind,
                "resource_type": resource_type,
                "stripe_mode": stripe_mode,
                "stripe_price_id": stripe_price_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        plan_key = d.pop("plan_key")

        price_kind = d.pop("price_kind")

        resource_type = d.pop("resource_type")

        stripe_mode = d.pop("stripe_mode")

        stripe_price_id = d.pop("stripe_price_id")

        schema = d.pop("$schema", UNSET)

        create_admin_billing_catalog_price_input_body = cls(
            plan_key=plan_key,
            price_kind=price_kind,
            resource_type=resource_type,
            stripe_mode=stripe_mode,
            stripe_price_id=stripe_price_id,
            schema=schema,
        )

        return create_admin_billing_catalog_price_input_body
