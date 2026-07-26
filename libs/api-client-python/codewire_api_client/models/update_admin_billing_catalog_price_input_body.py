from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateAdminBillingCatalogPriceInputBody")


@_attrs_define
class UpdateAdminBillingCatalogPriceInputBody:
    """
    Attributes:
        stripe_price_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    stripe_price_id: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        stripe_price_id = self.stripe_price_id

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "stripe_price_id": stripe_price_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        stripe_price_id = d.pop("stripe_price_id")

        schema = d.pop("$schema", UNSET)

        update_admin_billing_catalog_price_input_body = cls(
            stripe_price_id=stripe_price_id,
            schema=schema,
        )

        return update_admin_billing_catalog_price_input_body
