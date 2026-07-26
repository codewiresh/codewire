from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateAdminBillingCatalogSettingInputBody")


@_attrs_define
class UpdateAdminBillingCatalogSettingInputBody:
    """
    Attributes:
        int_value (int):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    int_value: int
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        int_value = self.int_value

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "int_value": int_value,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        int_value = d.pop("int_value")

        schema = d.pop("$schema", UNSET)

        update_admin_billing_catalog_setting_input_body = cls(
            int_value=int_value,
            schema=schema,
        )

        return update_admin_billing_catalog_setting_input_body
