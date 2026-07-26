from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="AdminBillingCatalogSetting")


@_attrs_define
class AdminBillingCatalogSetting:
    """
    Attributes:
        int_value (int):
        setting_key (str):
    """

    int_value: int
    setting_key: str

    def to_dict(self) -> dict[str, Any]:
        int_value = self.int_value

        setting_key = self.setting_key

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "int_value": int_value,
                "setting_key": setting_key,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        int_value = d.pop("int_value")

        setting_key = d.pop("setting_key")

        admin_billing_catalog_setting = cls(
            int_value=int_value,
            setting_key=setting_key,
        )

        return admin_billing_catalog_setting
