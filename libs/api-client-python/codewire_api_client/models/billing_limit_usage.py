from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="BillingLimitUsage")


@_attrs_define
class BillingLimitUsage:
    """
    Attributes:
        max_ (int):
        used (int):
    """

    max_: int
    used: int

    def to_dict(self) -> dict[str, Any]:
        max_ = self.max_

        used = self.used

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "max": max_,
                "used": used,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        max_ = d.pop("max")

        used = d.pop("used")

        billing_limit_usage = cls(
            max_=max_,
            used=used,
        )

        return billing_limit_usage
