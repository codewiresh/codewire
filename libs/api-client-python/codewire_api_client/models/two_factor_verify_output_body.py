from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="TwoFactorVerifyOutputBody")


@_attrs_define
class TwoFactorVerifyOutputBody:
    """
    Attributes:
        enabled (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    enabled: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        enabled = self.enabled

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "enabled": enabled,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enabled = d.pop("enabled")

        schema = d.pop("$schema", UNSET)

        two_factor_verify_output_body = cls(
            enabled=enabled,
            schema=schema,
        )

        return two_factor_verify_output_body
