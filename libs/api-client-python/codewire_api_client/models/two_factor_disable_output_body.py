from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="TwoFactorDisableOutputBody")


@_attrs_define
class TwoFactorDisableOutputBody:
    """
    Attributes:
        disabled (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    disabled: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        disabled = self.disabled

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "disabled": disabled,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        disabled = d.pop("disabled")

        schema = d.pop("$schema", UNSET)

        two_factor_disable_output_body = cls(
            disabled=disabled,
            schema=schema,
        )

        return two_factor_disable_output_body
