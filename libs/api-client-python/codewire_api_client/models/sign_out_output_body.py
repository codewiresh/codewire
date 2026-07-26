from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SignOutOutputBody")


@_attrs_define
class SignOutOutputBody:
    """
    Attributes:
        success (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    success: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        success = self.success

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "success": success,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        success = d.pop("success")

        schema = d.pop("$schema", UNSET)

        sign_out_output_body = cls(
            success=success,
            schema=schema,
        )

        return sign_out_output_body
