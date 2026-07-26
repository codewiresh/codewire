from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResetPasswordOutputBody")


@_attrs_define
class ResetPasswordOutputBody:
    """
    Attributes:
        reset (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    reset: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        reset = self.reset

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "reset": reset,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reset = d.pop("reset")

        schema = d.pop("$schema", UNSET)

        reset_password_output_body = cls(
            reset=reset,
            schema=schema,
        )

        return reset_password_output_body
