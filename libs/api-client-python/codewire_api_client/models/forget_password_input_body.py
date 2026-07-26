from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ForgetPasswordInputBody")


@_attrs_define
class ForgetPasswordInputBody:
    """
    Attributes:
        email (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    email: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "email": email,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        schema = d.pop("$schema", UNSET)

        forget_password_input_body = cls(
            email=email,
            schema=schema,
        )

        return forget_password_input_body
