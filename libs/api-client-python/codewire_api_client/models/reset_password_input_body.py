from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResetPasswordInputBody")


@_attrs_define
class ResetPasswordInputBody:
    """
    Attributes:
        new_password (str):
        token (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    new_password: str
    token: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        new_password = self.new_password

        token = self.token

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "newPassword": new_password,
                "token": token,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_password = d.pop("newPassword")

        token = d.pop("token")

        schema = d.pop("$schema", UNSET)

        reset_password_input_body = cls(
            new_password=new_password,
            token=token,
            schema=schema,
        )

        return reset_password_input_body
