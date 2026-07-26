from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ValidateTOTPInputBody")


@_attrs_define
class ValidateTOTPInputBody:
    """
    Attributes:
        code (str):
        token (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    code: str
    token: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        code = self.code

        token = self.token

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "code": code,
                "token": token,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        code = d.pop("code")

        token = d.pop("token")

        schema = d.pop("$schema", UNSET)

        validate_totp_input_body = cls(
            code=code,
            token=token,
            schema=schema,
        )

        return validate_totp_input_body
