from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SignUpRequest")


@_attrs_define
class SignUpRequest:
    """
    Attributes:
        email (str):
        invite_code (str):
        name (str):
        password (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    email: str
    invite_code: str
    name: str
    password: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        invite_code = self.invite_code

        name = self.name

        password = self.password

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "email": email,
                "invite_code": invite_code,
                "name": name,
                "password": password,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        invite_code = d.pop("invite_code")

        name = d.pop("name")

        password = d.pop("password")

        schema = d.pop("$schema", UNSET)

        sign_up_request = cls(
            email=email,
            invite_code=invite_code,
            name=name,
            password=password,
            schema=schema,
        )

        return sign_up_request
