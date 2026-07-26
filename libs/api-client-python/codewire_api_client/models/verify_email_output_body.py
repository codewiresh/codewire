from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="VerifyEmailOutputBody")


@_attrs_define
class VerifyEmailOutputBody:
    """
    Attributes:
        verified (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    verified: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        verified = self.verified

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "verified": verified,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        verified = d.pop("verified")

        schema = d.pop("$schema", UNSET)

        verify_email_output_body = cls(
            verified=verified,
            schema=schema,
        )

        return verify_email_output_body
