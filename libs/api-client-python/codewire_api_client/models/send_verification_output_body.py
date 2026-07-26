from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SendVerificationOutputBody")


@_attrs_define
class SendVerificationOutputBody:
    """
    Attributes:
        schema (str | Unset): A URL to the JSON Schema for this object.
        already_verified (bool | Unset):
        sent (bool | Unset):
    """

    schema: str | Unset = UNSET
    already_verified: bool | Unset = UNSET
    sent: bool | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        schema = self.schema

        already_verified = self.already_verified

        sent = self.sent

        field_dict: dict[str, Any] = {}

        field_dict.update({})
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if already_verified is not UNSET:
            field_dict["already_verified"] = already_verified
        if sent is not UNSET:
            field_dict["sent"] = sent

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        schema = d.pop("$schema", UNSET)

        already_verified = d.pop("already_verified", UNSET)

        sent = d.pop("sent", UNSET)

        send_verification_output_body = cls(
            schema=schema,
            already_verified=already_verified,
            sent=sent,
        )

        return send_verification_output_body
