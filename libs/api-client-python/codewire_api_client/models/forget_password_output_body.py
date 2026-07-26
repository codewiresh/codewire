from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ForgetPasswordOutputBody")


@_attrs_define
class ForgetPasswordOutputBody:
    """
    Attributes:
        sent (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    sent: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        sent = self.sent

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "sent": sent,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sent = d.pop("sent")

        schema = d.pop("$schema", UNSET)

        forget_password_output_body = cls(
            sent=sent,
            schema=schema,
        )

        return forget_password_output_body
