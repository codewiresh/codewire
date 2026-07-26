from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeleteSecretOutputBody")


@_attrs_define
class DeleteSecretOutputBody:
    """
    Attributes:
        status (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    status: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "status": status,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        schema = d.pop("$schema", UNSET)

        delete_secret_output_body = cls(
            status=status,
            schema=schema,
        )

        return delete_secret_output_body
