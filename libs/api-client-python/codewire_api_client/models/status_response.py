from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="StatusResponse")


@_attrs_define
class StatusResponse:
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

        status_response = cls(
            status=status,
            schema=schema,
        )

        return status_response
