from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExtendTTLInputBody")


@_attrs_define
class ExtendTTLInputBody:
    """
    Attributes:
        additional_seconds (int): Seconds to add to TTL (min 60, max 86400)
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    additional_seconds: int
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        additional_seconds = self.additional_seconds

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "additional_seconds": additional_seconds,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        additional_seconds = d.pop("additional_seconds")

        schema = d.pop("$schema", UNSET)

        extend_ttl_input_body = cls(
            additional_seconds=additional_seconds,
            schema=schema,
        )

        return extend_ttl_input_body
