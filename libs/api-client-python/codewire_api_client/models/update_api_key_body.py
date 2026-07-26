from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateAPIKeyBody")


@_attrs_define
class UpdateAPIKeyBody:
    """
    Attributes:
        schema (str | Unset): A URL to the JSON Schema for this object.
        disabled (bool | Unset): Set to true to disable, false to enable
    """

    schema: str | Unset = UNSET
    disabled: bool | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        schema = self.schema

        disabled = self.disabled

        field_dict: dict[str, Any] = {}

        field_dict.update({})
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if disabled is not UNSET:
            field_dict["disabled"] = disabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        schema = d.pop("$schema", UNSET)

        disabled = d.pop("disabled", UNSET)

        update_api_key_body = cls(
            schema=schema,
            disabled=disabled,
        )

        return update_api_key_body
