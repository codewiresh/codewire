from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="PortalRequest")


@_attrs_define
class PortalRequest:
    """
    Attributes:
        return_url (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    return_url: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        return_url = self.return_url

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "return_url": return_url,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        return_url = d.pop("return_url")

        schema = d.pop("$schema", UNSET)

        portal_request = cls(
            return_url=return_url,
            schema=schema,
        )

        return portal_request
