from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateOrgRequest")


@_attrs_define
class CreateOrgRequest:
    """
    Attributes:
        name (str):
        slug (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    name: str
    slug: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        slug = self.slug

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "name": name,
                "slug": slug,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        slug = d.pop("slug")

        schema = d.pop("$schema", UNSET)

        create_org_request = cls(
            name=name,
            slug=slug,
            schema=schema,
        )

        return create_org_request
