from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="Organization")


@_attrs_define
class Organization:
    """
    Attributes:
        created_at (str):
        created_by (str):
        id (str):
        name (str):
        slug (str):
        updated_at (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    created_at: str
    created_by: str
    id: str
    name: str
    slug: str
    updated_at: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        created_by = self.created_by

        id = self.id

        name = self.name

        slug = self.slug

        updated_at = self.updated_at

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "created_by": created_by,
                "id": id,
                "name": name,
                "slug": slug,
                "updated_at": updated_at,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        created_by = d.pop("created_by")

        id = d.pop("id")

        name = d.pop("name")

        slug = d.pop("slug")

        updated_at = d.pop("updated_at")

        schema = d.pop("$schema", UNSET)

        organization = cls(
            created_at=created_at,
            created_by=created_by,
            id=id,
            name=name,
            slug=slug,
            updated_at=updated_at,
            schema=schema,
        )

        return organization
