from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="AdminOrg")


@_attrs_define
class AdminOrg:
    """
    Attributes:
        created_at (str):
        id (str):
        name (str):
        slug (str):
    """

    created_at: str
    id: str
    name: str
    slug: str

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        id = self.id

        name = self.name

        slug = self.slug

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "id": id,
                "name": name,
                "slug": slug,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        id = d.pop("id")

        name = d.pop("name")

        slug = d.pop("slug")

        admin_org = cls(
            created_at=created_at,
            id=id,
            name=name,
            slug=slug,
        )

        return admin_org
