from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SecretProject")


@_attrs_define
class SecretProject:
    """
    Attributes:
        created_at (str):
        id (str):
        name (str):
        org_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        secret_count (int | Unset):
    """

    created_at: str
    id: str
    name: str
    org_id: str
    schema: str | Unset = UNSET
    secret_count: int | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        id = self.id

        name = self.name

        org_id = self.org_id

        schema = self.schema

        secret_count = self.secret_count

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "id": id,
                "name": name,
                "org_id": org_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if secret_count is not UNSET:
            field_dict["secret_count"] = secret_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        id = d.pop("id")

        name = d.pop("name")

        org_id = d.pop("org_id")

        schema = d.pop("$schema", UNSET)

        secret_count = d.pop("secret_count", UNSET)

        secret_project = cls(
            created_at=created_at,
            id=id,
            name=name,
            org_id=org_id,
            schema=schema,
            secret_count=secret_count,
        )

        return secret_project
