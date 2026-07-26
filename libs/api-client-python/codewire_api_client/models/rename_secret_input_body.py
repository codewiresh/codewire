from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="RenameSecretInputBody")


@_attrs_define
class RenameSecretInputBody:
    """
    Attributes:
        new_key (str): New secret key name
        org_id (str): Organization ID
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    new_key: str
    org_id: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        new_key = self.new_key

        org_id = self.org_id

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "new_key": new_key,
                "org_id": org_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_key = d.pop("new_key")

        org_id = d.pop("org_id")

        schema = d.pop("$schema", UNSET)

        rename_secret_input_body = cls(
            new_key=new_key,
            org_id=org_id,
            schema=schema,
        )

        return rename_secret_input_body
