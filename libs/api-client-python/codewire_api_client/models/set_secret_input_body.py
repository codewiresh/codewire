from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetSecretInputBody")


@_attrs_define
class SetSecretInputBody:
    """
    Attributes:
        key (str): Secret key name
        org_id (str): Organization ID
        value (str): Secret value
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    key: str
    org_id: str
    value: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        key = self.key

        org_id = self.org_id

        value = self.value

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "key": key,
                "org_id": org_id,
                "value": value,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        key = d.pop("key")

        org_id = d.pop("org_id")

        value = d.pop("value")

        schema = d.pop("$schema", UNSET)

        set_secret_input_body = cls(
            key=key,
            org_id=org_id,
            value=value,
            schema=schema,
        )

        return set_secret_input_body
