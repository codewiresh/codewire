from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAPIKeyBody")


@_attrs_define
class CreateAPIKeyBody:
    """
    Attributes:
        name (str): Display name for the key
        schema (str | Unset): A URL to the JSON Schema for this object.
        expires_in_days (int | Unset): Expiration in days from now
        scopes (list[str] | None | Unset): Scopes for the key
    """

    name: str
    schema: str | Unset = UNSET
    expires_in_days: int | Unset = UNSET
    scopes: list[str] | None | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        schema = self.schema

        expires_in_days = self.expires_in_days

        scopes: list[str] | None | Unset
        if isinstance(self.scopes, Unset):
            scopes = UNSET
        elif isinstance(self.scopes, list):
            scopes = self.scopes

        else:
            scopes = self.scopes

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "name": name,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if expires_in_days is not UNSET:
            field_dict["expires_in_days"] = expires_in_days
        if scopes is not UNSET:
            field_dict["scopes"] = scopes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        schema = d.pop("$schema", UNSET)

        expires_in_days = d.pop("expires_in_days", UNSET)

        def _parse_scopes(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                scopes_type_0 = cast(list[str], data)

                return scopes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        scopes = _parse_scopes(d.pop("scopes", UNSET))

        create_api_key_body = cls(
            name=name,
            schema=schema,
            expires_in_days=expires_in_days,
            scopes=scopes,
        )

        return create_api_key_body
