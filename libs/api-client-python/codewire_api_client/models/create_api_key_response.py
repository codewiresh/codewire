from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAPIKeyResponse")


@_attrs_define
class CreateAPIKeyResponse:
    """
    Attributes:
        created_at (str):
        id (str):
        key (str): Full API key (shown only once)
        key_prefix (str):
        name (str):
        org_id (str):
        scopes (list[str] | None):
        user_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        created_by_email (str | Unset):
        created_by_name (str | Unset):
        disabled_at (str | Unset):
        expires_at (str | Unset):
        last_used_at (str | Unset):
    """

    created_at: str
    id: str
    key: str
    key_prefix: str
    name: str
    org_id: str
    scopes: list[str] | None
    user_id: str
    schema: str | Unset = UNSET
    created_by_email: str | Unset = UNSET
    created_by_name: str | Unset = UNSET
    disabled_at: str | Unset = UNSET
    expires_at: str | Unset = UNSET
    last_used_at: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        id = self.id

        key = self.key

        key_prefix = self.key_prefix

        name = self.name

        org_id = self.org_id

        scopes: list[str] | None
        if isinstance(self.scopes, list):
            scopes = self.scopes

        else:
            scopes = self.scopes

        user_id = self.user_id

        schema = self.schema

        created_by_email = self.created_by_email

        created_by_name = self.created_by_name

        disabled_at = self.disabled_at

        expires_at = self.expires_at

        last_used_at = self.last_used_at

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "id": id,
                "key": key,
                "key_prefix": key_prefix,
                "name": name,
                "org_id": org_id,
                "scopes": scopes,
                "user_id": user_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if created_by_email is not UNSET:
            field_dict["created_by_email"] = created_by_email
        if created_by_name is not UNSET:
            field_dict["created_by_name"] = created_by_name
        if disabled_at is not UNSET:
            field_dict["disabled_at"] = disabled_at
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if last_used_at is not UNSET:
            field_dict["last_used_at"] = last_used_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        id = d.pop("id")

        key = d.pop("key")

        key_prefix = d.pop("key_prefix")

        name = d.pop("name")

        org_id = d.pop("org_id")

        def _parse_scopes(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                scopes_type_0 = cast(list[str], data)

                return scopes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        scopes = _parse_scopes(d.pop("scopes"))

        user_id = d.pop("user_id")

        schema = d.pop("$schema", UNSET)

        created_by_email = d.pop("created_by_email", UNSET)

        created_by_name = d.pop("created_by_name", UNSET)

        disabled_at = d.pop("disabled_at", UNSET)

        expires_at = d.pop("expires_at", UNSET)

        last_used_at = d.pop("last_used_at", UNSET)

        create_api_key_response = cls(
            created_at=created_at,
            id=id,
            key=key,
            key_prefix=key_prefix,
            name=name,
            org_id=org_id,
            scopes=scopes,
            user_id=user_id,
            schema=schema,
            created_by_email=created_by_email,
            created_by_name=created_by_name,
            disabled_at=disabled_at,
            expires_at=expires_at,
            last_used_at=last_used_at,
        )

        return create_api_key_response
