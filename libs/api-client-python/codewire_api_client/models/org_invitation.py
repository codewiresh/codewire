from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="OrgInvitation")


@_attrs_define
class OrgInvitation:
    """
    Attributes:
        created_at (str):
        email (str):
        expires_at (str):
        id (str):
        invited_by (str):
        inviter_name (None | str):
        org_id (str):
        org_name (str):
        role (str):
        status (str):
        token (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        accepted_at (str | Unset):
    """

    created_at: str
    email: str
    expires_at: str
    id: str
    invited_by: str
    inviter_name: None | str
    org_id: str
    org_name: str
    role: str
    status: str
    token: str
    schema: str | Unset = UNSET
    accepted_at: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        email = self.email

        expires_at = self.expires_at

        id = self.id

        invited_by = self.invited_by

        inviter_name: None | str
        inviter_name = self.inviter_name

        org_id = self.org_id

        org_name = self.org_name

        role = self.role

        status = self.status

        token = self.token

        schema = self.schema

        accepted_at = self.accepted_at

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "email": email,
                "expires_at": expires_at,
                "id": id,
                "invited_by": invited_by,
                "inviter_name": inviter_name,
                "org_id": org_id,
                "org_name": org_name,
                "role": role,
                "status": status,
                "token": token,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if accepted_at is not UNSET:
            field_dict["accepted_at"] = accepted_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        email = d.pop("email")

        expires_at = d.pop("expires_at")

        id = d.pop("id")

        invited_by = d.pop("invited_by")

        def _parse_inviter_name(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        inviter_name = _parse_inviter_name(d.pop("inviter_name"))

        org_id = d.pop("org_id")

        org_name = d.pop("org_name")

        role = d.pop("role")

        status = d.pop("status")

        token = d.pop("token")

        schema = d.pop("$schema", UNSET)

        accepted_at = d.pop("accepted_at", UNSET)

        org_invitation = cls(
            created_at=created_at,
            email=email,
            expires_at=expires_at,
            id=id,
            invited_by=invited_by,
            inviter_name=inviter_name,
            org_id=org_id,
            org_name=org_name,
            role=role,
            status=status,
            token=token,
            schema=schema,
            accepted_at=accepted_at,
        )

        return org_invitation
