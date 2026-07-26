from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AcceptInvitationResult")


@_attrs_define
class AcceptInvitationResult:
    """
    Attributes:
        org_id (str):
        status (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    org_id: str
    status: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        status = self.status

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "orgId": org_id,
                "status": status,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("orgId")

        status = d.pop("status")

        schema = d.pop("$schema", UNSET)

        accept_invitation_result = cls(
            org_id=org_id,
            status=status,
            schema=schema,
        )

        return accept_invitation_result
