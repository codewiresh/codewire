from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="InviteMemberRequest")


@_attrs_define
class InviteMemberRequest:
    """
    Attributes:
        email (str):
        role (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        assignments (list[str] | None | Unset): Assignments to grant (default: viewer)
    """

    email: str
    role: str
    schema: str | Unset = UNSET
    assignments: list[str] | None | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        role = self.role

        schema = self.schema

        assignments: list[str] | None | Unset
        if isinstance(self.assignments, Unset):
            assignments = UNSET
        elif isinstance(self.assignments, list):
            assignments = self.assignments

        else:
            assignments = self.assignments

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "email": email,
                "role": role,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if assignments is not UNSET:
            field_dict["assignments"] = assignments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        role = d.pop("role")

        schema = d.pop("$schema", UNSET)

        def _parse_assignments(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                assignments_type_0 = cast(list[str], data)

                return assignments_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        assignments = _parse_assignments(d.pop("assignments", UNSET))

        invite_member_request = cls(
            email=email,
            role=role,
            schema=schema,
            assignments=assignments,
        )

        return invite_member_request
