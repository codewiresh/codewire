from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="OrgMember")


@_attrs_define
class OrgMember:
    """
    Attributes:
        created_at (str):
        email (str):
        id (str):
        image (None | str):
        name (None | str):
        org_id (str):
        role (str):
        user_id (str):
        assignments (list[str] | None | Unset):
    """

    created_at: str
    email: str
    id: str
    image: None | str
    name: None | str
    org_id: str
    role: str
    user_id: str
    assignments: list[str] | None | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        email = self.email

        id = self.id

        image: None | str
        image = self.image

        name: None | str
        name = self.name

        org_id = self.org_id

        role = self.role

        user_id = self.user_id

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
                "created_at": created_at,
                "email": email,
                "id": id,
                "image": image,
                "name": name,
                "org_id": org_id,
                "role": role,
                "user_id": user_id,
            }
        )
        if assignments is not UNSET:
            field_dict["assignments"] = assignments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        email = d.pop("email")

        id = d.pop("id")

        def _parse_image(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        image = _parse_image(d.pop("image"))

        def _parse_name(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        name = _parse_name(d.pop("name"))

        org_id = d.pop("org_id")

        role = d.pop("role")

        user_id = d.pop("user_id")

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

        org_member = cls(
            created_at=created_at,
            email=email,
            id=id,
            image=image,
            name=name,
            org_id=org_id,
            role=role,
            user_id=user_id,
            assignments=assignments,
        )

        return org_member
