from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="OrgWithRole")


@_attrs_define
class OrgWithRole:
    """
    Attributes:
        billing_plan (str):
        billing_status (str):
        created_at (str):
        created_by (str):
        id (str):
        name (str):
        role (str):
        slug (str):
        trial_ends_at (None | str):
        updated_at (str):
        assignments (list[str] | None | Unset):
    """

    billing_plan: str
    billing_status: str
    created_at: str
    created_by: str
    id: str
    name: str
    role: str
    slug: str
    trial_ends_at: None | str
    updated_at: str
    assignments: list[str] | None | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        billing_plan = self.billing_plan

        billing_status = self.billing_status

        created_at = self.created_at

        created_by = self.created_by

        id = self.id

        name = self.name

        role = self.role

        slug = self.slug

        trial_ends_at: None | str
        trial_ends_at = self.trial_ends_at

        updated_at = self.updated_at

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
                "billing_plan": billing_plan,
                "billing_status": billing_status,
                "created_at": created_at,
                "created_by": created_by,
                "id": id,
                "name": name,
                "role": role,
                "slug": slug,
                "trial_ends_at": trial_ends_at,
                "updated_at": updated_at,
            }
        )
        if assignments is not UNSET:
            field_dict["assignments"] = assignments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        billing_plan = d.pop("billing_plan")

        billing_status = d.pop("billing_status")

        created_at = d.pop("created_at")

        created_by = d.pop("created_by")

        id = d.pop("id")

        name = d.pop("name")

        role = d.pop("role")

        slug = d.pop("slug")

        def _parse_trial_ends_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        trial_ends_at = _parse_trial_ends_at(d.pop("trial_ends_at"))

        updated_at = d.pop("updated_at")

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

        org_with_role = cls(
            billing_plan=billing_plan,
            billing_status=billing_status,
            created_at=created_at,
            created_by=created_by,
            id=id,
            name=name,
            role=role,
            slug=slug,
            trial_ends_at=trial_ends_at,
            updated_at=updated_at,
            assignments=assignments,
        )

        return org_with_role
