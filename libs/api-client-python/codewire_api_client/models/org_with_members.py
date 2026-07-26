from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..models.organization_deletion_state import OrganizationDeletionState
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.org_member import OrgMember


T = TypeVar("T", bound="OrgWithMembers")


@_attrs_define
class OrgWithMembers:
    """
    Attributes:
        created_at (str):
        created_by (str):
        id (str):
        members (list[OrgMember] | None):
        name (str):
        slug (str):
        updated_at (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        deletion_failure_code (None | str | Unset):
        deletion_operation_id (None | str | Unset):
        deletion_state (None | OrganizationDeletionState | Unset):
    """

    created_at: str
    created_by: str
    id: str
    members: list[OrgMember] | None
    name: str
    slug: str
    updated_at: str
    schema: str | Unset = UNSET
    deletion_failure_code: None | str | Unset = UNSET
    deletion_operation_id: None | str | Unset = UNSET
    deletion_state: None | OrganizationDeletionState | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        created_by = self.created_by

        id = self.id

        members: list[dict[str, Any]] | None
        if isinstance(self.members, list):
            members = []
            for members_type_0_item_data in self.members:
                members_type_0_item = members_type_0_item_data.to_dict()
                members.append(members_type_0_item)

        else:
            members = self.members

        name = self.name

        slug = self.slug

        updated_at = self.updated_at

        schema = self.schema

        deletion_failure_code = self.deletion_failure_code

        deletion_operation_id = self.deletion_operation_id

        deletion_state: None | str | Unset
        if isinstance(self.deletion_state, Unset):
            deletion_state = UNSET
        elif isinstance(self.deletion_state, OrganizationDeletionState):
            deletion_state = self.deletion_state.value
        else:
            deletion_state = self.deletion_state

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "created_by": created_by,
                "id": id,
                "members": members,
                "name": name,
                "slug": slug,
                "updated_at": updated_at,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if deletion_failure_code is not UNSET:
            field_dict["deletion_failure_code"] = deletion_failure_code
        if deletion_operation_id is not UNSET:
            field_dict["deletion_operation_id"] = deletion_operation_id
        if deletion_state is not UNSET:
            field_dict["deletion_state"] = deletion_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.org_member import OrgMember

        d = dict(src_dict)
        created_at = d.pop("created_at")

        created_by = d.pop("created_by")

        id = d.pop("id")

        def _parse_members(data: object) -> list[OrgMember] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                members_type_0 = []
                _members_type_0 = data
                for members_type_0_item_data in _members_type_0:
                    members_type_0_item = OrgMember.from_dict(members_type_0_item_data)

                    members_type_0.append(members_type_0_item)

                return members_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[OrgMember] | None, data)

        members = _parse_members(d.pop("members"))

        name = d.pop("name")

        slug = d.pop("slug")

        updated_at = d.pop("updated_at")

        schema = d.pop("$schema", UNSET)

        def _parse_deletion_failure_code(data: object) -> None | str | Unset:
            if data is None or isinstance(data, Unset):
                return data
            if isinstance(data, str):
                return data
            return cast(None | str | Unset, data)

        deletion_failure_code = _parse_deletion_failure_code(d.pop("deletion_failure_code", UNSET))

        def _parse_deletion_operation_id(data: object) -> None | str | Unset:
            if data is None or isinstance(data, Unset):
                return data
            if isinstance(data, str):
                return data
            return cast(None | str | Unset, data)

        deletion_operation_id = _parse_deletion_operation_id(d.pop("deletion_operation_id", UNSET))

        def _parse_deletion_state(data: object) -> None | OrganizationDeletionState | Unset:
            if data is None or isinstance(data, Unset):
                return data
            try:
                return OrganizationDeletionState(data)
            except ValueError:
                return cast(None | OrganizationDeletionState | Unset, data)

        deletion_state = _parse_deletion_state(d.pop("deletion_state", UNSET))

        org_with_members = cls(
            created_at=created_at,
            created_by=created_by,
            id=id,
            members=members,
            name=name,
            slug=slug,
            updated_at=updated_at,
            schema=schema,
            deletion_failure_code=deletion_failure_code,
            deletion_operation_id=deletion_operation_id,
            deletion_state=deletion_state,
        )

        return org_with_members
