from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateMemberAssignmentsInputBody")


@_attrs_define
class UpdateMemberAssignmentsInputBody:
    """
    Attributes:
        assignments (list[str] | None): List of assignments
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    assignments: list[str] | None
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        assignments: list[str] | None
        if isinstance(self.assignments, list):
            assignments = self.assignments

        else:
            assignments = self.assignments

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "assignments": assignments,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_assignments(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                assignments_type_0 = cast(list[str], data)

                return assignments_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        assignments = _parse_assignments(d.pop("assignments"))

        schema = d.pop("$schema", UNSET)

        update_member_assignments_input_body = cls(
            assignments=assignments,
            schema=schema,
        )

        return update_member_assignments_input_body
