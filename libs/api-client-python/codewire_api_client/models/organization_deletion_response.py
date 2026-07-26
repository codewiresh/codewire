from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..models.organization_deletion_state import OrganizationDeletionState

T = TypeVar("T", bound="OrganizationDeletionResponse")


@_attrs_define
class OrganizationDeletionResponse:
    """Accepted asynchronous organization deletion.

    Attributes:
        operation_id (str):
        state (OrganizationDeletionState):
    """

    operation_id: str
    state: OrganizationDeletionState

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "state": self.state.value,
        }

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        return cls(
            operation_id=d.pop("operation_id"),
            state=OrganizationDeletionState(d.pop("state")),
        )
