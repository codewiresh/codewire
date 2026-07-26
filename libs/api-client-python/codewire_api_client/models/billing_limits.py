from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

if TYPE_CHECKING:
    from ..models.billing_limit_usage import BillingLimitUsage


T = TypeVar("T", bound="BillingLimits")


@_attrs_define
class BillingLimits:
    """
    Attributes:
        concurrent_workspaces (int):
        storage_gb (int):
        team_members (BillingLimitUsage):
    """

    concurrent_workspaces: int
    storage_gb: int
    team_members: BillingLimitUsage

    def to_dict(self) -> dict[str, Any]:
        concurrent_workspaces = self.concurrent_workspaces

        storage_gb = self.storage_gb

        team_members = self.team_members.to_dict()

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "concurrent_workspaces": concurrent_workspaces,
                "storage_gb": storage_gb,
                "team_members": team_members,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.billing_limit_usage import BillingLimitUsage

        d = dict(src_dict)
        concurrent_workspaces = d.pop("concurrent_workspaces")

        storage_gb = d.pop("storage_gb")

        team_members = BillingLimitUsage.from_dict(d.pop("team_members"))

        billing_limits = cls(
            concurrent_workspaces=concurrent_workspaces,
            storage_gb=storage_gb,
            team_members=team_members,
        )

        return billing_limits
