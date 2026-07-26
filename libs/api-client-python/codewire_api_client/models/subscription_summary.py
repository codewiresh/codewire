from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="SubscriptionSummary")


@_attrs_define
class SubscriptionSummary:
    """
    Attributes:
        monthly_cost_cents (int):
        plan (str):
        plan_display_name (str):
        resource_type (str):
        status (str):
    """

    monthly_cost_cents: int
    plan: str
    plan_display_name: str
    resource_type: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        monthly_cost_cents = self.monthly_cost_cents

        plan = self.plan

        plan_display_name = self.plan_display_name

        resource_type = self.resource_type

        status = self.status

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "monthly_cost_cents": monthly_cost_cents,
                "plan": plan,
                "plan_display_name": plan_display_name,
                "resource_type": resource_type,
                "status": status,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        monthly_cost_cents = d.pop("monthly_cost_cents")

        plan = d.pop("plan")

        plan_display_name = d.pop("plan_display_name")

        resource_type = d.pop("resource_type")

        status = d.pop("status")

        subscription_summary = cls(
            monthly_cost_cents=monthly_cost_cents,
            plan=plan,
            plan_display_name=plan_display_name,
            resource_type=resource_type,
            status=status,
        )

        return subscription_summary
