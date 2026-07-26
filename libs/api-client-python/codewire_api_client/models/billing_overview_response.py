from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.billing_limits import BillingLimits
    from ..models.subscription_summary import SubscriptionSummary
    from ..models.usage_summary import UsageSummary


T = TypeVar("T", bound="BillingOverviewResponse")


@_attrs_define
class BillingOverviewResponse:
    """
    Attributes:
        active_subscriptions (int):
        billing_enabled (bool):
        current_month_usage (UsageSummary):
        current_period_end (None | str):
        extra_seat_price_cents (int):
        has_payment_method (bool):
        included_devs (int):
        limits (BillingLimits):
        plan (str):
        plan_display_name (str):
        seat_count (int):
        status (str):
        subscriptions (list[SubscriptionSummary] | None):
        total_monthly_cost_cents (int):
        trial_days (int):
        trial_end (None | str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    active_subscriptions: int
    billing_enabled: bool
    current_month_usage: UsageSummary
    current_period_end: None | str
    extra_seat_price_cents: int
    has_payment_method: bool
    included_devs: int
    limits: BillingLimits
    plan: str
    plan_display_name: str
    seat_count: int
    status: str
    subscriptions: list[SubscriptionSummary] | None
    total_monthly_cost_cents: int
    trial_days: int
    trial_end: None | str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        active_subscriptions = self.active_subscriptions

        billing_enabled = self.billing_enabled

        current_month_usage = self.current_month_usage.to_dict()

        current_period_end: None | str
        current_period_end = self.current_period_end

        extra_seat_price_cents = self.extra_seat_price_cents

        has_payment_method = self.has_payment_method

        included_devs = self.included_devs

        limits = self.limits.to_dict()

        plan = self.plan

        plan_display_name = self.plan_display_name

        seat_count = self.seat_count

        status = self.status

        subscriptions: list[dict[str, Any]] | None
        if isinstance(self.subscriptions, list):
            subscriptions = []
            for subscriptions_type_0_item_data in self.subscriptions:
                subscriptions_type_0_item = subscriptions_type_0_item_data.to_dict()
                subscriptions.append(subscriptions_type_0_item)

        else:
            subscriptions = self.subscriptions

        total_monthly_cost_cents = self.total_monthly_cost_cents

        trial_days = self.trial_days

        trial_end: None | str
        trial_end = self.trial_end

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "active_subscriptions": active_subscriptions,
                "billing_enabled": billing_enabled,
                "current_month_usage": current_month_usage,
                "current_period_end": current_period_end,
                "extra_seat_price_cents": extra_seat_price_cents,
                "has_payment_method": has_payment_method,
                "included_devs": included_devs,
                "limits": limits,
                "plan": plan,
                "plan_display_name": plan_display_name,
                "seat_count": seat_count,
                "status": status,
                "subscriptions": subscriptions,
                "total_monthly_cost_cents": total_monthly_cost_cents,
                "trial_days": trial_days,
                "trial_end": trial_end,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.billing_limits import BillingLimits
        from ..models.subscription_summary import SubscriptionSummary
        from ..models.usage_summary import UsageSummary

        d = dict(src_dict)
        active_subscriptions = d.pop("active_subscriptions")

        billing_enabled = d.pop("billing_enabled")

        current_month_usage = UsageSummary.from_dict(d.pop("current_month_usage"))

        def _parse_current_period_end(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        current_period_end = _parse_current_period_end(d.pop("current_period_end"))

        extra_seat_price_cents = d.pop("extra_seat_price_cents")

        has_payment_method = d.pop("has_payment_method")

        included_devs = d.pop("included_devs")

        limits = BillingLimits.from_dict(d.pop("limits"))

        plan = d.pop("plan")

        plan_display_name = d.pop("plan_display_name")

        seat_count = d.pop("seat_count")

        status = d.pop("status")

        def _parse_subscriptions(data: object) -> list[SubscriptionSummary] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                subscriptions_type_0 = []
                _subscriptions_type_0 = data
                for subscriptions_type_0_item_data in _subscriptions_type_0:
                    subscriptions_type_0_item = SubscriptionSummary.from_dict(subscriptions_type_0_item_data)

                    subscriptions_type_0.append(subscriptions_type_0_item)

                return subscriptions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[SubscriptionSummary] | None, data)

        subscriptions = _parse_subscriptions(d.pop("subscriptions"))

        total_monthly_cost_cents = d.pop("total_monthly_cost_cents")

        trial_days = d.pop("trial_days")

        def _parse_trial_end(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        trial_end = _parse_trial_end(d.pop("trial_end"))

        schema = d.pop("$schema", UNSET)

        billing_overview_response = cls(
            active_subscriptions=active_subscriptions,
            billing_enabled=billing_enabled,
            current_month_usage=current_month_usage,
            current_period_end=current_period_end,
            extra_seat_price_cents=extra_seat_price_cents,
            has_payment_method=has_payment_method,
            included_devs=included_devs,
            limits=limits,
            plan=plan,
            plan_display_name=plan_display_name,
            seat_count=seat_count,
            status=status,
            subscriptions=subscriptions,
            total_monthly_cost_cents=total_monthly_cost_cents,
            trial_days=trial_days,
            trial_end=trial_end,
            schema=schema,
        )

        return billing_overview_response
