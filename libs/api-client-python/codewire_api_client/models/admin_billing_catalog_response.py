from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.admin_billing_catalog_plan import AdminBillingCatalogPlan
    from ..models.admin_billing_catalog_price import AdminBillingCatalogPrice
    from ..models.admin_billing_catalog_setting import AdminBillingCatalogSetting


T = TypeVar("T", bound="AdminBillingCatalogResponse")


@_attrs_define
class AdminBillingCatalogResponse:
    """
    Attributes:
        plans (list[AdminBillingCatalogPlan] | None):
        prices (list[AdminBillingCatalogPrice] | None):
        settings (list[AdminBillingCatalogSetting] | None):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    plans: list[AdminBillingCatalogPlan] | None
    prices: list[AdminBillingCatalogPrice] | None
    settings: list[AdminBillingCatalogSetting] | None
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        plans: list[dict[str, Any]] | None
        if isinstance(self.plans, list):
            plans = []
            for plans_type_0_item_data in self.plans:
                plans_type_0_item = plans_type_0_item_data.to_dict()
                plans.append(plans_type_0_item)

        else:
            plans = self.plans

        prices: list[dict[str, Any]] | None
        if isinstance(self.prices, list):
            prices = []
            for prices_type_0_item_data in self.prices:
                prices_type_0_item = prices_type_0_item_data.to_dict()
                prices.append(prices_type_0_item)

        else:
            prices = self.prices

        settings: list[dict[str, Any]] | None
        if isinstance(self.settings, list):
            settings = []
            for settings_type_0_item_data in self.settings:
                settings_type_0_item = settings_type_0_item_data.to_dict()
                settings.append(settings_type_0_item)

        else:
            settings = self.settings

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "plans": plans,
                "prices": prices,
                "settings": settings,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_billing_catalog_plan import AdminBillingCatalogPlan
        from ..models.admin_billing_catalog_price import AdminBillingCatalogPrice
        from ..models.admin_billing_catalog_setting import AdminBillingCatalogSetting

        d = dict(src_dict)

        def _parse_plans(data: object) -> list[AdminBillingCatalogPlan] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                plans_type_0 = []
                _plans_type_0 = data
                for plans_type_0_item_data in _plans_type_0:
                    plans_type_0_item = AdminBillingCatalogPlan.from_dict(plans_type_0_item_data)

                    plans_type_0.append(plans_type_0_item)

                return plans_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminBillingCatalogPlan] | None, data)

        plans = _parse_plans(d.pop("plans"))

        def _parse_prices(data: object) -> list[AdminBillingCatalogPrice] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                prices_type_0 = []
                _prices_type_0 = data
                for prices_type_0_item_data in _prices_type_0:
                    prices_type_0_item = AdminBillingCatalogPrice.from_dict(prices_type_0_item_data)

                    prices_type_0.append(prices_type_0_item)

                return prices_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminBillingCatalogPrice] | None, data)

        prices = _parse_prices(d.pop("prices"))

        def _parse_settings(data: object) -> list[AdminBillingCatalogSetting] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                settings_type_0 = []
                _settings_type_0 = data
                for settings_type_0_item_data in _settings_type_0:
                    settings_type_0_item = AdminBillingCatalogSetting.from_dict(settings_type_0_item_data)

                    settings_type_0.append(settings_type_0_item)

                return settings_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminBillingCatalogSetting] | None, data)

        settings = _parse_settings(d.pop("settings"))

        schema = d.pop("$schema", UNSET)

        admin_billing_catalog_response = cls(
            plans=plans,
            prices=prices,
            settings=settings,
            schema=schema,
        )

        return admin_billing_catalog_response
