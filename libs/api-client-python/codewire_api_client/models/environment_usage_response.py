from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.environment_usage_entry import EnvironmentUsageEntry
    from ..models.environment_usage_hour import EnvironmentUsageHour
    from ..models.environment_usage_month import EnvironmentUsageMonth


T = TypeVar("T", bound="EnvironmentUsageResponse")


@_attrs_define
class EnvironmentUsageResponse:
    """
    Attributes:
        current_month (EnvironmentUsageMonth):
        hourly_breakdown (list[EnvironmentUsageHour] | None):
        per_environment (list[EnvironmentUsageEntry] | None):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    current_month: EnvironmentUsageMonth
    hourly_breakdown: list[EnvironmentUsageHour] | None
    per_environment: list[EnvironmentUsageEntry] | None
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        current_month = self.current_month.to_dict()

        hourly_breakdown: list[dict[str, Any]] | None
        if isinstance(self.hourly_breakdown, list):
            hourly_breakdown = []
            for hourly_breakdown_type_0_item_data in self.hourly_breakdown:
                hourly_breakdown_type_0_item = hourly_breakdown_type_0_item_data.to_dict()
                hourly_breakdown.append(hourly_breakdown_type_0_item)

        else:
            hourly_breakdown = self.hourly_breakdown

        per_environment: list[dict[str, Any]] | None
        if isinstance(self.per_environment, list):
            per_environment = []
            for per_environment_type_0_item_data in self.per_environment:
                per_environment_type_0_item = per_environment_type_0_item_data.to_dict()
                per_environment.append(per_environment_type_0_item)

        else:
            per_environment = self.per_environment

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "current_month": current_month,
                "hourly_breakdown": hourly_breakdown,
                "per_environment": per_environment,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.environment_usage_entry import EnvironmentUsageEntry
        from ..models.environment_usage_hour import EnvironmentUsageHour
        from ..models.environment_usage_month import EnvironmentUsageMonth

        d = dict(src_dict)
        current_month = EnvironmentUsageMonth.from_dict(d.pop("current_month"))

        def _parse_hourly_breakdown(data: object) -> list[EnvironmentUsageHour] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                hourly_breakdown_type_0 = []
                _hourly_breakdown_type_0 = data
                for hourly_breakdown_type_0_item_data in _hourly_breakdown_type_0:
                    hourly_breakdown_type_0_item = EnvironmentUsageHour.from_dict(hourly_breakdown_type_0_item_data)

                    hourly_breakdown_type_0.append(hourly_breakdown_type_0_item)

                return hourly_breakdown_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[EnvironmentUsageHour] | None, data)

        hourly_breakdown = _parse_hourly_breakdown(d.pop("hourly_breakdown"))

        def _parse_per_environment(data: object) -> list[EnvironmentUsageEntry] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                per_environment_type_0 = []
                _per_environment_type_0 = data
                for per_environment_type_0_item_data in _per_environment_type_0:
                    per_environment_type_0_item = EnvironmentUsageEntry.from_dict(per_environment_type_0_item_data)

                    per_environment_type_0.append(per_environment_type_0_item)

                return per_environment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[EnvironmentUsageEntry] | None, data)

        per_environment = _parse_per_environment(d.pop("per_environment"))

        schema = d.pop("$schema", UNSET)

        environment_usage_response = cls(
            current_month=current_month,
            hourly_breakdown=hourly_breakdown,
            per_environment=per_environment,
            schema=schema,
        )

        return environment_usage_response
