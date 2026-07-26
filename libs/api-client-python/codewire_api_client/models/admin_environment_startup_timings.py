from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.admin_environment_startup_timing import AdminEnvironmentStartupTiming


T = TypeVar("T", bound="AdminEnvironmentStartupTimings")


@_attrs_define
class AdminEnvironmentStartupTimings:
    """
    Attributes:
        created_at (str):
        environment_id (str):
        timings (list[AdminEnvironmentStartupTiming] | None):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    created_at: str
    environment_id: str
    timings: list[AdminEnvironmentStartupTiming] | None
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        environment_id = self.environment_id

        timings: list[dict[str, Any]] | None
        if isinstance(self.timings, list):
            timings = []
            for timings_type_0_item_data in self.timings:
                timings_type_0_item = timings_type_0_item_data.to_dict()
                timings.append(timings_type_0_item)

        else:
            timings = self.timings

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "environment_id": environment_id,
                "timings": timings,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_environment_startup_timing import AdminEnvironmentStartupTiming

        d = dict(src_dict)
        created_at = d.pop("created_at")

        environment_id = d.pop("environment_id")

        def _parse_timings(data: object) -> list[AdminEnvironmentStartupTiming] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                timings_type_0 = []
                _timings_type_0 = data
                for timings_type_0_item_data in _timings_type_0:
                    timings_type_0_item = AdminEnvironmentStartupTiming.from_dict(timings_type_0_item_data)

                    timings_type_0.append(timings_type_0_item)

                return timings_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminEnvironmentStartupTiming] | None, data)

        timings = _parse_timings(d.pop("timings"))

        schema = d.pop("$schema", UNSET)

        admin_environment_startup_timings = cls(
            created_at=created_at,
            environment_id=environment_id,
            timings=timings,
            schema=schema,
        )

        return admin_environment_startup_timings
