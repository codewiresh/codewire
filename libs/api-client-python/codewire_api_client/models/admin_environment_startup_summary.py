from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.admin_environment_startup_phase_summary import AdminEnvironmentStartupPhaseSummary


T = TypeVar("T", bound="AdminEnvironmentStartupSummary")


@_attrs_define
class AdminEnvironmentStartupSummary:
    """
    Attributes:
        generated_at (str):
        phase_durations (list[AdminEnvironmentStartupPhaseSummary] | None):
        running_without_gateway_ready_count (int):
        starting_backlog_count (int):
        starting_backlog_over_10m_count (int):
        starting_backlog_over_5m_count (int):
        window_minutes (int):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    generated_at: str
    phase_durations: list[AdminEnvironmentStartupPhaseSummary] | None
    running_without_gateway_ready_count: int
    starting_backlog_count: int
    starting_backlog_over_10m_count: int
    starting_backlog_over_5m_count: int
    window_minutes: int
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        generated_at = self.generated_at

        phase_durations: list[dict[str, Any]] | None
        if isinstance(self.phase_durations, list):
            phase_durations = []
            for phase_durations_type_0_item_data in self.phase_durations:
                phase_durations_type_0_item = phase_durations_type_0_item_data.to_dict()
                phase_durations.append(phase_durations_type_0_item)

        else:
            phase_durations = self.phase_durations

        running_without_gateway_ready_count = self.running_without_gateway_ready_count

        starting_backlog_count = self.starting_backlog_count

        starting_backlog_over_10m_count = self.starting_backlog_over_10m_count

        starting_backlog_over_5m_count = self.starting_backlog_over_5m_count

        window_minutes = self.window_minutes

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "generated_at": generated_at,
                "phase_durations": phase_durations,
                "running_without_gateway_ready_count": running_without_gateway_ready_count,
                "starting_backlog_count": starting_backlog_count,
                "starting_backlog_over_10m_count": starting_backlog_over_10m_count,
                "starting_backlog_over_5m_count": starting_backlog_over_5m_count,
                "window_minutes": window_minutes,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admin_environment_startup_phase_summary import AdminEnvironmentStartupPhaseSummary

        d = dict(src_dict)
        generated_at = d.pop("generated_at")

        def _parse_phase_durations(data: object) -> list[AdminEnvironmentStartupPhaseSummary] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                phase_durations_type_0 = []
                _phase_durations_type_0 = data
                for phase_durations_type_0_item_data in _phase_durations_type_0:
                    phase_durations_type_0_item = AdminEnvironmentStartupPhaseSummary.from_dict(
                        phase_durations_type_0_item_data
                    )

                    phase_durations_type_0.append(phase_durations_type_0_item)

                return phase_durations_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminEnvironmentStartupPhaseSummary] | None, data)

        phase_durations = _parse_phase_durations(d.pop("phase_durations"))

        running_without_gateway_ready_count = d.pop("running_without_gateway_ready_count")

        starting_backlog_count = d.pop("starting_backlog_count")

        starting_backlog_over_10m_count = d.pop("starting_backlog_over_10m_count")

        starting_backlog_over_5m_count = d.pop("starting_backlog_over_5m_count")

        window_minutes = d.pop("window_minutes")

        schema = d.pop("$schema", UNSET)

        admin_environment_startup_summary = cls(
            generated_at=generated_at,
            phase_durations=phase_durations,
            running_without_gateway_ready_count=running_without_gateway_ready_count,
            starting_backlog_count=starting_backlog_count,
            starting_backlog_over_10m_count=starting_backlog_over_10m_count,
            starting_backlog_over_5m_count=starting_backlog_over_5m_count,
            window_minutes=window_minutes,
            schema=schema,
        )

        return admin_environment_startup_summary
