from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdminEnvironmentStartupPhaseSummary")


@_attrs_define
class AdminEnvironmentStartupPhaseSummary:
    """
    Attributes:
        phase (str):
        sample_count (int):
        p50_ms (int | Unset):
        p95_ms (int | Unset):
    """

    phase: str
    sample_count: int
    p50_ms: int | Unset = UNSET
    p95_ms: int | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        phase = self.phase

        sample_count = self.sample_count

        p50_ms = self.p50_ms

        p95_ms = self.p95_ms

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "phase": phase,
                "sample_count": sample_count,
            }
        )
        if p50_ms is not UNSET:
            field_dict["p50_ms"] = p50_ms
        if p95_ms is not UNSET:
            field_dict["p95_ms"] = p95_ms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        phase = d.pop("phase")

        sample_count = d.pop("sample_count")

        p50_ms = d.pop("p50_ms", UNSET)

        p95_ms = d.pop("p95_ms", UNSET)

        admin_environment_startup_phase_summary = cls(
            phase=phase,
            sample_count=sample_count,
            p50_ms=p50_ms,
            p95_ms=p95_ms,
        )

        return admin_environment_startup_phase_summary
