from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="AppPort")


@_attrs_define
class AppPort:
    """
    Attributes:
        label (str):
        port (int):
        access (str | Unset):
    """

    label: str
    port: int
    access: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        label = self.label

        port = self.port

        access = self.access

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "label": label,
                "port": port,
            }
        )
        if access is not UNSET:
            field_dict["access"] = access

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        label = d.pop("label")

        port = d.pop("port")

        access = d.pop("access", UNSET)

        app_port = cls(
            label=label,
            port=port,
            access=access,
        )

        return app_port
