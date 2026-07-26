from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="FileEntry")


@_attrs_define
class FileEntry:
    """
    Attributes:
        is_dir (bool):
        mod_time (str):
        mode (str):
        name (str):
        size (int):
    """

    is_dir: bool
    mod_time: str
    mode: str
    name: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        is_dir = self.is_dir

        mod_time = self.mod_time

        mode = self.mode

        name = self.name

        size = self.size

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "is_dir": is_dir,
                "mod_time": mod_time,
                "mode": mode,
                "name": name,
                "size": size,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        is_dir = d.pop("is_dir")

        mod_time = d.pop("mod_time")

        mode = d.pop("mode")

        name = d.pop("name")

        size = d.pop("size")

        file_entry = cls(
            is_dir=is_dir,
            mod_time=mod_time,
            mode=mode,
            name=name,
            size=size,
        )

        return file_entry
