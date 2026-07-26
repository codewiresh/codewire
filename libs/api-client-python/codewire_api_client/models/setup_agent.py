from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="SetupAgent")


@_attrs_define
class SetupAgent:
    """
    Attributes:
        type_ (str): AI agent/tool id (claude-code, codex, gemini-cli, aider)
    """

    type_: str

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "type": type_,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = d.pop("type")

        setup_agent = cls(
            type_=type_,
        )

        return setup_agent
