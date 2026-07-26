from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeleteGitHubTokenOutputBody")


@_attrs_define
class DeleteGitHubTokenOutputBody:
    """
    Attributes:
        ok (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    ok: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        ok = self.ok

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "ok": ok,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ok = d.pop("ok")

        schema = d.pop("$schema", UNSET)

        delete_git_hub_token_output_body = cls(
            ok=ok,
            schema=schema,
        )

        return delete_git_hub_token_output_body
