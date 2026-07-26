from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="GitHubConfigOutputBody")


@_attrs_define
class GitHubConfigOutputBody:
    """
    Attributes:
        app_slug (str):
        client_id (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    app_slug: str
    client_id: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        app_slug = self.app_slug

        client_id = self.client_id

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "app_slug": app_slug,
                "client_id": client_id,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_slug = d.pop("app_slug")

        client_id = d.pop("client_id")

        schema = d.pop("$schema", UNSET)

        git_hub_config_output_body = cls(
            app_slug=app_slug,
            client_id=client_id,
            schema=schema,
        )

        return git_hub_config_output_body
