from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="GitHubStatusOutputBody")


@_attrs_define
class GitHubStatusOutputBody:
    """
    Attributes:
        connected (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
        connected_at (str | Unset):
        installation_id (int | Unset):
        username (str | Unset):
    """

    connected: bool
    schema: str | Unset = UNSET
    connected_at: str | Unset = UNSET
    installation_id: int | Unset = UNSET
    username: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        connected = self.connected

        schema = self.schema

        connected_at = self.connected_at

        installation_id = self.installation_id

        username = self.username

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "connected": connected,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if connected_at is not UNSET:
            field_dict["connected_at"] = connected_at
        if installation_id is not UNSET:
            field_dict["installation_id"] = installation_id
        if username is not UNSET:
            field_dict["username"] = username

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        connected = d.pop("connected")

        schema = d.pop("$schema", UNSET)

        connected_at = d.pop("connected_at", UNSET)

        installation_id = d.pop("installation_id", UNSET)

        username = d.pop("username", UNSET)

        git_hub_status_output_body = cls(
            connected=connected,
            schema=schema,
            connected_at=connected_at,
            installation_id=installation_id,
            username=username,
        )

        return git_hub_status_output_body
