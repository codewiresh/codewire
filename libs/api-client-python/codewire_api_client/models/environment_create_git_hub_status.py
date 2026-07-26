from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnvironmentCreateGitHubStatus")


@_attrs_define
class EnvironmentCreateGitHubStatus:
    """
    Attributes:
        connected (bool):
        connected_at (str | Unset):
        installation_id (int | Unset):
        username (str | Unset):
    """

    connected: bool
    connected_at: str | Unset = UNSET
    installation_id: int | Unset = UNSET
    username: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        connected = self.connected

        connected_at = self.connected_at

        installation_id = self.installation_id

        username = self.username

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "connected": connected,
            }
        )
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

        connected_at = d.pop("connected_at", UNSET)

        installation_id = d.pop("installation_id", UNSET)

        username = d.pop("username", UNSET)

        environment_create_git_hub_status = cls(
            connected=connected,
            connected_at=connected_at,
            installation_id=installation_id,
            username=username,
        )

        return environment_create_git_hub_status
