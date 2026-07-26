from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SaveGitHubTokenInputBody")


@_attrs_define
class SaveGitHubTokenInputBody:
    """
    Attributes:
        access_token (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        expires_at (str | Unset):
        github_username (str | Unset):
        installation_id (int | Unset):
        refresh_token (str | Unset):
        refresh_token_expires_at (str | Unset):
        token_type (str | Unset):
    """

    access_token: str
    schema: str | Unset = UNSET
    expires_at: str | Unset = UNSET
    github_username: str | Unset = UNSET
    installation_id: int | Unset = UNSET
    refresh_token: str | Unset = UNSET
    refresh_token_expires_at: str | Unset = UNSET
    token_type: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        access_token = self.access_token

        schema = self.schema

        expires_at = self.expires_at

        github_username = self.github_username

        installation_id = self.installation_id

        refresh_token = self.refresh_token

        refresh_token_expires_at = self.refresh_token_expires_at

        token_type = self.token_type

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "access_token": access_token,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if github_username is not UNSET:
            field_dict["github_username"] = github_username
        if installation_id is not UNSET:
            field_dict["installation_id"] = installation_id
        if refresh_token is not UNSET:
            field_dict["refresh_token"] = refresh_token
        if refresh_token_expires_at is not UNSET:
            field_dict["refresh_token_expires_at"] = refresh_token_expires_at
        if token_type is not UNSET:
            field_dict["token_type"] = token_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        access_token = d.pop("access_token")

        schema = d.pop("$schema", UNSET)

        expires_at = d.pop("expires_at", UNSET)

        github_username = d.pop("github_username", UNSET)

        installation_id = d.pop("installation_id", UNSET)

        refresh_token = d.pop("refresh_token", UNSET)

        refresh_token_expires_at = d.pop("refresh_token_expires_at", UNSET)

        token_type = d.pop("token_type", UNSET)

        save_git_hub_token_input_body = cls(
            access_token=access_token,
            schema=schema,
            expires_at=expires_at,
            github_username=github_username,
            installation_id=installation_id,
            refresh_token=refresh_token,
            refresh_token_expires_at=refresh_token_expires_at,
            token_type=token_type,
        )

        return save_git_hub_token_input_body
