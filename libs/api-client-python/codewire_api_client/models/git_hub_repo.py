from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="GitHubRepo")


@_attrs_define
class GitHubRepo:
    """
    Attributes:
        clone_url (str):
        default_branch (str):
        full_name (str):
        html_url (str):
        private (bool):
        updated_at (str):
        description (str | Unset):
        language (str | Unset):
    """

    clone_url: str
    default_branch: str
    full_name: str
    html_url: str
    private: bool
    updated_at: str
    description: str | Unset = UNSET
    language: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        clone_url = self.clone_url

        default_branch = self.default_branch

        full_name = self.full_name

        html_url = self.html_url

        private = self.private

        updated_at = self.updated_at

        description = self.description

        language = self.language

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "clone_url": clone_url,
                "default_branch": default_branch,
                "full_name": full_name,
                "html_url": html_url,
                "private": private,
                "updated_at": updated_at,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if language is not UNSET:
            field_dict["language"] = language

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        clone_url = d.pop("clone_url")

        default_branch = d.pop("default_branch")

        full_name = d.pop("full_name")

        html_url = d.pop("html_url")

        private = d.pop("private")

        updated_at = d.pop("updated_at")

        description = d.pop("description", UNSET)

        language = d.pop("language", UNSET)

        git_hub_repo = cls(
            clone_url=clone_url,
            default_branch=default_branch,
            full_name=full_name,
            html_url=html_url,
            private=private,
            updated_at=updated_at,
            description=description,
            language=language,
        )

        return git_hub_repo
