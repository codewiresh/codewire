from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectRequest")


@_attrs_define
class DetectRequest:
    """
    Attributes:
        repo_url (str): Git repository URL
        schema (str | Unset): A URL to the JSON Schema for this object.
        branch (str | Unset): Branch to analyze (default: repo default)
        github_token (str | Unset): Optional GitHub token for private repos
    """

    repo_url: str
    schema: str | Unset = UNSET
    branch: str | Unset = UNSET
    github_token: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        repo_url = self.repo_url

        schema = self.schema

        branch = self.branch

        github_token = self.github_token

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "repo_url": repo_url,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if branch is not UNSET:
            field_dict["branch"] = branch
        if github_token is not UNSET:
            field_dict["github_token"] = github_token

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_url = d.pop("repo_url")

        schema = d.pop("$schema", UNSET)

        branch = d.pop("branch", UNSET)

        github_token = d.pop("github_token", UNSET)

        detect_request = cls(
            repo_url=repo_url,
            schema=schema,
            branch=branch,
            github_token=github_token,
        )

        return detect_request
