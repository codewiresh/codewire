from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="RepoEntry")


@_attrs_define
class RepoEntry:
    """
    Attributes:
        url (str):
        branch (str | Unset):
    """

    url: str
    branch: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        url = self.url

        branch = self.branch

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "url": url,
            }
        )
        if branch is not UNSET:
            field_dict["branch"] = branch

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        url = d.pop("url")

        branch = d.pop("branch", UNSET)

        repo_entry = cls(
            url=url,
            branch=branch,
        )

        return repo_entry
