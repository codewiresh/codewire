from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SecretMetadata")


@_attrs_define
class SecretMetadata:
    """
    Attributes:
        key (str):
        created_at (str | Unset):
        updated_at (str | Unset):
    """

    key: str
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        key = self.key

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "key": key,
            }
        )
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        key = d.pop("key")

        created_at = d.pop("created_at", UNSET)

        updated_at = d.pop("updated_at", UNSET)

        secret_metadata = cls(
            key=key,
            created_at=created_at,
            updated_at=updated_at,
        )

        return secret_metadata
