from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="SessionResponse")


@_attrs_define
class SessionResponse:
    """
    Attributes:
        expires_at (str):
        id (str):
        token (str):
    """

    expires_at: str
    id: str
    token: str

    def to_dict(self) -> dict[str, Any]:
        expires_at = self.expires_at

        id = self.id

        token = self.token

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "expires_at": expires_at,
                "id": id,
                "token": token,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        expires_at = d.pop("expires_at")

        id = d.pop("id")

        token = d.pop("token")

        session_response = cls(
            expires_at=expires_at,
            id=id,
            token=token,
        )

        return session_response
