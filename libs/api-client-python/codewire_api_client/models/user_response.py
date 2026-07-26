from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

T = TypeVar("T", bound="UserResponse")


@_attrs_define
class UserResponse:
    """
    Attributes:
        created_at (str):
        email (str):
        email_verified (bool):
        id (str):
        image (None | str):
        is_admin (bool):
        name (None | str):
        two_factor_enabled (bool):
    """

    created_at: str
    email: str
    email_verified: bool
    id: str
    image: None | str
    is_admin: bool
    name: None | str
    two_factor_enabled: bool

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at

        email = self.email

        email_verified = self.email_verified

        id = self.id

        image: None | str
        image = self.image

        is_admin = self.is_admin

        name: None | str
        name = self.name

        two_factor_enabled = self.two_factor_enabled

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "created_at": created_at,
                "email": email,
                "email_verified": email_verified,
                "id": id,
                "image": image,
                "is_admin": is_admin,
                "name": name,
                "two_factor_enabled": two_factor_enabled,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = d.pop("created_at")

        email = d.pop("email")

        email_verified = d.pop("email_verified")

        id = d.pop("id")

        def _parse_image(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        image = _parse_image(d.pop("image"))

        is_admin = d.pop("is_admin")

        def _parse_name(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        name = _parse_name(d.pop("name"))

        two_factor_enabled = d.pop("two_factor_enabled")

        user_response = cls(
            created_at=created_at,
            email=email,
            email_verified=email_verified,
            id=id,
            image=image,
            is_admin=is_admin,
            name=name,
            two_factor_enabled=two_factor_enabled,
        )

        return user_response
