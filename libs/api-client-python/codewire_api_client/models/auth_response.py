from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.session_response import SessionResponse
    from ..models.user_response import UserResponse


T = TypeVar("T", bound="AuthResponse")


@_attrs_define
class AuthResponse:
    """
    Attributes:
        session (SessionResponse):
        user (UserResponse):
        schema (str | Unset): A URL to the JSON Schema for this object.
        skip_2fa_setup (bool | Unset):
    """

    session: SessionResponse
    user: UserResponse
    schema: str | Unset = UNSET
    skip_2fa_setup: bool | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        session = self.session.to_dict()

        user = self.user.to_dict()

        schema = self.schema

        skip_2fa_setup = self.skip_2fa_setup

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "session": session,
                "user": user,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if skip_2fa_setup is not UNSET:
            field_dict["skip_2fa_setup"] = skip_2fa_setup

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.session_response import SessionResponse
        from ..models.user_response import UserResponse

        d = dict(src_dict)
        session = SessionResponse.from_dict(d.pop("session"))

        user = UserResponse.from_dict(d.pop("user"))

        schema = d.pop("$schema", UNSET)

        skip_2fa_setup = d.pop("skip_2fa_setup", UNSET)

        auth_response = cls(
            session=session,
            user=user,
            schema=schema,
            skip_2fa_setup=skip_2fa_setup,
        )

        return auth_response
