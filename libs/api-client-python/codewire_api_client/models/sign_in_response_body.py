from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.session_response import SessionResponse
    from ..models.user_response import UserResponse


T = TypeVar("T", bound="SignInResponseBody")


@_attrs_define
class SignInResponseBody:
    """
    Attributes:
        schema (str | Unset): A URL to the JSON Schema for this object.
        session (SessionResponse | Unset):
        skip_2fa_setup (bool | Unset):
        two_factor_required (bool | Unset):
        two_factor_token (str | Unset):
        user (UserResponse | Unset):
    """

    schema: str | Unset = UNSET
    session: SessionResponse | Unset = UNSET
    skip_2fa_setup: bool | Unset = UNSET
    two_factor_required: bool | Unset = UNSET
    two_factor_token: str | Unset = UNSET
    user: UserResponse | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        schema = self.schema

        session: dict[str, Any] | Unset = UNSET
        if not isinstance(self.session, Unset):
            session = self.session.to_dict()

        skip_2fa_setup = self.skip_2fa_setup

        two_factor_required = self.two_factor_required

        two_factor_token = self.two_factor_token

        user: dict[str, Any] | Unset = UNSET
        if not isinstance(self.user, Unset):
            user = self.user.to_dict()

        field_dict: dict[str, Any] = {}

        field_dict.update({})
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if session is not UNSET:
            field_dict["session"] = session
        if skip_2fa_setup is not UNSET:
            field_dict["skip_2fa_setup"] = skip_2fa_setup
        if two_factor_required is not UNSET:
            field_dict["twoFactorRequired"] = two_factor_required
        if two_factor_token is not UNSET:
            field_dict["twoFactorToken"] = two_factor_token
        if user is not UNSET:
            field_dict["user"] = user

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.session_response import SessionResponse
        from ..models.user_response import UserResponse

        d = dict(src_dict)
        schema = d.pop("$schema", UNSET)

        _session = d.pop("session", UNSET)
        session: SessionResponse | Unset
        if isinstance(_session, Unset):
            session = UNSET
        else:
            session = SessionResponse.from_dict(_session)

        skip_2fa_setup = d.pop("skip_2fa_setup", UNSET)

        two_factor_required = d.pop("twoFactorRequired", UNSET)

        two_factor_token = d.pop("twoFactorToken", UNSET)

        _user = d.pop("user", UNSET)
        user: UserResponse | Unset
        if isinstance(_user, Unset):
            user = UNSET
        else:
            user = UserResponse.from_dict(_user)

        sign_in_response_body = cls(
            schema=schema,
            session=session,
            skip_2fa_setup=skip_2fa_setup,
            two_factor_required=two_factor_required,
            two_factor_token=two_factor_token,
            user=user,
        )

        return sign_in_response_body
