from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnableTwoFactorResult")


@_attrs_define
class EnableTwoFactorResult:
    """
    Attributes:
        backup_codes (list[str] | None):
        secret (str):
        totp_uri (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    backup_codes: list[str] | None
    secret: str
    totp_uri: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        backup_codes: list[str] | None
        if isinstance(self.backup_codes, list):
            backup_codes = self.backup_codes

        else:
            backup_codes = self.backup_codes

        secret = self.secret

        totp_uri = self.totp_uri

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "backupCodes": backup_codes,
                "secret": secret,
                "totpUri": totp_uri,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_backup_codes(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                backup_codes_type_0 = cast(list[str], data)

                return backup_codes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        backup_codes = _parse_backup_codes(d.pop("backupCodes"))

        secret = d.pop("secret")

        totp_uri = d.pop("totpUri")

        schema = d.pop("$schema", UNSET)

        enable_two_factor_result = cls(
            backup_codes=backup_codes,
            secret=secret,
            totp_uri=totp_uri,
            schema=schema,
        )

        return enable_two_factor_result
