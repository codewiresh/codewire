from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.secret_metadata import SecretMetadata


T = TypeVar("T", bound="ListProjectSecretsOutputBody")


@_attrs_define
class ListProjectSecretsOutputBody:
    """
    Attributes:
        secrets (list[SecretMetadata] | None):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    secrets: list[SecretMetadata] | None
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        secrets: list[dict[str, Any]] | None
        if isinstance(self.secrets, list):
            secrets = []
            for secrets_type_0_item_data in self.secrets:
                secrets_type_0_item = secrets_type_0_item_data.to_dict()
                secrets.append(secrets_type_0_item)

        else:
            secrets = self.secrets

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "secrets": secrets,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.secret_metadata import SecretMetadata

        d = dict(src_dict)

        def _parse_secrets(data: object) -> list[SecretMetadata] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                secrets_type_0 = []
                _secrets_type_0 = data
                for secrets_type_0_item_data in _secrets_type_0:
                    secrets_type_0_item = SecretMetadata.from_dict(secrets_type_0_item_data)

                    secrets_type_0.append(secrets_type_0_item)

                return secrets_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[SecretMetadata] | None, data)

        secrets = _parse_secrets(d.pop("secrets"))

        schema = d.pop("$schema", UNSET)

        list_project_secrets_output_body = cls(
            secrets=secrets,
            schema=schema,
        )

        return list_project_secrets_output_body
