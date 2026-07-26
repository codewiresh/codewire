from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnvironmentPort")


@_attrs_define
class EnvironmentPort:
    """
    Attributes:
        access (str):
        created_at (str):
        environment_id (str):
        id (str):
        label (str):
        port (int):
        schema (str | Unset): A URL to the JSON Schema for this object.
        preview_url (str | Unset):
    """

    access: str
    created_at: str
    environment_id: str
    id: str
    label: str
    port: int
    schema: str | Unset = UNSET
    preview_url: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        access = self.access

        created_at = self.created_at

        environment_id = self.environment_id

        id = self.id

        label = self.label

        port = self.port

        schema = self.schema

        preview_url = self.preview_url

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "access": access,
                "created_at": created_at,
                "environment_id": environment_id,
                "id": id,
                "label": label,
                "port": port,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if preview_url is not UNSET:
            field_dict["preview_url"] = preview_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        access = d.pop("access")

        created_at = d.pop("created_at")

        environment_id = d.pop("environment_id")

        id = d.pop("id")

        label = d.pop("label")

        port = d.pop("port")

        schema = d.pop("$schema", UNSET)

        preview_url = d.pop("preview_url", UNSET)

        environment_port = cls(
            access=access,
            created_at=created_at,
            environment_id=environment_id,
            id=id,
            label=label,
            port=port,
            schema=schema,
            preview_url=preview_url,
        )

        return environment_port
