from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePortBody")


@_attrs_define
class CreatePortBody:
    """
    Attributes:
        label (str): DNS-safe label (lowercase alphanumeric + hyphens, 2-22 chars)
        port (int): Port number (1-65535, excluding reserved)
        schema (str | Unset): A URL to the JSON Schema for this object.
        access (str | Unset): Access level: public, org_members, or creator (default: creator)
    """

    label: str
    port: int
    schema: str | Unset = UNSET
    access: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        label = self.label

        port = self.port

        schema = self.schema

        access = self.access

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "label": label,
                "port": port,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if access is not UNSET:
            field_dict["access"] = access

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        label = d.pop("label")

        port = d.pop("port")

        schema = d.pop("$schema", UNSET)

        access = d.pop("access", UNSET)

        create_port_body = cls(
            label=label,
            port=port,
            schema=schema,
            access=access,
        )

        return create_port_body
