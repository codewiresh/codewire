from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetAdminBillingCatalogPlanArchiveInputBody")


@_attrs_define
class SetAdminBillingCatalogPlanArchiveInputBody:
    """
    Attributes:
        archived (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    archived: bool
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        archived = self.archived

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "archived": archived,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        archived = d.pop("archived")

        schema = d.pop("$schema", UNSET)

        set_admin_billing_catalog_plan_archive_input_body = cls(
            archived=archived,
            schema=schema,
        )

        return set_admin_billing_catalog_plan_archive_input_body
