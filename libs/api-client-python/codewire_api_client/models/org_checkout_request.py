from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="OrgCheckoutRequest")


@_attrs_define
class OrgCheckoutRequest:
    """
    Attributes:
        cancel_url (str):
        plan (str):
        success_url (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    cancel_url: str
    plan: str
    success_url: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        cancel_url = self.cancel_url

        plan = self.plan

        success_url = self.success_url

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cancel_url": cancel_url,
                "plan": plan,
                "success_url": success_url,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cancel_url = d.pop("cancel_url")

        plan = d.pop("plan")

        success_url = d.pop("success_url")

        schema = d.pop("$schema", UNSET)

        org_checkout_request = cls(
            cancel_url=cancel_url,
            plan=plan,
            success_url=success_url,
            schema=schema,
        )

        return org_checkout_request
