from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateBillingSetupInputBody")


@_attrs_define
class CreateBillingSetupInputBody:
    """
    Attributes:
        cancel_url (str): Redirect URL on cancel
        success_url (str): Redirect URL on success
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    cancel_url: str
    success_url: str
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        cancel_url = self.cancel_url

        success_url = self.success_url

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "cancel_url": cancel_url,
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

        success_url = d.pop("success_url")

        schema = d.pop("$schema", UNSET)

        create_billing_setup_input_body = cls(
            cancel_url=cancel_url,
            success_url=success_url,
            schema=schema,
        )

        return create_billing_setup_input_body
