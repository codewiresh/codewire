from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="BillingEventResponse")


@_attrs_define
class BillingEventResponse:
    """
    Attributes:
        amount_cents (int | None):
        created_at (str):
        currency (str):
        event_type (str):
        id (int):
        org_id (None | str):
        stripe_item_id (None | str):
        metadata (Any | Unset):
    """

    amount_cents: int | None
    created_at: str
    currency: str
    event_type: str
    id: int
    org_id: None | str
    stripe_item_id: None | str
    metadata: Any | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        amount_cents: int | None
        amount_cents = self.amount_cents

        created_at = self.created_at

        currency = self.currency

        event_type = self.event_type

        id = self.id

        org_id: None | str
        org_id = self.org_id

        stripe_item_id: None | str
        stripe_item_id = self.stripe_item_id

        metadata = self.metadata

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "amount_cents": amount_cents,
                "created_at": created_at,
                "currency": currency,
                "event_type": event_type,
                "id": id,
                "org_id": org_id,
                "stripe_item_id": stripe_item_id,
            }
        )
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_amount_cents(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        amount_cents = _parse_amount_cents(d.pop("amount_cents"))

        created_at = d.pop("created_at")

        currency = d.pop("currency")

        event_type = d.pop("event_type")

        id = d.pop("id")

        def _parse_org_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        org_id = _parse_org_id(d.pop("org_id"))

        def _parse_stripe_item_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        stripe_item_id = _parse_stripe_item_id(d.pop("stripe_item_id"))

        metadata = d.pop("metadata", UNSET)

        billing_event_response = cls(
            amount_cents=amount_cents,
            created_at=created_at,
            currency=currency,
            event_type=event_type,
            id=id,
            org_id=org_id,
            stripe_item_id=stripe_item_id,
            metadata=metadata,
        )

        return billing_event_response
