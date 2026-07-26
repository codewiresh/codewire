from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

T = TypeVar("T", bound="InvoiceResponse")


@_attrs_define
class InvoiceResponse:
    """
    Attributes:
        amount_due (int):
        amount_paid (int):
        created_at (str):
        currency (str):
        hosted_invoice_url (None | str):
        id (str):
        invoice_pdf (None | str):
        period_end (None | str):
        period_start (None | str):
        status (str):
        stripe_invoice_id (str):
    """

    amount_due: int
    amount_paid: int
    created_at: str
    currency: str
    hosted_invoice_url: None | str
    id: str
    invoice_pdf: None | str
    period_end: None | str
    period_start: None | str
    status: str
    stripe_invoice_id: str

    def to_dict(self) -> dict[str, Any]:
        amount_due = self.amount_due

        amount_paid = self.amount_paid

        created_at = self.created_at

        currency = self.currency

        hosted_invoice_url: None | str
        hosted_invoice_url = self.hosted_invoice_url

        id = self.id

        invoice_pdf: None | str
        invoice_pdf = self.invoice_pdf

        period_end: None | str
        period_end = self.period_end

        period_start: None | str
        period_start = self.period_start

        status = self.status

        stripe_invoice_id = self.stripe_invoice_id

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "amount_due": amount_due,
                "amount_paid": amount_paid,
                "created_at": created_at,
                "currency": currency,
                "hosted_invoice_url": hosted_invoice_url,
                "id": id,
                "invoice_pdf": invoice_pdf,
                "period_end": period_end,
                "period_start": period_start,
                "status": status,
                "stripe_invoice_id": stripe_invoice_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        amount_due = d.pop("amount_due")

        amount_paid = d.pop("amount_paid")

        created_at = d.pop("created_at")

        currency = d.pop("currency")

        def _parse_hosted_invoice_url(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        hosted_invoice_url = _parse_hosted_invoice_url(d.pop("hosted_invoice_url"))

        id = d.pop("id")

        def _parse_invoice_pdf(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        invoice_pdf = _parse_invoice_pdf(d.pop("invoice_pdf"))

        def _parse_period_end(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        period_end = _parse_period_end(d.pop("period_end"))

        def _parse_period_start(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        period_start = _parse_period_start(d.pop("period_start"))

        status = d.pop("status")

        stripe_invoice_id = d.pop("stripe_invoice_id")

        invoice_response = cls(
            amount_due=amount_due,
            amount_paid=amount_paid,
            created_at=created_at,
            currency=currency,
            hosted_invoice_url=hosted_invoice_url,
            id=id,
            invoice_pdf=invoice_pdf,
            period_end=period_end,
            period_start=period_start,
            status=status,
            stripe_invoice_id=stripe_invoice_id,
        )

        return invoice_response
