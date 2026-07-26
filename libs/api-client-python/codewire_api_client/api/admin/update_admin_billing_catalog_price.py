from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.success_response import SuccessResponse
from ...models.update_admin_billing_catalog_price_input_body import UpdateAdminBillingCatalogPriceInputBody
from ...types import Response


def _get_kwargs(
    resource_type: str,
    plan_key: str,
    stripe_mode: str,
    price_kind: str,
    *,
    body: UpdateAdminBillingCatalogPriceInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/admin/billing/catalog/prices/{resource_type}/{plan_key}/{stripe_mode}/{price_kind}".format(
            resource_type=quote(str(resource_type), safe=""),
            plan_key=quote(str(plan_key), safe=""),
            stripe_mode=quote(str(stripe_mode), safe=""),
            price_kind=quote(str(price_kind), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorModel | SuccessResponse:
    if response.status_code == 200:
        response_200 = SuccessResponse.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | SuccessResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    resource_type: str,
    plan_key: str,
    stripe_mode: str,
    price_kind: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogPriceInputBody,
) -> Response[ErrorModel | SuccessResponse]:
    """Update billing catalog price

    Args:
        resource_type (str): Resource type
        plan_key (str): Plan key
        stripe_mode (str): Stripe mode
        price_kind (str): Price kind
        body (UpdateAdminBillingCatalogPriceInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SuccessResponse]
    """

    kwargs = _get_kwargs(
        resource_type=resource_type,
        plan_key=plan_key,
        stripe_mode=stripe_mode,
        price_kind=price_kind,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    resource_type: str,
    plan_key: str,
    stripe_mode: str,
    price_kind: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogPriceInputBody,
) -> ErrorModel | SuccessResponse | None:
    """Update billing catalog price

    Args:
        resource_type (str): Resource type
        plan_key (str): Plan key
        stripe_mode (str): Stripe mode
        price_kind (str): Price kind
        body (UpdateAdminBillingCatalogPriceInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SuccessResponse
    """

    return sync_detailed(
        resource_type=resource_type,
        plan_key=plan_key,
        stripe_mode=stripe_mode,
        price_kind=price_kind,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    resource_type: str,
    plan_key: str,
    stripe_mode: str,
    price_kind: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogPriceInputBody,
) -> Response[ErrorModel | SuccessResponse]:
    """Update billing catalog price

    Args:
        resource_type (str): Resource type
        plan_key (str): Plan key
        stripe_mode (str): Stripe mode
        price_kind (str): Price kind
        body (UpdateAdminBillingCatalogPriceInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SuccessResponse]
    """

    kwargs = _get_kwargs(
        resource_type=resource_type,
        plan_key=plan_key,
        stripe_mode=stripe_mode,
        price_kind=price_kind,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    resource_type: str,
    plan_key: str,
    stripe_mode: str,
    price_kind: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogPriceInputBody,
) -> ErrorModel | SuccessResponse | None:
    """Update billing catalog price

    Args:
        resource_type (str): Resource type
        plan_key (str): Plan key
        stripe_mode (str): Stripe mode
        price_kind (str): Price kind
        body (UpdateAdminBillingCatalogPriceInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SuccessResponse
    """

    return (
        await asyncio_detailed(
            resource_type=resource_type,
            plan_key=plan_key,
            stripe_mode=stripe_mode,
            price_kind=price_kind,
            client=client,
            body=body,
        )
    ).parsed
