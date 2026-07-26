from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.checkout_url_response import CheckoutURLResponse
from ...models.error_model import ErrorModel
from ...models.org_checkout_request import OrgCheckoutRequest
from ...types import Response


def _get_kwargs(
    org_id: str,
    *,
    body: OrgCheckoutRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/organizations/{org_id}/billing/checkout".format(
            org_id=quote(str(org_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CheckoutURLResponse | ErrorModel:
    if response.status_code == 200:
        response_200 = CheckoutURLResponse.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[CheckoutURLResponse | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
    body: OrgCheckoutRequest,
) -> Response[CheckoutURLResponse | ErrorModel]:
    """Create org checkout session

    Args:
        org_id (str): Organization ID
        body (OrgCheckoutRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CheckoutURLResponse | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    *,
    client: AuthenticatedClient,
    body: OrgCheckoutRequest,
) -> CheckoutURLResponse | ErrorModel | None:
    """Create org checkout session

    Args:
        org_id (str): Organization ID
        body (OrgCheckoutRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CheckoutURLResponse | ErrorModel
    """

    return sync_detailed(
        org_id=org_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
    body: OrgCheckoutRequest,
) -> Response[CheckoutURLResponse | ErrorModel]:
    """Create org checkout session

    Args:
        org_id (str): Organization ID
        body (OrgCheckoutRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CheckoutURLResponse | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    *,
    client: AuthenticatedClient,
    body: OrgCheckoutRequest,
) -> CheckoutURLResponse | ErrorModel | None:
    """Create org checkout session

    Args:
        org_id (str): Organization ID
        body (OrgCheckoutRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CheckoutURLResponse | ErrorModel
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            client=client,
            body=body,
        )
    ).parsed
