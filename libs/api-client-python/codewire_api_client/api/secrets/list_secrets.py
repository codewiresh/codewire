from http import HTTPStatus
from typing import Any

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.list_secrets_output_body import ListSecretsOutputBody
from ...types import UNSET, Response


def _get_kwargs(
    *,
    org_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/secrets",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | ListSecretsOutputBody:
    if response.status_code == 200:
        response_200 = ListSecretsOutputBody.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | ListSecretsOutputBody]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[ErrorModel | ListSecretsOutputBody]:
    """List secret keys for an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | ListSecretsOutputBody]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> ErrorModel | ListSecretsOutputBody | None:
    """List secret keys for an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | ListSecretsOutputBody
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[ErrorModel | ListSecretsOutputBody]:
    """List secret keys for an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | ListSecretsOutputBody]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> ErrorModel | ListSecretsOutputBody | None:
    """List secret keys for an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | ListSecretsOutputBody
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
        )
    ).parsed
