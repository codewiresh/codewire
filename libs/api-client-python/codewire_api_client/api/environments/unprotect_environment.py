from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.status_response import StatusResponse
from ...types import Response


def _get_kwargs(
    org_id: str,
    env_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/organizations/{org_id}/environments/{env_id}/unprotect".format(
            org_id=quote(str(org_id), safe=""),
            env_id=quote(str(env_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorModel | StatusResponse:
    if response.status_code == 200:
        response_200 = StatusResponse.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | StatusResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ErrorModel | StatusResponse]:
    """Remove deletion protection from an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | StatusResponse]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
) -> ErrorModel | StatusResponse | None:
    """Remove deletion protection from an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | StatusResponse
    """

    return sync_detailed(
        org_id=org_id,
        env_id=env_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ErrorModel | StatusResponse]:
    """Remove deletion protection from an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | StatusResponse]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
) -> ErrorModel | StatusResponse | None:
    """Remove deletion protection from an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | StatusResponse
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            env_id=env_id,
            client=client,
        )
    ).parsed
