from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.environment import Environment
from ...models.error_model import ErrorModel
from ...types import Response


def _get_kwargs(
    org_id: str,
    env_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/organizations/{org_id}/environments/{env_id}".format(
            org_id=quote(str(org_id), safe=""),
            env_id=quote(str(env_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Environment | ErrorModel:
    if response.status_code == 200:
        response_200 = Environment.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Environment | ErrorModel]:
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
) -> Response[Environment | ErrorModel]:
    """Get an environment by ID

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Environment | ErrorModel]
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
) -> Environment | ErrorModel | None:
    """Get an environment by ID

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Environment | ErrorModel
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
) -> Response[Environment | ErrorModel]:
    """Get an environment by ID

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Environment | ErrorModel]
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
) -> Environment | ErrorModel | None:
    """Get an environment by ID

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Environment | ErrorModel
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            env_id=env_id,
            client=client,
        )
    ).parsed
