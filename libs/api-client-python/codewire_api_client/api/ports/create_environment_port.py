from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.create_port_body import CreatePortBody
from ...models.environment_port import EnvironmentPort
from ...models.error_model import ErrorModel
from ...types import Response


def _get_kwargs(
    org_id: str,
    env_id: str,
    *,
    body: CreatePortBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/organizations/{org_id}/environments/{env_id}/ports".format(
            org_id=quote(str(org_id), safe=""),
            env_id=quote(str(env_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> EnvironmentPort | ErrorModel:
    if response.status_code == 201:
        response_201 = EnvironmentPort.from_dict(response.json())

        return response_201

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[EnvironmentPort | ErrorModel]:
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
    body: CreatePortBody,
) -> Response[EnvironmentPort | ErrorModel]:
    """Register a port for preview access

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (CreatePortBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EnvironmentPort | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
        body=body,
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
    body: CreatePortBody,
) -> EnvironmentPort | ErrorModel | None:
    """Register a port for preview access

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (CreatePortBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EnvironmentPort | ErrorModel
    """

    return sync_detailed(
        org_id=org_id,
        env_id=env_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
    body: CreatePortBody,
) -> Response[EnvironmentPort | ErrorModel]:
    """Register a port for preview access

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (CreatePortBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EnvironmentPort | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
    body: CreatePortBody,
) -> EnvironmentPort | ErrorModel | None:
    """Register a port for preview access

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (CreatePortBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EnvironmentPort | ErrorModel
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            env_id=env_id,
            client=client,
            body=body,
        )
    ).parsed
