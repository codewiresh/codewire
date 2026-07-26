from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.admin_environment_startup_timings import AdminEnvironmentStartupTimings
from ...models.error_model import ErrorModel
from ...types import Response


def _get_kwargs(
    environment_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/admin/environments/{environment_id}/startup-timings".format(
            environment_id=quote(str(environment_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AdminEnvironmentStartupTimings | ErrorModel:
    if response.status_code == 200:
        response_200 = AdminEnvironmentStartupTimings.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AdminEnvironmentStartupTimings | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    environment_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[AdminEnvironmentStartupTimings | ErrorModel]:
    """Get startup timing milestones for an environment

    Args:
        environment_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminEnvironmentStartupTimings | ErrorModel]
    """

    kwargs = _get_kwargs(
        environment_id=environment_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    environment_id: str,
    *,
    client: AuthenticatedClient,
) -> AdminEnvironmentStartupTimings | ErrorModel | None:
    """Get startup timing milestones for an environment

    Args:
        environment_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminEnvironmentStartupTimings | ErrorModel
    """

    return sync_detailed(
        environment_id=environment_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    environment_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[AdminEnvironmentStartupTimings | ErrorModel]:
    """Get startup timing milestones for an environment

    Args:
        environment_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminEnvironmentStartupTimings | ErrorModel]
    """

    kwargs = _get_kwargs(
        environment_id=environment_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    environment_id: str,
    *,
    client: AuthenticatedClient,
) -> AdminEnvironmentStartupTimings | ErrorModel | None:
    """Get startup timing milestones for an environment

    Args:
        environment_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminEnvironmentStartupTimings | ErrorModel
    """

    return (
        await asyncio_detailed(
            environment_id=environment_id,
            client=client,
        )
    ).parsed
