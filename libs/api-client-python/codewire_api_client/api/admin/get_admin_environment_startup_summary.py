from http import HTTPStatus
from typing import Any

import httpx

from ...client import AuthenticatedClient, Client
from ...models.admin_environment_startup_summary import AdminEnvironmentStartupSummary
from ...models.error_model import ErrorModel
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    window_minutes: int | Unset = 240,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["window_minutes"] = window_minutes

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/admin/environments/startup-summary",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AdminEnvironmentStartupSummary | ErrorModel:
    if response.status_code == 200:
        response_200 = AdminEnvironmentStartupSummary.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AdminEnvironmentStartupSummary | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 240,
) -> Response[AdminEnvironmentStartupSummary | ErrorModel]:
    """Get startup backlog and recent timing percentiles

    Args:
        window_minutes (int | Unset): Lookback window for startup duration percentiles Default:
            240.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminEnvironmentStartupSummary | ErrorModel]
    """

    kwargs = _get_kwargs(
        window_minutes=window_minutes,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 240,
) -> AdminEnvironmentStartupSummary | ErrorModel | None:
    """Get startup backlog and recent timing percentiles

    Args:
        window_minutes (int | Unset): Lookback window for startup duration percentiles Default:
            240.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminEnvironmentStartupSummary | ErrorModel
    """

    return sync_detailed(
        client=client,
        window_minutes=window_minutes,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 240,
) -> Response[AdminEnvironmentStartupSummary | ErrorModel]:
    """Get startup backlog and recent timing percentiles

    Args:
        window_minutes (int | Unset): Lookback window for startup duration percentiles Default:
            240.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminEnvironmentStartupSummary | ErrorModel]
    """

    kwargs = _get_kwargs(
        window_minutes=window_minutes,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 240,
) -> AdminEnvironmentStartupSummary | ErrorModel | None:
    """Get startup backlog and recent timing percentiles

    Args:
        window_minutes (int | Unset): Lookback window for startup duration percentiles Default:
            240.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminEnvironmentStartupSummary | ErrorModel
    """

    return (
        await asyncio_detailed(
            client=client,
            window_minutes=window_minutes,
        )
    ).parsed
