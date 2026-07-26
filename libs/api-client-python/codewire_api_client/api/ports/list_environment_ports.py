from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.environment_port import EnvironmentPort
from ...models.error_model import ErrorModel
from ...types import Response


def _get_kwargs(
    org_id: str,
    env_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/organizations/{org_id}/environments/{env_id}/ports".format(
            org_id=quote(str(org_id), safe=""),
            env_id=quote(str(env_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[EnvironmentPort] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[EnvironmentPort] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = EnvironmentPort.from_dict(response_200_type_0_item_data)

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[EnvironmentPort] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[EnvironmentPort] | None]:
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
) -> Response[ErrorModel | list[EnvironmentPort] | None]:
    """List ports for an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[EnvironmentPort] | None]
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
) -> ErrorModel | list[EnvironmentPort] | None | None:
    """List ports for an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[EnvironmentPort] | None
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
) -> Response[ErrorModel | list[EnvironmentPort] | None]:
    """List ports for an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[EnvironmentPort] | None]
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
) -> ErrorModel | list[EnvironmentPort] | None | None:
    """List ports for an environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[EnvironmentPort] | None
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            env_id=env_id,
            client=client,
        )
    ).parsed
