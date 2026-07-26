from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.environment import Environment
from ...models.error_model import ErrorModel
from ...types import UNSET, Response, Unset


def _get_kwargs(
    org_id: str,
    *,
    type_: str | Unset = UNSET,
    state: str | Unset = UNSET,
    include_destroyed: bool | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["type"] = type_

    params["state"] = state

    params["include_destroyed"] = include_destroyed

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/organizations/{org_id}/environments".format(
            org_id=quote(str(org_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[Environment] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[Environment] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = Environment.from_dict(response_200_type_0_item_data)

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Environment] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[Environment] | None]:
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
    type_: str | Unset = UNSET,
    state: str | Unset = UNSET,
    include_destroyed: bool | Unset = UNSET,
) -> Response[ErrorModel | list[Environment] | None]:
    """List environments for an organization

    Args:
        org_id (str): Organization ID
        type_ (str | Unset): Filter by type (sandbox)
        state (str | Unset): Filter by state
        include_destroyed (bool | Unset): Include destroyed environments (excluded by default)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[Environment] | None]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        type_=type_,
        state=state,
        include_destroyed=include_destroyed,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    *,
    client: AuthenticatedClient,
    type_: str | Unset = UNSET,
    state: str | Unset = UNSET,
    include_destroyed: bool | Unset = UNSET,
) -> ErrorModel | list[Environment] | None | None:
    """List environments for an organization

    Args:
        org_id (str): Organization ID
        type_ (str | Unset): Filter by type (sandbox)
        state (str | Unset): Filter by state
        include_destroyed (bool | Unset): Include destroyed environments (excluded by default)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[Environment] | None
    """

    return sync_detailed(
        org_id=org_id,
        client=client,
        type_=type_,
        state=state,
        include_destroyed=include_destroyed,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
    type_: str | Unset = UNSET,
    state: str | Unset = UNSET,
    include_destroyed: bool | Unset = UNSET,
) -> Response[ErrorModel | list[Environment] | None]:
    """List environments for an organization

    Args:
        org_id (str): Organization ID
        type_ (str | Unset): Filter by type (sandbox)
        state (str | Unset): Filter by state
        include_destroyed (bool | Unset): Include destroyed environments (excluded by default)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[Environment] | None]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        type_=type_,
        state=state,
        include_destroyed=include_destroyed,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    *,
    client: AuthenticatedClient,
    type_: str | Unset = UNSET,
    state: str | Unset = UNSET,
    include_destroyed: bool | Unset = UNSET,
) -> ErrorModel | list[Environment] | None | None:
    """List environments for an organization

    Args:
        org_id (str): Organization ID
        type_ (str | Unset): Filter by type (sandbox)
        state (str | Unset): Filter by state
        include_destroyed (bool | Unset): Include destroyed environments (excluded by default)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[Environment] | None
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            client=client,
            type_=type_,
            state=state,
            include_destroyed=include_destroyed,
        )
    ).parsed
