from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.file_entry import FileEntry
from ...types import UNSET, Response, Unset


def _get_kwargs(
    org_id: str,
    env_id: str,
    *,
    path: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["path"] = path

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/organizations/{org_id}/environments/{env_id}/files".format(
            org_id=quote(str(org_id), safe=""),
            env_id=quote(str(env_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[FileEntry] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[FileEntry] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = FileEntry.from_dict(response_200_type_0_item_data)

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[FileEntry] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[FileEntry] | None]:
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
    path: str | Unset = UNSET,
) -> Response[ErrorModel | list[FileEntry] | None]:
    """List files in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        path (str | Unset): Directory path

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[FileEntry] | None]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
        path=path,
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
    path: str | Unset = UNSET,
) -> ErrorModel | list[FileEntry] | None | None:
    """List files in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        path (str | Unset): Directory path

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[FileEntry] | None
    """

    return sync_detailed(
        org_id=org_id,
        env_id=env_id,
        client=client,
        path=path,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
    path: str | Unset = UNSET,
) -> Response[ErrorModel | list[FileEntry] | None]:
    """List files in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        path (str | Unset): Directory path

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[FileEntry] | None]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
        path=path,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
    path: str | Unset = UNSET,
) -> ErrorModel | list[FileEntry] | None | None:
    """List files in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        path (str | Unset): Directory path

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[FileEntry] | None
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            env_id=env_id,
            client=client,
            path=path,
        )
    ).parsed
