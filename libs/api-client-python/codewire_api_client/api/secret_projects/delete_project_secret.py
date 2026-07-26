from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...types import Response


def _get_kwargs(
    org_id: str,
    project_id: str,
    key: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/organizations/{org_id}/secret-projects/{project_id}/secrets/{key}".format(
            org_id=quote(str(org_id), safe=""),
            project_id=quote(str(project_id), safe=""),
            key=quote(str(key), safe=""),
        ),
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | ErrorModel:
    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    project_id: str,
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | ErrorModel]:
    """Delete a secret from a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        key (str): Secret key name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        project_id=project_id,
        key=key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    project_id: str,
    key: str,
    *,
    client: AuthenticatedClient,
) -> Any | ErrorModel | None:
    """Delete a secret from a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        key (str): Secret key name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorModel
    """

    return sync_detailed(
        org_id=org_id,
        project_id=project_id,
        key=key,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    project_id: str,
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | ErrorModel]:
    """Delete a secret from a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        key (str): Secret key name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        project_id=project_id,
        key=key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    project_id: str,
    key: str,
    *,
    client: AuthenticatedClient,
) -> Any | ErrorModel | None:
    """Delete a secret from a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        key (str): Secret key name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorModel
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            project_id=project_id,
            key=key,
            client=client,
        )
    ).parsed
