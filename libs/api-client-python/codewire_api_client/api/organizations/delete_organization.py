from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.organization_deletion_response import OrganizationDeletionResponse
from ...types import Response


def _get_kwargs(
    org_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/organizations/{org_id}".format(
            org_id=quote(str(org_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | ErrorModel | OrganizationDeletionResponse:
    if response.status_code == 202:
        response_202 = OrganizationDeletionResponse.from_dict(response.json())
        return response_202

    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | ErrorModel | OrganizationDeletionResponse]:
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
) -> Response[Any | ErrorModel | OrganizationDeletionResponse]:
    """Delete an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorModel | OrganizationDeletionResponse]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Any | ErrorModel | OrganizationDeletionResponse | None:
    """Delete an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorModel | OrganizationDeletionResponse
    """

    return sync_detailed(
        org_id=org_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | ErrorModel | OrganizationDeletionResponse]:
    """Delete an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorModel | OrganizationDeletionResponse]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Any | ErrorModel | OrganizationDeletionResponse | None:
    """Delete an organization

    Args:
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorModel | OrganizationDeletionResponse
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            client=client,
        )
    ).parsed
