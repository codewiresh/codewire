from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...types import Response


def _get_kwargs(
    org_id: str,
    invitation_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/organizations/{org_id}/invitations/{invitation_id}".format(
            org_id=quote(str(org_id), safe=""),
            invitation_id=quote(str(invitation_id), safe=""),
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
    invitation_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | ErrorModel]:
    """Revoke an invitation

    Args:
        org_id (str): Organization ID
        invitation_id (str): Invitation ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        invitation_id=invitation_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    invitation_id: str,
    *,
    client: AuthenticatedClient,
) -> Any | ErrorModel | None:
    """Revoke an invitation

    Args:
        org_id (str): Organization ID
        invitation_id (str): Invitation ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorModel
    """

    return sync_detailed(
        org_id=org_id,
        invitation_id=invitation_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    invitation_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[Any | ErrorModel]:
    """Revoke an invitation

    Args:
        org_id (str): Organization ID
        invitation_id (str): Invitation ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        invitation_id=invitation_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    invitation_id: str,
    *,
    client: AuthenticatedClient,
) -> Any | ErrorModel | None:
    """Revoke an invitation

    Args:
        org_id (str): Organization ID
        invitation_id (str): Invitation ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorModel
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            invitation_id=invitation_id,
            client=client,
        )
    ).parsed
