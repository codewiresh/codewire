from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.api_key import APIKey
from ...models.error_model import ErrorModel
from ...models.update_api_key_body import UpdateAPIKeyBody
from ...types import Response


def _get_kwargs(
    org_id: str,
    key_id: str,
    *,
    body: UpdateAPIKeyBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/api/v1/organizations/{org_id}/api-keys/{key_id}".format(
            org_id=quote(str(org_id), safe=""),
            key_id=quote(str(key_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> APIKey | ErrorModel:
    if response.status_code == 200:
        response_200 = APIKey.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[APIKey | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAPIKeyBody,
) -> Response[APIKey | ErrorModel]:
    """Update an API key (disable/enable)

    Args:
        org_id (str): Organization ID
        key_id (str): API Key ID
        body (UpdateAPIKeyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APIKey | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        key_id=key_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAPIKeyBody,
) -> APIKey | ErrorModel | None:
    """Update an API key (disable/enable)

    Args:
        org_id (str): Organization ID
        key_id (str): API Key ID
        body (UpdateAPIKeyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APIKey | ErrorModel
    """

    return sync_detailed(
        org_id=org_id,
        key_id=key_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAPIKeyBody,
) -> Response[APIKey | ErrorModel]:
    """Update an API key (disable/enable)

    Args:
        org_id (str): Organization ID
        key_id (str): API Key ID
        body (UpdateAPIKeyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APIKey | ErrorModel]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        key_id=key_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    key_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAPIKeyBody,
) -> APIKey | ErrorModel | None:
    """Update an API key (disable/enable)

    Args:
        org_id (str): Organization ID
        key_id (str): API Key ID
        body (UpdateAPIKeyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APIKey | ErrorModel
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            key_id=key_id,
            client=client,
            body=body,
        )
    ).parsed
