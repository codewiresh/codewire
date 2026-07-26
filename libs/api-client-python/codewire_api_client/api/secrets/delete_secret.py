from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.delete_secret_output_body import DeleteSecretOutputBody
from ...models.error_model import ErrorModel
from ...types import UNSET, Response


def _get_kwargs(
    key: str,
    *,
    org_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/secrets/{key}".format(
            key=quote(str(key), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DeleteSecretOutputBody | ErrorModel:
    if response.status_code == 200:
        response_200 = DeleteSecretOutputBody.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[DeleteSecretOutputBody | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[DeleteSecretOutputBody | ErrorModel]:
    """Delete a secret for an organization

    Args:
        key (str): Secret key name
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteSecretOutputBody | ErrorModel]
    """

    kwargs = _get_kwargs(
        key=key,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> DeleteSecretOutputBody | ErrorModel | None:
    """Delete a secret for an organization

    Args:
        key (str): Secret key name
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteSecretOutputBody | ErrorModel
    """

    return sync_detailed(
        key=key,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[DeleteSecretOutputBody | ErrorModel]:
    """Delete a secret for an organization

    Args:
        key (str): Secret key name
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteSecretOutputBody | ErrorModel]
    """

    kwargs = _get_kwargs(
        key=key,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> DeleteSecretOutputBody | ErrorModel | None:
    """Delete a secret for an organization

    Args:
        key (str): Secret key name
        org_id (str): Organization ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteSecretOutputBody | ErrorModel
    """

    return (
        await asyncio_detailed(
            key=key,
            client=client,
            org_id=org_id,
        )
    ).parsed
