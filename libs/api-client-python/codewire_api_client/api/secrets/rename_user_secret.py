from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.rename_user_secret_input_body import RenameUserSecretInputBody
from ...models.set_secret_output_body import SetSecretOutputBody
from ...types import Response


def _get_kwargs(
    key: str,
    *,
    body: RenameUserSecretInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/user/secrets/{key}/rename".format(
            key=quote(str(key), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | SetSecretOutputBody:
    if response.status_code == 200:
        response_200 = SetSecretOutputBody.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | SetSecretOutputBody]:
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
    body: RenameUserSecretInputBody,
) -> Response[ErrorModel | SetSecretOutputBody]:
    """Rename a secret key for the authenticated user

    Args:
        key (str): Current secret key name
        body (RenameUserSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SetSecretOutputBody]
    """

    kwargs = _get_kwargs(
        key=key,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key: str,
    *,
    client: AuthenticatedClient,
    body: RenameUserSecretInputBody,
) -> ErrorModel | SetSecretOutputBody | None:
    """Rename a secret key for the authenticated user

    Args:
        key (str): Current secret key name
        body (RenameUserSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SetSecretOutputBody
    """

    return sync_detailed(
        key=key,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
    body: RenameUserSecretInputBody,
) -> Response[ErrorModel | SetSecretOutputBody]:
    """Rename a secret key for the authenticated user

    Args:
        key (str): Current secret key name
        body (RenameUserSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SetSecretOutputBody]
    """

    kwargs = _get_kwargs(
        key=key,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key: str,
    *,
    client: AuthenticatedClient,
    body: RenameUserSecretInputBody,
) -> ErrorModel | SetSecretOutputBody | None:
    """Rename a secret key for the authenticated user

    Args:
        key (str): Current secret key name
        body (RenameUserSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SetSecretOutputBody
    """

    return (
        await asyncio_detailed(
            key=key,
            client=client,
            body=body,
        )
    ).parsed
