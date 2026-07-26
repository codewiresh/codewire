from http import HTTPStatus
from typing import Any

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.sign_out_output_body import SignOutOutputBody
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    authorization: str | Unset = UNSET,
    codewire_session_token: str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(authorization, Unset):
        headers["Authorization"] = authorization

    cookies = {}
    if codewire_session_token is not UNSET:
        cookies["codewire.session_token"] = codewire_session_token

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/auth/sign-out",
        "cookies": cookies,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | SignOutOutputBody:
    if response.status_code == 200:
        response_200 = SignOutOutputBody.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | SignOutOutputBody]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    authorization: str | Unset = UNSET,
    codewire_session_token: str | Unset = UNSET,
) -> Response[ErrorModel | SignOutOutputBody]:
    """Sign out and invalidate session

    Args:
        authorization (str | Unset): Bearer token
        codewire_session_token (str | Unset): Session cookie

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SignOutOutputBody]
    """

    kwargs = _get_kwargs(
        authorization=authorization,
        codewire_session_token=codewire_session_token,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    authorization: str | Unset = UNSET,
    codewire_session_token: str | Unset = UNSET,
) -> ErrorModel | SignOutOutputBody | None:
    """Sign out and invalidate session

    Args:
        authorization (str | Unset): Bearer token
        codewire_session_token (str | Unset): Session cookie

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SignOutOutputBody
    """

    return sync_detailed(
        client=client,
        authorization=authorization,
        codewire_session_token=codewire_session_token,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    authorization: str | Unset = UNSET,
    codewire_session_token: str | Unset = UNSET,
) -> Response[ErrorModel | SignOutOutputBody]:
    """Sign out and invalidate session

    Args:
        authorization (str | Unset): Bearer token
        codewire_session_token (str | Unset): Session cookie

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SignOutOutputBody]
    """

    kwargs = _get_kwargs(
        authorization=authorization,
        codewire_session_token=codewire_session_token,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    authorization: str | Unset = UNSET,
    codewire_session_token: str | Unset = UNSET,
) -> ErrorModel | SignOutOutputBody | None:
    """Sign out and invalidate session

    Args:
        authorization (str | Unset): Bearer token
        codewire_session_token (str | Unset): Session cookie

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SignOutOutputBody
    """

    return (
        await asyncio_detailed(
            client=client,
            authorization=authorization,
            codewire_session_token=codewire_session_token,
        )
    ).parsed
