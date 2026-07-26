from http import HTTPStatus
from typing import Any

import httpx

from ...client import AuthenticatedClient, Client
from ...models.auth_response import AuthResponse
from ...models.error_model import ErrorModel
from ...models.validate_totp_input_body import ValidateTOTPInputBody
from ...types import Response


def _get_kwargs(
    *,
    body: ValidateTOTPInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/auth/two-factor/validate",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> AuthResponse | ErrorModel:
    if response.status_code == 200:
        response_200 = AuthResponse.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AuthResponse | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: ValidateTOTPInputBody,
) -> Response[AuthResponse | ErrorModel]:
    """Validate TOTP code during sign-in

    Args:
        body (ValidateTOTPInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthResponse | ErrorModel]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    body: ValidateTOTPInputBody,
) -> AuthResponse | ErrorModel | None:
    """Validate TOTP code during sign-in

    Args:
        body (ValidateTOTPInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthResponse | ErrorModel
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: ValidateTOTPInputBody,
) -> Response[AuthResponse | ErrorModel]:
    """Validate TOTP code during sign-in

    Args:
        body (ValidateTOTPInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthResponse | ErrorModel]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    body: ValidateTOTPInputBody,
) -> AuthResponse | ErrorModel | None:
    """Validate TOTP code during sign-in

    Args:
        body (ValidateTOTPInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthResponse | ErrorModel
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
