from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.exec_body import ExecBody
from ...models.exec_result import ExecResult
from ...types import Response


def _get_kwargs(
    org_id: str,
    env_id: str,
    *,
    body: ExecBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/organizations/{org_id}/environments/{env_id}/exec".format(
            org_id=quote(str(org_id), safe=""),
            env_id=quote(str(env_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorModel | ExecResult:
    if response.status_code == 200:
        response_200 = ExecResult.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | ExecResult]:
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
    body: ExecBody,
) -> Response[ErrorModel | ExecResult]:
    """Execute a command in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (ExecBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | ExecResult]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
        body=body,
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
    body: ExecBody,
) -> ErrorModel | ExecResult | None:
    """Execute a command in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (ExecBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | ExecResult
    """

    return sync_detailed(
        org_id=org_id,
        env_id=env_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
    body: ExecBody,
) -> Response[ErrorModel | ExecResult]:
    """Execute a command in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (ExecBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | ExecResult]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        env_id=env_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    env_id: str,
    *,
    client: AuthenticatedClient,
    body: ExecBody,
) -> ErrorModel | ExecResult | None:
    """Execute a command in a sandbox environment

    Args:
        org_id (str): Organization ID
        env_id (str): Environment ID
        body (ExecBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | ExecResult
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            env_id=env_id,
            client=client,
            body=body,
        )
    ).parsed
