from http import HTTPStatus
from typing import Any, cast

import httpx

from ...client import AuthenticatedClient, Client
from ...models.audit_log_entry import AuditLogEntry
from ...models.error_model import ErrorModel
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
    action: str | Unset = UNSET,
    severity: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params["offset"] = offset

    params["action"] = action

    params["severity"] = severity

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/admin/audit-logs",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[AuditLogEntry] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[AuditLogEntry] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = AuditLogEntry.from_dict(response_200_type_0_item_data)

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AuditLogEntry] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[AuditLogEntry] | None]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
    action: str | Unset = UNSET,
    severity: str | Unset = UNSET,
) -> Response[ErrorModel | list[AuditLogEntry] | None]:
    """List audit logs

    Args:
        limit (int | Unset): Page size Default: 50.
        offset (int | Unset): Offset Default: 0.
        action (str | Unset): Filter by action
        severity (str | Unset): Filter by severity

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[AuditLogEntry] | None]
    """

    kwargs = _get_kwargs(
        limit=limit,
        offset=offset,
        action=action,
        severity=severity,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
    action: str | Unset = UNSET,
    severity: str | Unset = UNSET,
) -> ErrorModel | list[AuditLogEntry] | None | None:
    """List audit logs

    Args:
        limit (int | Unset): Page size Default: 50.
        offset (int | Unset): Offset Default: 0.
        action (str | Unset): Filter by action
        severity (str | Unset): Filter by severity

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[AuditLogEntry] | None
    """

    return sync_detailed(
        client=client,
        limit=limit,
        offset=offset,
        action=action,
        severity=severity,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
    action: str | Unset = UNSET,
    severity: str | Unset = UNSET,
) -> Response[ErrorModel | list[AuditLogEntry] | None]:
    """List audit logs

    Args:
        limit (int | Unset): Page size Default: 50.
        offset (int | Unset): Offset Default: 0.
        action (str | Unset): Filter by action
        severity (str | Unset): Filter by severity

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[AuditLogEntry] | None]
    """

    kwargs = _get_kwargs(
        limit=limit,
        offset=offset,
        action=action,
        severity=severity,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
    action: str | Unset = UNSET,
    severity: str | Unset = UNSET,
) -> ErrorModel | list[AuditLogEntry] | None | None:
    """List audit logs

    Args:
        limit (int | Unset): Page size Default: 50.
        offset (int | Unset): Offset Default: 0.
        action (str | Unset): Filter by action
        severity (str | Unset): Filter by severity

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[AuditLogEntry] | None
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
            offset=offset,
            action=action,
            severity=severity,
        )
    ).parsed
