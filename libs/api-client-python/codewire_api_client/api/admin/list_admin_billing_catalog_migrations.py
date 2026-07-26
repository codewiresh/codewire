from http import HTTPStatus
from typing import Any, cast

import httpx

from ...client import AuthenticatedClient, Client
from ...models.admin_billing_catalog_migration_run import AdminBillingCatalogMigrationRun
from ...models.error_model import ErrorModel
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 25,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/admin/billing/catalog/subscription-migrations",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[AdminBillingCatalogMigrationRun] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[AdminBillingCatalogMigrationRun] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = AdminBillingCatalogMigrationRun.from_dict(response_200_type_0_item_data)

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminBillingCatalogMigrationRun] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[AdminBillingCatalogMigrationRun] | None]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 25,
) -> Response[ErrorModel | list[AdminBillingCatalogMigrationRun] | None]:
    """List billing subscription migrations

    Args:
        limit (int | Unset): Page size Default: 25.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[AdminBillingCatalogMigrationRun] | None]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 25,
) -> ErrorModel | list[AdminBillingCatalogMigrationRun] | None | None:
    """List billing subscription migrations

    Args:
        limit (int | Unset): Page size Default: 25.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[AdminBillingCatalogMigrationRun] | None
    """

    return sync_detailed(
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 25,
) -> Response[ErrorModel | list[AdminBillingCatalogMigrationRun] | None]:
    """List billing subscription migrations

    Args:
        limit (int | Unset): Page size Default: 25.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[AdminBillingCatalogMigrationRun] | None]
    """

    kwargs = _get_kwargs(
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 25,
) -> ErrorModel | list[AdminBillingCatalogMigrationRun] | None | None:
    """List billing subscription migrations

    Args:
        limit (int | Unset): Page size Default: 25.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[AdminBillingCatalogMigrationRun] | None
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
        )
    ).parsed
