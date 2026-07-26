from http import HTTPStatus
from typing import Any

import httpx

from ...client import AuthenticatedClient, Client
from ...models.admin_billing_catalog_migration_run import AdminBillingCatalogMigrationRun
from ...models.error_model import ErrorModel
from ...models.run_admin_billing_catalog_migration_input_body import RunAdminBillingCatalogMigrationInputBody
from ...types import Response


def _get_kwargs(
    *,
    body: RunAdminBillingCatalogMigrationInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/admin/billing/catalog/subscription-migrations",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AdminBillingCatalogMigrationRun | ErrorModel:
    if response.status_code == 200:
        response_200 = AdminBillingCatalogMigrationRun.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AdminBillingCatalogMigrationRun | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: RunAdminBillingCatalogMigrationInputBody,
) -> Response[AdminBillingCatalogMigrationRun | ErrorModel]:
    """Run billing subscription migration

    Args:
        body (RunAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminBillingCatalogMigrationRun | ErrorModel]
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
    client: AuthenticatedClient,
    body: RunAdminBillingCatalogMigrationInputBody,
) -> AdminBillingCatalogMigrationRun | ErrorModel | None:
    """Run billing subscription migration

    Args:
        body (RunAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminBillingCatalogMigrationRun | ErrorModel
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: RunAdminBillingCatalogMigrationInputBody,
) -> Response[AdminBillingCatalogMigrationRun | ErrorModel]:
    """Run billing subscription migration

    Args:
        body (RunAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminBillingCatalogMigrationRun | ErrorModel]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: RunAdminBillingCatalogMigrationInputBody,
) -> AdminBillingCatalogMigrationRun | ErrorModel | None:
    """Run billing subscription migration

    Args:
        body (RunAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminBillingCatalogMigrationRun | ErrorModel
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
