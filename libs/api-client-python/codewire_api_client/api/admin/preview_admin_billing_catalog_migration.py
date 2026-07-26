from http import HTTPStatus
from typing import Any

import httpx

from ...client import AuthenticatedClient, Client
from ...models.admin_billing_catalog_migration_preview import AdminBillingCatalogMigrationPreview
from ...models.error_model import ErrorModel
from ...models.preview_admin_billing_catalog_migration_input_body import PreviewAdminBillingCatalogMigrationInputBody
from ...types import Response


def _get_kwargs(
    *,
    body: PreviewAdminBillingCatalogMigrationInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/admin/billing/catalog/subscription-migrations/preview",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AdminBillingCatalogMigrationPreview | ErrorModel:
    if response.status_code == 200:
        response_200 = AdminBillingCatalogMigrationPreview.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AdminBillingCatalogMigrationPreview | ErrorModel]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: PreviewAdminBillingCatalogMigrationInputBody,
) -> Response[AdminBillingCatalogMigrationPreview | ErrorModel]:
    """Preview billing subscription migration

    Args:
        body (PreviewAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminBillingCatalogMigrationPreview | ErrorModel]
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
    body: PreviewAdminBillingCatalogMigrationInputBody,
) -> AdminBillingCatalogMigrationPreview | ErrorModel | None:
    """Preview billing subscription migration

    Args:
        body (PreviewAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminBillingCatalogMigrationPreview | ErrorModel
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: PreviewAdminBillingCatalogMigrationInputBody,
) -> Response[AdminBillingCatalogMigrationPreview | ErrorModel]:
    """Preview billing subscription migration

    Args:
        body (PreviewAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminBillingCatalogMigrationPreview | ErrorModel]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: PreviewAdminBillingCatalogMigrationInputBody,
) -> AdminBillingCatalogMigrationPreview | ErrorModel | None:
    """Preview billing subscription migration

    Args:
        body (PreviewAdminBillingCatalogMigrationInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminBillingCatalogMigrationPreview | ErrorModel
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
