from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.success_response import SuccessResponse
from ...models.update_admin_billing_catalog_setting_input_body import UpdateAdminBillingCatalogSettingInputBody
from ...types import Response


def _get_kwargs(
    setting_key: str,
    *,
    body: UpdateAdminBillingCatalogSettingInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/admin/billing/catalog/settings/{setting_key}".format(
            setting_key=quote(str(setting_key), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorModel | SuccessResponse:
    if response.status_code == 200:
        response_200 = SuccessResponse.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | SuccessResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    setting_key: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogSettingInputBody,
) -> Response[ErrorModel | SuccessResponse]:
    """Update billing catalog setting

    Args:
        setting_key (str): Setting key
        body (UpdateAdminBillingCatalogSettingInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SuccessResponse]
    """

    kwargs = _get_kwargs(
        setting_key=setting_key,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    setting_key: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogSettingInputBody,
) -> ErrorModel | SuccessResponse | None:
    """Update billing catalog setting

    Args:
        setting_key (str): Setting key
        body (UpdateAdminBillingCatalogSettingInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SuccessResponse
    """

    return sync_detailed(
        setting_key=setting_key,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    setting_key: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogSettingInputBody,
) -> Response[ErrorModel | SuccessResponse]:
    """Update billing catalog setting

    Args:
        setting_key (str): Setting key
        body (UpdateAdminBillingCatalogSettingInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SuccessResponse]
    """

    kwargs = _get_kwargs(
        setting_key=setting_key,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    setting_key: str,
    *,
    client: AuthenticatedClient,
    body: UpdateAdminBillingCatalogSettingInputBody,
) -> ErrorModel | SuccessResponse | None:
    """Update billing catalog setting

    Args:
        setting_key (str): Setting key
        body (UpdateAdminBillingCatalogSettingInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SuccessResponse
    """

    return (
        await asyncio_detailed(
            setting_key=setting_key,
            client=client,
            body=body,
        )
    ).parsed
