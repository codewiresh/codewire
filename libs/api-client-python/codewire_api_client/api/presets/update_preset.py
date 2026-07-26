from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.preset import Preset
from ...models.update_preset_body import UpdatePresetBody
from ...types import Response


def _get_kwargs(
    org_id: str,
    preset_id: str,
    *,
    body: UpdatePresetBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/api/v1/organizations/{org_id}/presets/{preset_id}".format(
            org_id=quote(str(org_id), safe=""),
            preset_id=quote(str(preset_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorModel | Preset:
    if response.status_code == 200:
        response_200 = Preset.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[ErrorModel | Preset]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    preset_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePresetBody,
) -> Response[ErrorModel | Preset]:
    """Update a preset

    Args:
        org_id (str): Organization ID
        preset_id (str): Preset ID
        body (UpdatePresetBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | Preset]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        preset_id=preset_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    preset_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePresetBody,
) -> ErrorModel | Preset | None:
    """Update a preset

    Args:
        org_id (str): Organization ID
        preset_id (str): Preset ID
        body (UpdatePresetBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | Preset
    """

    return sync_detailed(
        org_id=org_id,
        preset_id=preset_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    preset_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePresetBody,
) -> Response[ErrorModel | Preset]:
    """Update a preset

    Args:
        org_id (str): Organization ID
        preset_id (str): Preset ID
        body (UpdatePresetBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | Preset]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        preset_id=preset_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    preset_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePresetBody,
) -> ErrorModel | Preset | None:
    """Update a preset

    Args:
        org_id (str): Organization ID
        preset_id (str): Preset ID
        body (UpdatePresetBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | Preset
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            preset_id=preset_id,
            client=client,
            body=body,
        )
    ).parsed
