from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.admin_environment_lifecycle_journal_entry import AdminEnvironmentLifecycleJournalEntry
from ...models.error_model import ErrorModel
from ...types import UNSET, Response, Unset


def _get_kwargs(
    environment_id: str,
    *,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/admin/environments/{environment_id}/lifecycle-journal".format(
            environment_id=quote(str(environment_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[AdminEnvironmentLifecycleJournalEntry] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = AdminEnvironmentLifecycleJournalEntry.from_dict(
                        response_200_type_0_item_data
                    )

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AdminEnvironmentLifecycleJournalEntry] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    environment_id: str,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None]:
    """List environment lifecycle journal entries

    Args:
        environment_id (str): Environment ID
        limit (int | Unset): Maximum entries to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None]
    """

    kwargs = _get_kwargs(
        environment_id=environment_id,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    environment_id: str,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None | None:
    """List environment lifecycle journal entries

    Args:
        environment_id (str): Environment ID
        limit (int | Unset): Maximum entries to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None
    """

    return sync_detailed(
        environment_id=environment_id,
        client=client,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    environment_id: str,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> Response[ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None]:
    """List environment lifecycle journal entries

    Args:
        environment_id (str): Environment ID
        limit (int | Unset): Maximum entries to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None]
    """

    kwargs = _get_kwargs(
        environment_id=environment_id,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    environment_id: str,
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
) -> ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None | None:
    """List environment lifecycle journal entries

    Args:
        environment_id (str): Environment ID
        limit (int | Unset): Maximum entries to return Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[AdminEnvironmentLifecycleJournalEntry] | None
    """

    return (
        await asyncio_detailed(
            environment_id=environment_id,
            client=client,
            limit=limit,
        )
    ).parsed
