from http import HTTPStatus
from typing import Any, cast

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.git_hub_repo import GitHubRepo
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    page: int | Unset = UNSET,
    per_page: int | Unset = UNSET,
    search: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["page"] = page

    params["per_page"] = per_page

    params["search"] = search

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/github/repos",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | list[GitHubRepo] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[GitHubRepo] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = []
                _response_200_type_0 = data
                for response_200_type_0_item_data in _response_200_type_0:
                    response_200_type_0_item = GitHubRepo.from_dict(response_200_type_0_item_data)

                    response_200_type_0.append(response_200_type_0_item)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[GitHubRepo] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[GitHubRepo] | None]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    page: int | Unset = UNSET,
    per_page: int | Unset = UNSET,
    search: str | Unset = UNSET,
) -> Response[ErrorModel | list[GitHubRepo] | None]:
    """List GitHub repositories accessible to the connected user

    Args:
        page (int | Unset): Page number (default 1)
        per_page (int | Unset): Results per page (default 30, max 100)
        search (str | Unset): Filter repos by name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[GitHubRepo] | None]
    """

    kwargs = _get_kwargs(
        page=page,
        per_page=per_page,
        search=search,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    page: int | Unset = UNSET,
    per_page: int | Unset = UNSET,
    search: str | Unset = UNSET,
) -> ErrorModel | list[GitHubRepo] | None | None:
    """List GitHub repositories accessible to the connected user

    Args:
        page (int | Unset): Page number (default 1)
        per_page (int | Unset): Results per page (default 30, max 100)
        search (str | Unset): Filter repos by name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[GitHubRepo] | None
    """

    return sync_detailed(
        client=client,
        page=page,
        per_page=per_page,
        search=search,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    page: int | Unset = UNSET,
    per_page: int | Unset = UNSET,
    search: str | Unset = UNSET,
) -> Response[ErrorModel | list[GitHubRepo] | None]:
    """List GitHub repositories accessible to the connected user

    Args:
        page (int | Unset): Page number (default 1)
        per_page (int | Unset): Results per page (default 30, max 100)
        search (str | Unset): Filter repos by name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[GitHubRepo] | None]
    """

    kwargs = _get_kwargs(
        page=page,
        per_page=per_page,
        search=search,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    page: int | Unset = UNSET,
    per_page: int | Unset = UNSET,
    search: str | Unset = UNSET,
) -> ErrorModel | list[GitHubRepo] | None | None:
    """List GitHub repositories accessible to the connected user

    Args:
        page (int | Unset): Page number (default 1)
        per_page (int | Unset): Results per page (default 30, max 100)
        search (str | Unset): Filter repos by name

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[GitHubRepo] | None
    """

    return (
        await asyncio_detailed(
            client=client,
            page=page,
            per_page=per_page,
            search=search,
        )
    ).parsed
