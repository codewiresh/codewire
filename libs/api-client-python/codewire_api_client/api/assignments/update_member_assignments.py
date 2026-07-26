from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.update_member_assignments_input_body import UpdateMemberAssignmentsInputBody
from ...types import Response


def _get_kwargs(
    org_id: str,
    member_id: str,
    *,
    body: UpdateMemberAssignmentsInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/organizations/{org_id}/members/{member_id}/assignments".format(
            org_id=quote(str(org_id), safe=""),
            member_id=quote(str(member_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorModel | list[str] | None:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                response_200_type_0 = cast(list[str], data)

                return response_200_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        response_200 = _parse_response_200(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | list[str] | None]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    member_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateMemberAssignmentsInputBody,
) -> Response[ErrorModel | list[str] | None]:
    """Update assignments for a member

    Args:
        org_id (str): Organization ID
        member_id (str): Member ID
        body (UpdateMemberAssignmentsInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[str] | None]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        member_id=member_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    member_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateMemberAssignmentsInputBody,
) -> ErrorModel | list[str] | None | None:
    """Update assignments for a member

    Args:
        org_id (str): Organization ID
        member_id (str): Member ID
        body (UpdateMemberAssignmentsInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[str] | None
    """

    return sync_detailed(
        org_id=org_id,
        member_id=member_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    member_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateMemberAssignmentsInputBody,
) -> Response[ErrorModel | list[str] | None]:
    """Update assignments for a member

    Args:
        org_id (str): Organization ID
        member_id (str): Member ID
        body (UpdateMemberAssignmentsInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | list[str] | None]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        member_id=member_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    member_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateMemberAssignmentsInputBody,
) -> ErrorModel | list[str] | None | None:
    """Update assignments for a member

    Args:
        org_id (str): Organization ID
        member_id (str): Member ID
        body (UpdateMemberAssignmentsInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | list[str] | None
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            member_id=member_id,
            client=client,
            body=body,
        )
    ).parsed
