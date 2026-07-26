from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.list_project_secrets_output_body import ListProjectSecretsOutputBody
from ...types import Response


def _get_kwargs(
    org_id: str,
    project_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/organizations/{org_id}/secret-projects/{project_id}/secrets".format(
            org_id=quote(str(org_id), safe=""),
            project_id=quote(str(project_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | ListProjectSecretsOutputBody:
    if response.status_code == 200:
        response_200 = ListProjectSecretsOutputBody.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | ListProjectSecretsOutputBody]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    project_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ErrorModel | ListProjectSecretsOutputBody]:
    """List secret keys in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | ListProjectSecretsOutputBody]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        project_id=project_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    project_id: str,
    *,
    client: AuthenticatedClient,
) -> ErrorModel | ListProjectSecretsOutputBody | None:
    """List secret keys in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | ListProjectSecretsOutputBody
    """

    return sync_detailed(
        org_id=org_id,
        project_id=project_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    project_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ErrorModel | ListProjectSecretsOutputBody]:
    """List secret keys in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | ListProjectSecretsOutputBody]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        project_id=project_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    project_id: str,
    *,
    client: AuthenticatedClient,
) -> ErrorModel | ListProjectSecretsOutputBody | None:
    """List secret keys in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | ListProjectSecretsOutputBody
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            project_id=project_id,
            client=client,
        )
    ).parsed
