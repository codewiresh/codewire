from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...models.error_model import ErrorModel
from ...models.set_project_secret_input_body import SetProjectSecretInputBody
from ...models.set_secret_output_body import SetSecretOutputBody
from ...types import Response


def _get_kwargs(
    org_id: str,
    project_id: str,
    *,
    body: SetProjectSecretInputBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/organizations/{org_id}/secret-projects/{project_id}/secrets".format(
            org_id=quote(str(org_id), safe=""),
            project_id=quote(str(project_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorModel | SetSecretOutputBody:
    if response.status_code == 200:
        response_200 = SetSecretOutputBody.from_dict(response.json())

        return response_200

    response_default = ErrorModel.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorModel | SetSecretOutputBody]:
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
    body: SetProjectSecretInputBody,
) -> Response[ErrorModel | SetSecretOutputBody]:
    """Set a secret in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        body (SetProjectSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SetSecretOutputBody]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        project_id=project_id,
        body=body,
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
    body: SetProjectSecretInputBody,
) -> ErrorModel | SetSecretOutputBody | None:
    """Set a secret in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        body (SetProjectSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SetSecretOutputBody
    """

    return sync_detailed(
        org_id=org_id,
        project_id=project_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    project_id: str,
    *,
    client: AuthenticatedClient,
    body: SetProjectSecretInputBody,
) -> Response[ErrorModel | SetSecretOutputBody]:
    """Set a secret in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        body (SetProjectSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorModel | SetSecretOutputBody]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        project_id=project_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    project_id: str,
    *,
    client: AuthenticatedClient,
    body: SetProjectSecretInputBody,
) -> ErrorModel | SetSecretOutputBody | None:
    """Set a secret in a project

    Args:
        org_id (str): Organization ID
        project_id (str): Secret project ID
        body (SetProjectSecretInputBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorModel | SetSecretOutputBody
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            project_id=project_id,
            client=client,
            body=body,
        )
    ).parsed
