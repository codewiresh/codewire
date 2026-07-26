from __future__ import annotations

from codewire._context import ConnectContext
from codewire._convert import proto_to_dict
from codewire.v1.secret_connect import SecretServiceClientSync
from codewire.v1.secret_pb2 import (
    CreateSecretProjectRequest,
    DeleteProjectSecretRequest,
    DeleteSecretProjectRequest,
    DeleteSecretRequest,
    DeleteUserSecretRequest,
    ListProjectSecretsRequest,
    ListSecretProjectsRequest,
    ListSecretsRequest,
    ListUserSecretsRequest,
    RenameProjectSecretRequest,
    RenameSecretRequest,
    RenameUserSecretRequest,
    SetProjectSecretRequest,
    SetSecretRequest,
    SetUserSecretRequest,
)


class Secrets:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(SecretServiceClientSync)

    def list(self) -> list[dict]:
        request = ListSecretsRequest(org_id=self._context.resolve_org_id())
        return _list_all(
            self._context, self._client.list_secrets, request, "secrets"
        )

    def set(self, key: str, value: str) -> None:
        self._context.unary(
            self._client.set_secret,
            SetSecretRequest(
                org_id=self._context.resolve_org_id(), key=key, value=value
            ),
        )

    def delete(self, key: str) -> None:
        self._context.unary(
            self._client.delete_secret,
            DeleteSecretRequest(org_id=self._context.resolve_org_id(), key=key),
        )

    def rename(self, old_key: str, new_key: str) -> None:
        self._context.unary(
            self._client.rename_secret,
            RenameSecretRequest(
                org_id=self._context.resolve_org_id(), key=old_key, new_key=new_key
            ),
        )

    def list_user(self) -> list[dict]:
        return _list_all(
            self._context,
            self._client.list_user_secrets,
            ListUserSecretsRequest(),
            "secrets",
        )

    def set_user(self, key: str, value: str) -> None:
        self._context.unary(self._client.set_user_secret, SetUserSecretRequest(key=key, value=value))

    def delete_user(self, key: str) -> None:
        self._context.unary(self._client.delete_user_secret, DeleteUserSecretRequest(key=key))

    def rename_user(self, old_key: str, new_key: str) -> None:
        self._context.unary(
            self._client.rename_user_secret,
            RenameUserSecretRequest(key=old_key, new_key=new_key),
        )


class SecretProjects:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(SecretServiceClientSync)

    def create(self, name: str) -> dict:
        response = self._context.unary(
            self._client.create_secret_project,
            CreateSecretProjectRequest(org_id=self._context.resolve_org_id(), name=name),
        )
        if not response.HasField("secret_project"):
            raise RuntimeError("secret project response omitted secret_project")
        return proto_to_dict(response.secret_project)

    def list(self) -> list[dict]:
        request = ListSecretProjectsRequest(org_id=self._context.resolve_org_id())
        return _list_all(
            self._context, self._client.list_secret_projects, request, "secret_projects"
        )

    def delete(self, project_id: str) -> None:
        self._context.unary(
            self._client.delete_secret_project,
            DeleteSecretProjectRequest(
                org_id=self._context.resolve_org_id(), secret_project_id=project_id
            ),
        )

    def list_secrets(self, project_id: str) -> list[dict]:
        request = ListProjectSecretsRequest(
            org_id=self._context.resolve_org_id(), secret_project_id=project_id
        )
        return _list_all(
            self._context, self._client.list_project_secrets, request, "secrets"
        )

    def set_secret(self, project_id: str, key: str, value: str) -> None:
        self._context.unary(
            self._client.set_project_secret,
            SetProjectSecretRequest(
                org_id=self._context.resolve_org_id(),
                secret_project_id=project_id,
                key=key,
                value=value,
            ),
        )

    def delete_secret(self, project_id: str, key: str) -> None:
        self._context.unary(
            self._client.delete_project_secret,
            DeleteProjectSecretRequest(
                org_id=self._context.resolve_org_id(),
                secret_project_id=project_id,
                key=key,
            ),
        )

    def rename_secret(self, project_id: str, old_key: str, new_key: str) -> None:
        self._context.unary(
            self._client.rename_project_secret,
            RenameProjectSecretRequest(
                org_id=self._context.resolve_org_id(),
                secret_project_id=project_id,
                key=old_key,
                new_key=new_key,
            ),
        )


def _list_all(context: ConnectContext, call, request, field_name: str) -> list[dict]:
    values: list[dict] = []
    while True:
        response = context.unary(call, request)
        values.extend(proto_to_dict(value) for value in getattr(response, field_name))
        if not response.next_page_token:
            return values
        request.page_token = response.next_page_token
