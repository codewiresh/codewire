from __future__ import annotations

from codewire._context import ConnectContext
from codewire._convert import api_key_to_dict
from codewire.v1.api_key_connect import ApiKeyServiceClientSync
from codewire.v1.api_key_pb2 import (
    CreateApiKeyRequest,
    DeleteApiKeyRequest,
    ListApiKeysRequest,
    UpdateApiKeyRequest,
)


class APIKeys:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(ApiKeyServiceClientSync)

    def create(
        self,
        *,
        name: str,
        scopes: list[str] | None = None,
        expires_in_days: int | None = None,
    ) -> dict:
        request = CreateApiKeyRequest(
            org_id=self._context.resolve_org_id(), name=name, scopes=scopes or []
        )
        if expires_in_days is not None:
            request.expires_in_days = expires_in_days
        response = self._context.unary(self._client.create_api_key, request)
        if not response.HasField("api_key"):
            raise RuntimeError("api key response omitted api_key")
        result = api_key_to_dict(response.api_key)
        result["key"] = response.key
        return result

    def list(self) -> list[dict]:
        response = self._context.unary(
            self._client.list_api_keys,
            ListApiKeysRequest(org_id=self._context.resolve_org_id()),
        )
        return [api_key_to_dict(api_key) for api_key in response.api_keys]

    def update(self, key_id: str, *, disabled: bool | None = None) -> dict:
        request = UpdateApiKeyRequest(
            org_id=self._context.resolve_org_id(), key_id=key_id
        )
        if disabled is not None:
            request.disabled = disabled
        response = self._context.unary(self._client.update_api_key, request)
        if not response.HasField("api_key"):
            raise RuntimeError("api key response omitted api_key")
        return api_key_to_dict(response.api_key)

    def delete(self, key_id: str) -> None:
        self._context.unary(
            self._client.delete_api_key,
            DeleteApiKeyRequest(
                org_id=self._context.resolve_org_id(), key_id=key_id
            ),
        )

    def close(self) -> None:
        self._client.close()
