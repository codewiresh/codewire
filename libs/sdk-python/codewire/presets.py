from __future__ import annotations

from typing import Any

from codewire._context import ConnectContext
from codewire._convert import (
    assert_preset_converter_coverage,
    preset_to_dict,
    project_spec_from_dict,
)
from codewire.v1.preset_connect import PresetServiceClientSync
from codewire.v1.preset_pb2 import (
    CreatePresetRequest,
    DeletePresetRequest,
    GetPresetRequest,
    ListPresetsRequest,
    UpdatePresetRequest,
)


class Presets:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(PresetServiceClientSync)

    def create(
        self,
        *,
        name: str,
        project_spec: dict[str, Any],
        slug: str | None = None,
        description: str | None = None,
        default_ttl_seconds: int | None = None,
    ) -> dict:
        """Create a new sandbox preset through PresetService."""
        assert_preset_converter_coverage()
        request = CreatePresetRequest(
            org_id=self._context.resolve_org_id(), name=name, slug=slug or ""
        )
        _set_create_fields(
            request,
            description=description,
            default_ttl_seconds=default_ttl_seconds,
        )
        request.project_spec.CopyFrom(project_spec_from_dict(project_spec))
        response = self._context.unary(self._client.create_preset, request)
        if not response.HasField("preset"):
            raise RuntimeError("preset response omitted preset")
        return preset_to_dict(response.preset)

    def list(self) -> list[dict]:
        assert_preset_converter_coverage()
        request = ListPresetsRequest(org_id=self._context.resolve_org_id())
        values: list[dict] = []
        while True:
            response = self._context.unary(self._client.list_presets, request)
            values.extend(preset_to_dict(value) for value in response.presets)
            if not response.next_page_token:
                break
            request.page_token = response.next_page_token
        return values

    def get(self, preset_id: str) -> dict:
        assert_preset_converter_coverage()
        response = self._context.unary(
            self._client.get_preset,
            GetPresetRequest(
                org_id=self._context.resolve_org_id(), preset_id=preset_id
            ),
        )
        if not response.HasField("preset"):
            raise RuntimeError("preset response omitted preset")
        return preset_to_dict(response.preset)

    def update(
        self,
        preset_id: str,
        *,
        name: str | None = None,
        slug: str | None = None,
        description: str | None = None,
        default_ttl_seconds: int | None = None,
        project_spec: dict[str, Any] | None = None,
    ) -> dict:
        assert_preset_converter_coverage()
        request = UpdatePresetRequest(
            org_id=self._context.resolve_org_id(), preset_id=preset_id
        )
        _set_update_fields(
            request,
            name=name,
            slug=slug,
            description=description,
            default_ttl_seconds=default_ttl_seconds,
        )
        if project_spec is not None:
            request.project_spec.CopyFrom(project_spec_from_dict(project_spec))
        response = self._context.unary(self._client.update_preset, request)
        if not response.HasField("preset"):
            raise RuntimeError("preset response omitted preset")
        return preset_to_dict(response.preset)

    def delete(self, preset_id: str) -> None:
        self._context.unary(
            self._client.delete_preset,
            DeletePresetRequest(
                org_id=self._context.resolve_org_id(), preset_id=preset_id
            ),
        )


def _set_create_fields(request: CreatePresetRequest, **fields: object) -> None:
    for name, value in fields.items():
        if value is not None:
            setattr(request, name, value)


def _set_update_fields(request: UpdatePresetRequest, **fields: object) -> None:
    for name, value in fields.items():
        if value is not None:
            setattr(request, name, value)
