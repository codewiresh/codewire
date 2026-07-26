from __future__ import annotations

from codewire._context import ConnectContext
from codewire._convert import preset_to_dict
from codewire.v1.preset_connect import PresetServiceClientSync
from codewire.v1.preset_pb2 import (
    CreatePresetRequest,
    DeletePresetRequest,
    GetPresetRequest,
    ListPresetsRequest,
    UpdatePresetRequest,
)


class Templates:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(PresetServiceClientSync)

    def create(
        self,
        *,
        name: str,
        type: str,
        slug: str | None = None,
        description: str | None = None,
        image: str | None = None,
        install_command: str | None = None,
        startup_script: str | None = None,
        default_cpu_millicores: int | None = None,
        default_memory_mb: int | None = None,
        default_disk_gb: int | None = None,
        default_ttl_seconds: int | None = None,
        secret_project: str | None = None,
    ) -> dict:
        """Create a new sandbox preset through PresetService."""
        # The REST handler always created sandbox presets; retain the public
        # argument without turning it into an invented protocol field.
        del type
        request = CreatePresetRequest(
            org_id=self._context.resolve_org_id(), name=name, slug=slug or ""
        )
        _set_create_fields(
            request,
            description=description,
            image=image,
            install_command=install_command,
            startup_script=startup_script,
            default_cpu_millicores=default_cpu_millicores,
            default_memory_mb=default_memory_mb,
            default_disk_gb=default_disk_gb,
            default_ttl_seconds=default_ttl_seconds,
        )
        if secret_project:
            request.secret_project_id = self._context.resolve_secret_project_id(
                secret_project
            )
        response = self._context.unary(self._client.create_preset, request)
        if not response.HasField("preset"):
            raise RuntimeError("preset response omitted preset")
        return preset_to_dict(response.preset)

    def list(self, *, type: str | None = None) -> list[dict]:
        # REST accepted this query parameter but its handler always returned all
        # presets. Preserve that public behavior without inventing a
        # client-side filter or an off-contract Connect field.
        del type
        request = ListPresetsRequest(org_id=self._context.resolve_org_id())
        values: list[dict] = []
        while True:
            response = self._context.unary(self._client.list_presets, request)
            values.extend(preset_to_dict(value) for value in response.presets)
            if not response.next_page_token:
                break
            request.page_token = response.next_page_token
        return values

    def get(self, template_id: str) -> dict:
        response = self._context.unary(
            self._client.get_preset,
            GetPresetRequest(
                org_id=self._context.resolve_org_id(), preset_id=template_id
            ),
        )
        if not response.HasField("preset"):
            raise RuntimeError("preset response omitted preset")
        return preset_to_dict(response.preset)

    def update(
        self,
        template_id: str,
        *,
        name: str | None = None,
        slug: str | None = None,
        description: str | None = None,
        image: str | None = None,
        install_command: str | None = None,
        startup_script: str | None = None,
        default_cpu_millicores: int | None = None,
        default_memory_mb: int | None = None,
        default_disk_gb: int | None = None,
        default_ttl_seconds: int | None = None,
        secret_project: str | None = None,
    ) -> dict:
        request = UpdatePresetRequest(
            org_id=self._context.resolve_org_id(), preset_id=template_id
        )
        _set_update_fields(
            request,
            name=name,
            slug=slug,
            description=description,
            image=image,
            install_command=install_command,
            startup_script=startup_script,
            default_cpu_millicores=default_cpu_millicores,
            default_memory_mb=default_memory_mb,
            default_disk_gb=default_disk_gb,
            default_ttl_seconds=default_ttl_seconds,
        )
        if secret_project is not None:
            request.secret_project_id = (
                self._context.resolve_secret_project_id(secret_project)
                if secret_project
                else ""
            )
        response = self._context.unary(self._client.update_preset, request)
        if not response.HasField("preset"):
            raise RuntimeError("preset response omitted preset")
        return preset_to_dict(response.preset)

    def delete(self, template_id: str) -> None:
        self._context.unary(
            self._client.delete_preset,
            DeletePresetRequest(
                org_id=self._context.resolve_org_id(), preset_id=template_id
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
