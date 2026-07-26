from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.setup_config import SetupConfig


T = TypeVar("T", bound="Preset")


@_attrs_define
class Preset:
    """
    Attributes:
        build_status (str):
        created_at (str):
        default_cpu_millicores (int):
        default_disk_gb (int):
        default_memory_mb (int):
        id (str):
        name (str):
        official (bool):
        schema (str | Unset): A URL to the JSON Schema for this object.
        build_error (str | Unset):
        default_setup_config (SetupConfig | Unset):
        default_ttl_seconds (int | Unset):
        description (str | Unset):
        image (str | Unset):
        language (str | Unset):
        org_id (str | Unset):
        secret_project_id (str | Unset):
        slug (str | Unset):
    """

    build_status: str
    created_at: str
    default_cpu_millicores: int
    default_disk_gb: int
    default_memory_mb: int
    id: str
    name: str
    official: bool
    schema: str | Unset = UNSET
    build_error: str | Unset = UNSET
    default_setup_config: SetupConfig | Unset = UNSET
    default_ttl_seconds: int | Unset = UNSET
    description: str | Unset = UNSET
    image: str | Unset = UNSET
    language: str | Unset = UNSET
    org_id: str | Unset = UNSET
    secret_project_id: str | Unset = UNSET
    slug: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        build_status = self.build_status

        created_at = self.created_at

        default_cpu_millicores = self.default_cpu_millicores

        default_disk_gb = self.default_disk_gb

        default_memory_mb = self.default_memory_mb

        id = self.id

        name = self.name

        official = self.official

        schema = self.schema

        build_error = self.build_error

        default_setup_config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.default_setup_config, Unset):
            default_setup_config = self.default_setup_config.to_dict()

        default_ttl_seconds = self.default_ttl_seconds

        description = self.description

        image = self.image

        language = self.language

        org_id = self.org_id

        secret_project_id = self.secret_project_id

        slug = self.slug

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "build_status": build_status,
                "created_at": created_at,
                "default_cpu_millicores": default_cpu_millicores,
                "default_disk_gb": default_disk_gb,
                "default_memory_mb": default_memory_mb,
                "id": id,
                "name": name,
                "official": official,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if build_error is not UNSET:
            field_dict["build_error"] = build_error
        if default_setup_config is not UNSET:
            field_dict["default_setup_config"] = default_setup_config
        if default_ttl_seconds is not UNSET:
            field_dict["default_ttl_seconds"] = default_ttl_seconds
        if description is not UNSET:
            field_dict["description"] = description
        if image is not UNSET:
            field_dict["image"] = image
        if language is not UNSET:
            field_dict["language"] = language
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if secret_project_id is not UNSET:
            field_dict["secret_project_id"] = secret_project_id
        if slug is not UNSET:
            field_dict["slug"] = slug

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.setup_config import SetupConfig

        d = dict(src_dict)
        build_status = d.pop("build_status")

        created_at = d.pop("created_at")

        default_cpu_millicores = d.pop("default_cpu_millicores")

        default_disk_gb = d.pop("default_disk_gb")

        default_memory_mb = d.pop("default_memory_mb")

        id = d.pop("id")

        name = d.pop("name")

        official = d.pop("official")

        schema = d.pop("$schema", UNSET)

        build_error = d.pop("build_error", UNSET)

        _default_setup_config = d.pop("default_setup_config", UNSET)
        default_setup_config: SetupConfig | Unset
        if isinstance(_default_setup_config, Unset):
            default_setup_config = UNSET
        else:
            default_setup_config = SetupConfig.from_dict(_default_setup_config)

        default_ttl_seconds = d.pop("default_ttl_seconds", UNSET)

        description = d.pop("description", UNSET)

        image = d.pop("image", UNSET)

        language = d.pop("language", UNSET)

        org_id = d.pop("org_id", UNSET)

        secret_project_id = d.pop("secret_project_id", UNSET)

        slug = d.pop("slug", UNSET)

        preset = cls(
            build_status=build_status,
            created_at=created_at,
            default_cpu_millicores=default_cpu_millicores,
            default_disk_gb=default_disk_gb,
            default_memory_mb=default_memory_mb,
            id=id,
            name=name,
            official=official,
            schema=schema,
            build_error=build_error,
            default_setup_config=default_setup_config,
            default_ttl_seconds=default_ttl_seconds,
            description=description,
            image=image,
            language=language,
            org_id=org_id,
            secret_project_id=secret_project_id,
            slug=slug,
        )

        return preset
