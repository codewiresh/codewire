from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.environment_create_git_hub_status import EnvironmentCreateGitHubStatus
    from ..models.preset import Preset
    from ..models.secret_project import SecretProject


T = TypeVar("T", bound="EnvironmentCreateOptionsBody")


@_attrs_define
class EnvironmentCreateOptionsBody:
    """
    Attributes:
        github_status (EnvironmentCreateGitHubStatus):
        presets (list[Preset] | None):
        secret_projects (list[SecretProject] | None):
        schema (str | Unset): A URL to the JSON Schema for this object.
    """

    github_status: EnvironmentCreateGitHubStatus
    presets: list[Preset] | None
    secret_projects: list[SecretProject] | None
    schema: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        github_status = self.github_status.to_dict()

        presets: list[dict[str, Any]] | None
        if isinstance(self.presets, list):
            presets = []
            for presets_type_0_item_data in self.presets:
                presets_type_0_item = presets_type_0_item_data.to_dict()
                presets.append(presets_type_0_item)

        else:
            presets = self.presets

        secret_projects: list[dict[str, Any]] | None
        if isinstance(self.secret_projects, list):
            secret_projects = []
            for secret_projects_type_0_item_data in self.secret_projects:
                secret_projects_type_0_item = secret_projects_type_0_item_data.to_dict()
                secret_projects.append(secret_projects_type_0_item)

        else:
            secret_projects = self.secret_projects

        schema = self.schema

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "github_status": github_status,
                "presets": presets,
                "secret_projects": secret_projects,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.environment_create_git_hub_status import EnvironmentCreateGitHubStatus
        from ..models.preset import Preset
        from ..models.secret_project import SecretProject

        d = dict(src_dict)
        github_status = EnvironmentCreateGitHubStatus.from_dict(d.pop("github_status"))

        def _parse_presets(data: object) -> list[Preset] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                presets_type_0 = []
                _presets_type_0 = data
                for presets_type_0_item_data in _presets_type_0:
                    presets_type_0_item = Preset.from_dict(presets_type_0_item_data)

                    presets_type_0.append(presets_type_0_item)

                return presets_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Preset] | None, data)

        presets = _parse_presets(d.pop("presets"))

        def _parse_secret_projects(data: object) -> list[SecretProject] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                secret_projects_type_0 = []
                _secret_projects_type_0 = data
                for secret_projects_type_0_item_data in _secret_projects_type_0:
                    secret_projects_type_0_item = SecretProject.from_dict(secret_projects_type_0_item_data)

                    secret_projects_type_0.append(secret_projects_type_0_item)

                return secret_projects_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[SecretProject] | None, data)

        secret_projects = _parse_secret_projects(d.pop("secret_projects"))

        schema = d.pop("$schema", UNSET)

        environment_create_options_body = cls(
            github_status=github_status,
            presets=presets,
            secret_projects=secret_projects,
            schema=schema,
        )

        return environment_create_options_body
