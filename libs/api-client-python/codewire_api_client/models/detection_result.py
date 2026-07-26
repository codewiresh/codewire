from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.app_port import AppPort
    from ..models.setup_agent import SetupAgent


T = TypeVar("T", bound="DetectionResult")


@_attrs_define
class DetectionResult:
    """
    Attributes:
        app_ports (list[AppPort] | None):
        cpu (str):
        framework (str):
        has_compose (bool):
        install_command (str):
        language (str):
        memory (str):
        needs_docker (bool):
        preset_image (str):
        preset_slug (str):
        project_type (str):
        setup_notes (str):
        startup_script (str):
        suggested_name (str):
        schema (str | Unset): A URL to the JSON Schema for this object.
        agents (list[SetupAgent] | None | Unset):
        include_org_secrets (bool | Unset):
        include_user_secrets (bool | Unset):
        install_agents (bool | Unset):
        secret_project (str | Unset):
    """

    app_ports: list[AppPort] | None
    cpu: str
    framework: str
    has_compose: bool
    install_command: str
    language: str
    memory: str
    needs_docker: bool
    preset_image: str
    preset_slug: str
    project_type: str
    setup_notes: str
    startup_script: str
    suggested_name: str
    schema: str | Unset = UNSET
    agents: list[SetupAgent] | None | Unset = UNSET
    include_org_secrets: bool | Unset = UNSET
    include_user_secrets: bool | Unset = UNSET
    install_agents: bool | Unset = UNSET
    secret_project: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        app_ports: list[dict[str, Any]] | None
        if isinstance(self.app_ports, list):
            app_ports = []
            for app_ports_type_0_item_data in self.app_ports:
                app_ports_type_0_item = app_ports_type_0_item_data.to_dict()
                app_ports.append(app_ports_type_0_item)

        else:
            app_ports = self.app_ports

        cpu = self.cpu

        framework = self.framework

        has_compose = self.has_compose

        install_command = self.install_command

        language = self.language

        memory = self.memory

        needs_docker = self.needs_docker

        preset_image = self.preset_image

        preset_slug = self.preset_slug

        project_type = self.project_type

        setup_notes = self.setup_notes

        startup_script = self.startup_script

        suggested_name = self.suggested_name

        schema = self.schema

        agents: list[dict[str, Any]] | None | Unset
        if isinstance(self.agents, Unset):
            agents = UNSET
        elif isinstance(self.agents, list):
            agents = []
            for agents_type_0_item_data in self.agents:
                agents_type_0_item = agents_type_0_item_data.to_dict()
                agents.append(agents_type_0_item)

        else:
            agents = self.agents

        include_org_secrets = self.include_org_secrets

        include_user_secrets = self.include_user_secrets

        install_agents = self.install_agents

        secret_project = self.secret_project

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "app_ports": app_ports,
                "cpu": cpu,
                "framework": framework,
                "has_compose": has_compose,
                "install_command": install_command,
                "language": language,
                "memory": memory,
                "needs_docker": needs_docker,
                "preset_image": preset_image,
                "preset_slug": preset_slug,
                "project_type": project_type,
                "setup_notes": setup_notes,
                "startup_script": startup_script,
                "suggested_name": suggested_name,
            }
        )
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if agents is not UNSET:
            field_dict["agents"] = agents
        if include_org_secrets is not UNSET:
            field_dict["include_org_secrets"] = include_org_secrets
        if include_user_secrets is not UNSET:
            field_dict["include_user_secrets"] = include_user_secrets
        if install_agents is not UNSET:
            field_dict["install_agents"] = install_agents
        if secret_project is not UNSET:
            field_dict["secret_project"] = secret_project

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.app_port import AppPort
        from ..models.setup_agent import SetupAgent

        d = dict(src_dict)

        def _parse_app_ports(data: object) -> list[AppPort] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                app_ports_type_0 = []
                _app_ports_type_0 = data
                for app_ports_type_0_item_data in _app_ports_type_0:
                    app_ports_type_0_item = AppPort.from_dict(app_ports_type_0_item_data)

                    app_ports_type_0.append(app_ports_type_0_item)

                return app_ports_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[AppPort] | None, data)

        app_ports = _parse_app_ports(d.pop("app_ports"))

        cpu = d.pop("cpu")

        framework = d.pop("framework")

        has_compose = d.pop("has_compose")

        install_command = d.pop("install_command")

        language = d.pop("language")

        memory = d.pop("memory")

        needs_docker = d.pop("needs_docker")

        preset_image = d.pop("preset_image")

        preset_slug = d.pop("preset_slug")

        project_type = d.pop("project_type")

        setup_notes = d.pop("setup_notes")

        startup_script = d.pop("startup_script")

        suggested_name = d.pop("suggested_name")

        schema = d.pop("$schema", UNSET)

        def _parse_agents(data: object) -> list[SetupAgent] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                agents_type_0 = []
                _agents_type_0 = data
                for agents_type_0_item_data in _agents_type_0:
                    agents_type_0_item = SetupAgent.from_dict(agents_type_0_item_data)

                    agents_type_0.append(agents_type_0_item)

                return agents_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[SetupAgent] | None | Unset, data)

        agents = _parse_agents(d.pop("agents", UNSET))

        include_org_secrets = d.pop("include_org_secrets", UNSET)

        include_user_secrets = d.pop("include_user_secrets", UNSET)

        install_agents = d.pop("install_agents", UNSET)

        secret_project = d.pop("secret_project", UNSET)

        detection_result = cls(
            app_ports=app_ports,
            cpu=cpu,
            framework=framework,
            has_compose=has_compose,
            install_command=install_command,
            language=language,
            memory=memory,
            needs_docker=needs_docker,
            preset_image=preset_image,
            preset_slug=preset_slug,
            project_type=project_type,
            setup_notes=setup_notes,
            startup_script=startup_script,
            suggested_name=suggested_name,
            schema=schema,
            agents=agents,
            include_org_secrets=include_org_secrets,
            include_user_secrets=include_user_secrets,
            install_agents=install_agents,
            secret_project=secret_project,
        )

        return detection_result
