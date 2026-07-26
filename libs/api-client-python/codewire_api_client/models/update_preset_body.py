from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.app_port import AppPort
    from ..models.setup_agent import SetupAgent
    from ..models.update_preset_body_agent_env import UpdatePresetBodyAgentEnv
    from ..models.update_preset_body_env_vars import UpdatePresetBodyEnvVars


T = TypeVar("T", bound="UpdatePresetBody")


@_attrs_define
class UpdatePresetBody:
    """
    Attributes:
        schema (str | Unset): A URL to the JSON Schema for this object.
        agent (str | Unset):
        agent_env (UpdatePresetBodyAgentEnv | Unset):
        agents (list[SetupAgent] | None | Unset):
        app_ports (list[AppPort] | None | Unset):
        default_cpu_millicores (int | Unset):
        default_disk_gb (int | Unset):
        default_memory_mb (int | Unset):
        default_ttl_seconds (int | Unset):
        description (str | Unset):
        env_vars (UpdatePresetBodyEnvVars | Unset):
        image (str | Unset):
        include_org_secrets (bool | Unset):
        include_user_secrets (bool | Unset):
        install_agents (bool | Unset):
        install_command (str | Unset):
        name (str | Unset):
        secret_project (str | Unset):
        slug (str | Unset):
        startup_script (str | Unset):
    """

    schema: str | Unset = UNSET
    agent: str | Unset = UNSET
    agent_env: UpdatePresetBodyAgentEnv | Unset = UNSET
    agents: list[SetupAgent] | None | Unset = UNSET
    app_ports: list[AppPort] | None | Unset = UNSET
    default_cpu_millicores: int | Unset = UNSET
    default_disk_gb: int | Unset = UNSET
    default_memory_mb: int | Unset = UNSET
    default_ttl_seconds: int | Unset = UNSET
    description: str | Unset = UNSET
    env_vars: UpdatePresetBodyEnvVars | Unset = UNSET
    image: str | Unset = UNSET
    include_org_secrets: bool | Unset = UNSET
    include_user_secrets: bool | Unset = UNSET
    install_agents: bool | Unset = UNSET
    install_command: str | Unset = UNSET
    name: str | Unset = UNSET
    secret_project: str | Unset = UNSET
    slug: str | Unset = UNSET
    startup_script: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        schema = self.schema

        agent = self.agent

        agent_env: dict[str, Any] | Unset = UNSET
        if not isinstance(self.agent_env, Unset):
            agent_env = self.agent_env.to_dict()

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

        app_ports: list[dict[str, Any]] | None | Unset
        if isinstance(self.app_ports, Unset):
            app_ports = UNSET
        elif isinstance(self.app_ports, list):
            app_ports = []
            for app_ports_type_0_item_data in self.app_ports:
                app_ports_type_0_item = app_ports_type_0_item_data.to_dict()
                app_ports.append(app_ports_type_0_item)

        else:
            app_ports = self.app_ports

        default_cpu_millicores = self.default_cpu_millicores

        default_disk_gb = self.default_disk_gb

        default_memory_mb = self.default_memory_mb

        default_ttl_seconds = self.default_ttl_seconds

        description = self.description

        env_vars: dict[str, Any] | Unset = UNSET
        if not isinstance(self.env_vars, Unset):
            env_vars = self.env_vars.to_dict()

        image = self.image

        include_org_secrets = self.include_org_secrets

        include_user_secrets = self.include_user_secrets

        install_agents = self.install_agents

        install_command = self.install_command

        name = self.name

        secret_project = self.secret_project

        slug = self.slug

        startup_script = self.startup_script

        field_dict: dict[str, Any] = {}

        field_dict.update({})
        if schema is not UNSET:
            field_dict["$schema"] = schema
        if agent is not UNSET:
            field_dict["agent"] = agent
        if agent_env is not UNSET:
            field_dict["agent_env"] = agent_env
        if agents is not UNSET:
            field_dict["agents"] = agents
        if app_ports is not UNSET:
            field_dict["app_ports"] = app_ports
        if default_cpu_millicores is not UNSET:
            field_dict["default_cpu_millicores"] = default_cpu_millicores
        if default_disk_gb is not UNSET:
            field_dict["default_disk_gb"] = default_disk_gb
        if default_memory_mb is not UNSET:
            field_dict["default_memory_mb"] = default_memory_mb
        if default_ttl_seconds is not UNSET:
            field_dict["default_ttl_seconds"] = default_ttl_seconds
        if description is not UNSET:
            field_dict["description"] = description
        if env_vars is not UNSET:
            field_dict["env_vars"] = env_vars
        if image is not UNSET:
            field_dict["image"] = image
        if include_org_secrets is not UNSET:
            field_dict["include_org_secrets"] = include_org_secrets
        if include_user_secrets is not UNSET:
            field_dict["include_user_secrets"] = include_user_secrets
        if install_agents is not UNSET:
            field_dict["install_agents"] = install_agents
        if install_command is not UNSET:
            field_dict["install_command"] = install_command
        if name is not UNSET:
            field_dict["name"] = name
        if secret_project is not UNSET:
            field_dict["secret_project"] = secret_project
        if slug is not UNSET:
            field_dict["slug"] = slug
        if startup_script is not UNSET:
            field_dict["startup_script"] = startup_script

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.app_port import AppPort
        from ..models.setup_agent import SetupAgent
        from ..models.update_preset_body_agent_env import UpdatePresetBodyAgentEnv
        from ..models.update_preset_body_env_vars import UpdatePresetBodyEnvVars

        d = dict(src_dict)
        schema = d.pop("$schema", UNSET)

        agent = d.pop("agent", UNSET)

        _agent_env = d.pop("agent_env", UNSET)
        agent_env: UpdatePresetBodyAgentEnv | Unset
        if isinstance(_agent_env, Unset):
            agent_env = UNSET
        else:
            agent_env = UpdatePresetBodyAgentEnv.from_dict(_agent_env)

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

        def _parse_app_ports(data: object) -> list[AppPort] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
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
            return cast(list[AppPort] | None | Unset, data)

        app_ports = _parse_app_ports(d.pop("app_ports", UNSET))

        default_cpu_millicores = d.pop("default_cpu_millicores", UNSET)

        default_disk_gb = d.pop("default_disk_gb", UNSET)

        default_memory_mb = d.pop("default_memory_mb", UNSET)

        default_ttl_seconds = d.pop("default_ttl_seconds", UNSET)

        description = d.pop("description", UNSET)

        _env_vars = d.pop("env_vars", UNSET)
        env_vars: UpdatePresetBodyEnvVars | Unset
        if isinstance(_env_vars, Unset):
            env_vars = UNSET
        else:
            env_vars = UpdatePresetBodyEnvVars.from_dict(_env_vars)

        image = d.pop("image", UNSET)

        include_org_secrets = d.pop("include_org_secrets", UNSET)

        include_user_secrets = d.pop("include_user_secrets", UNSET)

        install_agents = d.pop("install_agents", UNSET)

        install_command = d.pop("install_command", UNSET)

        name = d.pop("name", UNSET)

        secret_project = d.pop("secret_project", UNSET)

        slug = d.pop("slug", UNSET)

        startup_script = d.pop("startup_script", UNSET)

        update_preset_body = cls(
            schema=schema,
            agent=agent,
            agent_env=agent_env,
            agents=agents,
            app_ports=app_ports,
            default_cpu_millicores=default_cpu_millicores,
            default_disk_gb=default_disk_gb,
            default_memory_mb=default_memory_mb,
            default_ttl_seconds=default_ttl_seconds,
            description=description,
            env_vars=env_vars,
            image=image,
            include_org_secrets=include_org_secrets,
            include_user_secrets=include_user_secrets,
            install_agents=install_agents,
            install_command=install_command,
            name=name,
            secret_project=secret_project,
            slug=slug,
            startup_script=startup_script,
        )

        return update_preset_body
