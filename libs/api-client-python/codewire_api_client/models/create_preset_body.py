from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.app_port import AppPort
    from ..models.create_preset_body_agent_env import CreatePresetBodyAgentEnv
    from ..models.create_preset_body_env_vars import CreatePresetBodyEnvVars
    from ..models.setup_agent import SetupAgent


T = TypeVar("T", bound="CreatePresetBody")


@_attrs_define
class CreatePresetBody:
    """
    Attributes:
        name (str): Preset name
        schema (str | Unset): A URL to the JSON Schema for this object.
        agent (str | Unset): Default AI agent
        agent_env (CreatePresetBodyAgentEnv | Unset): Default agent environment variables
        agents (list[SetupAgent] | None | Unset): Default AI agent tools expected in the environment
        app_ports (list[AppPort] | None | Unset): Default application ports
        default_cpu_millicores (int | Unset): Default CPU millicores
        default_disk_gb (int | Unset): Default disk GB
        default_memory_mb (int | Unset): Default memory MB
        default_ttl_seconds (int | Unset): Default TTL seconds
        description (str | Unset): Preset description
        env_vars (CreatePresetBodyEnvVars | Unset): Default environment variables
        image (str | Unset): Container image for the preset's sandbox runtime
        include_org_secrets (bool | Unset): Include org-level secrets by default
        include_user_secrets (bool | Unset): Include user-level secrets by default
        install_agents (bool | Unset): Install selected agent tools during setup by default
        install_command (str | Unset): Default install command
        secret_project (str | Unset): Default secret project name
        slug (str | Unset): Preset short name for CLI use
        startup_script (str | Unset): Default startup script
    """

    name: str
    schema: str | Unset = UNSET
    agent: str | Unset = UNSET
    agent_env: CreatePresetBodyAgentEnv | Unset = UNSET
    agents: list[SetupAgent] | None | Unset = UNSET
    app_ports: list[AppPort] | None | Unset = UNSET
    default_cpu_millicores: int | Unset = UNSET
    default_disk_gb: int | Unset = UNSET
    default_memory_mb: int | Unset = UNSET
    default_ttl_seconds: int | Unset = UNSET
    description: str | Unset = UNSET
    env_vars: CreatePresetBodyEnvVars | Unset = UNSET
    image: str | Unset = UNSET
    include_org_secrets: bool | Unset = UNSET
    include_user_secrets: bool | Unset = UNSET
    install_agents: bool | Unset = UNSET
    install_command: str | Unset = UNSET
    secret_project: str | Unset = UNSET
    slug: str | Unset = UNSET
    startup_script: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        name = self.name

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

        secret_project = self.secret_project

        slug = self.slug

        startup_script = self.startup_script

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "name": name,
            }
        )
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
        from ..models.create_preset_body_agent_env import CreatePresetBodyAgentEnv
        from ..models.create_preset_body_env_vars import CreatePresetBodyEnvVars
        from ..models.setup_agent import SetupAgent

        d = dict(src_dict)
        name = d.pop("name")

        schema = d.pop("$schema", UNSET)

        agent = d.pop("agent", UNSET)

        _agent_env = d.pop("agent_env", UNSET)
        agent_env: CreatePresetBodyAgentEnv | Unset
        if isinstance(_agent_env, Unset):
            agent_env = UNSET
        else:
            agent_env = CreatePresetBodyAgentEnv.from_dict(_agent_env)

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
        env_vars: CreatePresetBodyEnvVars | Unset
        if isinstance(_env_vars, Unset):
            env_vars = UNSET
        else:
            env_vars = CreatePresetBodyEnvVars.from_dict(_env_vars)

        image = d.pop("image", UNSET)

        include_org_secrets = d.pop("include_org_secrets", UNSET)

        include_user_secrets = d.pop("include_user_secrets", UNSET)

        install_agents = d.pop("install_agents", UNSET)

        install_command = d.pop("install_command", UNSET)

        secret_project = d.pop("secret_project", UNSET)

        slug = d.pop("slug", UNSET)

        startup_script = d.pop("startup_script", UNSET)

        create_preset_body = cls(
            name=name,
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
            secret_project=secret_project,
            slug=slug,
            startup_script=startup_script,
        )

        return create_preset_body
