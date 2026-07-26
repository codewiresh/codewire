from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.app_port import AppPort
    from ..models.create_environment_body_agent_env import CreateEnvironmentBodyAgentEnv
    from ..models.create_environment_body_env_vars import CreateEnvironmentBodyEnvVars
    from ..models.repo_entry import RepoEntry
    from ..models.setup_agent import SetupAgent


T = TypeVar("T", bound="CreateEnvironmentBody")


@_attrs_define
class CreateEnvironmentBody:
    """
    Attributes:
        schema (str | Unset): A URL to the JSON Schema for this object.
        agent (str | Unset): AI agent to install (claude-code, codex, gemini-cli, aider)
        agent_env (CreateEnvironmentBodyAgentEnv | Unset): Agent environment variables
        agents (list[SetupAgent] | None | Unset): AI agent tools expected in the environment
        app_ports (list[AppPort] | None | Unset): Application ports to register
        branch (str | Unset): Branch to checkout
        cpu_millicores (int | Unset): CPU in millicores
        disk_gb (int | Unset): Disk in GB
        env_vars (CreateEnvironmentBodyEnvVars | Unset): Environment variables
        image (str | Unset): Container image (find-or-create preset)
        include_org_secrets (bool | Unset): Include org-level secrets (default true)
        include_user_secrets (bool | Unset): Include user-level secrets (default true)
        install_agents (bool | Unset): Install selected agent tools during setup instead of relying on the image
        install_command (str | Unset): Install command to run after clone
        memory_mb (int | Unset): Memory in MB
        name (str | Unset): Environment name
        preset_id (str | Unset): Preset to create from
        preset_slug (str | Unset): Preset short name (e.g. go, node, python)
        repo_url (str | Unset): Git repo URL (triggers detection if no image)
        repos (list[RepoEntry] | None | Unset): Multiple repos to clone (overrides repo_url)
        secret_project (str | Unset): Secret project name to bind
        startup_script (str | Unset): Startup script to run after install
        ttl_seconds (int | Unset): TTL in seconds
    """

    schema: str | Unset = UNSET
    agent: str | Unset = UNSET
    agent_env: CreateEnvironmentBodyAgentEnv | Unset = UNSET
    agents: list[SetupAgent] | None | Unset = UNSET
    app_ports: list[AppPort] | None | Unset = UNSET
    branch: str | Unset = UNSET
    cpu_millicores: int | Unset = UNSET
    disk_gb: int | Unset = UNSET
    env_vars: CreateEnvironmentBodyEnvVars | Unset = UNSET
    image: str | Unset = UNSET
    include_org_secrets: bool | Unset = UNSET
    include_user_secrets: bool | Unset = UNSET
    install_agents: bool | Unset = UNSET
    install_command: str | Unset = UNSET
    memory_mb: int | Unset = UNSET
    name: str | Unset = UNSET
    preset_id: str | Unset = UNSET
    preset_slug: str | Unset = UNSET
    repo_url: str | Unset = UNSET
    repos: list[RepoEntry] | None | Unset = UNSET
    secret_project: str | Unset = UNSET
    startup_script: str | Unset = UNSET
    ttl_seconds: int | Unset = UNSET

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

        branch = self.branch

        cpu_millicores = self.cpu_millicores

        disk_gb = self.disk_gb

        env_vars: dict[str, Any] | Unset = UNSET
        if not isinstance(self.env_vars, Unset):
            env_vars = self.env_vars.to_dict()

        image = self.image

        include_org_secrets = self.include_org_secrets

        include_user_secrets = self.include_user_secrets

        install_agents = self.install_agents

        install_command = self.install_command

        memory_mb = self.memory_mb

        name = self.name

        preset_id = self.preset_id

        preset_slug = self.preset_slug

        repo_url = self.repo_url

        repos: list[dict[str, Any]] | None | Unset
        if isinstance(self.repos, Unset):
            repos = UNSET
        elif isinstance(self.repos, list):
            repos = []
            for repos_type_0_item_data in self.repos:
                repos_type_0_item = repos_type_0_item_data.to_dict()
                repos.append(repos_type_0_item)

        else:
            repos = self.repos

        secret_project = self.secret_project

        startup_script = self.startup_script

        ttl_seconds = self.ttl_seconds

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
        if branch is not UNSET:
            field_dict["branch"] = branch
        if cpu_millicores is not UNSET:
            field_dict["cpu_millicores"] = cpu_millicores
        if disk_gb is not UNSET:
            field_dict["disk_gb"] = disk_gb
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
        if memory_mb is not UNSET:
            field_dict["memory_mb"] = memory_mb
        if name is not UNSET:
            field_dict["name"] = name
        if preset_id is not UNSET:
            field_dict["preset_id"] = preset_id
        if preset_slug is not UNSET:
            field_dict["preset_slug"] = preset_slug
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if repos is not UNSET:
            field_dict["repos"] = repos
        if secret_project is not UNSET:
            field_dict["secret_project"] = secret_project
        if startup_script is not UNSET:
            field_dict["startup_script"] = startup_script
        if ttl_seconds is not UNSET:
            field_dict["ttl_seconds"] = ttl_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.app_port import AppPort
        from ..models.create_environment_body_agent_env import CreateEnvironmentBodyAgentEnv
        from ..models.create_environment_body_env_vars import CreateEnvironmentBodyEnvVars
        from ..models.repo_entry import RepoEntry
        from ..models.setup_agent import SetupAgent

        d = dict(src_dict)
        schema = d.pop("$schema", UNSET)

        agent = d.pop("agent", UNSET)

        _agent_env = d.pop("agent_env", UNSET)
        agent_env: CreateEnvironmentBodyAgentEnv | Unset
        if isinstance(_agent_env, Unset):
            agent_env = UNSET
        else:
            agent_env = CreateEnvironmentBodyAgentEnv.from_dict(_agent_env)

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

        branch = d.pop("branch", UNSET)

        cpu_millicores = d.pop("cpu_millicores", UNSET)

        disk_gb = d.pop("disk_gb", UNSET)

        _env_vars = d.pop("env_vars", UNSET)
        env_vars: CreateEnvironmentBodyEnvVars | Unset
        if isinstance(_env_vars, Unset):
            env_vars = UNSET
        else:
            env_vars = CreateEnvironmentBodyEnvVars.from_dict(_env_vars)

        image = d.pop("image", UNSET)

        include_org_secrets = d.pop("include_org_secrets", UNSET)

        include_user_secrets = d.pop("include_user_secrets", UNSET)

        install_agents = d.pop("install_agents", UNSET)

        install_command = d.pop("install_command", UNSET)

        memory_mb = d.pop("memory_mb", UNSET)

        name = d.pop("name", UNSET)

        preset_id = d.pop("preset_id", UNSET)

        preset_slug = d.pop("preset_slug", UNSET)

        repo_url = d.pop("repo_url", UNSET)

        def _parse_repos(data: object) -> list[RepoEntry] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                repos_type_0 = []
                _repos_type_0 = data
                for repos_type_0_item_data in _repos_type_0:
                    repos_type_0_item = RepoEntry.from_dict(repos_type_0_item_data)

                    repos_type_0.append(repos_type_0_item)

                return repos_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[RepoEntry] | None | Unset, data)

        repos = _parse_repos(d.pop("repos", UNSET))

        secret_project = d.pop("secret_project", UNSET)

        startup_script = d.pop("startup_script", UNSET)

        ttl_seconds = d.pop("ttl_seconds", UNSET)

        create_environment_body = cls(
            schema=schema,
            agent=agent,
            agent_env=agent_env,
            agents=agents,
            app_ports=app_ports,
            branch=branch,
            cpu_millicores=cpu_millicores,
            disk_gb=disk_gb,
            env_vars=env_vars,
            image=image,
            include_org_secrets=include_org_secrets,
            include_user_secrets=include_user_secrets,
            install_agents=install_agents,
            install_command=install_command,
            memory_mb=memory_mb,
            name=name,
            preset_id=preset_id,
            preset_slug=preset_slug,
            repo_url=repo_url,
            repos=repos,
            secret_project=secret_project,
            startup_script=startup_script,
            ttl_seconds=ttl_seconds,
        )

        return create_environment_body
