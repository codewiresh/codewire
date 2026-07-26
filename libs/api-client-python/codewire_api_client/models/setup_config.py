from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.app_port import AppPort
    from ..models.repo_entry import RepoEntry
    from ..models.setup_agent import SetupAgent
    from ..models.setup_config_agent_env import SetupConfigAgentEnv
    from ..models.setup_config_env_vars import SetupConfigEnvVars


T = TypeVar("T", bound="SetupConfig")


@_attrs_define
class SetupConfig:
    """
    Attributes:
        agent (str | Unset):
        agent_env (SetupConfigAgentEnv | Unset):
        agents (list[SetupAgent] | None | Unset):
        app_ports (list[AppPort] | None | Unset):
        branch (str | Unset):
        env_vars (SetupConfigEnvVars | Unset):
        include_org_secrets (bool | Unset):
        include_user_secrets (bool | Unset):
        install_agents (bool | Unset):
        install_command (str | Unset):
        repo_url (str | Unset):
        repos (list[RepoEntry] | None | Unset):
        startup_script (str | Unset):
    """

    agent: str | Unset = UNSET
    agent_env: SetupConfigAgentEnv | Unset = UNSET
    agents: list[SetupAgent] | None | Unset = UNSET
    app_ports: list[AppPort] | None | Unset = UNSET
    branch: str | Unset = UNSET
    env_vars: SetupConfigEnvVars | Unset = UNSET
    include_org_secrets: bool | Unset = UNSET
    include_user_secrets: bool | Unset = UNSET
    install_agents: bool | Unset = UNSET
    install_command: str | Unset = UNSET
    repo_url: str | Unset = UNSET
    repos: list[RepoEntry] | None | Unset = UNSET
    startup_script: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
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

        env_vars: dict[str, Any] | Unset = UNSET
        if not isinstance(self.env_vars, Unset):
            env_vars = self.env_vars.to_dict()

        include_org_secrets = self.include_org_secrets

        include_user_secrets = self.include_user_secrets

        install_agents = self.install_agents

        install_command = self.install_command

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

        startup_script = self.startup_script

        field_dict: dict[str, Any] = {}

        field_dict.update({})
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
        if env_vars is not UNSET:
            field_dict["env_vars"] = env_vars
        if include_org_secrets is not UNSET:
            field_dict["include_org_secrets"] = include_org_secrets
        if include_user_secrets is not UNSET:
            field_dict["include_user_secrets"] = include_user_secrets
        if install_agents is not UNSET:
            field_dict["install_agents"] = install_agents
        if install_command is not UNSET:
            field_dict["install_command"] = install_command
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if repos is not UNSET:
            field_dict["repos"] = repos
        if startup_script is not UNSET:
            field_dict["startup_script"] = startup_script

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.app_port import AppPort
        from ..models.repo_entry import RepoEntry
        from ..models.setup_agent import SetupAgent
        from ..models.setup_config_agent_env import SetupConfigAgentEnv
        from ..models.setup_config_env_vars import SetupConfigEnvVars

        d = dict(src_dict)
        agent = d.pop("agent", UNSET)

        _agent_env = d.pop("agent_env", UNSET)
        agent_env: SetupConfigAgentEnv | Unset
        if isinstance(_agent_env, Unset):
            agent_env = UNSET
        else:
            agent_env = SetupConfigAgentEnv.from_dict(_agent_env)

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

        _env_vars = d.pop("env_vars", UNSET)
        env_vars: SetupConfigEnvVars | Unset
        if isinstance(_env_vars, Unset):
            env_vars = UNSET
        else:
            env_vars = SetupConfigEnvVars.from_dict(_env_vars)

        include_org_secrets = d.pop("include_org_secrets", UNSET)

        include_user_secrets = d.pop("include_user_secrets", UNSET)

        install_agents = d.pop("install_agents", UNSET)

        install_command = d.pop("install_command", UNSET)

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

        startup_script = d.pop("startup_script", UNSET)

        setup_config = cls(
            agent=agent,
            agent_env=agent_env,
            agents=agents,
            app_ports=app_ports,
            branch=branch,
            env_vars=env_vars,
            include_org_secrets=include_org_secrets,
            include_user_secrets=include_user_secrets,
            install_agents=install_agents,
            install_command=install_command,
            repo_url=repo_url,
            repos=repos,
            startup_script=startup_script,
        )

        return setup_config
