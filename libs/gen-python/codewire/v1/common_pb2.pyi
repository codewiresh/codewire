from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ScaffoldPlaceholder(_message.Message):
    __slots__ = ("note",)
    NOTE_FIELD_NUMBER: _ClassVar[int]
    note: str
    def __init__(self, note: _Optional[str] = ...) -> None: ...

class RepoEntry(_message.Message):
    __slots__ = ("url", "branch")
    URL_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    url: str
    branch: str
    def __init__(self, url: _Optional[str] = ..., branch: _Optional[str] = ...) -> None: ...

class AppPort(_message.Message):
    __slots__ = ("port", "label", "access")
    PORT_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    port: int
    label: str
    access: str
    def __init__(self, port: _Optional[int] = ..., label: _Optional[str] = ..., access: _Optional[str] = ...) -> None: ...

class SetupAgent(_message.Message):
    __slots__ = ("type",)
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: str
    def __init__(self, type: _Optional[str] = ...) -> None: ...

class SetupConfig(_message.Message):
    __slots__ = ("repo_url", "branch", "repos", "install_command", "startup_script", "env_vars", "agents", "install_agents", "agent", "agent_env", "app_ports", "include_org_secrets", "include_user_secrets")
    class EnvVarsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class AgentEnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    REPO_URL_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    REPOS_FIELD_NUMBER: _ClassVar[int]
    INSTALL_COMMAND_FIELD_NUMBER: _ClassVar[int]
    STARTUP_SCRIPT_FIELD_NUMBER: _ClassVar[int]
    ENV_VARS_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    INSTALL_AGENTS_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    AGENT_ENV_FIELD_NUMBER: _ClassVar[int]
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ORG_SECRETS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_USER_SECRETS_FIELD_NUMBER: _ClassVar[int]
    repo_url: str
    branch: str
    repos: _containers.RepeatedCompositeFieldContainer[RepoEntry]
    install_command: str
    startup_script: str
    env_vars: _containers.ScalarMap[str, str]
    agents: _containers.RepeatedCompositeFieldContainer[SetupAgent]
    install_agents: bool
    agent: str
    agent_env: _containers.ScalarMap[str, str]
    app_ports: _containers.RepeatedCompositeFieldContainer[AppPort]
    include_org_secrets: bool
    include_user_secrets: bool
    def __init__(self, repo_url: _Optional[str] = ..., branch: _Optional[str] = ..., repos: _Optional[_Iterable[_Union[RepoEntry, _Mapping]]] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., env_vars: _Optional[_Mapping[str, str]] = ..., agents: _Optional[_Iterable[_Union[SetupAgent, _Mapping]]] = ..., install_agents: _Optional[bool] = ..., agent: _Optional[str] = ..., agent_env: _Optional[_Mapping[str, str]] = ..., app_ports: _Optional[_Iterable[_Union[AppPort, _Mapping]]] = ..., include_org_secrets: _Optional[bool] = ..., include_user_secrets: _Optional[bool] = ...) -> None: ...
