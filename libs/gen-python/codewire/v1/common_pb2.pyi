from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProjectWorkspaceMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROJECT_WORKSPACE_MODE_UNSPECIFIED: _ClassVar[ProjectWorkspaceMode]
    PROJECT_WORKSPACE_MODE_AUTO: _ClassVar[ProjectWorkspaceMode]
    PROJECT_WORKSPACE_MODE_CLONE: _ClassVar[ProjectWorkspaceMode]
    PROJECT_WORKSPACE_MODE_DIRECT: _ClassVar[ProjectWorkspaceMode]

class ProjectSkillSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROJECT_SKILL_SOURCE_UNSPECIFIED: _ClassVar[ProjectSkillSource]
    PROJECT_SKILL_SOURCE_REPOSITORY: _ClassVar[ProjectSkillSource]
    PROJECT_SKILL_SOURCE_USER: _ClassVar[ProjectSkillSource]
PROJECT_WORKSPACE_MODE_UNSPECIFIED: ProjectWorkspaceMode
PROJECT_WORKSPACE_MODE_AUTO: ProjectWorkspaceMode
PROJECT_WORKSPACE_MODE_CLONE: ProjectWorkspaceMode
PROJECT_WORKSPACE_MODE_DIRECT: ProjectWorkspaceMode
PROJECT_SKILL_SOURCE_UNSPECIFIED: ProjectSkillSource
PROJECT_SKILL_SOURCE_REPOSITORY: ProjectSkillSource
PROJECT_SKILL_SOURCE_USER: ProjectSkillSource

class ScaffoldPlaceholder(_message.Message):
    __slots__ = ("note",)
    NOTE_FIELD_NUMBER: _ClassVar[int]
    note: str
    def __init__(self, note: _Optional[str] = ...) -> None: ...

class RepoEntry(_message.Message):
    __slots__ = ("url", "branch", "mount_path", "revision")
    URL_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    MOUNT_PATH_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    url: str
    branch: str
    mount_path: str
    revision: str
    def __init__(self, url: _Optional[str] = ..., branch: _Optional[str] = ..., mount_path: _Optional[str] = ..., revision: _Optional[str] = ...) -> None: ...

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
    __slots__ = ("repo_url", "branch", "repos", "install_command", "startup_script", "env_vars", "agents", "install_agents", "agent", "app_ports", "include_org_secrets", "include_user_secrets", "project_spec")
    class EnvVarsEntry(_message.Message):
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
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ORG_SECRETS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_USER_SECRETS_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_FIELD_NUMBER: _ClassVar[int]
    repo_url: str
    branch: str
    repos: _containers.RepeatedCompositeFieldContainer[RepoEntry]
    install_command: str
    startup_script: str
    env_vars: _containers.ScalarMap[str, str]
    agents: _containers.RepeatedCompositeFieldContainer[SetupAgent]
    install_agents: bool
    agent: str
    app_ports: _containers.RepeatedCompositeFieldContainer[AppPort]
    include_org_secrets: bool
    include_user_secrets: bool
    project_spec: ProjectSpec
    def __init__(self, repo_url: _Optional[str] = ..., branch: _Optional[str] = ..., repos: _Optional[_Iterable[_Union[RepoEntry, _Mapping]]] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., env_vars: _Optional[_Mapping[str, str]] = ..., agents: _Optional[_Iterable[_Union[SetupAgent, _Mapping]]] = ..., install_agents: _Optional[bool] = ..., agent: _Optional[str] = ..., app_ports: _Optional[_Iterable[_Union[AppPort, _Mapping]]] = ..., include_org_secrets: _Optional[bool] = ..., include_user_secrets: _Optional[bool] = ..., project_spec: _Optional[_Union[ProjectSpec, _Mapping]] = ...) -> None: ...

class ProjectAgents(_message.Message):
    __slots__ = ("install", "tools")
    INSTALL_FIELD_NUMBER: _ClassVar[int]
    TOOLS_FIELD_NUMBER: _ClassVar[int]
    install: bool
    tools: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, install: _Optional[bool] = ..., tools: _Optional[_Iterable[str]] = ...) -> None: ...

class ProjectSkillSelection(_message.Message):
    __slots__ = ("source", "reference", "agents")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    source: ProjectSkillSource
    reference: str
    agents: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, source: _Optional[_Union[ProjectSkillSource, str]] = ..., reference: _Optional[str] = ..., agents: _Optional[_Iterable[str]] = ...) -> None: ...

class ProjectResources(_message.Message):
    __slots__ = ("cpu_millicores", "memory_mib", "disk_gib")
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    DISK_GIB_FIELD_NUMBER: _ClassVar[int]
    cpu_millicores: int
    memory_mib: int
    disk_gib: int
    def __init__(self, cpu_millicores: _Optional[int] = ..., memory_mib: _Optional[int] = ..., disk_gib: _Optional[int] = ...) -> None: ...

class ProjectSecretBindings(_message.Message):
    __slots__ = ("project", "include_org", "include_user", "organization", "user")
    PROJECT_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ORG_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_USER_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    project: str
    include_org: bool
    include_user: bool
    organization: bool
    user: bool
    def __init__(self, project: _Optional[str] = ..., include_org: _Optional[bool] = ..., include_user: _Optional[bool] = ..., organization: _Optional[bool] = ..., user: _Optional[bool] = ...) -> None: ...

class ProjectCredentialReference(_message.Message):
    __slots__ = ("provider", "account")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    ACCOUNT_FIELD_NUMBER: _ClassVar[int]
    provider: str
    account: str
    def __init__(self, provider: _Optional[str] = ..., account: _Optional[str] = ...) -> None: ...

class ProjectAccessBinding(_message.Message):
    __slots__ = ("profile",)
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    profile: str
    def __init__(self, profile: _Optional[str] = ...) -> None: ...

class ProjectSpec(_message.Message):
    __slots__ = ("schema_version", "preset", "image", "repositories", "working_directory", "install_command", "startup_script", "environment", "agents", "skills", "application_ports", "resources", "secrets", "credentials", "workspace_mode", "access")
    class EnvironmentEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class CredentialsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ProjectCredentialReference
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ProjectCredentialReference, _Mapping]] = ...) -> None: ...
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    PRESET_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    REPOSITORIES_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIRECTORY_FIELD_NUMBER: _ClassVar[int]
    INSTALL_COMMAND_FIELD_NUMBER: _ClassVar[int]
    STARTUP_SCRIPT_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    SKILLS_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_PORTS_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_MODE_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    schema_version: int
    preset: str
    image: str
    repositories: _containers.RepeatedCompositeFieldContainer[RepoEntry]
    working_directory: str
    install_command: str
    startup_script: str
    environment: _containers.ScalarMap[str, str]
    agents: ProjectAgents
    skills: _containers.RepeatedCompositeFieldContainer[ProjectSkillSelection]
    application_ports: _containers.RepeatedCompositeFieldContainer[AppPort]
    resources: ProjectResources
    secrets: ProjectSecretBindings
    credentials: _containers.MessageMap[str, ProjectCredentialReference]
    workspace_mode: ProjectWorkspaceMode
    access: ProjectAccessBinding
    def __init__(self, schema_version: _Optional[int] = ..., preset: _Optional[str] = ..., image: _Optional[str] = ..., repositories: _Optional[_Iterable[_Union[RepoEntry, _Mapping]]] = ..., working_directory: _Optional[str] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., environment: _Optional[_Mapping[str, str]] = ..., agents: _Optional[_Union[ProjectAgents, _Mapping]] = ..., skills: _Optional[_Iterable[_Union[ProjectSkillSelection, _Mapping]]] = ..., application_ports: _Optional[_Iterable[_Union[AppPort, _Mapping]]] = ..., resources: _Optional[_Union[ProjectResources, _Mapping]] = ..., secrets: _Optional[_Union[ProjectSecretBindings, _Mapping]] = ..., credentials: _Optional[_Mapping[str, ProjectCredentialReference]] = ..., workspace_mode: _Optional[_Union[ProjectWorkspaceMode, str]] = ..., access: _Optional[_Union[ProjectAccessBinding, _Mapping]] = ...) -> None: ...
