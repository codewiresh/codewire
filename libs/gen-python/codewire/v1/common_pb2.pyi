from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProjectSkillSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROJECT_SKILL_SOURCE_UNSPECIFIED: _ClassVar[ProjectSkillSource]
    PROJECT_SKILL_SOURCE_REPOSITORY: _ClassVar[ProjectSkillSource]
    PROJECT_SKILL_SOURCE_USER: _ClassVar[ProjectSkillSource]

class ProjectStoragePlacement(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROJECT_STORAGE_PLACEMENT_UNSPECIFIED: _ClassVar[ProjectStoragePlacement]
    PROJECT_STORAGE_PLACEMENT_LOCAL: _ClassVar[ProjectStoragePlacement]
    PROJECT_STORAGE_PLACEMENT_PLATFORM: _ClassVar[ProjectStoragePlacement]
PROJECT_SKILL_SOURCE_UNSPECIFIED: ProjectSkillSource
PROJECT_SKILL_SOURCE_REPOSITORY: ProjectSkillSource
PROJECT_SKILL_SOURCE_USER: ProjectSkillSource
PROJECT_STORAGE_PLACEMENT_UNSPECIFIED: ProjectStoragePlacement
PROJECT_STORAGE_PLACEMENT_LOCAL: ProjectStoragePlacement
PROJECT_STORAGE_PLACEMENT_PLATFORM: ProjectStoragePlacement

class ScaffoldPlaceholder(_message.Message):
    __slots__ = ("note",)
    NOTE_FIELD_NUMBER: _ClassVar[int]
    note: str
    def __init__(self, note: _Optional[str] = ...) -> None: ...

class RepositorySpec(_message.Message):
    __slots__ = ("source", "branch", "destination", "revision", "known_hosts")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    KNOWN_HOSTS_FIELD_NUMBER: _ClassVar[int]
    source: str
    branch: str
    destination: str
    revision: str
    known_hosts: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, source: _Optional[str] = ..., branch: _Optional[str] = ..., destination: _Optional[str] = ..., revision: _Optional[str] = ..., known_hosts: _Optional[_Iterable[str]] = ...) -> None: ...

class ApplicationPort(_message.Message):
    __slots__ = ("port", "label", "access")
    PORT_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    port: int
    label: str
    access: str
    def __init__(self, port: _Optional[int] = ..., label: _Optional[str] = ..., access: _Optional[str] = ...) -> None: ...

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
    __slots__ = ("project", "organization", "user")
    PROJECT_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    project: str
    organization: bool
    user: ProjectStoragePlacement
    def __init__(self, project: _Optional[str] = ..., organization: _Optional[bool] = ..., user: _Optional[_Union[ProjectStoragePlacement, str]] = ...) -> None: ...

class ProjectCredentialBinding(_message.Message):
    __slots__ = ("profile",)
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    profile: str
    def __init__(self, profile: _Optional[str] = ...) -> None: ...

class ProjectSpec(_message.Message):
    __slots__ = ("schema_version", "preset", "image", "repositories", "working_directory", "install_command", "startup_script", "environment", "agents", "skills", "application_ports", "resources", "secrets", "credentials")
    class EnvironmentEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
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
    schema_version: int
    preset: str
    image: str
    repositories: _containers.RepeatedCompositeFieldContainer[RepositorySpec]
    working_directory: str
    install_command: str
    startup_script: str
    environment: _containers.ScalarMap[str, str]
    agents: ProjectAgents
    skills: _containers.RepeatedCompositeFieldContainer[ProjectSkillSelection]
    application_ports: _containers.RepeatedCompositeFieldContainer[ApplicationPort]
    resources: ProjectResources
    secrets: ProjectSecretBindings
    credentials: ProjectCredentialBinding
    def __init__(self, schema_version: _Optional[int] = ..., preset: _Optional[str] = ..., image: _Optional[str] = ..., repositories: _Optional[_Iterable[_Union[RepositorySpec, _Mapping]]] = ..., working_directory: _Optional[str] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., environment: _Optional[_Mapping[str, str]] = ..., agents: _Optional[_Union[ProjectAgents, _Mapping]] = ..., skills: _Optional[_Iterable[_Union[ProjectSkillSelection, _Mapping]]] = ..., application_ports: _Optional[_Iterable[_Union[ApplicationPort, _Mapping]]] = ..., resources: _Optional[_Union[ProjectResources, _Mapping]] = ..., secrets: _Optional[_Union[ProjectSecretBindings, _Mapping]] = ..., credentials: _Optional[_Union[ProjectCredentialBinding, _Mapping]] = ...) -> None: ...
