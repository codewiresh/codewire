import datetime

from codewire.v1 import common_pb2 as _common_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Preset(_message.Message):
    __slots__ = ("id", "org_id", "name", "slug", "language", "official", "description", "build_status", "build_error", "default_cpu_millicores", "default_memory_mb", "default_disk_gb", "default_ttl_seconds", "image", "default_setup_config", "secret_project_id", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    OFFICIAL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    BUILD_STATUS_FIELD_NUMBER: _ClassVar[int]
    BUILD_ERROR_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_DISK_GB_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_SETUP_CONFIG_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    name: str
    slug: str
    language: str
    official: bool
    description: str
    build_status: str
    build_error: str
    default_cpu_millicores: int
    default_memory_mb: int
    default_disk_gb: int
    default_ttl_seconds: int
    image: str
    default_setup_config: _common_pb2.SetupConfig
    secret_project_id: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., language: _Optional[str] = ..., official: _Optional[bool] = ..., description: _Optional[str] = ..., build_status: _Optional[str] = ..., build_error: _Optional[str] = ..., default_cpu_millicores: _Optional[int] = ..., default_memory_mb: _Optional[int] = ..., default_disk_gb: _Optional[int] = ..., default_ttl_seconds: _Optional[int] = ..., image: _Optional[str] = ..., default_setup_config: _Optional[_Union[_common_pb2.SetupConfig, _Mapping]] = ..., secret_project_id: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListPresetsRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListPresetsResponse(_message.Message):
    __slots__ = ("presets", "next_page_token")
    PRESETS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    presets: _containers.RepeatedCompositeFieldContainer[Preset]
    next_page_token: str
    def __init__(self, presets: _Optional[_Iterable[_Union[Preset, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreatePresetRequest(_message.Message):
    __slots__ = ("org_id", "name", "slug", "description", "default_cpu_millicores", "default_memory_mb", "default_disk_gb", "default_ttl_seconds", "image", "install_command", "startup_script", "env_vars", "agents", "install_agents", "agent", "agent_env", "app_ports", "include_org_secrets", "include_user_secrets", "secret_project_id")
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
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_DISK_GB_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
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
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    slug: str
    description: str
    default_cpu_millicores: int
    default_memory_mb: int
    default_disk_gb: int
    default_ttl_seconds: int
    image: str
    install_command: str
    startup_script: str
    env_vars: _containers.ScalarMap[str, str]
    agents: _containers.RepeatedCompositeFieldContainer[_common_pb2.SetupAgent]
    install_agents: bool
    agent: str
    agent_env: _containers.ScalarMap[str, str]
    app_ports: _containers.RepeatedCompositeFieldContainer[_common_pb2.AppPort]
    include_org_secrets: bool
    include_user_secrets: bool
    secret_project_id: str
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., description: _Optional[str] = ..., default_cpu_millicores: _Optional[int] = ..., default_memory_mb: _Optional[int] = ..., default_disk_gb: _Optional[int] = ..., default_ttl_seconds: _Optional[int] = ..., image: _Optional[str] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., env_vars: _Optional[_Mapping[str, str]] = ..., agents: _Optional[_Iterable[_Union[_common_pb2.SetupAgent, _Mapping]]] = ..., install_agents: _Optional[bool] = ..., agent: _Optional[str] = ..., agent_env: _Optional[_Mapping[str, str]] = ..., app_ports: _Optional[_Iterable[_Union[_common_pb2.AppPort, _Mapping]]] = ..., include_org_secrets: _Optional[bool] = ..., include_user_secrets: _Optional[bool] = ..., secret_project_id: _Optional[str] = ...) -> None: ...

class CreatePresetResponse(_message.Message):
    __slots__ = ("preset",)
    PRESET_FIELD_NUMBER: _ClassVar[int]
    preset: Preset
    def __init__(self, preset: _Optional[_Union[Preset, _Mapping]] = ...) -> None: ...

class GetPresetRequest(_message.Message):
    __slots__ = ("org_id", "preset_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ...) -> None: ...

class GetPresetResponse(_message.Message):
    __slots__ = ("preset",)
    PRESET_FIELD_NUMBER: _ClassVar[int]
    preset: Preset
    def __init__(self, preset: _Optional[_Union[Preset, _Mapping]] = ...) -> None: ...

class EnvVarMap(_message.Message):
    __slots__ = ("values",)
    class ValuesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.ScalarMap[str, str]
    def __init__(self, values: _Optional[_Mapping[str, str]] = ...) -> None: ...

class AgentList(_message.Message):
    __slots__ = ("values",)
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[_common_pb2.SetupAgent]
    def __init__(self, values: _Optional[_Iterable[_Union[_common_pb2.SetupAgent, _Mapping]]] = ...) -> None: ...

class AgentEnvMap(_message.Message):
    __slots__ = ("values",)
    class ValuesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.ScalarMap[str, str]
    def __init__(self, values: _Optional[_Mapping[str, str]] = ...) -> None: ...

class AppPortList(_message.Message):
    __slots__ = ("values",)
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[_common_pb2.AppPort]
    def __init__(self, values: _Optional[_Iterable[_Union[_common_pb2.AppPort, _Mapping]]] = ...) -> None: ...

class UpdatePresetRequest(_message.Message):
    __slots__ = ("org_id", "preset_id", "name", "description", "slug", "default_cpu_millicores", "default_memory_mb", "default_disk_gb", "default_ttl_seconds", "image", "install_command", "startup_script", "env_vars", "agents", "install_agents", "agent", "agent_env", "app_ports", "include_org_secrets", "include_user_secrets", "secret_project_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_DISK_GB_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
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
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    name: str
    description: str
    slug: str
    default_cpu_millicores: int
    default_memory_mb: int
    default_disk_gb: int
    default_ttl_seconds: int
    image: str
    install_command: str
    startup_script: str
    env_vars: EnvVarMap
    agents: AgentList
    install_agents: bool
    agent: str
    agent_env: AgentEnvMap
    app_ports: AppPortList
    include_org_secrets: bool
    include_user_secrets: bool
    secret_project_id: str
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., slug: _Optional[str] = ..., default_cpu_millicores: _Optional[int] = ..., default_memory_mb: _Optional[int] = ..., default_disk_gb: _Optional[int] = ..., default_ttl_seconds: _Optional[int] = ..., image: _Optional[str] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., env_vars: _Optional[_Union[EnvVarMap, _Mapping]] = ..., agents: _Optional[_Union[AgentList, _Mapping]] = ..., install_agents: _Optional[bool] = ..., agent: _Optional[str] = ..., agent_env: _Optional[_Union[AgentEnvMap, _Mapping]] = ..., app_ports: _Optional[_Union[AppPortList, _Mapping]] = ..., include_org_secrets: _Optional[bool] = ..., include_user_secrets: _Optional[bool] = ..., secret_project_id: _Optional[str] = ...) -> None: ...

class UpdatePresetResponse(_message.Message):
    __slots__ = ("preset",)
    PRESET_FIELD_NUMBER: _ClassVar[int]
    preset: Preset
    def __init__(self, preset: _Optional[_Union[Preset, _Mapping]] = ...) -> None: ...

class DeletePresetRequest(_message.Message):
    __slots__ = ("org_id", "preset_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ...) -> None: ...

class DeletePresetResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
