import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WorkloadSecretSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    WORKLOAD_SECRET_SOURCE_UNSPECIFIED: _ClassVar[WorkloadSecretSource]
    WORKLOAD_SECRET_SOURCE_ORGANIZATION: _ClassVar[WorkloadSecretSource]
    WORKLOAD_SECRET_SOURCE_PROJECT: _ClassVar[WorkloadSecretSource]
    WORKLOAD_SECRET_SOURCE_USER: _ClassVar[WorkloadSecretSource]
    WORKLOAD_SECRET_SOURCE_EXPLICIT_ENVIRONMENT: _ClassVar[WorkloadSecretSource]
WORKLOAD_SECRET_SOURCE_UNSPECIFIED: WorkloadSecretSource
WORKLOAD_SECRET_SOURCE_ORGANIZATION: WorkloadSecretSource
WORKLOAD_SECRET_SOURCE_PROJECT: WorkloadSecretSource
WORKLOAD_SECRET_SOURCE_USER: WorkloadSecretSource
WORKLOAD_SECRET_SOURCE_EXPLICIT_ENVIRONMENT: WorkloadSecretSource

class SecretMetadata(_message.Message):
    __slots__ = ("key", "created_at", "updated_at")
    KEY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    key: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, key: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListSecretsRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListSecretsResponse(_message.Message):
    __slots__ = ("secrets", "next_page_token")
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    secrets: _containers.RepeatedCompositeFieldContainer[SecretMetadata]
    next_page_token: str
    def __init__(self, secrets: _Optional[_Iterable[_Union[SecretMetadata, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class SetSecretRequest(_message.Message):
    __slots__ = ("org_id", "key", "value")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    key: str
    value: str
    def __init__(self, org_id: _Optional[str] = ..., key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class SetSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteSecretRequest(_message.Message):
    __slots__ = ("org_id", "key")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    key: str
    def __init__(self, org_id: _Optional[str] = ..., key: _Optional[str] = ...) -> None: ...

class DeleteSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RenameSecretRequest(_message.Message):
    __slots__ = ("org_id", "key", "new_key")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    NEW_KEY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    key: str
    new_key: str
    def __init__(self, org_id: _Optional[str] = ..., key: _Optional[str] = ..., new_key: _Optional[str] = ...) -> None: ...

class RenameSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListUserSecretsRequest(_message.Message):
    __slots__ = ("page_size", "page_token")
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    page_size: int
    page_token: str
    def __init__(self, page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListUserSecretsResponse(_message.Message):
    __slots__ = ("secrets", "next_page_token")
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    secrets: _containers.RepeatedCompositeFieldContainer[SecretMetadata]
    next_page_token: str
    def __init__(self, secrets: _Optional[_Iterable[_Union[SecretMetadata, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class SetUserSecretRequest(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class SetUserSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteUserSecretRequest(_message.Message):
    __slots__ = ("key",)
    KEY_FIELD_NUMBER: _ClassVar[int]
    key: str
    def __init__(self, key: _Optional[str] = ...) -> None: ...

class DeleteUserSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RenameUserSecretRequest(_message.Message):
    __slots__ = ("key", "new_key")
    KEY_FIELD_NUMBER: _ClassVar[int]
    NEW_KEY_FIELD_NUMBER: _ClassVar[int]
    key: str
    new_key: str
    def __init__(self, key: _Optional[str] = ..., new_key: _Optional[str] = ...) -> None: ...

class RenameUserSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SecretProject(_message.Message):
    __slots__ = ("id", "org_id", "name", "secret_count", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SECRET_COUNT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    name: str
    secret_count: int
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., name: _Optional[str] = ..., secret_count: _Optional[int] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListSecretProjectsRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListSecretProjectsResponse(_message.Message):
    __slots__ = ("secret_projects", "next_page_token")
    SECRET_PROJECTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    secret_projects: _containers.RepeatedCompositeFieldContainer[SecretProject]
    next_page_token: str
    def __init__(self, secret_projects: _Optional[_Iterable[_Union[SecretProject, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateSecretProjectRequest(_message.Message):
    __slots__ = ("org_id", "name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class CreateSecretProjectResponse(_message.Message):
    __slots__ = ("secret_project",)
    SECRET_PROJECT_FIELD_NUMBER: _ClassVar[int]
    secret_project: SecretProject
    def __init__(self, secret_project: _Optional[_Union[SecretProject, _Mapping]] = ...) -> None: ...

class DeleteSecretProjectRequest(_message.Message):
    __slots__ = ("org_id", "secret_project_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    secret_project_id: str
    def __init__(self, org_id: _Optional[str] = ..., secret_project_id: _Optional[str] = ...) -> None: ...

class DeleteSecretProjectResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListProjectSecretsRequest(_message.Message):
    __slots__ = ("org_id", "secret_project_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    secret_project_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., secret_project_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListProjectSecretsResponse(_message.Message):
    __slots__ = ("secrets", "next_page_token")
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    secrets: _containers.RepeatedCompositeFieldContainer[SecretMetadata]
    next_page_token: str
    def __init__(self, secrets: _Optional[_Iterable[_Union[SecretMetadata, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class SetProjectSecretRequest(_message.Message):
    __slots__ = ("org_id", "secret_project_id", "key", "value")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    secret_project_id: str
    key: str
    value: str
    def __init__(self, org_id: _Optional[str] = ..., secret_project_id: _Optional[str] = ..., key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class SetProjectSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteProjectSecretRequest(_message.Message):
    __slots__ = ("org_id", "secret_project_id", "key")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    secret_project_id: str
    key: str
    def __init__(self, org_id: _Optional[str] = ..., secret_project_id: _Optional[str] = ..., key: _Optional[str] = ...) -> None: ...

class DeleteProjectSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RenameProjectSecretRequest(_message.Message):
    __slots__ = ("org_id", "secret_project_id", "key", "new_key")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    NEW_KEY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    secret_project_id: str
    key: str
    new_key: str
    def __init__(self, org_id: _Optional[str] = ..., secret_project_id: _Optional[str] = ..., key: _Optional[str] = ..., new_key: _Optional[str] = ...) -> None: ...

class RenameProjectSecretResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PreviewWorkloadSecretResolutionRequest(_message.Message):
    __slots__ = ("org_id", "organization", "secret_project_id", "user", "explicit_environment_keys")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    EXPLICIT_ENVIRONMENT_KEYS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    organization: bool
    secret_project_id: str
    user: bool
    explicit_environment_keys: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, org_id: _Optional[str] = ..., organization: _Optional[bool] = ..., secret_project_id: _Optional[str] = ..., user: _Optional[bool] = ..., explicit_environment_keys: _Optional[_Iterable[str]] = ...) -> None: ...

class ResolvedWorkloadSecretMetadata(_message.Message):
    __slots__ = ("key", "source", "overridden_sources")
    KEY_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    OVERRIDDEN_SOURCES_FIELD_NUMBER: _ClassVar[int]
    key: str
    source: WorkloadSecretSource
    overridden_sources: _containers.RepeatedScalarFieldContainer[WorkloadSecretSource]
    def __init__(self, key: _Optional[str] = ..., source: _Optional[_Union[WorkloadSecretSource, str]] = ..., overridden_sources: _Optional[_Iterable[_Union[WorkloadSecretSource, str]]] = ...) -> None: ...

class PreviewWorkloadSecretResolutionResponse(_message.Message):
    __slots__ = ("secrets",)
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    secrets: _containers.RepeatedCompositeFieldContainer[ResolvedWorkloadSecretMetadata]
    def __init__(self, secrets: _Optional[_Iterable[_Union[ResolvedWorkloadSecretMetadata, _Mapping]]] = ...) -> None: ...
