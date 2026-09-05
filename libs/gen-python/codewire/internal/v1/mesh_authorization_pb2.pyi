from codewire.v1 import organization_pb2 as _organization_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshAuthorizationPrincipalKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESH_AUTHORIZATION_PRINCIPAL_KIND_UNSPECIFIED: _ClassVar[MeshAuthorizationPrincipalKind]
    MESH_AUTHORIZATION_PRINCIPAL_KIND_USER: _ClassVar[MeshAuthorizationPrincipalKind]

class MeshAuthorizationCredentialKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESH_AUTHORIZATION_CREDENTIAL_KIND_UNSPECIFIED: _ClassVar[MeshAuthorizationCredentialKind]
    MESH_AUTHORIZATION_CREDENTIAL_KIND_SESSION_COOKIE: _ClassVar[MeshAuthorizationCredentialKind]
    MESH_AUTHORIZATION_CREDENTIAL_KIND_OAUTH_BEARER: _ClassVar[MeshAuthorizationCredentialKind]
    MESH_AUTHORIZATION_CREDENTIAL_KIND_API_KEY: _ClassVar[MeshAuthorizationCredentialKind]
MESH_AUTHORIZATION_PRINCIPAL_KIND_UNSPECIFIED: MeshAuthorizationPrincipalKind
MESH_AUTHORIZATION_PRINCIPAL_KIND_USER: MeshAuthorizationPrincipalKind
MESH_AUTHORIZATION_CREDENTIAL_KIND_UNSPECIFIED: MeshAuthorizationCredentialKind
MESH_AUTHORIZATION_CREDENTIAL_KIND_SESSION_COOKIE: MeshAuthorizationCredentialKind
MESH_AUTHORIZATION_CREDENTIAL_KIND_OAUTH_BEARER: MeshAuthorizationCredentialKind
MESH_AUTHORIZATION_CREDENTIAL_KIND_API_KEY: MeshAuthorizationCredentialKind

class ResolveMeshAuthorizationRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class ResolveMeshAuthorizationResponse(_message.Message):
    __slots__ = ("context",)
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    context: MeshAuthorizationContext
    def __init__(self, context: _Optional[_Union[MeshAuthorizationContext, _Mapping]] = ...) -> None: ...

class MeshAuthorizationContext(_message.Message):
    __slots__ = ("principal_id", "principal_kind", "org_id", "role", "credential_kind")
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_KIND_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KIND_FIELD_NUMBER: _ClassVar[int]
    principal_id: str
    principal_kind: MeshAuthorizationPrincipalKind
    org_id: str
    role: _organization_pb2.OrgRole
    credential_kind: MeshAuthorizationCredentialKind
    def __init__(self, principal_id: _Optional[str] = ..., principal_kind: _Optional[_Union[MeshAuthorizationPrincipalKind, str]] = ..., org_id: _Optional[str] = ..., role: _Optional[_Union[_organization_pb2.OrgRole, str]] = ..., credential_kind: _Optional[_Union[MeshAuthorizationCredentialKind, str]] = ...) -> None: ...
