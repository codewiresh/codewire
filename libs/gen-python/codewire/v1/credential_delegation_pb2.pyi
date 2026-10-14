from codewire.bridge.v1 import bridge_pb2 as _bridge_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CredentialDelegationProfile(_message.Message):
    __slots__ = ("profile_id", "profile_revision")
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    PROFILE_REVISION_FIELD_NUMBER: _ClassVar[int]
    profile_id: str
    profile_revision: int
    def __init__(self, profile_id: _Optional[str] = ..., profile_revision: _Optional[int] = ...) -> None: ...

class CredentialDelegationOpen(_message.Message):
    __slots__ = ("runtime", "org_id", "selection_sha256", "project_id", "user_secrets", "organization_secrets", "profile", "ordinary_environment_keys", "reserved_environment_keys")
    RUNTIME_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SELECTION_SHA256_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_SECRETS_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_SECRETS_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    ORDINARY_ENVIRONMENT_KEYS_FIELD_NUMBER: _ClassVar[int]
    RESERVED_ENVIRONMENT_KEYS_FIELD_NUMBER: _ClassVar[int]
    runtime: _bridge_pb2.CredentialBridgeOpen
    org_id: str
    selection_sha256: bytes
    project_id: str
    user_secrets: bool
    organization_secrets: bool
    profile: CredentialDelegationProfile
    ordinary_environment_keys: _containers.RepeatedScalarFieldContainer[str]
    reserved_environment_keys: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, runtime: _Optional[_Union[_bridge_pb2.CredentialBridgeOpen, _Mapping]] = ..., org_id: _Optional[str] = ..., selection_sha256: _Optional[bytes] = ..., project_id: _Optional[str] = ..., user_secrets: _Optional[bool] = ..., organization_secrets: _Optional[bool] = ..., profile: _Optional[_Union[CredentialDelegationProfile, _Mapping]] = ..., ordinary_environment_keys: _Optional[_Iterable[str]] = ..., reserved_environment_keys: _Optional[_Iterable[str]] = ...) -> None: ...

class CredentialDelegationKeepalive(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DelegateCredentialsRequest(_message.Message):
    __slots__ = ("open", "frame", "keepalive")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    FRAME_FIELD_NUMBER: _ClassVar[int]
    KEEPALIVE_FIELD_NUMBER: _ClassVar[int]
    open: CredentialDelegationOpen
    frame: _bridge_pb2.CredentialBridgeGuestMessage
    keepalive: CredentialDelegationKeepalive
    def __init__(self, open: _Optional[_Union[CredentialDelegationOpen, _Mapping]] = ..., frame: _Optional[_Union[_bridge_pb2.CredentialBridgeGuestMessage, _Mapping]] = ..., keepalive: _Optional[_Union[CredentialDelegationKeepalive, _Mapping]] = ...) -> None: ...

class DelegateCredentialsResponse(_message.Message):
    __slots__ = ("frame", "admitted", "keepalive", "accepts_keepalive")
    FRAME_FIELD_NUMBER: _ClassVar[int]
    ADMITTED_FIELD_NUMBER: _ClassVar[int]
    KEEPALIVE_FIELD_NUMBER: _ClassVar[int]
    ACCEPTS_KEEPALIVE_FIELD_NUMBER: _ClassVar[int]
    frame: _bridge_pb2.CredentialBridgeHostMessage
    admitted: CredentialDelegationOpen
    keepalive: CredentialDelegationKeepalive
    accepts_keepalive: bool
    def __init__(self, frame: _Optional[_Union[_bridge_pb2.CredentialBridgeHostMessage, _Mapping]] = ..., admitted: _Optional[_Union[CredentialDelegationOpen, _Mapping]] = ..., keepalive: _Optional[_Union[CredentialDelegationKeepalive, _Mapping]] = ..., accepts_keepalive: _Optional[bool] = ...) -> None: ...
