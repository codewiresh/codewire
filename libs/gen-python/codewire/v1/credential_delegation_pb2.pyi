from codewire.bridge.v1 import bridge_pb2 as _bridge_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentCredentialPlaceholdersRequest(_message.Message):
    __slots__ = ("selection", "capability_slots")
    SELECTION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_SLOTS_FIELD_NUMBER: _ClassVar[int]
    selection: CredentialDelegationOpen
    capability_slots: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, selection: _Optional[_Union[CredentialDelegationOpen, _Mapping]] = ..., capability_slots: _Optional[_Iterable[str]] = ...) -> None: ...

class EnvironmentCredentialPlaceholder(_message.Message):
    __slots__ = ("capability_slot", "placeholder")
    CAPABILITY_SLOT_FIELD_NUMBER: _ClassVar[int]
    PLACEHOLDER_FIELD_NUMBER: _ClassVar[int]
    capability_slot: str
    placeholder: str
    def __init__(self, capability_slot: _Optional[str] = ..., placeholder: _Optional[str] = ...) -> None: ...

class EnvironmentCredentialPlaceholdersResponse(_message.Message):
    __slots__ = ("placeholders",)
    PLACEHOLDERS_FIELD_NUMBER: _ClassVar[int]
    placeholders: _containers.RepeatedCompositeFieldContainer[EnvironmentCredentialPlaceholder]
    def __init__(self, placeholders: _Optional[_Iterable[_Union[EnvironmentCredentialPlaceholder, _Mapping]]] = ...) -> None: ...

class FrontDoorDelegationRequest(_message.Message):
    __slots__ = ("frame",)
    FRAME_FIELD_NUMBER: _ClassVar[int]
    frame: _bridge_pb2.CredentialBridgeGuestMessage
    def __init__(self, frame: _Optional[_Union[_bridge_pb2.CredentialBridgeGuestMessage, _Mapping]] = ...) -> None: ...

class FrontDoorDelegationResponse(_message.Message):
    __slots__ = ("admitted", "frame")
    ADMITTED_FIELD_NUMBER: _ClassVar[int]
    FRAME_FIELD_NUMBER: _ClassVar[int]
    admitted: FrontDoorDelegationAdmitted
    frame: _bridge_pb2.CredentialBridgeHostMessage
    def __init__(self, admitted: _Optional[_Union[FrontDoorDelegationAdmitted, _Mapping]] = ..., frame: _Optional[_Union[_bridge_pb2.CredentialBridgeHostMessage, _Mapping]] = ...) -> None: ...

class FrontDoorDelegationAdmitted(_message.Message):
    __slots__ = ("capabilities",)
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, capabilities: _Optional[_Iterable[str]] = ...) -> None: ...

class CredentialDelegationProfile(_message.Message):
    __slots__ = ("profile_id", "profile_revision")
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    PROFILE_REVISION_FIELD_NUMBER: _ClassVar[int]
    profile_id: str
    profile_revision: int
    def __init__(self, profile_id: _Optional[str] = ..., profile_revision: _Optional[int] = ...) -> None: ...

class CredentialDelegationOpen(_message.Message):
    __slots__ = ("runtime", "org_id", "selection_sha256", "project_id", "user_secrets", "organization_secrets", "profile", "ordinary_environment_keys", "reserved_environment_keys", "front_door")
    RUNTIME_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SELECTION_SHA256_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_SECRETS_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_SECRETS_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    ORDINARY_ENVIRONMENT_KEYS_FIELD_NUMBER: _ClassVar[int]
    RESERVED_ENVIRONMENT_KEYS_FIELD_NUMBER: _ClassVar[int]
    FRONT_DOOR_FIELD_NUMBER: _ClassVar[int]
    runtime: _bridge_pb2.CredentialBridgeOpen
    org_id: str
    selection_sha256: bytes
    project_id: str
    user_secrets: bool
    organization_secrets: bool
    profile: CredentialDelegationProfile
    ordinary_environment_keys: _containers.RepeatedScalarFieldContainer[str]
    reserved_environment_keys: _containers.RepeatedScalarFieldContainer[str]
    front_door: bool
    def __init__(self, runtime: _Optional[_Union[_bridge_pb2.CredentialBridgeOpen, _Mapping]] = ..., org_id: _Optional[str] = ..., selection_sha256: _Optional[bytes] = ..., project_id: _Optional[str] = ..., user_secrets: _Optional[bool] = ..., organization_secrets: _Optional[bool] = ..., profile: _Optional[_Union[CredentialDelegationProfile, _Mapping]] = ..., ordinary_environment_keys: _Optional[_Iterable[str]] = ..., reserved_environment_keys: _Optional[_Iterable[str]] = ..., front_door: _Optional[bool] = ...) -> None: ...

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
    __slots__ = ("frame", "admitted", "keepalive", "accepts_keepalive", "front_door_epoch")
    FRAME_FIELD_NUMBER: _ClassVar[int]
    ADMITTED_FIELD_NUMBER: _ClassVar[int]
    KEEPALIVE_FIELD_NUMBER: _ClassVar[int]
    ACCEPTS_KEEPALIVE_FIELD_NUMBER: _ClassVar[int]
    FRONT_DOOR_EPOCH_FIELD_NUMBER: _ClassVar[int]
    frame: _bridge_pb2.CredentialBridgeHostMessage
    admitted: CredentialDelegationOpen
    keepalive: CredentialDelegationKeepalive
    accepts_keepalive: bool
    front_door_epoch: bytes
    def __init__(self, frame: _Optional[_Union[_bridge_pb2.CredentialBridgeHostMessage, _Mapping]] = ..., admitted: _Optional[_Union[CredentialDelegationOpen, _Mapping]] = ..., keepalive: _Optional[_Union[CredentialDelegationKeepalive, _Mapping]] = ..., accepts_keepalive: _Optional[bool] = ..., front_door_epoch: _Optional[bytes] = ...) -> None: ...
