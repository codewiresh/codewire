import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HostPlatform(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOST_PLATFORM_UNSPECIFIED: _ClassVar[HostPlatform]
    HOST_PLATFORM_LINUX_X86_64_KVM: _ClassVar[HostPlatform]
    HOST_PLATFORM_DARWIN_ARM64_VZ: _ClassVar[HostPlatform]

class HostState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOST_STATE_UNSPECIFIED: _ClassVar[HostState]
    HOST_STATE_ONLINE: _ClassVar[HostState]
    HOST_STATE_OFFLINE: _ClassVar[HostState]
    HOST_STATE_REVOKED: _ClassVar[HostState]
HOST_PLATFORM_UNSPECIFIED: HostPlatform
HOST_PLATFORM_LINUX_X86_64_KVM: HostPlatform
HOST_PLATFORM_DARWIN_ARM64_VZ: HostPlatform
HOST_STATE_UNSPECIFIED: HostState
HOST_STATE_ONLINE: HostState
HOST_STATE_OFFLINE: HostState
HOST_STATE_REVOKED: HostState

class HostLimits(_message.Message):
    __slots__ = ("max_vms", "max_vcpus", "max_memory_mib", "max_disk_gib")
    MAX_VMS_FIELD_NUMBER: _ClassVar[int]
    MAX_VCPUS_FIELD_NUMBER: _ClassVar[int]
    MAX_MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    MAX_DISK_GIB_FIELD_NUMBER: _ClassVar[int]
    max_vms: int
    max_vcpus: int
    max_memory_mib: int
    max_disk_gib: int
    def __init__(self, max_vms: _Optional[int] = ..., max_vcpus: _Optional[int] = ..., max_memory_mib: _Optional[int] = ..., max_disk_gib: _Optional[int] = ...) -> None: ...

class Host(_message.Message):
    __slots__ = ("id", "org_id", "owner_user_id", "name", "platform", "capability_version", "public_key", "state", "provide", "limits", "organization_grant", "granted_user_ids", "created_at", "last_seen_at", "revoked_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_USER_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_VERSION_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    PROVIDE_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_GRANT_FIELD_NUMBER: _ClassVar[int]
    GRANTED_USER_IDS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_AT_FIELD_NUMBER: _ClassVar[int]
    REVOKED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    owner_user_id: str
    name: str
    platform: HostPlatform
    capability_version: int
    public_key: bytes
    state: HostState
    provide: bool
    limits: HostLimits
    organization_grant: bool
    granted_user_ids: _containers.RepeatedScalarFieldContainer[str]
    created_at: _timestamp_pb2.Timestamp
    last_seen_at: _timestamp_pb2.Timestamp
    revoked_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., owner_user_id: _Optional[str] = ..., name: _Optional[str] = ..., platform: _Optional[_Union[HostPlatform, str]] = ..., capability_version: _Optional[int] = ..., public_key: _Optional[bytes] = ..., state: _Optional[_Union[HostState, str]] = ..., provide: _Optional[bool] = ..., limits: _Optional[_Union[HostLimits, _Mapping]] = ..., organization_grant: _Optional[bool] = ..., granted_user_ids: _Optional[_Iterable[str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., last_seen_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., revoked_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnrollHostRequest(_message.Message):
    __slots__ = ("org_id", "name", "platform", "capability_version", "public_key", "enrollment_signature")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_VERSION_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    platform: HostPlatform
    capability_version: int
    public_key: bytes
    enrollment_signature: bytes
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ..., platform: _Optional[_Union[HostPlatform, str]] = ..., capability_version: _Optional[int] = ..., public_key: _Optional[bytes] = ..., enrollment_signature: _Optional[bytes] = ...) -> None: ...

class EnrollHostResponse(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: Host
    def __init__(self, host: _Optional[_Union[Host, _Mapping]] = ...) -> None: ...

class ListHostsRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListHostsResponse(_message.Message):
    __slots__ = ("hosts", "next_page_token")
    HOSTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    hosts: _containers.RepeatedCompositeFieldContainer[Host]
    next_page_token: str
    def __init__(self, hosts: _Optional[_Iterable[_Union[Host, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class GetHostRequest(_message.Message):
    __slots__ = ("org_id", "host_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    host_id: str
    def __init__(self, org_id: _Optional[str] = ..., host_id: _Optional[str] = ...) -> None: ...

class GetHostResponse(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: Host
    def __init__(self, host: _Optional[_Union[Host, _Mapping]] = ...) -> None: ...

class UpdateHostProvideRequest(_message.Message):
    __slots__ = ("org_id", "host_id", "provide", "limits")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDE_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    host_id: str
    provide: bool
    limits: HostLimits
    def __init__(self, org_id: _Optional[str] = ..., host_id: _Optional[str] = ..., provide: _Optional[bool] = ..., limits: _Optional[_Union[HostLimits, _Mapping]] = ...) -> None: ...

class UpdateHostProvideResponse(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: Host
    def __init__(self, host: _Optional[_Union[Host, _Mapping]] = ...) -> None: ...

class GrantHostRequest(_message.Message):
    __slots__ = ("org_id", "host_id", "user_id", "organization")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    host_id: str
    user_id: str
    organization: bool
    def __init__(self, org_id: _Optional[str] = ..., host_id: _Optional[str] = ..., user_id: _Optional[str] = ..., organization: _Optional[bool] = ...) -> None: ...

class GrantHostResponse(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: Host
    def __init__(self, host: _Optional[_Union[Host, _Mapping]] = ...) -> None: ...

class RevokeHostGrantRequest(_message.Message):
    __slots__ = ("org_id", "host_id", "user_id", "organization")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    host_id: str
    user_id: str
    organization: bool
    def __init__(self, org_id: _Optional[str] = ..., host_id: _Optional[str] = ..., user_id: _Optional[str] = ..., organization: _Optional[bool] = ...) -> None: ...

class RevokeHostGrantResponse(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: Host
    def __init__(self, host: _Optional[_Union[Host, _Mapping]] = ...) -> None: ...

class RevokeHostRequest(_message.Message):
    __slots__ = ("org_id", "host_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    host_id: str
    def __init__(self, org_id: _Optional[str] = ..., host_id: _Optional[str] = ...) -> None: ...

class RevokeHostResponse(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: Host
    def __init__(self, host: _Optional[_Union[Host, _Mapping]] = ...) -> None: ...

class LeaveHostRequest(_message.Message):
    __slots__ = ("org_id", "host_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    host_id: str
    def __init__(self, org_id: _Optional[str] = ..., host_id: _Optional[str] = ...) -> None: ...

class LeaveHostResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
