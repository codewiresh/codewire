import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SnapshotState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SNAPSHOT_STATE_UNSPECIFIED: _ClassVar[SnapshotState]
    SNAPSHOT_STATE_CAPTURING: _ClassVar[SnapshotState]
    SNAPSHOT_STATE_READY: _ClassVar[SnapshotState]
    SNAPSHOT_STATE_FAILED: _ClassVar[SnapshotState]
    SNAPSHOT_STATE_DELETING: _ClassVar[SnapshotState]
SNAPSHOT_STATE_UNSPECIFIED: SnapshotState
SNAPSHOT_STATE_CAPTURING: SnapshotState
SNAPSHOT_STATE_READY: SnapshotState
SNAPSHOT_STATE_FAILED: SnapshotState
SNAPSHOT_STATE_DELETING: SnapshotState

class Snapshot(_message.Message):
    __slots__ = ("id", "org_id", "name", "source_environment_id", "state", "failure_code", "size_bytes", "created_at", "last_used_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SOURCE_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_CODE_FIELD_NUMBER: _ClassVar[int]
    SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_USED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    name: str
    source_environment_id: str
    state: SnapshotState
    failure_code: str
    size_bytes: int
    created_at: _timestamp_pb2.Timestamp
    last_used_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., name: _Optional[str] = ..., source_environment_id: _Optional[str] = ..., state: _Optional[_Union[SnapshotState, str]] = ..., failure_code: _Optional[str] = ..., size_bytes: _Optional[int] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., last_used_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CreateSnapshotRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    name: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class CreateSnapshotResponse(_message.Message):
    __slots__ = ("snapshot",)
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    snapshot: Snapshot
    def __init__(self, snapshot: _Optional[_Union[Snapshot, _Mapping]] = ...) -> None: ...

class ListSnapshotsRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class ListSnapshotsResponse(_message.Message):
    __slots__ = ("snapshots",)
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    snapshots: _containers.RepeatedCompositeFieldContainer[Snapshot]
    def __init__(self, snapshots: _Optional[_Iterable[_Union[Snapshot, _Mapping]]] = ...) -> None: ...

class GetSnapshotRequest(_message.Message):
    __slots__ = ("org_id", "snapshot_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    snapshot_id: str
    def __init__(self, org_id: _Optional[str] = ..., snapshot_id: _Optional[str] = ...) -> None: ...

class GetSnapshotResponse(_message.Message):
    __slots__ = ("snapshot",)
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    snapshot: Snapshot
    def __init__(self, snapshot: _Optional[_Union[Snapshot, _Mapping]] = ...) -> None: ...

class DeleteSnapshotRequest(_message.Message):
    __slots__ = ("org_id", "snapshot_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    snapshot_id: str
    def __init__(self, org_id: _Optional[str] = ..., snapshot_id: _Optional[str] = ...) -> None: ...

class DeleteSnapshotResponse(_message.Message):
    __slots__ = ("snapshot",)
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    snapshot: Snapshot
    def __init__(self, snapshot: _Optional[_Union[Snapshot, _Mapping]] = ...) -> None: ...
