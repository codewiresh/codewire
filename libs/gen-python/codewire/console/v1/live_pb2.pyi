import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WatchRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class WatchResponse(_message.Message):
    __slots__ = ("resync", "heartbeat", "sandbox", "resize", "credit", "audit")
    RESYNC_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    RESIZE_FIELD_NUMBER: _ClassVar[int]
    CREDIT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    resync: LiveResync
    heartbeat: LiveHeartbeat
    sandbox: SandboxChanged
    resize: ResizeChanged
    credit: CreditChanged
    audit: AuditChanged
    def __init__(self, resync: _Optional[_Union[LiveResync, _Mapping]] = ..., heartbeat: _Optional[_Union[LiveHeartbeat, _Mapping]] = ..., sandbox: _Optional[_Union[SandboxChanged, _Mapping]] = ..., resize: _Optional[_Union[ResizeChanged, _Mapping]] = ..., credit: _Optional[_Union[CreditChanged, _Mapping]] = ..., audit: _Optional[_Union[AuditChanged, _Mapping]] = ...) -> None: ...

class LiveResync(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class LiveHeartbeat(_message.Message):
    __slots__ = ("sent_at",)
    SENT_AT_FIELD_NUMBER: _ClassVar[int]
    sent_at: _timestamp_pb2.Timestamp
    def __init__(self, sent_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SandboxChanged(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class ResizeChanged(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class AuditChanged(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class CreditChanged(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...
