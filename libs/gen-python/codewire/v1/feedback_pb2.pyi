import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FeedbackPlacement(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FEEDBACK_PLACEMENT_UNSPECIFIED: _ClassVar[FeedbackPlacement]
    FEEDBACK_PLACEMENT_LOCAL: _ClassVar[FeedbackPlacement]
    FEEDBACK_PLACEMENT_CLOUD: _ClassVar[FeedbackPlacement]
FEEDBACK_PLACEMENT_UNSPECIFIED: FeedbackPlacement
FEEDBACK_PLACEMENT_LOCAL: FeedbackPlacement
FEEDBACK_PLACEMENT_CLOUD: FeedbackPlacement

class SubmitFeedbackRequest(_message.Message):
    __slots__ = ("message", "cli_version", "os", "arch", "placement", "environment_id", "org_id")
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CLI_VERSION_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    PLACEMENT_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    message: str
    cli_version: str
    os: str
    arch: str
    placement: FeedbackPlacement
    environment_id: str
    org_id: str
    def __init__(self, message: _Optional[str] = ..., cli_version: _Optional[str] = ..., os: _Optional[str] = ..., arch: _Optional[str] = ..., placement: _Optional[_Union[FeedbackPlacement, str]] = ..., environment_id: _Optional[str] = ..., org_id: _Optional[str] = ...) -> None: ...

class SubmitFeedbackResponse(_message.Message):
    __slots__ = ("id", "created_at", "signed_in")
    ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    SIGNED_IN_FIELD_NUMBER: _ClassVar[int]
    id: str
    created_at: _timestamp_pb2.Timestamp
    signed_in: bool
    def __init__(self, id: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., signed_in: _Optional[bool] = ...) -> None: ...
