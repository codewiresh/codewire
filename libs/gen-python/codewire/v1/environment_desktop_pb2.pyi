import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentDesktopState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_DESKTOP_STATE_UNSPECIFIED: _ClassVar[EnvironmentDesktopState]
    ENVIRONMENT_DESKTOP_STATE_UNAVAILABLE: _ClassVar[EnvironmentDesktopState]
    ENVIRONMENT_DESKTOP_STATE_STOPPED: _ClassVar[EnvironmentDesktopState]
    ENVIRONMENT_DESKTOP_STATE_STARTING: _ClassVar[EnvironmentDesktopState]
    ENVIRONMENT_DESKTOP_STATE_RUNNING: _ClassVar[EnvironmentDesktopState]
ENVIRONMENT_DESKTOP_STATE_UNSPECIFIED: EnvironmentDesktopState
ENVIRONMENT_DESKTOP_STATE_UNAVAILABLE: EnvironmentDesktopState
ENVIRONMENT_DESKTOP_STATE_STOPPED: EnvironmentDesktopState
ENVIRONMENT_DESKTOP_STATE_STARTING: EnvironmentDesktopState
ENVIRONMENT_DESKTOP_STATE_RUNNING: EnvironmentDesktopState

class EnvironmentDesktop(_message.Message):
    __slots__ = ("state", "unavailable_reason", "running")
    STATE_FIELD_NUMBER: _ClassVar[int]
    UNAVAILABLE_REASON_FIELD_NUMBER: _ClassVar[int]
    RUNNING_FIELD_NUMBER: _ClassVar[int]
    state: EnvironmentDesktopState
    unavailable_reason: str
    running: EnvironmentDesktopRunning
    def __init__(self, state: _Optional[_Union[EnvironmentDesktopState, str]] = ..., unavailable_reason: _Optional[str] = ..., running: _Optional[_Union[EnvironmentDesktopRunning, _Mapping]] = ...) -> None: ...

class EnvironmentDesktopRunning(_message.Message):
    __slots__ = ("display", "port", "started_at", "viewer_password")
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    VIEWER_PASSWORD_FIELD_NUMBER: _ClassVar[int]
    display: str
    port: int
    started_at: _timestamp_pb2.Timestamp
    viewer_password: str
    def __init__(self, display: _Optional[str] = ..., port: _Optional[int] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., viewer_password: _Optional[str] = ...) -> None: ...

class StartDesktopRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class StartDesktopResponse(_message.Message):
    __slots__ = ("desktop",)
    DESKTOP_FIELD_NUMBER: _ClassVar[int]
    desktop: EnvironmentDesktop
    def __init__(self, desktop: _Optional[_Union[EnvironmentDesktop, _Mapping]] = ...) -> None: ...

class GetDesktopRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetDesktopResponse(_message.Message):
    __slots__ = ("desktop",)
    DESKTOP_FIELD_NUMBER: _ClassVar[int]
    desktop: EnvironmentDesktop
    def __init__(self, desktop: _Optional[_Union[EnvironmentDesktop, _Mapping]] = ...) -> None: ...

class StopDesktopRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class StopDesktopResponse(_message.Message):
    __slots__ = ("desktop",)
    DESKTOP_FIELD_NUMBER: _ClassVar[int]
    desktop: EnvironmentDesktop
    def __init__(self, desktop: _Optional[_Union[EnvironmentDesktop, _Mapping]] = ...) -> None: ...
