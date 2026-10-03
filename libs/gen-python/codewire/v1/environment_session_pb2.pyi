import datetime

from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentSessionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_SESSION_STATE_UNSPECIFIED: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_STARTING: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_RUNNING: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_STOPPING: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_STOPPED: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_EXITED: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_FAILED: _ClassVar[EnvironmentSessionState]
    ENVIRONMENT_SESSION_STATE_INTERRUPTED: _ClassVar[EnvironmentSessionState]

class EnvironmentSessionOutputStream(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_SESSION_OUTPUT_STREAM_UNSPECIFIED: _ClassVar[EnvironmentSessionOutputStream]
    ENVIRONMENT_SESSION_OUTPUT_STREAM_STDOUT: _ClassVar[EnvironmentSessionOutputStream]
    ENVIRONMENT_SESSION_OUTPUT_STREAM_STDERR: _ClassVar[EnvironmentSessionOutputStream]
    ENVIRONMENT_SESSION_OUTPUT_STREAM_PTY: _ClassVar[EnvironmentSessionOutputStream]
ENVIRONMENT_SESSION_STATE_UNSPECIFIED: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_STARTING: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_RUNNING: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_STOPPING: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_STOPPED: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_EXITED: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_FAILED: EnvironmentSessionState
ENVIRONMENT_SESSION_STATE_INTERRUPTED: EnvironmentSessionState
ENVIRONMENT_SESSION_OUTPUT_STREAM_UNSPECIFIED: EnvironmentSessionOutputStream
ENVIRONMENT_SESSION_OUTPUT_STREAM_STDOUT: EnvironmentSessionOutputStream
ENVIRONMENT_SESSION_OUTPUT_STREAM_STDERR: EnvironmentSessionOutputStream
ENVIRONMENT_SESSION_OUTPUT_STREAM_PTY: EnvironmentSessionOutputStream

class EnvironmentSession(_message.Message):
    __slots__ = ("session_id", "state", "command", "working_dir", "pty", "created_at", "started_at", "finished_at", "exit_code", "output_end_offset", "status_message", "output_start_offset", "name", "parent_session_id", "cleanup_unknown", "launch_generation")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    PTY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    FINISHED_AT_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_END_OFFSET_FIELD_NUMBER: _ClassVar[int]
    STATUS_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_START_OFFSET_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PARENT_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    CLEANUP_UNKNOWN_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    state: EnvironmentSessionState
    command: _containers.RepeatedScalarFieldContainer[str]
    working_dir: str
    pty: bool
    created_at: _timestamp_pb2.Timestamp
    started_at: _timestamp_pb2.Timestamp
    finished_at: _timestamp_pb2.Timestamp
    exit_code: int
    output_end_offset: int
    status_message: str
    output_start_offset: int
    name: str
    parent_session_id: str
    cleanup_unknown: bool
    launch_generation: int
    def __init__(self, session_id: _Optional[str] = ..., state: _Optional[_Union[EnvironmentSessionState, str]] = ..., command: _Optional[_Iterable[str]] = ..., working_dir: _Optional[str] = ..., pty: _Optional[bool] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., finished_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., exit_code: _Optional[int] = ..., output_end_offset: _Optional[int] = ..., status_message: _Optional[str] = ..., output_start_offset: _Optional[int] = ..., name: _Optional[str] = ..., parent_session_id: _Optional[str] = ..., cleanup_unknown: _Optional[bool] = ..., launch_generation: _Optional[int] = ...) -> None: ...

class EnvironmentSessionOutputChunk(_message.Message):
    __slots__ = ("offset", "next_offset", "stream", "data")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    NEXT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    STREAM_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    offset: int
    next_offset: int
    stream: EnvironmentSessionOutputStream
    data: bytes
    def __init__(self, offset: _Optional[int] = ..., next_offset: _Optional[int] = ..., stream: _Optional[_Union[EnvironmentSessionOutputStream, str]] = ..., data: _Optional[bytes] = ...) -> None: ...

class LaunchSessionRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "command", "working_dir", "env", "pty", "term", "columns", "rows", "name", "parent_session_id")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    PTY_FIELD_NUMBER: _ClassVar[int]
    TERM_FIELD_NUMBER: _ClassVar[int]
    COLUMNS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PARENT_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    command: _containers.RepeatedScalarFieldContainer[str]
    working_dir: str
    env: _containers.ScalarMap[str, str]
    pty: bool
    term: str
    columns: int
    rows: int
    name: str
    parent_session_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., command: _Optional[_Iterable[str]] = ..., working_dir: _Optional[str] = ..., env: _Optional[_Mapping[str, str]] = ..., pty: _Optional[bool] = ..., term: _Optional[str] = ..., columns: _Optional[int] = ..., rows: _Optional[int] = ..., name: _Optional[str] = ..., parent_session_id: _Optional[str] = ...) -> None: ...

class LaunchSessionResponse(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: EnvironmentSession
    def __init__(self, session: _Optional[_Union[EnvironmentSession, _Mapping]] = ...) -> None: ...

class ListSessionsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class ListSessionsResponse(_message.Message):
    __slots__ = ("sessions",)
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    sessions: _containers.RepeatedCompositeFieldContainer[EnvironmentSession]
    def __init__(self, sessions: _Optional[_Iterable[_Union[EnvironmentSession, _Mapping]]] = ...) -> None: ...

class GetSessionRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "session_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    session_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., session_id: _Optional[str] = ...) -> None: ...

class GetSessionResponse(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: EnvironmentSession
    def __init__(self, session: _Optional[_Union[EnvironmentSession, _Mapping]] = ...) -> None: ...

class StopSessionRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "session_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    session_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., session_id: _Optional[str] = ...) -> None: ...

class StopSessionResponse(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: EnvironmentSession
    def __init__(self, session: _Optional[_Union[EnvironmentSession, _Mapping]] = ...) -> None: ...

class RestartSessionRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "session_id", "expected_launch_generation")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    session_id: str
    expected_launch_generation: int
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., session_id: _Optional[str] = ..., expected_launch_generation: _Optional[int] = ...) -> None: ...

class RestartSessionResponse(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: EnvironmentSession
    def __init__(self, session: _Optional[_Union[EnvironmentSession, _Mapping]] = ...) -> None: ...

class SendSessionInputRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "session_id", "data")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    session_id: str
    data: bytes
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., session_id: _Optional[str] = ..., data: _Optional[bytes] = ...) -> None: ...

class SendSessionInputResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ReadSessionOutputRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "session_id", "offset", "limit", "allow_history_gap")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    ALLOW_HISTORY_GAP_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    session_id: str
    offset: int
    limit: int
    allow_history_gap: bool
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., session_id: _Optional[str] = ..., offset: _Optional[int] = ..., limit: _Optional[int] = ..., allow_history_gap: _Optional[bool] = ...) -> None: ...

class ReadSessionOutputResponse(_message.Message):
    __slots__ = ("chunks", "next_offset", "eof", "retained_start_offset", "history_gap")
    CHUNKS_FIELD_NUMBER: _ClassVar[int]
    NEXT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    RETAINED_START_OFFSET_FIELD_NUMBER: _ClassVar[int]
    HISTORY_GAP_FIELD_NUMBER: _ClassVar[int]
    chunks: _containers.RepeatedCompositeFieldContainer[EnvironmentSessionOutputChunk]
    next_offset: int
    eof: bool
    retained_start_offset: int
    history_gap: bool
    def __init__(self, chunks: _Optional[_Iterable[_Union[EnvironmentSessionOutputChunk, _Mapping]]] = ..., next_offset: _Optional[int] = ..., eof: _Optional[bool] = ..., retained_start_offset: _Optional[int] = ..., history_gap: _Optional[bool] = ...) -> None: ...

class AttachSessionOpen(_message.Message):
    __slots__ = ("org_id", "environment_id", "session_id", "output_offset")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    session_id: str
    output_offset: int
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., session_id: _Optional[str] = ..., output_offset: _Optional[int] = ...) -> None: ...

class AttachSessionResize(_message.Message):
    __slots__ = ("columns", "rows")
    COLUMNS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    columns: int
    rows: int
    def __init__(self, columns: _Optional[int] = ..., rows: _Optional[int] = ...) -> None: ...

class AttachSessionRequest(_message.Message):
    __slots__ = ("open", "stdin", "resize", "detach")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    RESIZE_FIELD_NUMBER: _ClassVar[int]
    DETACH_FIELD_NUMBER: _ClassVar[int]
    open: AttachSessionOpen
    stdin: bytes
    resize: AttachSessionResize
    detach: _empty_pb2.Empty
    def __init__(self, open: _Optional[_Union[AttachSessionOpen, _Mapping]] = ..., stdin: _Optional[bytes] = ..., resize: _Optional[_Union[AttachSessionResize, _Mapping]] = ..., detach: _Optional[_Union[_empty_pb2.Empty, _Mapping]] = ...) -> None: ...

class AttachSessionStatus(_message.Message):
    __slots__ = ("session",)
    SESSION_FIELD_NUMBER: _ClassVar[int]
    session: EnvironmentSession
    def __init__(self, session: _Optional[_Union[EnvironmentSession, _Mapping]] = ...) -> None: ...

class EnvironmentSessionOutputGap(_message.Message):
    __slots__ = ("requested_offset", "retained_start_offset")
    REQUESTED_OFFSET_FIELD_NUMBER: _ClassVar[int]
    RETAINED_START_OFFSET_FIELD_NUMBER: _ClassVar[int]
    requested_offset: int
    retained_start_offset: int
    def __init__(self, requested_offset: _Optional[int] = ..., retained_start_offset: _Optional[int] = ...) -> None: ...

class AttachSessionResponse(_message.Message):
    __slots__ = ("output", "status", "history_gap")
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HISTORY_GAP_FIELD_NUMBER: _ClassVar[int]
    output: EnvironmentSessionOutputChunk
    status: AttachSessionStatus
    history_gap: EnvironmentSessionOutputGap
    def __init__(self, output: _Optional[_Union[EnvironmentSessionOutputChunk, _Mapping]] = ..., status: _Optional[_Union[AttachSessionStatus, _Mapping]] = ..., history_gap: _Optional[_Union[EnvironmentSessionOutputGap, _Mapping]] = ...) -> None: ...
