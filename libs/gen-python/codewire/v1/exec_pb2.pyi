import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ExecRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "command", "working_dir", "env", "timeout")
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
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    command: _containers.RepeatedScalarFieldContainer[str]
    working_dir: str
    env: _containers.ScalarMap[str, str]
    timeout: _duration_pb2.Duration
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., command: _Optional[_Iterable[str]] = ..., working_dir: _Optional[str] = ..., env: _Optional[_Mapping[str, str]] = ..., timeout: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class ExecResponse(_message.Message):
    __slots__ = ("exit_code", "stdout", "stderr")
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    exit_code: int
    stdout: bytes
    stderr: bytes
    def __init__(self, exit_code: _Optional[int] = ..., stdout: _Optional[bytes] = ..., stderr: _Optional[bytes] = ...) -> None: ...

class StreamExecRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "command", "working_dir", "env")
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
    org_id: str
    environment_id: str
    command: _containers.RepeatedScalarFieldContainer[str]
    working_dir: str
    env: _containers.ScalarMap[str, str]
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., command: _Optional[_Iterable[str]] = ..., working_dir: _Optional[str] = ..., env: _Optional[_Mapping[str, str]] = ...) -> None: ...

class StreamExecResponse(_message.Message):
    __slots__ = ("stdout", "stderr", "exit_code")
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    stdout: bytes
    stderr: bytes
    exit_code: int
    def __init__(self, stdout: _Optional[bytes] = ..., stderr: _Optional[bytes] = ..., exit_code: _Optional[int] = ...) -> None: ...

class RunStart(_message.Message):
    __slots__ = ("org_id", "environment_id", "command", "working_dir", "env", "timeout", "allocate_tty", "term", "columns", "rows")
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
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    ALLOCATE_TTY_FIELD_NUMBER: _ClassVar[int]
    TERM_FIELD_NUMBER: _ClassVar[int]
    COLUMNS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    command: _containers.RepeatedScalarFieldContainer[str]
    working_dir: str
    env: _containers.ScalarMap[str, str]
    timeout: _duration_pb2.Duration
    allocate_tty: bool
    term: str
    columns: int
    rows: int
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., command: _Optional[_Iterable[str]] = ..., working_dir: _Optional[str] = ..., env: _Optional[_Mapping[str, str]] = ..., timeout: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., allocate_tty: _Optional[bool] = ..., term: _Optional[str] = ..., columns: _Optional[int] = ..., rows: _Optional[int] = ...) -> None: ...

class RunResize(_message.Message):
    __slots__ = ("columns", "rows")
    COLUMNS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    columns: int
    rows: int
    def __init__(self, columns: _Optional[int] = ..., rows: _Optional[int] = ...) -> None: ...

class RunRequest(_message.Message):
    __slots__ = ("start", "stdin", "resize", "close_stdin")
    START_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    RESIZE_FIELD_NUMBER: _ClassVar[int]
    CLOSE_STDIN_FIELD_NUMBER: _ClassVar[int]
    start: RunStart
    stdin: bytes
    resize: RunResize
    close_stdin: _empty_pb2.Empty
    def __init__(self, start: _Optional[_Union[RunStart, _Mapping]] = ..., stdin: _Optional[bytes] = ..., resize: _Optional[_Union[RunResize, _Mapping]] = ..., close_stdin: _Optional[_Union[_empty_pb2.Empty, _Mapping]] = ...) -> None: ...

class RunResponse(_message.Message):
    __slots__ = ("stdout", "stderr", "exit_code")
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    stdout: bytes
    stderr: bytes
    exit_code: int
    def __init__(self, stdout: _Optional[bytes] = ..., stderr: _Optional[bytes] = ..., exit_code: _Optional[int] = ...) -> None: ...
