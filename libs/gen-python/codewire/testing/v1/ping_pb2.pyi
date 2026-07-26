from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class PublicPingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PublicPingResponse(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class PingRequest(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class PingResponse(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class AdminPingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class AdminPingResponse(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class StreamPingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class StreamPingResponse(_message.Message):
    __slots__ = ("sequence", "total")
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    sequence: int
    total: int
    def __init__(self, sequence: _Optional[int] = ..., total: _Optional[int] = ...) -> None: ...
