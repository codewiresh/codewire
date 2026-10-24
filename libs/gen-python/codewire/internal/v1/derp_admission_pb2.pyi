from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class CheckNodeKeyRequest(_message.Message):
    __slots__ = ("node_key",)
    NODE_KEY_FIELD_NUMBER: _ClassVar[int]
    node_key: bytes
    def __init__(self, node_key: _Optional[bytes] = ...) -> None: ...

class CheckNodeKeyResponse(_message.Message):
    __slots__ = ("registered",)
    REGISTERED_FIELD_NUMBER: _ClassVar[int]
    registered: bool
    def __init__(self, registered: _Optional[bool] = ...) -> None: ...
