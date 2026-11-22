from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DiscoKeyBinding(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DISCO_KEY_BINDING_UNSPECIFIED: _ClassVar[DiscoKeyBinding]
    DISCO_KEY_BINDING_UNBOUND: _ClassVar[DiscoKeyBinding]
    DISCO_KEY_BINDING_BOUND_HERE: _ClassVar[DiscoKeyBinding]
    DISCO_KEY_BINDING_BOUND_ELSEWHERE: _ClassVar[DiscoKeyBinding]
DISCO_KEY_BINDING_UNSPECIFIED: DiscoKeyBinding
DISCO_KEY_BINDING_UNBOUND: DiscoKeyBinding
DISCO_KEY_BINDING_BOUND_HERE: DiscoKeyBinding
DISCO_KEY_BINDING_BOUND_ELSEWHERE: DiscoKeyBinding

class CheckDiscoKeyRequest(_message.Message):
    __slots__ = ("disco_key", "environment_id")
    DISCO_KEY_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    disco_key: bytes
    environment_id: str
    def __init__(self, disco_key: _Optional[bytes] = ..., environment_id: _Optional[str] = ...) -> None: ...

class CheckDiscoKeyResponse(_message.Message):
    __slots__ = ("binding",)
    BINDING_FIELD_NUMBER: _ClassVar[int]
    binding: DiscoKeyBinding
    def __init__(self, binding: _Optional[_Union[DiscoKeyBinding, str]] = ...) -> None: ...
