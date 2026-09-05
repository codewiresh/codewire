from codewire.v1 import preset_pb2 as _preset_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetEnvironmentCreateOptionsRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentCreateOptionsResponse(_message.Message):
    __slots__ = ("presets",)
    PRESETS_FIELD_NUMBER: _ClassVar[int]
    presets: _containers.RepeatedCompositeFieldContainer[_preset_pb2.Preset]
    def __init__(self, presets: _Optional[_Iterable[_Union[_preset_pb2.Preset, _Mapping]]] = ...) -> None: ...

class IssueTerminalTicketRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IssueTerminalTicketResponse(_message.Message):
    __slots__ = ("ticket",)
    TICKET_FIELD_NUMBER: _ClassVar[int]
    ticket: str
    def __init__(self, ticket: _Optional[str] = ...) -> None: ...
