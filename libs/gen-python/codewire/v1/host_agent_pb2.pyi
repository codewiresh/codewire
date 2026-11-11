from codewire.v1 import host_pb2 as _host_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AttachHostRequest(_message.Message):
    __slots__ = ("open", "proof", "hello", "ping")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    PROOF_FIELD_NUMBER: _ClassVar[int]
    HELLO_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    open: HostAttachOpen
    proof: HostAttachProof
    hello: HostHello
    ping: HostPing
    def __init__(self, open: _Optional[_Union[HostAttachOpen, _Mapping]] = ..., proof: _Optional[_Union[HostAttachProof, _Mapping]] = ..., hello: _Optional[_Union[HostHello, _Mapping]] = ..., ping: _Optional[_Union[HostPing, _Mapping]] = ...) -> None: ...

class AttachHostResponse(_message.Message):
    __slots__ = ("challenge", "attached", "pong", "revoked")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    ATTACHED_FIELD_NUMBER: _ClassVar[int]
    PONG_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    challenge: HostChallenge
    attached: HostAttached
    pong: HostPong
    revoked: HostRevoked
    def __init__(self, challenge: _Optional[_Union[HostChallenge, _Mapping]] = ..., attached: _Optional[_Union[HostAttached, _Mapping]] = ..., pong: _Optional[_Union[HostPong, _Mapping]] = ..., revoked: _Optional[_Union[HostRevoked, _Mapping]] = ...) -> None: ...

class HostAttachOpen(_message.Message):
    __slots__ = ("host_id",)
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    host_id: str
    def __init__(self, host_id: _Optional[str] = ...) -> None: ...

class HostChallenge(_message.Message):
    __slots__ = ("nonce",)
    NONCE_FIELD_NUMBER: _ClassVar[int]
    nonce: bytes
    def __init__(self, nonce: _Optional[bytes] = ...) -> None: ...

class HostAttachProof(_message.Message):
    __slots__ = ("signature",)
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    signature: bytes
    def __init__(self, signature: _Optional[bytes] = ...) -> None: ...

class HostAttached(_message.Message):
    __slots__ = ("ping_interval_seconds", "offline_after_seconds", "rechallenge_interval_seconds", "proof_timeout_seconds")
    PING_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    OFFLINE_AFTER_SECONDS_FIELD_NUMBER: _ClassVar[int]
    RECHALLENGE_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    PROOF_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ping_interval_seconds: int
    offline_after_seconds: int
    rechallenge_interval_seconds: int
    proof_timeout_seconds: int
    def __init__(self, ping_interval_seconds: _Optional[int] = ..., offline_after_seconds: _Optional[int] = ..., rechallenge_interval_seconds: _Optional[int] = ..., proof_timeout_seconds: _Optional[int] = ...) -> None: ...

class HostHello(_message.Message):
    __slots__ = ("capability_version", "platform")
    CAPABILITY_VERSION_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    capability_version: int
    platform: _host_pb2.HostPlatform
    def __init__(self, capability_version: _Optional[int] = ..., platform: _Optional[_Union[_host_pb2.HostPlatform, str]] = ...) -> None: ...

class HostPing(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostPong(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostRevoked(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
