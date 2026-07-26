import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshCoordinateRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESH_COORDINATE_ROLE_UNSPECIFIED: _ClassVar[MeshCoordinateRole]
    MESH_COORDINATE_ROLE_PEER: _ClassVar[MeshCoordinateRole]
    MESH_COORDINATE_ROLE_DIAL: _ClassVar[MeshCoordinateRole]
MESH_COORDINATE_ROLE_UNSPECIFIED: MeshCoordinateRole
MESH_COORDINATE_ROLE_PEER: MeshCoordinateRole
MESH_COORDINATE_ROLE_DIAL: MeshCoordinateRole

class CoordinateNode(_message.Message):
    __slots__ = ("id", "as_of", "key", "disco_key", "preferred_derp", "derp_latency", "endpoints", "addresses")
    class DerpLatencyEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: float
        def __init__(self, key: _Optional[str] = ..., value: _Optional[float] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    AS_OF_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    DISCO_KEY_FIELD_NUMBER: _ClassVar[int]
    PREFERRED_DERP_FIELD_NUMBER: _ClassVar[int]
    DERP_LATENCY_FIELD_NUMBER: _ClassVar[int]
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    id: str
    as_of: _timestamp_pb2.Timestamp
    key: str
    disco_key: str
    preferred_derp: int
    derp_latency: _containers.ScalarMap[str, float]
    endpoints: _containers.RepeatedScalarFieldContainer[str]
    addresses: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, id: _Optional[str] = ..., as_of: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[str] = ..., disco_key: _Optional[str] = ..., preferred_derp: _Optional[int] = ..., derp_latency: _Optional[_Mapping[str, float]] = ..., endpoints: _Optional[_Iterable[str]] = ..., addresses: _Optional[_Iterable[str]] = ...) -> None: ...

class CoordinateRequest(_message.Message):
    __slots__ = ("node", "hello", "ping")
    NODE_FIELD_NUMBER: _ClassVar[int]
    HELLO_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    node: CoordinateNode
    hello: CoordinateHello
    ping: CoordinatePing
    def __init__(self, node: _Optional[_Union[CoordinateNode, _Mapping]] = ..., hello: _Optional[_Union[CoordinateHello, _Mapping]] = ..., ping: _Optional[_Union[CoordinatePing, _Mapping]] = ...) -> None: ...

class CoordinateHello(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class MeshCoordinatorServiceCoordinateRequest(_message.Message):
    __slots__ = ("node", "hello", "ping", "subscribe")
    NODE_FIELD_NUMBER: _ClassVar[int]
    HELLO_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIBE_FIELD_NUMBER: _ClassVar[int]
    node: CoordinateNode
    hello: MeshCoordinateHello
    ping: CoordinatePing
    subscribe: MeshCoordinateSubscribe
    def __init__(self, node: _Optional[_Union[CoordinateNode, _Mapping]] = ..., hello: _Optional[_Union[MeshCoordinateHello, _Mapping]] = ..., ping: _Optional[_Union[CoordinatePing, _Mapping]] = ..., subscribe: _Optional[_Union[MeshCoordinateSubscribe, _Mapping]] = ...) -> None: ...

class MeshCoordinateHello(_message.Message):
    __slots__ = ("org_id", "network_id", "role")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    role: MeshCoordinateRole
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., role: _Optional[_Union[MeshCoordinateRole, str]] = ...) -> None: ...

class MeshCoordinateSubscribe(_message.Message):
    __slots__ = ("target_node",)
    TARGET_NODE_FIELD_NUMBER: _ClassVar[int]
    target_node: str
    def __init__(self, target_node: _Optional[str] = ...) -> None: ...

class CoordinateResponse(_message.Message):
    __slots__ = ("peer_update", "peer_remove", "derp_map", "ping")
    PEER_UPDATE_FIELD_NUMBER: _ClassVar[int]
    PEER_REMOVE_FIELD_NUMBER: _ClassVar[int]
    DERP_MAP_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    peer_update: CoordinatePeerUpdate
    peer_remove: CoordinatePeerRemove
    derp_map: CoordinateDerpMap
    ping: CoordinatePing
    def __init__(self, peer_update: _Optional[_Union[CoordinatePeerUpdate, _Mapping]] = ..., peer_remove: _Optional[_Union[CoordinatePeerRemove, _Mapping]] = ..., derp_map: _Optional[_Union[CoordinateDerpMap, _Mapping]] = ..., ping: _Optional[_Union[CoordinatePing, _Mapping]] = ...) -> None: ...

class MeshCoordinatorServiceCoordinateResponse(_message.Message):
    __slots__ = ("peer_update", "peer_remove", "derp_map", "ping")
    PEER_UPDATE_FIELD_NUMBER: _ClassVar[int]
    PEER_REMOVE_FIELD_NUMBER: _ClassVar[int]
    DERP_MAP_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    peer_update: CoordinatePeerUpdate
    peer_remove: CoordinatePeerRemove
    derp_map: CoordinateDerpMap
    ping: CoordinatePing
    def __init__(self, peer_update: _Optional[_Union[CoordinatePeerUpdate, _Mapping]] = ..., peer_remove: _Optional[_Union[CoordinatePeerRemove, _Mapping]] = ..., derp_map: _Optional[_Union[CoordinateDerpMap, _Mapping]] = ..., ping: _Optional[_Union[CoordinatePing, _Mapping]] = ...) -> None: ...

class CoordinatePing(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CoordinatePeerUpdate(_message.Message):
    __slots__ = ("nodes",)
    NODES_FIELD_NUMBER: _ClassVar[int]
    nodes: _containers.RepeatedCompositeFieldContainer[CoordinateNode]
    def __init__(self, nodes: _Optional[_Iterable[_Union[CoordinateNode, _Mapping]]] = ...) -> None: ...

class CoordinatePeerRemove(_message.Message):
    __slots__ = ("peer_id",)
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    def __init__(self, peer_id: _Optional[str] = ...) -> None: ...

class CoordinateDerpMap(_message.Message):
    __slots__ = ("derp_map_json",)
    DERP_MAP_JSON_FIELD_NUMBER: _ClassVar[int]
    derp_map_json: bytes
    def __init__(self, derp_map_json: _Optional[bytes] = ...) -> None: ...
