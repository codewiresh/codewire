from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class IssueGatewayBindingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IssueGatewayBindingResponse(_message.Message):
    __slots__ = ("environment_id", "sidecar_token", "workspace_pod_ip", "app_ports", "runtime_transport")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    SIDECAR_TOKEN_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_POD_IP_FIELD_NUMBER: _ClassVar[int]
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_TRANSPORT_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    sidecar_token: str
    workspace_pod_ip: str
    app_ports: _containers.RepeatedScalarFieldContainer[int]
    runtime_transport: RuntimeTransport
    def __init__(self, environment_id: _Optional[str] = ..., sidecar_token: _Optional[str] = ..., workspace_pod_ip: _Optional[str] = ..., app_ports: _Optional[_Iterable[int]] = ..., runtime_transport: _Optional[_Union[RuntimeTransport, _Mapping]] = ...) -> None: ...

class RuntimeTransport(_message.Message):
    __slots__ = ("runtime_region", "transport_zone", "peer_relay", "direct_udp", "stun", "derp")
    RUNTIME_REGION_FIELD_NUMBER: _ClassVar[int]
    TRANSPORT_ZONE_FIELD_NUMBER: _ClassVar[int]
    PEER_RELAY_FIELD_NUMBER: _ClassVar[int]
    DIRECT_UDP_FIELD_NUMBER: _ClassVar[int]
    STUN_FIELD_NUMBER: _ClassVar[int]
    DERP_FIELD_NUMBER: _ClassVar[int]
    runtime_region: str
    transport_zone: str
    peer_relay: PeerRelayTransport
    direct_udp: DirectUdpTransport
    stun: EndpointList
    derp: EndpointList
    def __init__(self, runtime_region: _Optional[str] = ..., transport_zone: _Optional[str] = ..., peer_relay: _Optional[_Union[PeerRelayTransport, _Mapping]] = ..., direct_udp: _Optional[_Union[DirectUdpTransport, _Mapping]] = ..., stun: _Optional[_Union[EndpointList, _Mapping]] = ..., derp: _Optional[_Union[EndpointList, _Mapping]] = ...) -> None: ...

class PeerRelayTransport(_message.Message):
    __slots__ = ("public_endpoints", "dns", "allocator_url", "bind_addrs")
    PUBLIC_ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    DNS_FIELD_NUMBER: _ClassVar[int]
    ALLOCATOR_URL_FIELD_NUMBER: _ClassVar[int]
    BIND_ADDRS_FIELD_NUMBER: _ClassVar[int]
    public_endpoints: _containers.RepeatedScalarFieldContainer[str]
    dns: str
    allocator_url: str
    bind_addrs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, public_endpoints: _Optional[_Iterable[str]] = ..., dns: _Optional[str] = ..., allocator_url: _Optional[str] = ..., bind_addrs: _Optional[_Iterable[str]] = ...) -> None: ...

class DirectUdpTransport(_message.Message):
    __slots__ = ("vip", "port_start", "port_end")
    VIP_FIELD_NUMBER: _ClassVar[int]
    PORT_START_FIELD_NUMBER: _ClassVar[int]
    PORT_END_FIELD_NUMBER: _ClassVar[int]
    vip: str
    port_start: int
    port_end: int
    def __init__(self, vip: _Optional[str] = ..., port_start: _Optional[int] = ..., port_end: _Optional[int] = ...) -> None: ...

class EndpointList(_message.Message):
    __slots__ = ("endpoints",)
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    endpoints: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, endpoints: _Optional[_Iterable[str]] = ...) -> None: ...
