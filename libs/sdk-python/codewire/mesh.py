"""Generated-Connect-backed Mesh API client for the Codewire Python SDK."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timezone
from typing import Any, Literal, TypeVar

from connectrpc.errors import ConnectError
from google.protobuf.descriptor import Descriptor
from google.protobuf.duration_pb2 import Duration
from google.protobuf.timestamp_pb2 import Timestamp

from codewire._transport import ConnectTransport
from codewire.errors import codewire_error_from_connect
from codewire.v1 import (
    mesh_group_pb2,
    mesh_kv_pb2,
    mesh_network_pb2,
    mesh_node_pb2,
)
from codewire.v1.mesh_group_connect import MeshGroupServiceClientSync
from codewire.v1.mesh_kv_connect import MeshKeyValueServiceClientSync
from codewire.v1.mesh_network_connect import MeshNetworkServiceClientSync
from codewire.v1.mesh_node_connect import MeshNodeServiceClientSync


ResponseT = TypeVar("ResponseT")
MeshGroupMessagesPolicy = Literal["", "internal-only", "open"]
MeshGroupDebugPolicy = Literal["", "none", "observe-only", "full"]


# -- Types --------------------------------------------------------------------


@dataclass
class MeshNetwork:
    id: str
    org_id: str
    created_at: str
    node_count: int
    invite_count: int


@dataclass
class MeshNode:
    org_id: str
    network_id: str
    name: str
    peer_url: str
    # Whether the node holds a live coordinator session now.
    connected: bool
    # When its coordinator session last heard from it; None from a server
    # that does not report it.
    last_seen_at: str | None = None


@dataclass
class MeshEnrollment:
    id: str
    org_id: str
    network_id: str
    node_name: str
    owner_user_id: str
    issued_by_user_id: str
    expires_at: str
    created_at: str
    redeemed_at: str | None
    enrollment_code: str


@dataclass
class MeshNodeRegistration:
    """Non-secret result of consuming a one-use enrollment capability."""

    node: MeshNode
    enrollment: MeshEnrollment


@dataclass
class MeshKVEntry:
    org_id: str
    network_id: str
    namespace: str
    key: str
    value: bytes
    expires_at: str | None


@dataclass
class MeshGroupMember:
    org_id: str
    network_id: str
    group_name: str
    node_name: str
    session_name: str
    created_at: str


@dataclass
class MeshGroupPolicy:
    org_id: str
    network_id: str
    group_name: str
    messages_policy: MeshGroupMessagesPolicy
    debug_policy: MeshGroupDebugPolicy
    updated_at: str


@dataclass
class MeshGroup:
    org_id: str
    network_id: str
    name: str
    created_at: str
    created_by_user_id: str
    members: list[MeshGroupMember]
    policy: MeshGroupPolicy | None


# -- Conversion ---------------------------------------------------------------


def _unary(
    transport: ConnectTransport,
    call: Callable[..., ResponseT],
    request: object,
) -> ResponseT:
    try:
        return transport.unary(call, request)
    except ConnectError as error:
        raise codewire_error_from_connect(error) from error


def _message(response: Any, field: str, label: str) -> Any:
    if not response.HasField(field):
        raise RuntimeError(f"Mesh {label} response omitted {field}")
    return getattr(response, field)


def _timestamp(value: Timestamp, label: str) -> str:
    try:
        converted = value.ToDatetime(tzinfo=timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValueError(f"invalid Mesh {label}: {error}") from error
    return converted.isoformat(timespec="seconds").replace("+00:00", "Z")


def _required_timestamp(message: Any, field: str, label: str) -> str:
    if not message.HasField(field):
        raise RuntimeError(f"Mesh {label} is missing")
    return _timestamp(getattr(message, field), label)


def _optional_timestamp(message: Any, field: str, label: str) -> str | None:
    if not message.HasField(field):
        return None
    return _timestamp(getattr(message, field), label)


def _duration(name: str, seconds: int | None) -> Duration | None:
    if seconds is None or seconds == 0:
        return None
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 0:
        raise ValueError(f"Mesh {name} must be a non-negative integer")
    return Duration(seconds=seconds)


def _messages_policy_from_proto(value: int) -> MeshGroupMessagesPolicy:
    if value == mesh_group_pb2.MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED:
        return ""
    if value == mesh_group_pb2.MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY:
        return "internal-only"
    if value == mesh_group_pb2.MESH_GROUP_MESSAGES_POLICY_OPEN:
        return "open"
    raise ValueError(f"unknown Mesh messages policy {value}")


def _messages_policy_to_proto(value: MeshGroupMessagesPolicy) -> int:
    if value == "":
        return mesh_group_pb2.MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED
    if value == "internal-only":
        return mesh_group_pb2.MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY
    if value == "open":
        return mesh_group_pb2.MESH_GROUP_MESSAGES_POLICY_OPEN
    raise ValueError(f"unknown Mesh messages policy {value}")


def _debug_policy_from_proto(value: int) -> MeshGroupDebugPolicy:
    if value == mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_UNSPECIFIED:
        return ""
    if value == mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_NONE:
        return "none"
    if value == mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY:
        return "observe-only"
    if value == mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_FULL:
        return "full"
    raise ValueError(f"unknown Mesh debug policy {value}")


def _debug_policy_to_proto(value: MeshGroupDebugPolicy) -> int:
    if value == "":
        return mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_UNSPECIFIED
    if value == "none":
        return mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_NONE
    if value == "observe-only":
        return mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY
    if value == "full":
        return mesh_group_pb2.MESH_GROUP_DEBUG_POLICY_FULL
    raise ValueError(f"unknown Mesh debug policy {value}")


def _network_from_proto(network: mesh_network_pb2.MeshNetwork) -> MeshNetwork:
    return MeshNetwork(
        id=network.id,
        org_id=network.org_id,
        created_at=_required_timestamp(
            network, "created_at", "network created_at"
        ),
        node_count=network.node_count,
        invite_count=network.invite_count,
    )


def _node_from_proto(node: mesh_node_pb2.MeshNode) -> MeshNode:
    return MeshNode(
        org_id=node.org_id,
        network_id=node.network_id,
        name=node.name,
        peer_url=node.peer_url,
        connected=node.connected,
        last_seen_at=_optional_timestamp(node, "last_seen_at", "node last_seen_at"),
    )


def _enrollment_from_proto(
    enrollment: mesh_node_pb2.MeshNodeEnrollment,
    enrollment_code: str,
) -> MeshEnrollment:
    return MeshEnrollment(
        id=enrollment.id,
        org_id=enrollment.org_id,
        network_id=enrollment.network_id,
        node_name=enrollment.node_name,
        owner_user_id=enrollment.owner_user_id,
        issued_by_user_id=enrollment.issued_by_user_id,
        expires_at=_required_timestamp(
            enrollment, "expires_at", "enrollment expires_at"
        ),
        created_at=_required_timestamp(
            enrollment, "created_at", "enrollment created_at"
        ),
        redeemed_at=_optional_timestamp(
            enrollment, "redeemed_at", "enrollment redeemed_at"
        ),
        enrollment_code=enrollment_code,
    )


def _member_from_proto(
    member: mesh_group_pb2.MeshGroupMember,
) -> MeshGroupMember:
    return MeshGroupMember(
        org_id=member.org_id,
        network_id=member.network_id,
        group_name=member.group_name,
        node_name=member.node_name,
        session_name=member.session_name,
        created_at=_required_timestamp(
            member, "created_at", "group member created_at"
        ),
    )


def _policy_from_proto(
    policy: mesh_group_pb2.MeshGroupPolicy,
) -> MeshGroupPolicy:
    return MeshGroupPolicy(
        org_id=policy.org_id,
        network_id=policy.network_id,
        group_name=policy.group_name,
        messages_policy=_messages_policy_from_proto(policy.messages_policy),
        debug_policy=_debug_policy_from_proto(policy.debug_policy),
        updated_at=_required_timestamp(
            policy, "updated_at", "group policy updated_at"
        ),
    )


def _group_from_proto(group: mesh_group_pb2.MeshGroup) -> MeshGroup:
    return MeshGroup(
        org_id=group.org_id,
        network_id=group.network_id,
        name=group.name,
        created_at=_required_timestamp(group, "created_at", "group created_at"),
        created_by_user_id=group.created_by_user_id,
        members=[_member_from_proto(member) for member in group.members],
        policy=(
            _policy_from_proto(group.policy)
            if group.HasField("policy")
            else None
        ),
    )


def _entry_from_proto(entry: mesh_kv_pb2.MeshKeyValue) -> MeshKVEntry:
    return MeshKVEntry(
        org_id=entry.org_id,
        network_id=entry.network_id,
        namespace=entry.namespace,
        key=entry.key,
        value=bytes(entry.value),
        expires_at=_optional_timestamp(
            entry, "expires_at", "key value expires_at"
        ),
    )


def _assert_fields(
    descriptor: Descriptor,
    expected: tuple[str, ...],
) -> None:
    actual = tuple(field.name for field in descriptor.fields)
    if actual != expected:
        raise RuntimeError(
            f"Mesh converter field coverage drift for "
            f"{descriptor.full_name}: {actual!r}"
        )


def assert_mesh_converter_coverage() -> None:
    """Fail if a published Mesh message gains an unmapped field."""

    _assert_fields(
        mesh_network_pb2.MeshNetwork.DESCRIPTOR,
        ("id", "org_id", "created_at", "node_count", "invite_count"),
    )
    _assert_fields(
        mesh_node_pb2.MeshNode.DESCRIPTOR,
        ("org_id", "network_id", "name", "peer_url", "connected", "last_seen_at"),
    )
    _assert_fields(
        mesh_node_pb2.MeshNodeEnrollment.DESCRIPTOR,
        (
            "id",
            "org_id",
            "network_id",
            "node_name",
            "owner_user_id",
            "issued_by_user_id",
            "expires_at",
            "created_at",
            "redeemed_at",
        ),
    )
    _assert_fields(
        mesh_group_pb2.MeshGroup.DESCRIPTOR,
        (
            "org_id",
            "network_id",
            "name",
            "created_at",
            "created_by_user_id",
            "members",
            "policy",
        ),
    )
    _assert_fields(
        mesh_group_pb2.MeshGroupMember.DESCRIPTOR,
        (
            "org_id",
            "network_id",
            "group_name",
            "node_name",
            "session_name",
            "created_at",
        ),
    )
    _assert_fields(
        mesh_group_pb2.MeshGroupPolicy.DESCRIPTOR,
        (
            "org_id",
            "network_id",
            "group_name",
            "messages_policy",
            "debug_policy",
            "updated_at",
        ),
    )
    _assert_fields(
        mesh_kv_pb2.MeshKeyValue.DESCRIPTOR,
        (
            "org_id",
            "network_id",
            "namespace",
            "key",
            "value",
            "expires_at",
        ),
    )


# -- Services -----------------------------------------------------------------


class MeshNetworks:
    def __init__(
        self,
        transport: ConnectTransport,
        client: MeshNetworkServiceClientSync,
    ) -> None:
        self._transport = transport
        self._client = client

    def create(self, org_id: str, network_id: str) -> MeshNetwork:
        response = _unary(
            self._transport,
            self._client.create_mesh_network,
            mesh_network_pb2.CreateMeshNetworkRequest(
                org_id=org_id, network_id=network_id
            ),
        )
        return _network_from_proto(
            _message(response, "network", "create network")
        )

    def delete(self, org_id: str, network_id: str) -> None:
        _unary(
            self._transport,
            self._client.delete_mesh_network,
            mesh_network_pb2.DeleteMeshNetworkRequest(
                org_id=org_id, network_id=network_id
            ),
        )

    def list(self, org_id: str) -> list[MeshNetwork]:
        networks: list[MeshNetwork] = []
        page_token = ""
        while True:
            response = _unary(
                self._transport,
                self._client.list_mesh_networks,
                mesh_network_pb2.ListMeshNetworksRequest(
                    org_id=org_id, page_token=page_token
                ),
            )
            networks.extend(
                _network_from_proto(network) for network in response.networks
            )
            page_token = response.next_page_token
            if not page_token:
                return networks


class MeshNodes:
    def __init__(
        self,
        transport: ConnectTransport,
        client: MeshNodeServiceClientSync,
        public_transport: ConnectTransport,
        public_client: MeshNodeServiceClientSync,
    ) -> None:
        self._transport = transport
        self._client = client
        self._public_transport = public_transport
        self._public_client = public_client

    def list(self, org_id: str, network_id: str) -> list[MeshNode]:
        nodes: list[MeshNode] = []
        page_token = ""
        while True:
            response = _unary(
                self._transport,
                self._client.list_mesh_nodes,
                mesh_node_pb2.ListMeshNodesRequest(
                    org_id=org_id,
                    network_id=network_id,
                    page_token=page_token,
                ),
            )
            nodes.extend(_node_from_proto(node) for node in response.nodes)
            page_token = response.next_page_token
            if not page_token:
                return nodes

    def revoke(self, org_id: str, network_id: str, node_name: str) -> None:
        _unary(
            self._transport,
            self._client.revoke_mesh_node,
            mesh_node_pb2.RevokeMeshNodeRequest(
                org_id=org_id,
                network_id=network_id,
                node_name=node_name,
            ),
        )

    def create_enrollment(
        self,
        org_id: str,
        network_id: str,
        node_name: str,
        *,
        ttl_seconds: int | None = None,
    ) -> MeshEnrollment:
        request = mesh_node_pb2.CreateMeshNodeEnrollmentRequest(
            org_id=org_id,
            network_id=network_id,
            node_name=node_name,
        )
        ttl = _duration("enrollment ttl_seconds", ttl_seconds)
        if ttl is not None:
            request.ttl.CopyFrom(ttl)
        response = _unary(
            self._transport,
            self._client.create_mesh_node_enrollment,
            request,
        )
        return _enrollment_from_proto(
            _message(response, "enrollment", "create enrollment"),
            response.enrollment_code,
        )

    def redeem_enrollment(
        self,
        enrollment_code: str,
        node_name: str,
    ) -> MeshNodeRegistration:
        """Consume a one-use capability without sending a bearer."""

        response = _unary(
            self._public_transport,
            self._public_client.redeem_mesh_node_enrollment,
            mesh_node_pb2.RedeemMeshNodeEnrollmentRequest(
                enrollment_code=enrollment_code,
                node_name=node_name,
            ),
        )
        return MeshNodeRegistration(
            node=_node_from_proto(_message(response, "node", "redeem enrollment")),
            enrollment=_enrollment_from_proto(
                _message(response, "enrollment", "redeem enrollment"),
                "",
            ),
        )


class MeshGroups:
    def __init__(
        self,
        transport: ConnectTransport,
        client: MeshGroupServiceClientSync,
    ) -> None:
        self._transport = transport
        self._client = client

    def create(
        self,
        org_id: str,
        network_id: str,
        name: str,
    ) -> MeshGroup:
        response = _unary(
            self._transport,
            self._client.create_mesh_group,
            mesh_group_pb2.CreateMeshGroupRequest(
                org_id=org_id, network_id=network_id, name=name
            ),
        )
        return _group_from_proto(_message(response, "group", "create group"))

    def list(self, org_id: str, network_id: str) -> list[MeshGroup]:
        groups: list[MeshGroup] = []
        page_token = ""
        while True:
            response = _unary(
                self._transport,
                self._client.list_mesh_groups,
                mesh_group_pb2.ListMeshGroupsRequest(
                    org_id=org_id,
                    network_id=network_id,
                    page_token=page_token,
                ),
            )
            groups.extend(_group_from_proto(group) for group in response.groups)
            page_token = response.next_page_token
            if not page_token:
                return groups

    def get(
        self,
        org_id: str,
        network_id: str,
        name: str,
    ) -> MeshGroup:
        response = _unary(
            self._transport,
            self._client.get_mesh_group,
            mesh_group_pb2.GetMeshGroupRequest(
                org_id=org_id,
                network_id=network_id,
                group_name=name,
            ),
        )
        return _group_from_proto(_message(response, "group", "get group"))

    def delete(self, org_id: str, network_id: str, name: str) -> None:
        _unary(
            self._transport,
            self._client.delete_mesh_group,
            mesh_group_pb2.DeleteMeshGroupRequest(
                org_id=org_id,
                network_id=network_id,
                group_name=name,
            ),
        )

    def add_member(
        self,
        org_id: str,
        network_id: str,
        group_name: str,
        node_name: str,
        session_name: str,
    ) -> MeshGroupMember:
        response = _unary(
            self._transport,
            self._client.add_mesh_group_member,
            mesh_group_pb2.AddMeshGroupMemberRequest(
                org_id=org_id,
                network_id=network_id,
                group_name=group_name,
                node_name=node_name,
                session_name=session_name,
            ),
        )
        return _member_from_proto(
            _message(response, "member", "add group member")
        )

    def remove_member(
        self,
        org_id: str,
        network_id: str,
        group_name: str,
        node_name: str,
        session_name: str,
    ) -> None:
        _unary(
            self._transport,
            self._client.remove_mesh_group_member,
            mesh_group_pb2.RemoveMeshGroupMemberRequest(
                org_id=org_id,
                network_id=network_id,
                group_name=group_name,
                node_name=node_name,
                session_name=session_name,
            ),
        )

    def set_policy(
        self,
        org_id: str,
        network_id: str,
        group_name: str,
        messages_policy: MeshGroupMessagesPolicy,
        debug_policy: MeshGroupDebugPolicy,
    ) -> MeshGroupPolicy:
        response = _unary(
            self._transport,
            self._client.set_mesh_group_policy,
            mesh_group_pb2.SetMeshGroupPolicyRequest(
                org_id=org_id,
                network_id=network_id,
                group_name=group_name,
                messages_policy=_messages_policy_to_proto(messages_policy),
                debug_policy=_debug_policy_to_proto(debug_policy),
            ),
        )
        return _policy_from_proto(
            _message(response, "policy", "set group policy")
        )


class MeshKV:
    def __init__(
        self,
        transport: ConnectTransport,
        client: MeshKeyValueServiceClientSync,
    ) -> None:
        self._transport = transport
        self._client = client

    def set(
        self,
        org_id: str,
        network_id: str,
        namespace: str,
        key: str,
        value: bytes | str,
        *,
        ttl_seconds: int | None = None,
    ) -> MeshKVEntry:
        request = mesh_kv_pb2.SetMeshKeyValueRequest(
            org_id=org_id,
            network_id=network_id,
            namespace=namespace,
            key=key,
            value=value.encode("utf-8") if isinstance(value, str) else value,
        )
        ttl = _duration("key value ttl_seconds", ttl_seconds)
        if ttl is not None:
            request.ttl.CopyFrom(ttl)
        response = _unary(
            self._transport,
            self._client.set_mesh_key_value,
            request,
        )
        return _entry_from_proto(
            _message(response, "entry", "set key value")
        )

    def get(
        self,
        org_id: str,
        network_id: str,
        namespace: str,
        key: str,
    ) -> MeshKVEntry:
        response = _unary(
            self._transport,
            self._client.get_mesh_key_value,
            mesh_kv_pb2.GetMeshKeyValueRequest(
                org_id=org_id,
                network_id=network_id,
                namespace=namespace,
                key=key,
            ),
        )
        return _entry_from_proto(
            _message(response, "entry", "get key value")
        )

    def list(
        self,
        org_id: str,
        network_id: str,
        namespace: str,
        prefix: str = "",
    ) -> list[MeshKVEntry]:
        entries: list[MeshKVEntry] = []
        page_token = ""
        while True:
            response = _unary(
                self._transport,
                self._client.list_mesh_key_values,
                mesh_kv_pb2.ListMeshKeyValuesRequest(
                    org_id=org_id,
                    network_id=network_id,
                    namespace=namespace,
                    prefix=prefix,
                    page_token=page_token,
                ),
            )
            entries.extend(
                _entry_from_proto(entry) for entry in response.entries
            )
            page_token = response.next_page_token
            if not page_token:
                return entries

    def delete(
        self,
        org_id: str,
        network_id: str,
        namespace: str,
        key: str,
    ) -> None:
        _unary(
            self._transport,
            self._client.delete_mesh_key_value,
            mesh_kv_pb2.DeleteMeshKeyValueRequest(
                org_id=org_id,
                network_id=network_id,
                namespace=namespace,
                key=key,
            ),
        )


# -- Client -------------------------------------------------------------------


class MeshClient:
    """One ergonomic façade over the generated Mesh Connect clients."""

    def __init__(
        self,
        mesh_url: str,
        auth_token: str,
        *,
        timeout: float = 30,
        http_client: Any = None,
    ) -> None:
        self._base_url = mesh_url.rstrip("/")
        self._transport = ConnectTransport(
            self._base_url,
            auth_token,
            timeout=timeout,
            http_client=http_client,
        )
        self._public_transport = ConnectTransport(
            self._base_url,
            "",
            timeout=timeout,
            http_client=http_client,
        )
        self._network_client = self._transport.client(
            MeshNetworkServiceClientSync
        )
        self._node_client = self._transport.client(MeshNodeServiceClientSync)
        self._public_node_client = self._public_transport.client(
            MeshNodeServiceClientSync
        )
        self._group_client = self._transport.client(MeshGroupServiceClientSync)
        self._kv_client = self._transport.client(
            MeshKeyValueServiceClientSync
        )
        self.networks = MeshNetworks(self._transport, self._network_client)
        self.nodes = MeshNodes(
            self._transport,
            self._node_client,
            self._public_transport,
            self._public_node_client,
        )
        self.groups = MeshGroups(self._transport, self._group_client)
        self.kv = MeshKV(self._transport, self._kv_client)
        assert_mesh_converter_coverage()

    def close(self) -> None:
        self._network_client.close()
        self._node_client.close()
        self._public_node_client.close()
        self._group_client.close()
        self._kv_client.close()

    def __enter__(self) -> MeshClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
