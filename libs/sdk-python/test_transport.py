"""Focused tests for the private generated Connect transport boundary."""

from __future__ import annotations

import io
import sys
import threading
import unittest
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import codewire
from codewire.mesh import (
    MeshClient,
    _debug_policy_from_proto,
    _debug_policy_to_proto,
    _messages_policy_from_proto,
    _messages_policy_to_proto,
    assert_mesh_converter_coverage,
)
from connectrpc.client import ConnectClientSync
from connectrpc.code import Code
from connectrpc.errors import ConnectError, ErrorDetail
from google.protobuf.timestamp_pb2 import Timestamp
from google.rpc.error_details_pb2 import BadRequest, ErrorInfo
from protobuf.wkt import Any

from codewire._convert import (
    environment_to_dict,
    file_entry_to_dict,
    preset_to_dict,
    proto_to_dict,
)
from codewire._transport import ConnectTransport
from codewire.errors import codewire_error_from_connect
from codewire.v1.api_key_pb2 import ApiKey
from codewire.v1.common_pb2 import (
    ApplicationPort,
    ProjectAgents,
    ProjectSecretBindings,
    ProjectSkillSelection,
    ProjectSkillSource,
    ProjectSpec,
    RepositorySpec,
)
from codewire.v1.environment_pb2 import (
    DesiredState,
    Environment,
    EnvironmentState,
    IsolationTier,
)
from codewire.v1.file_pb2 import FileEntry
from codewire.v1.mesh_group_connect import MeshGroupServiceWSGIApplication
from codewire.v1.mesh_group_pb2 import (
    AddMeshGroupMemberResponse,
    CreateMeshGroupResponse,
    DeleteMeshGroupResponse,
    GetMeshGroupResponse,
    ListMeshGroupsResponse,
    MeshGroup,
    MeshGroupDebugPolicy,
    MeshGroupMember,
    MeshGroupMessagesPolicy,
    MeshGroupPolicy,
    RemoveMeshGroupMemberResponse,
    SetMeshGroupPolicyResponse,
)
from codewire.v1.mesh_kv_connect import MeshKeyValueServiceWSGIApplication
from codewire.v1.mesh_kv_pb2 import (
    DeleteMeshKeyValueResponse,
    GetMeshKeyValueResponse,
    ListMeshKeyValuesResponse,
    MeshKeyValue,
    SetMeshKeyValueResponse,
)
from codewire.v1.mesh_network_connect import MeshNetworkServiceWSGIApplication
from codewire.v1.mesh_network_pb2 import (
    CreateMeshNetworkResponse,
    DeleteMeshNetworkResponse,
    ListMeshNetworksResponse,
    MeshNetwork,
)
from codewire.v1.mesh_node_connect import MeshNodeServiceWSGIApplication
from codewire.v1.mesh_node_pb2 import (
    CreateMeshNodeEnrollmentResponse,
    ListMeshNodesResponse,
    MeshNode,
    MeshNodeEnrollment,
    RedeemMeshNodeEnrollmentResponse,
    RevokeMeshNodeResponse,
)
from codewire.v1.port_pb2 import Port, PortAccess
from codewire.v1.preset_pb2 import Preset


def _connect_detail(message: BadRequest | ErrorInfo) -> ErrorDetail:
    return ErrorDetail(
        Any(
            type_url=f"type.googleapis.com/{message.DESCRIPTOR.full_name}",
            value=message.SerializeToString(),
        )
    )


class GeneratedClientDouble(ConnectClientSync):
    def __init__(
        self,
        address: str,
        *,
        timeout_ms: int | None = None,
        http_client: object | None = None,
    ) -> None:
        self.address = address
        self.timeout_ms = timeout_ms
        self.http_client = http_client


class TransportTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = ConnectTransport(
            "https://codewire.example/", "cw_test", timeout=12.5
        )

    def test_generated_transport_is_not_part_of_the_public_sdk_surface(self) -> None:
        self.assertNotIn("ConnectTransport", codewire.__all__)

    def test_constructs_synchronous_generated_client_with_deadline(self) -> None:
        client = self.transport.client(GeneratedClientDouble)

        self.assertEqual(client.address, "https://codewire.example")
        self.assertEqual(client.timeout_ms, 12_500)
        self.assertIsNone(client.http_client)

    def test_unary_forwards_bearer_metadata_and_per_call_deadline(self) -> None:
        observed: dict[str, object] = {}

        def call(request: object, **kwargs: object) -> str:
            observed["request"] = request
            observed.update(kwargs)
            return "response"

        response = self.transport.unary(call, "request", timeout_ms=275)

        self.assertEqual(response, "response")
        self.assertEqual(observed["request"], "request")
        self.assertEqual(
            observed["headers"], {"Authorization": "Bearer cw_test"}
        )
        self.assertEqual(observed["timeout_ms"], 275)

    def test_connect_deadline_error_is_not_translated(self) -> None:
        expected = ConnectError(Code.DEADLINE_EXCEEDED, "deadline elapsed")

        def call(request: object, **kwargs: object) -> object:
            raise expected

        with self.assertRaisesRegex(ConnectError, "deadline elapsed") as raised:
            self.transport.unary(call, "request")

        self.assertIs(raised.exception, expected)

    def test_sync_cancellation_is_not_swallowed(self) -> None:
        def call(request: object, **kwargs: object) -> object:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.transport.unary(call, "request")

    def test_server_stream_remains_lazy_and_forwards_metadata(self) -> None:
        observed: dict[str, object] = {}

        def call(request: object, **kwargs: object) -> Iterator[str]:
            observed["request"] = request
            observed.update(kwargs)
            yield "first"
            yield "second"

        stream = self.transport.server_stream(call, "request", timeout_ms=525)

        self.assertEqual(list(stream), ["first", "second"])
        self.assertEqual(observed["request"], "request")
        self.assertEqual(
            observed["headers"], {"Authorization": "Bearer cw_test"}
        )
        self.assertEqual(observed["timeout_ms"], 525)

    def test_converter_keeps_native_ints_and_second_precision_timestamps(self) -> None:
        timestamp = Timestamp()
        timestamp.FromJsonString("2026-01-01T00:00:00.987654321Z")
        value = proto_to_dict(
            FileEntry(
                name="large.bin",
                size=9_223_372_036_854,
                mode=0o644,
                mod_time=timestamp,
            )
        )

        self.assertEqual(value["size"], 9_223_372_036_854)
        self.assertIsInstance(value["size"], int)
        self.assertEqual(value["mod_time"], "2026-01-01T00:00:00Z")

    def test_api_key_converter_matches_the_rest_resource_shape(self) -> None:
        created_at = Timestamp()
        created_at.FromJsonString("2026-01-01T00:00:00.987654321Z")
        last_used_at = Timestamp()
        last_used_at.FromJsonString("2026-01-02T00:00:00.123456789Z")
        expires_at = Timestamp()
        expires_at.FromJsonString("2026-01-03T00:00:00Z")
        disabled_at = Timestamp()
        disabled_at.FromJsonString("2026-01-04T00:00:00Z")
        api_key = ApiKey(
            id="key_1",
            user_id="user_1",
            org_id="org_1",
            name="deploy",
            key_prefix="cw_abc",
            scopes=["environments:read"],
            created_at=created_at,
            created_by_name="Ada Lovelace",
            created_by_email="ada@example.test",
        )
        api_key.last_used_at.CopyFrom(last_used_at)
        api_key.expires_at.CopyFrom(expires_at)
        api_key.disabled_at.CopyFrom(disabled_at)

        self.assertEqual(
            proto_to_dict(api_key),
            {
                "id": "key_1",
                "user_id": "user_1",
                "org_id": "org_1",
                "name": "deploy",
                "key_prefix": "cw_abc",
                "scopes": ["environments:read"],
                "last_used_at": "2026-01-02T00:00:00Z",
                "expires_at": "2026-01-03T00:00:00Z",
                "disabled_at": "2026-01-04T00:00:00Z",
                "created_at": "2026-01-01T00:00:00Z",
                "created_by_name": "Ada Lovelace",
                "created_by_email": "ada@example.test",
            },
        )

    def test_environment_converter_renders_the_network_attachment(self) -> None:
        from codewire.v1.environment_pb2 import (
            NetworkAttachmentFailure,
            NetworkAttachmentState,
        )

        value = environment_to_dict(
            Environment(
                network="work",
                network_state=NetworkAttachmentState.NETWORK_ATTACHMENT_STATE_FAILED,
                network_failure=NetworkAttachmentFailure.NETWORK_ATTACHMENT_FAILURE_NOT_A_MEMBER,
            )
        )
        self.assertEqual(
            (value["network"], value["network_state"], value["network_failure"]),
            ("work", "failed", "not_a_member"),
        )
        detached = environment_to_dict(Environment())
        self.assertNotIn("network_state", detached)
        self.assertNotIn("network_failure", detached)

    def test_environment_converter_preserves_native_values_and_short_enums(self) -> None:
        created_at = Timestamp()
        created_at.FromJsonString("2026-01-01T00:00:00.987654321Z")
        value = environment_to_dict(
            Environment(
                id="env_1",
                org_id="org_1",
                created_by="user_1",
                preset_id="preset_1",
                type="sandbox",
                name="demo",
                state=EnvironmentState.ENVIRONMENT_STATE_RUNNING,
                desired_state=DesiredState.DESIRED_STATE_STARTED,
                error_code="no_capacity",
                error_reason="none",
                isolation_tier=IsolationTier.ISOLATION_TIER_CONFIDENTIAL,
                recoverable=True,
                state_changed_at=created_at,
                retry_count=2,
                setup_phase=3,
                setup_complete=True,
                setup_error="setup",
                ttl_seconds=3600,
                shutdown_at=created_at,
                cpu_millicores=2_000,
                memory_mb=4_096,
                disk_gb=20,
                total_running_seconds=60,
                created_at=created_at,
                started_at=created_at,
                stopped_at=created_at,
                destroyed_at=created_at,
                protected=True,
                deletion_requested_at=created_at,
                deletion_grace_until=created_at,
                preset_name="Python",
                network="net_1",
                ports=[
                    Port(
                        id="port_1",
                        environment_id="env_1",
                        port=8080,
                        label="web",
                        access=PortAccess.PORT_ACCESS_PUBLIC,
                        preview_url="https://preview.example.test",
                        created_at=created_at,
                    )
                ],
            )
        )

        self.assertEqual(
            value,
            {
                "id": "env_1",
                "org_id": "org_1",
                "created_by": "user_1",
                "preset_id": "preset_1",
                "type": "sandbox",
                "name": "demo",
                "state": "running",
                "desired_state": "started",
                "error_code": "no_capacity",
                "error_reason": "none",
                "isolation_tier": "confidential",
                "recoverable": True,
                "state_changed_at": "2026-01-01T00:00:00Z",
                "retry_count": 2,
                "setup_phase": 3,
                "setup_complete": True,
                "setup_error": "setup",
                "ttl_seconds": 3600,
                "shutdown_at": "2026-01-01T00:00:00Z",
                "cpu_millicores": 2_000,
                "memory_mb": 4_096,
                "disk_gb": 20,
                "total_running_seconds": 60,
                "created_at": "2026-01-01T00:00:00Z",
                "started_at": "2026-01-01T00:00:00Z",
                "stopped_at": "2026-01-01T00:00:00Z",
                "destroyed_at": "2026-01-01T00:00:00Z",
                "protected": True,
                "deletion_requested_at": "2026-01-01T00:00:00Z",
                "deletion_grace_until": "2026-01-01T00:00:00Z",
                "preset_name": "Python",
                "network": "net_1",
                "operation_generation": 0,
                "ports": [
                    {
                        "id": "port_1",
                        "environment_id": "env_1",
                        "port": 8080,
                        "label": "web",
                        "access": "public",
                        "preview_url": "https://preview.example.test",
                        "created_at": "2026-01-01T00:00:00Z",
                    }
                ],
            },
        )
        self.assertIsInstance(value["cpu_millicores"], int)

    def test_file_and_preset_converters_keep_sdk_value_shape(self) -> None:
        mod_time = Timestamp()
        mod_time.FromJsonString("2026-01-01T00:00:00.987654321Z")
        file_value = file_entry_to_dict(
            FileEntry(
                name="script.sh",
                size=42,
                mode=0o755,
                mod_time=mod_time,
            )
        )
        preset_value = preset_to_dict(
            Preset(
                id="preset_1",
                name="Python",
                project_spec=ProjectSpec(
                    schema_version=1,
                    working_directory="/workspace/a",
                    repositories=[
                        RepositorySpec(
                            source="https://example.test/a",
                            branch="branch",
                            destination="/workspace/a",
                        ),
                        RepositorySpec(
                            source="https://example.test/b",
                            revision="deadbeef",
                            destination="/workspace/b",
                        ),
                    ],
                    install_command="pip install",
                    startup_script="python app.py",
                    environment={"PYTHONUNBUFFERED": "1"},
                    agents=ProjectAgents(install=True, tools=["claude"]),
                    skills=[
                        ProjectSkillSelection(
                            source=ProjectSkillSource.PROJECT_SKILL_SOURCE_USER,
                            reference="personal",
                            agents=["codex"],
                        )
                    ],
                    application_ports=[
                        ApplicationPort(port=8080, label="web", access="public")
                    ],
                    secrets=ProjectSecretBindings(
                        project="development", organization=True
                    ),
                ),
            )
        )

        self.assertEqual(file_value["mode"], "0755")
        self.assertEqual(file_value["mod_time"], "2026-01-01T00:00:00Z")
        project = preset_value["project_spec"]
        self.assertEqual(project["schema_version"], 1)
        self.assertEqual(project["working_directory"], "/workspace/a")
        self.assertEqual(
            project["repositories"],
            [
                {
                    "source": "https://example.test/a",
                    "branch": "branch",
                    "destination": "/workspace/a",
                    "known_hosts": [],
                },
                {
                    "source": "https://example.test/b",
                    "branch": "",
                    "destination": "/workspace/b",
                    "revision": "deadbeef",
                    "known_hosts": [],
                },
            ],
        )
        self.assertEqual(project["install_command"], "pip install")
        self.assertEqual(project["startup_script"], "python app.py")
        self.assertEqual(project["environment"], {"PYTHONUNBUFFERED": "1"})
        self.assertEqual(project["agents"], {"install": True, "tools": ["claude"]})
        self.assertEqual(project["skills"][0]["source"], "user")
        self.assertEqual(
            project["application_ports"],
            [{"port": 8080, "label": "web", "access": "public"}],
        )
        self.assertEqual(
            project["secrets"],
            {"project": "development", "organization": True},
        )

    def test_connect_error_maps_status_violations_and_request_id(self) -> None:
        error = ConnectError(
            Code.INVALID_ARGUMENT,
            "invalid API key",
            [
                _connect_detail(
                    BadRequest(
                        field_violations=[
                            BadRequest.FieldViolation(
                                field="name", description="must not be blank"
                            )
                        ]
                    )
                ),
                _connect_detail(ErrorInfo(metadata={"request_id": "req_api_key"})),
            ],
        )

        mapped = codewire_error_from_connect(error)

        self.assertEqual(mapped.status, 400)
        self.assertEqual(mapped.detail, "invalid API key")
        self.assertEqual(mapped.request_id, "req_api_key")
        self.assertEqual(
            mapped.violations,
            [{"field": "name", "description": "must not be blank"}],
        )

    def test_connect_error_maps_all_canonical_statuses(self) -> None:
        expected = {
            Code.CANCELED: 499,
            Code.INVALID_ARGUMENT: 400,
            Code.FAILED_PRECONDITION: 400,
            Code.OUT_OF_RANGE: 400,
            Code.DEADLINE_EXCEEDED: 504,
            Code.NOT_FOUND: 404,
            Code.ALREADY_EXISTS: 409,
            Code.ABORTED: 409,
            Code.PERMISSION_DENIED: 403,
            Code.RESOURCE_EXHAUSTED: 429,
            Code.UNIMPLEMENTED: 501,
            Code.UNAVAILABLE: 503,
            Code.UNAUTHENTICATED: 401,
            Code.UNKNOWN: 500,
            Code.INTERNAL: 500,
            Code.DATA_LOSS: 500,
        }

        for code, status in expected.items():
            with self.subTest(code=code):
                self.assertEqual(
                    codewire_error_from_connect(ConnectError(code, "failed")).status,
                    status,
                )


MESH_ORG_ID = "org-exact"
MESH_NETWORK_ID = "network-exact"
MESH_CREATED_AT = Timestamp()
MESH_CREATED_AT.FromJsonString("2026-04-01T00:00:00Z")
MESH_UPDATED_AT = Timestamp()
MESH_UPDATED_AT.FromJsonString("2026-04-01T01:00:00Z")
MESH_EXPIRES_AT = Timestamp()
MESH_EXPIRES_AT.FromJsonString("2026-04-02T00:00:00Z")
MESH_REDEEMED_AT = Timestamp()
MESH_REDEEMED_AT.FromJsonString("2026-04-01T02:00:00Z")


class MeshServiceFixture:
    calls: set[str] = set()

    @classmethod
    def reset(cls) -> None:
        cls.calls = set()

    @classmethod
    def _record(
        cls,
        operation: str,
        request: object,
        ctx: object,
        *,
        network: bool = False,
    ) -> None:
        cls.calls.add(operation)
        request_headers = getattr(ctx, "request_headers")
        if request_headers.get("authorization") != "Bearer cw_mesh_test":
            raise ConnectError(Code.UNAUTHENTICATED, "unauthorized")
        if getattr(request, "org_id") != MESH_ORG_ID:
            raise ConnectError(Code.NOT_FOUND, "organization not found")
        if network and getattr(request, "network_id") != MESH_NETWORK_ID:
            raise ConnectError(Code.NOT_FOUND, "network not found")

    @staticmethod
    def _network(network_id: str = MESH_NETWORK_ID) -> MeshNetwork:
        return MeshNetwork(
            id=network_id,
            org_id=MESH_ORG_ID,
            created_at=MESH_CREATED_AT,
            node_count=7,
            invite_count=3,
        )

    @staticmethod
    def _node(name: str) -> MeshNode:
        return MeshNode(
            org_id=MESH_ORG_ID,
            network_id=MESH_NETWORK_ID,
            name=name,
            peer_url=f"https://peer.example/{name}",
            connected=True,
            last_seen_at=MESH_CREATED_AT,
        )

    @staticmethod
    def _member() -> MeshGroupMember:
        return MeshGroupMember(
            org_id=MESH_ORG_ID,
            network_id=MESH_NETWORK_ID,
            group_name="group-one",
            node_name="node-one",
            session_name="session-one",
            created_at=MESH_CREATED_AT,
        )

    @classmethod
    def _policy(
        cls,
        messages_policy: int,
        debug_policy: int,
    ) -> MeshGroupPolicy:
        return MeshGroupPolicy(
            org_id=MESH_ORG_ID,
            network_id=MESH_NETWORK_ID,
            group_name="group-one",
            messages_policy=messages_policy,
            debug_policy=debug_policy,
            updated_at=MESH_UPDATED_AT,
        )

    @classmethod
    def _group(
        cls,
        name: str,
        messages_policy: int = MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_OPEN,
        debug_policy: int = MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_FULL,
    ) -> MeshGroup:
        return MeshGroup(
            org_id=MESH_ORG_ID,
            network_id=MESH_NETWORK_ID,
            name=name,
            created_at=MESH_CREATED_AT,
            created_by_user_id="creator-user",
            members=[cls._member()],
            policy=cls._policy(messages_policy, debug_policy),
        )

    @staticmethod
    def _entry(key: str) -> MeshKeyValue:
        return MeshKeyValue(
            org_id=MESH_ORG_ID,
            network_id=MESH_NETWORK_ID,
            namespace="namespace-one",
            key=key,
            value=b"\x00\x01\x02\xff",
            expires_at=MESH_EXPIRES_AT,
        )

    def list_mesh_networks(self, request, ctx):
        self._record("ListMeshNetworks", request, ctx)
        if not request.page_token:
            return ListMeshNetworksResponse(
                networks=[self._network("network-one")],
                next_page_token="network-page-two",
            )
        if request.page_token != "network-page-two":
            raise ConnectError(Code.INVALID_ARGUMENT, "bad network page")
        return ListMeshNetworksResponse(
            networks=[self._network("network-two")]
        )

    def create_mesh_network(self, request, ctx):
        self._record("CreateMeshNetwork", request, ctx)
        if request.network_id == "reject-me":
            raise ConnectError(
                Code.INVALID_ARGUMENT,
                "invalid network",
                [
                    _connect_detail(
                        ErrorInfo(metadata={"request_id": "req_mesh"})
                    )
                ],
            )
        if request.network_id != MESH_NETWORK_ID:
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong network")
        return CreateMeshNetworkResponse(network=self._network())

    def delete_mesh_network(self, request, ctx):
        self._record("DeleteMeshNetwork", request, ctx, network=True)
        return DeleteMeshNetworkResponse()

    def join_mesh_network(self, request, ctx):
        raise ConnectError(Code.UNIMPLEMENTED, "not exercised by WI-7C")

    def list_mesh_nodes(self, request, ctx):
        self._record("ListMeshNodes", request, ctx, network=True)
        if not request.page_token:
            return ListMeshNodesResponse(
                nodes=[self._node("node-one")],
                next_page_token="node-page-two",
            )
        if request.page_token != "node-page-two":
            raise ConnectError(Code.INVALID_ARGUMENT, "bad node page")
        return ListMeshNodesResponse(nodes=[self._node("node-two")])

    def revoke_mesh_node(self, request, ctx):
        self._record("RevokeMeshNode", request, ctx, network=True)
        if request.node_name != "node-one":
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong node")
        return RevokeMeshNodeResponse()

    def create_mesh_node_enrollment(self, request, ctx):
        self._record(
            "CreateMeshNodeEnrollment", request, ctx, network=True
        )
        if (
            request.node_name != "node-one"
            or not request.HasField("ttl")
            or request.ttl.seconds != 1_020
            or request.ttl.nanos != 0
        ):
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong enrollment")
        return CreateMeshNodeEnrollmentResponse(
            enrollment=MeshNodeEnrollment(
                id="enrollment-one",
                org_id=MESH_ORG_ID,
                network_id=MESH_NETWORK_ID,
                node_name="node-one",
                owner_user_id="owner-user",
                issued_by_user_id="issuer-user",
                expires_at=MESH_EXPIRES_AT,
                created_at=MESH_CREATED_AT,
                redeemed_at=MESH_REDEEMED_AT,
            ),
            enrollment_code="secret-one-use-code",
        )

    def redeem_mesh_node_enrollment(self, request, ctx):
        self.calls.add("RedeemMeshNodeEnrollment")
        if getattr(ctx, "request_headers").get("authorization") is not None:
            raise ConnectError(Code.UNAUTHENTICATED, "unexpected bearer")
        if (
            request.enrollment_code != "secret-enrollment"
            or request.node_name != "node-one"
        ):
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong redemption")
        return RedeemMeshNodeEnrollmentResponse(
            node=self._node("node-one"),
            enrollment=MeshNodeEnrollment(
                id="enrollment-one",
                org_id=MESH_ORG_ID,
                network_id=MESH_NETWORK_ID,
                node_name="node-one",
                owner_user_id="owner-user",
                issued_by_user_id="issuer-user",
                expires_at=MESH_EXPIRES_AT,
                created_at=MESH_CREATED_AT,
                redeemed_at=MESH_REDEEMED_AT,
            ),
        )

    def list_mesh_groups(self, request, ctx):
        self._record("ListMeshGroups", request, ctx, network=True)
        if not request.page_token:
            return ListMeshGroupsResponse(
                groups=[self._group("group-one")],
                next_page_token="group-page-two",
            )
        if request.page_token != "group-page-two":
            raise ConnectError(Code.INVALID_ARGUMENT, "bad group page")
        return ListMeshGroupsResponse(
            groups=[
                self._group(
                    "group-two",
                    MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY,
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_NONE,
                ),
                self._group(
                    "group-three",
                    MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED,
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY,
                ),
                self._group(
                    "group-four",
                    MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_OPEN,
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_UNSPECIFIED,
                ),
            ]
        )

    def create_mesh_group(self, request, ctx):
        self._record("CreateMeshGroup", request, ctx, network=True)
        return CreateMeshGroupResponse(group=self._group(request.name))

    def get_mesh_group(self, request, ctx):
        self._record("GetMeshGroup", request, ctx, network=True)
        return GetMeshGroupResponse(group=self._group(request.group_name))

    def delete_mesh_group(self, request, ctx):
        self._record("DeleteMeshGroup", request, ctx, network=True)
        return DeleteMeshGroupResponse()

    def set_mesh_group_policy(self, request, ctx):
        self._record("SetMeshGroupPolicy", request, ctx, network=True)
        return SetMeshGroupPolicyResponse(
            policy=self._policy(
                request.messages_policy, request.debug_policy
            )
        )

    def add_mesh_group_member(self, request, ctx):
        self._record("AddMeshGroupMember", request, ctx, network=True)
        if (
            request.group_name,
            request.node_name,
            request.session_name,
        ) != ("group-one", "node-one", "session-one"):
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong member")
        return AddMeshGroupMemberResponse(member=self._member())

    def remove_mesh_group_member(self, request, ctx):
        self._record("RemoveMeshGroupMember", request, ctx, network=True)
        return RemoveMeshGroupMemberResponse()

    def list_mesh_key_values(self, request, ctx):
        self._record("ListMeshKeyValues", request, ctx, network=True)
        if (request.namespace, request.prefix) != ("namespace-one", "key"):
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong key prefix")
        if not request.page_token:
            return ListMeshKeyValuesResponse(
                entries=[self._entry("key-one")],
                next_page_token="kv-page-two",
            )
        if request.page_token != "kv-page-two":
            raise ConnectError(Code.INVALID_ARGUMENT, "bad key page")
        return ListMeshKeyValuesResponse(entries=[self._entry("key-two")])

    def get_mesh_key_value(self, request, ctx):
        self._record("GetMeshKeyValue", request, ctx, network=True)
        return GetMeshKeyValueResponse(entry=self._entry(request.key))

    def set_mesh_key_value(self, request, ctx):
        self._record("SetMeshKeyValue", request, ctx, network=True)
        if (
            request.namespace != "namespace-one"
            or request.key != "key-one"
            or request.value != b"\x00\x01\x02\xff"
            or not request.HasField("ttl")
            or request.ttl.seconds != 23
            or request.ttl.nanos != 0
        ):
            raise ConnectError(Code.INVALID_ARGUMENT, "wrong key value")
        return SetMeshKeyValueResponse(entry=self._entry(request.key))

    def delete_mesh_key_value(self, request, ctx):
        self._record("DeleteMeshKeyValue", request, ctx, network=True)
        return DeleteMeshKeyValueResponse()


MESH_FIXTURE = MeshServiceFixture()
MESH_CONNECT_APPS = {
    "/codewire.v1.MeshNetworkService/": MeshNetworkServiceWSGIApplication(
        MESH_FIXTURE
    ),
    "/codewire.v1.MeshNodeService/": MeshNodeServiceWSGIApplication(
        MESH_FIXTURE
    ),
    "/codewire.v1.MeshGroupService/": MeshGroupServiceWSGIApplication(
        MESH_FIXTURE
    ),
    "/codewire.v1.MeshKeyValueService/": MeshKeyValueServiceWSGIApplication(
        MESH_FIXTURE
    ),
}


class MeshHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _read_body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def _serve_connect(self) -> None:
        path, _, query = self.path.partition("?")
        app = next(
            (
                candidate
                for prefix, candidate in MESH_CONNECT_APPS.items()
                if path.startswith(prefix)
            ),
            None,
        )
        if app is None:
            self.send_error(404)
            return
        body = self._read_body()
        environ = {
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "SERVER_NAME": self.server.server_address[0],
            "SERVER_PORT": str(self.server.server_address[1]),
            "SERVER_PROTOCOL": self.request_version,
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        for name, value in self.headers.items():
            key = name.upper().replace("-", "_")
            environ[
                key
                if key in {"CONTENT_LENGTH", "CONTENT_TYPE"}
                else f"HTTP_{key}"
            ] = value
        response: dict[str, object] = {}

        def start_response(status, headers, exc_info=None):
            response["status"] = status
            response["headers"] = headers

        chunks = app(environ, start_response)
        try:
            response_body = b"".join(chunks)
        finally:
            close = getattr(chunks, "close", None)
            if close is not None:
                close()
        self.send_response(int(str(response["status"]).split(" ", 1)[0]))
        for name, value in response["headers"]:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self) -> None:
        self._serve_connect()


class MeshConnectTransportTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        MeshServiceFixture.reset()
        cls.server = HTTPServer(("127.0.0.1", 0), MeshHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        cls.client = MeshClient(
            f"http://127.0.0.1:{cls.server.server_address[1]}",
            "cw_mesh_test",
        )

    def setUp(self) -> None:
        MeshServiceFixture.reset()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_generated_mesh_capabilities_and_golden_conversion(self) -> None:
        created_network = self.client.networks.create(
            MESH_ORG_ID, MESH_NETWORK_ID
        )
        self.assertEqual(
            created_network,
            codewire.MeshNetwork(
                id=MESH_NETWORK_ID,
                org_id=MESH_ORG_ID,
                created_at="2026-04-01T00:00:00Z",
                node_count=7,
                invite_count=3,
            ),
        )
        self.assertEqual(
            [network.id for network in self.client.networks.list(MESH_ORG_ID)],
            ["network-one", "network-two"],
        )

        nodes = self.client.nodes.list(MESH_ORG_ID, MESH_NETWORK_ID)
        self.assertEqual([node.name for node in nodes], ["node-one", "node-two"])
        self.assertEqual(nodes[0].org_id, MESH_ORG_ID)
        self.assertEqual(nodes[0].network_id, MESH_NETWORK_ID)
        self.assertEqual(
            nodes[0].peer_url, "https://peer.example/node-one"
        )
        self.assertTrue(nodes[0].connected)
        self.assertEqual(nodes[0].last_seen_at, "2026-04-01T00:00:00Z")
        self.client.nodes.revoke(
            MESH_ORG_ID, MESH_NETWORK_ID, "node-one"
        )
        enrollment = self.client.nodes.create_enrollment(
            MESH_ORG_ID,
            MESH_NETWORK_ID,
            "node-one",
            ttl_seconds=1_020,
        )
        self.assertEqual(enrollment.id, "enrollment-one")
        self.assertEqual(enrollment.org_id, MESH_ORG_ID)
        self.assertEqual(enrollment.network_id, MESH_NETWORK_ID)
        self.assertEqual(enrollment.node_name, "node-one")
        self.assertEqual(enrollment.owner_user_id, "owner-user")
        self.assertEqual(enrollment.issued_by_user_id, "issuer-user")
        self.assertEqual(enrollment.expires_at, "2026-04-02T00:00:00Z")
        self.assertEqual(enrollment.created_at, "2026-04-01T00:00:00Z")
        self.assertEqual(enrollment.redeemed_at, "2026-04-01T02:00:00Z")
        self.assertEqual(enrollment.enrollment_code, "secret-one-use-code")

        created_group = self.client.groups.create(
            MESH_ORG_ID, MESH_NETWORK_ID, "group-one"
        )
        self.assertEqual(created_group.org_id, MESH_ORG_ID)
        self.assertEqual(created_group.network_id, MESH_NETWORK_ID)
        self.assertEqual(created_group.name, "group-one")
        self.assertEqual(created_group.created_at, "2026-04-01T00:00:00Z")
        self.assertEqual(created_group.created_by_user_id, "creator-user")
        self.assertEqual(len(created_group.members), 1)
        self.assertEqual(
            created_group.members[0],
            codewire.MeshGroupMember(
                org_id=MESH_ORG_ID,
                network_id=MESH_NETWORK_ID,
                group_name="group-one",
                node_name="node-one",
                session_name="session-one",
                created_at="2026-04-01T00:00:00Z",
            ),
        )
        self.assertIsNotNone(created_group.policy)
        self.assertEqual(created_group.policy.messages_policy, "open")
        self.assertEqual(created_group.policy.debug_policy, "full")
        self.assertEqual(
            created_group.policy.updated_at, "2026-04-01T01:00:00Z"
        )
        groups = self.client.groups.list(MESH_ORG_ID, MESH_NETWORK_ID)
        self.assertEqual(
            [
                (group.policy.messages_policy, group.policy.debug_policy)
                for group in groups
            ],
            [
                ("open", "full"),
                ("internal-only", "none"),
                ("", "observe-only"),
                ("open", ""),
            ],
        )
        self.assertEqual(
            self.client.groups.get(
                MESH_ORG_ID, MESH_NETWORK_ID, "group-one"
            ).name,
            "group-one",
        )
        member = self.client.groups.add_member(
            MESH_ORG_ID,
            MESH_NETWORK_ID,
            "group-one",
            "node-one",
            "session-one",
        )
        self.assertEqual(member.group_name, "group-one")
        self.client.groups.remove_member(
            MESH_ORG_ID,
            MESH_NETWORK_ID,
            "group-one",
            "node-one",
            "session-one",
        )
        policy = self.client.groups.set_policy(
            MESH_ORG_ID,
            MESH_NETWORK_ID,
            "group-one",
            "internal-only",
            "observe-only",
        )
        self.assertEqual(policy.messages_policy, "internal-only")
        self.assertEqual(policy.debug_policy, "observe-only")
        self.client.groups.delete(
            MESH_ORG_ID, MESH_NETWORK_ID, "group-one"
        )

        set_entry = self.client.kv.set(
            MESH_ORG_ID,
            MESH_NETWORK_ID,
            "namespace-one",
            "key-one",
            b"\x00\x01\x02\xff",
            ttl_seconds=23,
        )
        self.assertEqual(
            set_entry,
            codewire.MeshKVEntry(
                org_id=MESH_ORG_ID,
                network_id=MESH_NETWORK_ID,
                namespace="namespace-one",
                key="key-one",
                value=b"\x00\x01\x02\xff",
                expires_at="2026-04-02T00:00:00Z",
            ),
        )
        self.assertEqual(
            self.client.kv.get(
                MESH_ORG_ID,
                MESH_NETWORK_ID,
                "namespace-one",
                "key-one",
            ),
            set_entry,
        )
        self.assertEqual(
            [
                entry.key
                for entry in self.client.kv.list(
                    MESH_ORG_ID,
                    MESH_NETWORK_ID,
                    "namespace-one",
                    "key",
                )
            ],
            ["key-one", "key-two"],
        )
        self.client.kv.delete(
            MESH_ORG_ID,
            MESH_NETWORK_ID,
            "namespace-one",
            "key-one",
        )

        registration = self.client.nodes.redeem_enrollment(
            "secret-enrollment", "node-one"
        )
        self.assertEqual(registration.node.org_id, MESH_ORG_ID)
        self.assertEqual(registration.node.network_id, MESH_NETWORK_ID)
        self.assertEqual(registration.node.name, "node-one")
        self.assertEqual(registration.enrollment.id, "enrollment-one")
        self.assertEqual(registration.enrollment.enrollment_code, "")
        self.client.networks.delete(MESH_ORG_ID, MESH_NETWORK_ID)

        self.assertEqual(
            MeshServiceFixture.calls,
            {
                "CreateMeshNetwork",
                "ListMeshNetworks",
                "ListMeshNodes",
                "RevokeMeshNode",
                "CreateMeshNodeEnrollment",
                "CreateMeshGroup",
                "ListMeshGroups",
                "GetMeshGroup",
                "DeleteMeshGroup",
                "SetMeshGroupPolicy",
                "AddMeshGroupMember",
                "RemoveMeshGroupMember",
                "SetMeshKeyValue",
                "GetMeshKeyValue",
                "ListMeshKeyValues",
                "DeleteMeshKeyValue",
                "DeleteMeshNetwork",
                "RedeemMeshNodeEnrollment",
            },
        )

    def test_connect_error_uses_the_canonical_sdk_shape(self) -> None:
        with self.assertRaises(codewire.CodewireError) as raised:
            self.client.networks.create(MESH_ORG_ID, "reject-me")

        self.assertEqual(raised.exception.status, 400)
        self.assertEqual(raised.exception.detail, "invalid network")
        self.assertEqual(raised.exception.request_id, "req_mesh")

    def test_converter_descriptors_and_every_enum_value_are_locked(self) -> None:
        assert_mesh_converter_coverage()
        self.assertEqual(
            [
                _messages_policy_from_proto(value)
                for value in (
                    MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED,
                    MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY,
                    MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_OPEN,
                )
            ],
            ["", "internal-only", "open"],
        )
        self.assertEqual(
            [
                _messages_policy_to_proto(value)
                for value in ("", "internal-only", "open")
            ],
            [
                MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED,
                MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY,
                MeshGroupMessagesPolicy.MESH_GROUP_MESSAGES_POLICY_OPEN,
            ],
        )
        self.assertEqual(
            [
                _debug_policy_from_proto(value)
                for value in (
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_UNSPECIFIED,
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_NONE,
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY,
                    MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_FULL,
                )
            ],
            ["", "none", "observe-only", "full"],
        )
        self.assertEqual(
            [
                _debug_policy_to_proto(value)
                for value in ("", "none", "observe-only", "full")
            ],
            [
                MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_UNSPECIFIED,
                MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_NONE,
                MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY,
                MeshGroupDebugPolicy.MESH_GROUP_DEBUG_POLICY_FULL,
            ],
        )
        with self.assertRaisesRegex(ValueError, "unknown Mesh messages"):
            _messages_policy_from_proto(99)
        with self.assertRaisesRegex(ValueError, "unknown Mesh debug"):
            _debug_policy_from_proto(99)
