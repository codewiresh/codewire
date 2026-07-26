"""Focused tests for the private generated Connect transport boundary."""

from __future__ import annotations

import unittest
from collections.abc import Iterator

import codewire
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
from codewire.v1.common_pb2 import AppPort, RepoEntry, SetupAgent, SetupConfig
from codewire.v1.environment_pb2 import (
    DesiredState,
    Environment,
    EnvironmentState,
)
from codewire.v1.file_pb2 import FileEntry
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
                error_reason="none",
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
                "error_reason": "none",
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
                default_setup_config=SetupConfig(
                    repo_url="https://example.test/repository",
                    branch="main",
                    repos=[RepoEntry(url="https://example.test/a", branch="branch")],
                    install_command="pip install",
                    startup_script="python app.py",
                    env_vars={"PYTHONUNBUFFERED": "1"},
                    agents=[SetupAgent(type="claude")],
                    install_agents=True,
                    agent="claude",
                    agent_env={"MODE": "test"},
                    app_ports=[AppPort(port=8080, label="web", access="public")],
                    include_org_secrets=True,
                    include_user_secrets=False,
                ),
            )
        )

        self.assertEqual(file_value["mode"], "0755")
        self.assertEqual(file_value["mod_time"], "2026-01-01T00:00:00Z")
        self.assertEqual(preset_value["type"], "sandbox")
        self.assertEqual(preset_value["repo_url"], "https://example.test/repository")
        self.assertEqual(preset_value["branch"], "main")
        self.assertEqual(
            preset_value["repos"],
            [{"url": "https://example.test/a", "branch": "branch"}],
        )
        self.assertEqual(preset_value["install_command"], "pip install")
        self.assertEqual(preset_value["startup_script"], "python app.py")
        self.assertEqual(preset_value["env_vars"], {"PYTHONUNBUFFERED": "1"})
        self.assertEqual(preset_value["agents"], [{"type": "claude"}])
        self.assertTrue(preset_value["install_agents"])
        self.assertEqual(preset_value["agent"], "claude")
        self.assertEqual(preset_value["agent_env"], {"MODE": "test"})
        self.assertEqual(
            preset_value["app_ports"],
            [{"port": 8080, "label": "web", "access": "public"}],
        )
        self.assertTrue(preset_value["include_org_secrets"])
        self.assertFalse(preset_value["include_user_secrets"])
        self.assertNotIn("default_setup_config", preset_value)

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
