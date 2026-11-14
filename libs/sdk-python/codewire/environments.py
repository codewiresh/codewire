from __future__ import annotations

from typing import Any, BinaryIO

from google.protobuf.duration_pb2 import Duration

from codewire._context import ConnectContext
from codewire._convert import (
    assert_environment_converter_coverage,
    environment_resize_operation_to_dict,
    environment_resize_plan_to_dict,
    environment_source_selection_from_dict,
    environment_sources_update_to_dict,
    environment_to_dict,
    explicit_bool,
    port_to_dict,
    positive_uint64,
    project_spec_from_dict,
)
from codewire.environment import Environment
from codewire.environment_ops import exec_environment, list_environment_ports
from codewire.files import Files
from codewire.v1.environment_connect import EnvironmentServiceClientSync
from codewire.v1.environment_pb2 import (
    CreateEnvironmentRequest,
    DeleteEnvironmentRequest,
    EnvironmentState,
    EnvironmentResizeDisruptionPolicy,
    GetEnvironmentRequest,
    GetEnvironmentResizeOperationRequest,
    PlanEnvironmentResizeRequest,
    ListEnvironmentsRequest,
    ResizeEnvironmentRequest,
    StartEnvironmentRequest,
    StopEnvironmentRequest,
    UpdateEnvironmentSourcesRequest,
    IsolationTier,
)
from codewire.v1.port_connect import PortServiceClientSync
from codewire.v1.port_pb2 import (
    CreatePortRequest,
    DeletePortRequest,
    PortAccess,
)


def _environment_state(value: str | None) -> int:
    if not value:
        return EnvironmentState.ENVIRONMENT_STATE_UNSPECIFIED
    try:
        return EnvironmentState.Value(f"ENVIRONMENT_STATE_{value.upper()}")
    except ValueError:
        return -1


def _port_access(value: str | None) -> int:
    if not value:
        return PortAccess.PORT_ACCESS_UNSPECIFIED
    try:
        return PortAccess.Value(f"PORT_ACCESS_{value.upper()}")
    except ValueError:
        return -1


def _isolation_tier(value: str | None) -> int:
    if value is None or value == "" or value == "standard":
        return IsolationTier.ISOLATION_TIER_STANDARD
    if value == "confidential":
        return IsolationTier.ISOLATION_TIER_CONFIDENTIAL
    raise ValueError("codewire: isolation_tier must be standard or confidential")


class Environments:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(EnvironmentServiceClientSync)
        self._ports = context.transport.client(PortServiceClientSync)

    def create(
        self,
        *,
        project_spec: dict[str, Any],
        preset_id: str | None = None,
        name: str | None = None,
        ttl_seconds: int | None = None,
        isolation_tier: str | None = None,
        expected_profile_revision: int | None = None,
        confirm_personal_credentials: bool = False,
        confirm_personal_secrets: bool = False,
        omit_application_previews: bool = False,
        network: str | None = None,
        source_snapshot_id: str | None = None,
        network_policy: str | None = None,
        wait: bool = False,
        wait_timeout: float = 300,
    ) -> Environment:
        """Create a new environment through EnvironmentService."""
        assert_environment_converter_coverage()
        request = CreateEnvironmentRequest(
            org_id=self._context.resolve_org_id(),
            isolation_tier=_isolation_tier(isolation_tier),
            confirm_personal_credentials=explicit_bool(
                confirm_personal_credentials, "confirm_personal_credentials"
            ),
            confirm_personal_secrets=explicit_bool(
                confirm_personal_secrets, "confirm_personal_secrets"
            ),
            omit_application_previews=explicit_bool(
                omit_application_previews, "omit_application_previews"
            ),
        )
        if expected_profile_revision is not None:
            request.expected_profile_revision = positive_uint64(
                expected_profile_revision, "expected profile revision"
            )
        if preset_id is not None:
            request.preset_id = preset_id
        if name is not None:
            request.name = name
        if ttl_seconds is not None:
            request.ttl_seconds = ttl_seconds
        if source_snapshot_id is not None:
            # A hosted disk snapshot the caller created in the organization.
            if not isinstance(source_snapshot_id, str) or not source_snapshot_id:
                raise ValueError("codewire: source_snapshot_id must be a non-empty string")
            request.source_snapshot_id = source_snapshot_id
        if network is not None:
            # A hosted Codewire Mesh network, by name, in the organization.
            if not isinstance(network, str) or not network:
                raise ValueError("codewire: network must be a nonempty Mesh network name")
            request.network = network
        if network_policy is not None:
            # An organization network policy; none is `hosted-default`.
            if not isinstance(network_policy, str) or not network_policy:
                raise ValueError("codewire: network_policy must be a nonempty policy reference")
            request.network_policy = network_policy
        request.project_spec.CopyFrom(project_spec_from_dict(project_spec))
        if request.project_spec.HasField("credentials") != request.HasField("expected_profile_revision"):
            raise ValueError("codewire: credential profile selection requires its exact revision")

        response = self._context.unary(self._client.create_environment, request)
        if not response.HasField("environment"):
            raise RuntimeError("environment response omitted environment")
        environment = self._wrap(environment_to_dict(response.environment))
        if wait:
            environment.wait_ready(timeout=wait_timeout)
        return environment

    def update_sources(
        self,
        env_id: str,
        *,
        expected_operation_generation: int,
        expected: dict[str, Any],
        replacement: dict[str, Any],
        allow_restart: bool = False,
        confirm_personal_credentials: bool = False,
        confirm_personal_secrets: bool = False,
    ) -> dict[str, Any]:
        """Replace exactly the caller-observed selection; never fetch or retry CAS.

        An empty replacement clears sources. Restart and personal-source consent
        default to denied. The returned outcome is not a readiness assertion.
        """
        request = UpdateEnvironmentSourcesRequest(
            org_id=self._context.resolve_org_id(),
            environment_id=env_id,
            expected_operation_generation=positive_uint64(
                expected_operation_generation, "expected operation generation"
            ),
            expected=environment_source_selection_from_dict(expected),
            replacement=environment_source_selection_from_dict(replacement),
            allow_restart=explicit_bool(allow_restart, "allow_restart"),
            confirm_personal_credentials=explicit_bool(
                confirm_personal_credentials, "confirm_personal_credentials"
            ),
            confirm_personal_secrets=explicit_bool(
                confirm_personal_secrets, "confirm_personal_secrets"
            ),
        )
        response = self._context.unary(self._client.update_environment_sources, request)
        if response.environment_id != env_id:
            raise RuntimeError("source update response changed environment identity")
        return environment_sources_update_to_dict(response)

    def list(
        self, *, type: str | None = None, state: str | None = None
    ) -> list[Environment]:
        """List environments, optionally filtered by type or state."""
        request = ListEnvironmentsRequest(org_id=self._context.resolve_org_id())
        if type is not None:
            request.type = type
        if state is not None:
            request.state = _environment_state(state)
        environments: list[Environment] = []
        page_token = ""
        while True:
            request.page_token = page_token
            response = self._context.unary(self._client.list_environments, request)
            interval = _poll_interval(response.poll_interval)
            environments.extend(
                self._wrap(environment_to_dict(value), interval)
                for value in response.environments
            )
            page_token = response.next_page_token
            if not page_token:
                return environments

    def get(self, env_id: str) -> Environment:
        """Fetch a single environment by ID."""
        response = self._context.unary(
            self._client.get_environment,
            GetEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=env_id
            ),
        )
        if not response.HasField("environment"):
            raise RuntimeError("environment response omitted environment")
        return self._wrap(
            environment_to_dict(response.environment), _poll_interval(response.poll_interval)
        )

    def resize(
        self,
        env_id: str,
        *,
        cpu_millicores: int,
        memory_mb: int,
        disk_gb: int,
        request_id: str,
        force: bool = False,
        allow_restart: bool = False,
    ) -> dict:
        """Start an idempotent platform environment resize."""
        response = self._context.unary(
            self._client.resize_environment,
            ResizeEnvironmentRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=env_id,
                cpu_millicores=cpu_millicores,
                memory_mb=memory_mb,
                disk_gb=disk_gb,
                request_id=request_id,
                force=force,
                disruption_policy=(
                    EnvironmentResizeDisruptionPolicy.ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART
                    if allow_restart
                    else EnvironmentResizeDisruptionPolicy.ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY
                ),
            ),
        )
        if not response.HasField("operation"):
            raise RuntimeError("resize response omitted operation")
        return environment_resize_operation_to_dict(response.operation)

    def plan_resize(
        self,
        env_id: str,
        *,
        cpu_millicores: int,
        memory_mb: int,
        disk_gb: int,
    ) -> dict:
        """Return the platform's authoritative live/restart resize plan."""
        response = self._context.unary(
            self._client.plan_environment_resize,
            PlanEnvironmentResizeRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=env_id,
                cpu_millicores=cpu_millicores,
                memory_mb=memory_mb,
                disk_gb=disk_gb,
            ),
        )
        if not response.HasField("plan"):
            raise RuntimeError("resize plan response omitted plan")
        return environment_resize_plan_to_dict(response.plan)

    def get_resize_operation(self, env_id: str, operation_id: str) -> dict:
        """Read a durable platform environment resize operation."""
        response = self._context.unary(
            self._client.get_environment_resize_operation,
            GetEnvironmentResizeOperationRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=env_id,
                operation_id=operation_id,
            ),
        )
        if not response.HasField("operation"):
            raise RuntimeError("resize response omitted operation")
        return environment_resize_operation_to_dict(response.operation)

    def delete(self, env_id: str) -> None:
        self._context.unary(
            self._client.delete_environment,
            DeleteEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=env_id
            ),
        )

    def stop(self, env_id: str) -> None:
        self._context.unary(
            self._client.stop_environment,
            StopEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=env_id
            ),
        )

    def start(self, env_id: str) -> None:
        self._context.unary(
            self._client.start_environment,
            StartEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=env_id
            ),
        )

    def exec(
        self,
        env_id: str,
        *,
        command: list[str],
        working_dir: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> dict:
        return exec_environment(
            self._context,
            env_id,
            command=command,
            working_dir=working_dir,
            env=env,
            timeout=timeout,
        )

    def list_files(self, env_id: str, path: str | None = None) -> list[dict]:
        return Files(self._context, env_id).list(path or "/")

    def upload_file(self, env_id: str, src: bytes | BinaryIO, remote_path: str) -> None:
        Files(self._context, env_id).upload(src, remote_path)

    def download_file(self, env_id: str, remote_path: str) -> bytes:
        return Files(self._context, env_id).download(remote_path)

    def list_ports(self, env_id: str) -> list[dict]:
        return list_environment_ports(self._context, env_id)

    def create_port(
        self, env_id: str, *, port: int, label: str, access: str | None = None
    ) -> dict:
        response = self._context.unary(
            self._ports.create_port,
            CreatePortRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=env_id,
                port=port,
                label=label,
                access=_port_access(access),
            ),
        )
        if not response.HasField("port"):
            raise RuntimeError("port response omitted port")
        return port_to_dict(response.port)

    def delete_port(self, env_id: str, port_id: str) -> None:
        self._context.unary(
            self._ports.delete_port,
            DeletePortRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=env_id,
                port_id=port_id,
            ),
        )

    def _wrap(self, data: dict, poll_interval: float = 2) -> Environment:
        return Environment(data, self._context, poll_interval=poll_interval)


def _poll_interval(value: Duration) -> float:
    seconds = value.seconds + value.nanos / 1_000_000_000
    return seconds if seconds > 0 else 2
