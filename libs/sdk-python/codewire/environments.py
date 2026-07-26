from __future__ import annotations

from typing import BinaryIO

from google.protobuf.duration_pb2 import Duration

from codewire._context import ConnectContext
from codewire._convert import environment_to_dict, port_to_dict
from codewire.environment import Environment
from codewire.environment_ops import exec_environment, list_environment_ports
from codewire.files import Files
from codewire.v1.common_pb2 import AppPort
from codewire.v1.environment_connect import EnvironmentServiceClientSync
from codewire.v1.environment_pb2 import (
    CreateEnvironmentRequest,
    DeleteEnvironmentRequest,
    EnvironmentState,
    GetEnvironmentRequest,
    ListEnvironmentsRequest,
    StartEnvironmentRequest,
    StopEnvironmentRequest,
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


class Environments:
    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(EnvironmentServiceClientSync)
        self._ports = context.transport.client(PortServiceClientSync)

    def create(
        self,
        *,
        template_slug: str | None = None,
        template_id: str | None = None,
        name: str | None = None,
        type: str | None = None,
        ttl_seconds: int | None = None,
        repo_url: str | None = None,
        branch: str | None = None,
        image: str | None = None,
        cpu_millicores: int | None = None,
        memory_mb: int | None = None,
        disk_gb: int | None = None,
        startup_script: str | None = None,
        install_command: str | None = None,
        env_vars: dict[str, str] | None = None,
        agent: str | None = None,
        agent_env: dict[str, str] | None = None,
        app_ports: list[dict] | None = None,
        include_org_secrets: bool | None = None,
        include_user_secrets: bool | None = None,
        secret_project: str | None = None,
        wait: bool = False,
        wait_timeout: float = 300,
    ) -> Environment:
        """Create a new environment through EnvironmentService."""
        # ``type`` was never accepted by the REST create body. Keep the frozen
        # public argument but do not invent a second wire representation for it.
        del type
        request = CreateEnvironmentRequest(org_id=self._context.resolve_org_id())
        if template_slug is not None:
            request.preset_slug = template_slug
        if template_id is not None:
            request.preset_id = template_id
        if name is not None:
            request.name = name
        if ttl_seconds is not None:
            request.ttl_seconds = ttl_seconds
        if repo_url is not None:
            request.repo_url = repo_url
        if branch is not None:
            request.branch = branch
        if image is not None:
            request.image = image
        if cpu_millicores is not None:
            request.cpu_millicores = cpu_millicores
        if memory_mb is not None:
            request.memory_mb = memory_mb
        if disk_gb is not None:
            request.disk_gb = disk_gb
        if startup_script is not None:
            request.startup_script = startup_script
        if install_command is not None:
            request.install_command = install_command
        if env_vars is not None:
            request.env_vars.update(env_vars)
        if agent is not None:
            request.agent = agent
        if agent_env is not None:
            request.agent_env.update(agent_env)
        if app_ports is not None:
            request.app_ports.extend(
                AppPort(
                    port=item["port"],
                    label=item.get("label", ""),
                    access=item.get("access", ""),
                )
                for item in app_ports
            )
        if include_org_secrets is not None:
            request.include_org_secrets = include_org_secrets
        if include_user_secrets is not None:
            request.include_user_secrets = include_user_secrets
        if secret_project is not None:
            # Environment creation accepts the same project-name selector as
            # the REST body. PresetService uses a distinct ``*_id`` field,
            # which is resolved in Templates instead.
            request.secret_project = secret_project

        response = self._context.unary(self._client.create_environment, request)
        if not response.HasField("environment"):
            raise RuntimeError("environment response omitted environment")
        environment = self._wrap(environment_to_dict(response.environment))
        if wait:
            environment.wait_ready(timeout=wait_timeout)
        return environment

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
