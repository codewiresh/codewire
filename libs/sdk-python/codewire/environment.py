from __future__ import annotations

import time
from typing import BinaryIO

from codewire._context import ConnectContext
from codewire._convert import environment_to_dict, port_to_dict
from codewire.environment_ops import (
    exec_environment,
    list_environment_ports,
    poll_interval_seconds,
)
from codewire.files import Files
from codewire.v1.environment_connect import EnvironmentServiceClientSync
from codewire.v1.environment_pb2 import (
    DeleteEnvironmentRequest,
    GetEnvironmentRequest,
    StartEnvironmentRequest,
    StopEnvironmentRequest,
)
from codewire.v1.port_connect import PortServiceClientSync
from codewire.v1.port_pb2 import CreatePortRequest, DeletePortRequest, PortAccess


def _port_access(value: str | None) -> int:
    if not value:
        return PortAccess.PORT_ACCESS_UNSPECIFIED
    try:
        return PortAccess.Value(f"PORT_ACCESS_{value.upper()}")
    except ValueError:
        return -1


class Environment:
    """Wrapper around generated EnvironmentService values and operations."""

    def __init__(
        self, data: dict, context: ConnectContext, *, poll_interval: float = 2
    ) -> None:
        self._context = context
        self._environments = context.transport.client(EnvironmentServiceClientSync)
        self._ports = context.transport.client(PortServiceClientSync)
        self._poll_interval = poll_interval
        self._data = data
        for key, value in data.items():
            setattr(self, key, value)
        self.files = Files(context, self.id)

    def exec(
        self,
        *,
        command: list[str],
        working_dir: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> dict:
        return exec_environment(
            self._context,
            self.id,
            command=command,
            working_dir=working_dir,
            env=env,
            timeout=timeout,
        )

    def start(self) -> None:
        self._context.unary(
            self._environments.start_environment,
            StartEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=self.id
            ),
        )

    def stop(self) -> None:
        self._context.unary(
            self._environments.stop_environment,
            StopEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=self.id
            ),
        )

    def remove(self) -> None:
        self._context.unary(
            self._environments.delete_environment,
            DeleteEnvironmentRequest(
                org_id=self._context.resolve_org_id(), environment_id=self.id
            ),
        )

    def upload(self, src: bytes | BinaryIO, remote_path: str) -> None:
        """Deprecated: Use env.files.upload() instead."""
        self.files.upload(src, remote_path)

    def download(self, remote_path: str) -> bytes:
        """Deprecated: Use env.files.download() instead."""
        return self.files.download(remote_path)

    def list_files(self, path: str = "/") -> list[dict]:
        """Deprecated: Use env.files.list() instead."""
        return self.files.list(path)

    def list_ports(self) -> list[dict]:
        return list_environment_ports(self._context, self.id)

    def create_port(
        self, *, port: int, label: str, access: str | None = None
    ) -> dict:
        response = self._context.unary(
            self._ports.create_port,
            CreatePortRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=self.id,
                port=port,
                label=label,
                access=_port_access(access),
            ),
        )
        if not response.HasField("port"):
            raise RuntimeError("port response omitted port")
        return port_to_dict(response.port)

    def delete_port(self, port_id: str) -> None:
        self._context.unary(
            self._ports.delete_port,
            DeletePortRequest(
                org_id=self._context.resolve_org_id(),
                environment_id=self.id,
                port_id=port_id,
            ),
        )

    def wait_ready(self, *, timeout: float = 300, interval: float = 2) -> None:
        """Poll until running, honoring a positive server poll interval."""
        from codewire.errors import CodewireError

        deadline = time.monotonic() + timeout
        effective_interval = interval
        while time.monotonic() < deadline:
            response = self._context.unary(
                self._environments.get_environment,
                GetEnvironmentRequest(
                    org_id=self._context.resolve_org_id(), environment_id=self.id
                ),
            )
            if not response.HasField("environment"):
                raise RuntimeError("environment response omitted environment")
            data = environment_to_dict(response.environment)
            for key, value in data.items():
                setattr(self, key, value)
            self._data = data
            server_interval = poll_interval_seconds(response.poll_interval)
            if interval == 2 and server_interval is not None:
                effective_interval = server_interval
            if data.get("state") == "running":
                return
            if data.get("state") in ("error", "destroyed"):
                raise CodewireError(
                    0,
                    f"environment entered state {data['state']}: {data.get('error_reason', '')}",
                )
            time.sleep(effective_interval)
        raise CodewireError(0, f"environment not ready after {timeout}s")

    def __repr__(self) -> str:
        return f"<Environment id={getattr(self, 'id', '?')} state={getattr(self, 'state', '?')}>"
