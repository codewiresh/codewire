"""Shared generated-client operations for the ergonomic Environment wrapper."""

from __future__ import annotations

from google.protobuf.duration_pb2 import Duration

from codewire._context import ConnectContext
from codewire._convert import port_to_dict
from codewire.v1.exec_connect import ExecServiceClientSync
from codewire.v1.exec_pb2 import ExecRequest
from codewire.v1.port_connect import PortServiceClientSync
from codewire.v1.port_pb2 import ListPortsRequest


def exec_environment(
    context: ConnectContext,
    environment_id: str,
    *,
    command: list[str],
    working_dir: str | None,
    env: dict[str, str] | None,
    timeout: int | None,
) -> dict:
    request = ExecRequest(
        org_id=context.resolve_org_id(),
        environment_id=environment_id,
        command=command,
    )
    if working_dir is not None:
        request.working_dir = working_dir
    if env is not None:
        request.env.update(env)
    if timeout is not None:
        duration = Duration()
        duration.FromSeconds(timeout)
        request.timeout.CopyFrom(duration)
    client = context.transport.client(ExecServiceClientSync)
    response = context.unary(client.exec, request)
    return {
        "exit_code": response.exit_code,
        "stdout": bytes(response.stdout).decode("utf-8", errors="replace"),
        "stderr": bytes(response.stderr).decode("utf-8", errors="replace"),
    }


def list_environment_ports(context: ConnectContext, environment_id: str) -> list[dict]:
    client = context.transport.client(PortServiceClientSync)
    request = ListPortsRequest(
        org_id=context.resolve_org_id(), environment_id=environment_id
    )
    values: list[dict] = []
    while True:
        response = context.unary(client.list_ports, request)
        values.extend(port_to_dict(port) for port in response.ports)
        if not response.next_page_token:
            return values
        request.page_token = response.next_page_token


def poll_interval_seconds(value: Duration) -> float | None:
    seconds = value.seconds + value.nanos / 1_000_000_000
    return seconds if seconds > 0 else None
