"""An environment's graphical desktop.

A running desktop's answer carries ``viewer_password``, which the VNC server
asks a viewer for. It is not an access control; do not log it.
"""
from __future__ import annotations

from typing import Any

from codewire._context import ConnectContext
from codewire._convert import timestamp_string
from codewire.v1.environment_desktop_connect import EnvironmentDesktopServiceClientSync
from codewire.v1 import environment_desktop_pb2 as pb

# A start answers only once the desktop accepts a viewer. The server allows
# it 40 seconds; this waits a little longer, so its own answer arrives
# instead of a local timeout.
START_TIMEOUT_MS = 45_000

_STATES = {
    pb.ENVIRONMENT_DESKTOP_STATE_UNAVAILABLE: "unavailable",
    pb.ENVIRONMENT_DESKTOP_STATE_STOPPED: "stopped",
    pb.ENVIRONMENT_DESKTOP_STATE_STARTING: "starting",
    pb.ENVIRONMENT_DESKTOP_STATE_RUNNING: "running",
}


def desktop_to_dict(message: pb.EnvironmentDesktop) -> dict[str, Any]:
    """Render a desktop: ``state``, and ``unavailable_reason`` or ``running`` when set."""
    value: dict[str, Any] = {"state": _STATES.get(message.state, "unknown")}
    if message.unavailable_reason:
        value["unavailable_reason"] = message.unavailable_reason
    if message.HasField("running"):
        running = message.running
        value["running"] = {
            "display": running.display,
            "port": running.port,
            "viewer_password": running.viewer_password,
        }
        if running.HasField("started_at"):
            value["running"]["started_at"] = timestamp_string(running.started_at)
    return value


class Desktop:
    """Starts, reads and stops the desktop of one environment."""

    def __init__(self, context: ConnectContext, environment_id: str) -> None:
        self._context = context
        self._environment_id = environment_id
        self._client = context.transport.client(EnvironmentDesktopServiceClientSync)

    def start(self) -> dict[str, Any]:
        """Start the desktop, or return the one that runs."""
        response = self._context.unary(
            self._client.start_desktop,
            pb.StartDesktopRequest(
                org_id=self._context.resolve_org_id(), environment_id=self._environment_id
            ),
            timeout_ms=START_TIMEOUT_MS,
        )
        return _desktop(response)

    def get(self) -> dict[str, Any]:
        response = self._context.unary(
            self._client.get_desktop,
            pb.GetDesktopRequest(
                org_id=self._context.resolve_org_id(), environment_id=self._environment_id
            ),
        )
        return _desktop(response)

    def stop(self) -> dict[str, Any]:
        """Stop the desktop. Stopping one that does not run succeeds."""
        response = self._context.unary(
            self._client.stop_desktop,
            pb.StopDesktopRequest(
                org_id=self._context.resolve_org_id(), environment_id=self._environment_id
            ),
        )
        return _desktop(response)


def _desktop(response: Any) -> dict[str, Any]:
    if not response.HasField("desktop"):
        raise RuntimeError("desktop response omitted desktop")
    return desktop_to_dict(response.desktop)
