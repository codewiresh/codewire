"""Managed conversations bound to their original Pod and launch generation."""
from __future__ import annotations

import hashlib
import uuid

from codewire._context import ConnectContext
from codewire.v1 import environment_agent_pb2 as pb
from codewire.v1.environment_agent_connect import EnvironmentAgentServiceClientSync

RECORD_BYTES = 5 * 1024 * 1024


class _BoundedClient(EnvironmentAgentServiceClientSync):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs, read_max_bytes=RECORD_BYTES + 32 * 1024)


class PlatformAgentOutcomeUnknownError(RuntimeError):
    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        super().__init__(f"agent outcome is uncertain; observe the original request {request_id}")


def _request_id(value: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("agent request_id must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError("agent request_id must be a canonical UUID")


class PlatformAgents:
    def __init__(self, context: ConnectContext, environment_id: str) -> None:
        self._context = context
        self._environment_id = environment_id
        self._client = context.transport.client(_BoundedClient)

    def _scope(self, scope: pb.EnvironmentAgentScope) -> None:
        if (not scope.HasField("incarnation")
            or scope.incarnation.org_id != self._context.resolve_org_id()
            or scope.incarnation.environment_id != self._environment_id
            or len(scope.support_image_sha256) != 32 or scope.support_image_size == 0):
            raise ValueError("agent scope differs from this environment or omits support identity")

    def _request_scope(self, request) -> None:
        if (request.org_id != self._context.resolve_org_id()
            or request.environment_id != self._environment_id):
            raise ValueError("agent request scope differs from this environment")
        if not request.HasField("expected_scope"):
            raise ValueError("agent original scope is required")
        self._scope(request.expected_scope)

    def info(self) -> pb.GetEnvironmentAgentInfoResponse:
        value = self._context.unary(self._client.get_environment_agent_info,
            pb.GetEnvironmentAgentInfoRequest(org_id=self._context.resolve_org_id(),
                environment_id=self._environment_id), timeout_ms=90_000)
        if not value.HasField("scope"):
            raise RuntimeError("agent info omitted original scope")
        self._scope(value.scope)
        return value

    def mutate(self, request: pb.MutateEnvironmentAgentRequest) -> pb.EnvironmentAgentOperation:
        self._request_scope(request)
        _request_id(request.request_id)
        if request.ByteSize() > 256 * 1024 or request.WhichOneof("operation") is None:
            raise ValueError("agent mutation is missing or exceeds its bound")
        owned = pb.MutateEnvironmentAgentRequest()
        owned.CopyFrom(request)
        try:
            value = self._context.unary(self._client.mutate_environment_agent, owned, timeout_ms=240_000)
            if (not value.HasField("operation") or value.operation.request_id != owned.request_id
                or not value.operation.HasField("scope") or value.operation.scope != owned.expected_scope):
                raise RuntimeError("agent response changed its original request or scope")
            return value.operation
        except Exception as error:
            raise PlatformAgentOutcomeUnknownError(owned.request_id) from error

    def observe(self, request_id: str) -> pb.EnvironmentAgentOperation:
        _request_id(request_id)
        value = self._context.unary(self._client.observe_environment_agent,
            pb.ObserveEnvironmentAgentRequest(org_id=self._context.resolve_org_id(),
                environment_id=self._environment_id, request_id=request_id), timeout_ms=90_000)
        if not value.HasField("operation") or value.operation.request_id != request_id:
            raise RuntimeError("agent observation changed its original request")
        self._scope(value.operation.scope)
        return value.operation

    def list(self, request: pb.ListEnvironmentAgentsRequest) -> pb.ListEnvironmentAgentsResponse:
        self._request_scope(request)
        if request.ByteSize() > 32 * 1024:
            raise ValueError("agent list request exceeds its bound")
        owned = pb.ListEnvironmentAgentsRequest()
        owned.CopyFrom(request)
        value = self._context.unary(self._client.list_environment_agents, owned, timeout_ms=90_000)
        if not value.HasField("scope") or value.scope != owned.expected_scope or len(value.sessions) > 8:
            raise RuntimeError("agent list changed its original scope or exceeded its page bound")
        return value

    def read(self, request: pb.ReadEnvironmentAgentRequest) -> pb.ReadEnvironmentAgentResponse:
        self._request_scope(request)
        if request.ByteSize() > 32 * 1024:
            raise ValueError("agent read request exceeds its bound")
        owned = pb.ReadEnvironmentAgentRequest()
        owned.CopyFrom(request)
        value = self._context.unary(self._client.read_environment_agent, owned, timeout_ms=90_000)
        if (not value.HasField("scope") or value.scope != owned.expected_scope
            or value.session_id != owned.session_id or value.driver_id != owned.driver_id
            or value.launch_generation != owned.expected_launch_generation
            or value.kind != owned.kind or value.message_id != owned.message_id
            or len(value.record_json) > RECORD_BYTES or len(value.record_sha256) != 32
            or hashlib.sha256(value.record_json).digest() != value.record_sha256):
            raise RuntimeError("agent record changed its original scope, generation or digest")
        return value
