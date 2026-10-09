"""Bounded platform CW selection; never retries an uncertain mutation.

Generated messages retain Python's exact uint64 integers. Callers provide the
complete previously observed incarnation/selection and immutable identity.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO

from codewire._context import ConnectContext
from codewire.v1.environment_cw_runtime_connect import EnvironmentCwRuntimeServiceClientSync
from codewire.v1 import environment_cw_runtime_pb2 as pb

CHUNK_BYTES = 64 * 1024
MAX_BYTES = 256 * 1024 * 1024
MUTATION_TIMEOUT_MS = 960_000


class _BoundedClient(EnvironmentCwRuntimeServiceClientSync):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs, read_max_bytes=32 * 1024)


class CwRuntimeOutcomeUnknownError(RuntimeError):
    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        super().__init__("cw runtime outcome is uncertain; observe the original request_id")


def _requests(header: pb.UpdateEnvironmentCwRuntimeHeader, source: BinaryIO) -> Iterator[pb.UpdateEnvironmentCwRuntimeRequest]:
    size = header.identity.size
    if type(size) is not int or not 64 <= size <= MAX_BYTES:
        raise ValueError("cw runtime candidate size is invalid")
    if header.ByteSize() > 32 * 1024:
        raise ValueError("cw runtime header exceeds its bound")
    owned = pb.UpdateEnvironmentCwRuntimeHeader()
    owned.CopyFrom(header)
    yield pb.UpdateEnvironmentCwRuntimeRequest(header=owned)
    remaining = size
    chunks = 0
    while remaining:
        data = source.read(min(CHUNK_BYTES, remaining))
        if not isinstance(data, bytes) or not data or len(data) > min(CHUNK_BYTES, remaining):
            raise ValueError("cw runtime candidate stream is incomplete or invalid")
        remaining -= len(data)
        chunks += 1
        if chunks > 8192:
            raise ValueError("cw runtime candidate exceeds its chunk bound")
        yield pb.UpdateEnvironmentCwRuntimeRequest(chunk=data)
    if source.read(1) != b"":
        raise ValueError("cw runtime candidate stream exceeds its admitted size")


class CwRuntime:
    """Ordinary platform CW invocations; existing processes stay untouched."""
    def __init__(self, context: ConnectContext, environment_id: str) -> None:
        self._context = context
        self._environment_id = environment_id
        self._client = context.transport.client(_BoundedClient)

    def _scope(self, org_id: str, environment_id: str) -> None:
        if org_id != self._context.resolve_org_id() or environment_id != self._environment_id:
            raise ValueError("cw runtime request scope differs from this environment")

    def status(self) -> pb.GetEnvironmentCwRuntimeResponse:
        value = self._context.unary(self._client.get_environment_cw_runtime,
            pb.GetEnvironmentCwRuntimeRequest(org_id=self._context.resolve_org_id(), environment_id=self._environment_id), timeout_ms=180_000)
        if not value.HasField("incarnation") or not value.HasField("selection"):
            raise RuntimeError("cw runtime status omitted required metadata")
        return value

    def update(self, header: pb.UpdateEnvironmentCwRuntimeHeader, source: BinaryIO) -> pb.EnvironmentCwRuntimeOperation:
        self._scope(header.org_id, header.environment_id)
        if not header.request_id:
            raise ValueError("cw runtime request_id is required")
        if header.ByteSize() > 32 * 1024 or not 64 <= header.identity.size <= MAX_BYTES:
            raise ValueError("cw runtime header exceeds its bound")
        owned = pb.UpdateEnvironmentCwRuntimeHeader()
        owned.CopyFrom(header)
        try:
            value = self._context.client_stream(self._client.update_environment_cw_runtime,
                _requests(owned, source), timeout_ms=MUTATION_TIMEOUT_MS)
        except Exception as error:
            raise CwRuntimeOutcomeUnknownError(owned.request_id) from error
        if not value.HasField("operation") or value.operation.request_id != owned.request_id:
            raise CwRuntimeOutcomeUnknownError(owned.request_id)
        return value.operation

    def rollback(self, request: pb.RollbackEnvironmentCwRuntimeRequest) -> pb.EnvironmentCwRuntimeOperation:
        self._scope(request.org_id, request.environment_id)
        if not request.request_id:
            raise ValueError("cw runtime request_id is required")
        if request.ByteSize() > 32 * 1024:
            raise ValueError("cw runtime request exceeds its bound")
        owned = pb.RollbackEnvironmentCwRuntimeRequest()
        owned.CopyFrom(request)
        try:
            value = self._context.unary(self._client.rollback_environment_cw_runtime, owned, timeout_ms=MUTATION_TIMEOUT_MS)
        except Exception as error:
            raise CwRuntimeOutcomeUnknownError(owned.request_id) from error
        if not value.HasField("operation") or value.operation.request_id != owned.request_id:
            raise CwRuntimeOutcomeUnknownError(owned.request_id)
        return value.operation

    def observe(self, request_id: str) -> pb.EnvironmentCwRuntimeOperation:
        value = self._context.unary(self._client.observe_environment_cw_runtime,
            pb.ObserveEnvironmentCwRuntimeRequest(org_id=self._context.resolve_org_id(), environment_id=self._environment_id, request_id=request_id), timeout_ms=180_000)
        if not value.HasField("operation") or value.operation.request_id != request_id:
            raise RuntimeError("cw runtime observation omitted the saved operation")
        return value.operation
