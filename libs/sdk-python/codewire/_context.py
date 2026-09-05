"""Private shared state for generated Connect-backed SDK services."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TypeVar

from connectrpc.errors import ConnectError

from codewire._transport import ConnectTransport
from codewire.errors import codewire_error_from_connect


ResponseT = TypeVar("ResponseT")


class ConnectContext:
    """Own common generated clients, organization scope, and error mapping."""

    def __init__(self, transport: ConnectTransport, org_id: str) -> None:
        self.transport = transport
        self.org_id = org_id

    def resolve_org_id(self) -> str:
        if not self.org_id:
            raise ValueError(
                "org_id is required — pass org_id to Codewire() "
                "or set CODEWIRE_ORG_ID"
            )
        return self.org_id

    def unary(
        self,
        call: Callable[..., ResponseT],
        request: object,
        *,
        timeout_ms: int | None = None,
    ) -> ResponseT:
        try:
            return self.transport.unary(call, request, timeout_ms=timeout_ms)
        except ConnectError as error:
            raise codewire_error_from_connect(error) from error

    def server_stream(
        self,
        call: Callable[..., Iterator[ResponseT]],
        request: object,
        *,
        timeout_ms: int | None = None,
    ) -> Iterator[ResponseT]:
        try:
            stream = self.transport.server_stream(call, request, timeout_ms=timeout_ms)
            yield from stream
        except ConnectError as error:
            raise codewire_error_from_connect(error) from error

    def client_stream(
        self,
        call: Callable[..., ResponseT],
        request: Iterator[object],
        *,
        timeout_ms: int | None = None,
    ) -> ResponseT:
        try:
            return self.transport.client_stream(call, request, timeout_ms=timeout_ms)
        except ConnectError as error:
            raise codewire_error_from_connect(error) from error
