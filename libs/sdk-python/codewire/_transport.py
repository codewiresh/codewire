"""Private synchronous boundary over generated Connect clients.

The generated ``connectrpc`` surface is intentionally contained here. Public
SDK modules keep their existing ergonomic, dictionary-based API while later
transport-flip work items supply generated request and response conversion.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any, TypeVar

from connectrpc.client import ConnectClientSync


ClientT = TypeVar("ClientT", bound=ConnectClientSync)
ResponseT = TypeVar("ResponseT")


class _HttpxResponse:
    """Expose the response attributes the generated client consumes."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.status = response.status_code
        self.headers = response.headers

    @property
    def content(self) -> bytes:
        return self._response.content

    def json(self) -> Any:
        return self._response.json()


class _HttpxStreamResponse(_HttpxResponse):
    """Adapt HTTPX's streaming response to the generated runtime protocol."""

    trailers: Mapping[str, str] = {}

    @property
    def content(self) -> Iterator[bytes]:
        return self._response.iter_bytes()


class _HttpxClient:
    """Adapt the SDK's caller-owned HTTPX client to connectrpc's transport."""

    def __init__(self, http_client: Any) -> None:
        self._http_client = http_client

    def post(
        self,
        *,
        url: str,
        headers: Any = None,
        content: bytes | None = None,
        timeout: float | None = None,
    ) -> _HttpxResponse:
        response = self._http_client.post(
            url=url,
            headers=list(headers.items()) if headers is not None else None,
            content=content,
            timeout=timeout,
        )
        return _HttpxResponse(response)

    def get(
        self,
        *,
        url: str,
        headers: Any = None,
        timeout: float | None = None,
    ) -> _HttpxResponse:
        response = self._http_client.get(
            url=url,
            headers=list(headers.items()) if headers is not None else None,
            timeout=timeout,
        )
        return _HttpxResponse(response)

    @contextmanager
    def stream(
        self,
        *,
        method: str,
        url: str,
        headers: Any = None,
        content: Iterator[bytes] | None = None,
        timeout: float | None = None,
    ) -> Iterator[_HttpxStreamResponse]:
        with self._http_client.stream(
            method=method,
            url=url,
            headers=list(headers.items()) if headers is not None else None,
            content=content,
            timeout=timeout,
        ) as response:
            yield _HttpxStreamResponse(response)


class ConnectTransport:
    """Own generated synchronous clients, request metadata, and deadlines."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30,
        http_client: Any = None,
    ) -> None:
        self._address = base_url.rstrip("/")
        self._headers: Mapping[str, str] = (
            {"Authorization": f"Bearer {api_key}"} if api_key else {}
        )
        self._timeout_ms = int(timeout * 1000)
        self._http_client = (
            _HttpxClient(http_client) if http_client is not None else None
        )

    def client(self, client_type: type[ClientT]) -> ClientT:
        """Construct one generated synchronous client with the SDK deadline."""
        return client_type(
            self._address,
            timeout_ms=self._timeout_ms,
            http_client=self._http_client,
        )

    def unary(
        self,
        call: Callable[..., ResponseT],
        request: object,
        *,
        timeout_ms: int | None = None,
    ) -> ResponseT:
        """Issue a generated unary call without translating its errors."""
        return call(request, headers=self._headers, timeout_ms=timeout_ms)

    def server_stream(
        self,
        call: Callable[..., Iterator[ResponseT]],
        request: object,
        *,
        timeout_ms: int | None = None,
    ) -> Iterator[ResponseT]:
        """Return the generated stream lazily without consuming it."""
        return call(request, headers=self._headers, timeout_ms=timeout_ms)

    def client_stream(
        self,
        call: Callable[..., ResponseT],
        request: Iterator[object],
        *,
        timeout_ms: int | None = None,
    ) -> ResponseT:
        """Issue a generated client-streaming call without translating errors."""
        return call(request, headers=self._headers, timeout_ms=timeout_ms)
