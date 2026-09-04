from __future__ import annotations

import os
from typing import Any

from codewire._context import ConnectContext
from codewire._transport import ConnectTransport
from codewire.api_keys import APIKeys
from codewire.environments import Environments
from codewire.secrets import SecretProjects, Secrets
from codewire.templates import Templates

DEFAULT_BASE_URL = "https://codewire.sh"


class Codewire:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        org_id: str | None = None,
        timeout: float = 30,
        http_client: Any | None = None,
    ):
        # Missing credentials fail only when a generated Connect service sends
        # a request, so constructing the client does not access the platform.
        key = api_key or os.environ.get("CODEWIRE_API_KEY", "") or ""
        url = (
            base_url or os.environ.get("CODEWIRE_BASE_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        resolved_org = org_id or os.environ.get("CODEWIRE_ORG_ID", "")
        # The optional client is a caller-owned, HTTPX-compatible synchronous
        # transport adapter. The generated Connect core itself imports no
        # HTTPX implementation.
        self._connect = ConnectTransport(
            url, key, timeout=timeout, http_client=http_client
        )
        self._context = ConnectContext(self._connect, resolved_org)
        self.environments = Environments(self._context)
        self.templates = Templates(self._context)
        self.api_keys = APIKeys(self._context)
        self.secrets = Secrets(self._context)
        self.secret_projects = SecretProjects(self._context)

    def close(self) -> None:
        """Release generated SDK clients without closing a caller-owned client."""
        self.api_keys.close()

    def __enter__(self) -> Codewire:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
