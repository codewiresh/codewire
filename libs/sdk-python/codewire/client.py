from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from codewire._context import ConnectContext
from codewire._settings import DEFAULT_API_URL, report_once, resolve_settings
from codewire._transport import ConnectTransport
from codewire.api_keys import APIKeys
from codewire.audit import Audit
from codewire.access_profiles import AccessProfiles
from codewire.credentials import Credentials
from codewire.environments import Environments
from codewire.network_policies import NetworkPolicies
from codewire.sandbox_identity import SandboxIdentity
from codewire.secrets import SecretProjects, Secrets
from codewire.presets import Presets

# Older name of the default server, kept for callers that import it.
DEFAULT_BASE_URL = DEFAULT_API_URL


class Codewire:
    """The Codewire client.

    Its settings come from its arguments, the process environment, then
    ``.env.local`` and ``.env`` in the working directory, then the defaults:

    - ``api_key``: ``CODEWIRE_API_KEY``;
    - ``jwt_token``: ``CODEWIRE_JWT_TOKEN``; needs an organization;
    - ``organization_id``: ``CODEWIRE_ORGANIZATION_ID``, or ``CODEWIRE_ORG_ID``;
    - ``api_url``: ``CODEWIRE_API_URL``, or ``CODEWIRE_SERVER_URL``, or the
      older ``CODEWIRE_BASE_URL``; never from a ``.env`` file; default
      ``https://codewire.sh``.

    The key or token comes as a unit from the highest of those sources that
    sets either, the key winning within it; one in a lower source is ignored
    with a ``UserWarning``. The organization comes from the highest source at
    or above that one that sets it; only failing that from a lower source,
    with a ``UserWarning``. ``org_id`` and ``base_url`` are older names of
    ``organization_id`` and ``api_url``. Raises ``ValueError`` before any
    request when there is no credential, or a user token has no
    organization.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        org_id: str | None = None,
        timeout: float = 30,
        http_client: Any | None = None,
        *,
        jwt_token: str | None = None,
        organization_id: str | None = None,
        api_url: str | None = None,
    ):
        settings = resolve_settings(
            api_key=api_key,
            jwt_token=jwt_token,
            organization_id=organization_id or org_id,
            api_url=api_url or base_url,
            environ=os.environ,
            cwd=Path.cwd(),
        )
        report_once(settings.warnings)
        self._credential = settings.credential
        self._api_url = settings.api_url
        # The optional client is a caller-owned, HTTPX-compatible synchronous
        # transport adapter. The generated Connect core itself imports no
        # HTTPX implementation.
        self._connect = ConnectTransport(
            settings.api_url, settings.bearer, timeout=timeout, http_client=http_client
        )
        self._context = ConnectContext(self._connect, settings.organization_id)
        self.environments = Environments(self._context)
        self.presets = Presets(self._context)
        self.api_keys = APIKeys(self._context)
        self.secrets = Secrets(self._context)
        self.secret_projects = SecretProjects(self._context)
        self.access_profiles = AccessProfiles(self._context)
        self.network_policies = NetworkPolicies(self._context)
        self.sandbox_identity = SandboxIdentity(self._context)
        self.audit = Audit(self._context)
        self.credentials = Credentials(self._context)

    def __repr__(self) -> str:
        return (
            f"Codewire(api_url={self._api_url!r}, "
            f"organization_id={self._context.org_id!r}, "
            f"credential={self._credential!r})"
        )

    def close(self) -> None:
        """Release generated SDK clients without closing a caller-owned client."""
        self.api_keys.close()
        self.access_profiles.close()
        self.network_policies.close()
        self.sandbox_identity.close()
        self.audit.close()
        self.credentials.close()

    def __enter__(self) -> Codewire:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
