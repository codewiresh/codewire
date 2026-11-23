"""Where a client finds its settings: code, the environment, then .env files.

The order and the variables are specified in docs/dev/AUTH-POLICY.md,
"Signing in from the environment".
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

DEFAULT_API_URL = "https://codewire.sh"

API_KEY = "CODEWIRE_API_KEY"
JWT_TOKEN = "CODEWIRE_JWT_TOKEN"
ORGANIZATION = ("CODEWIRE_ORGANIZATION_ID", "CODEWIRE_ORG_ID")
# CODEWIRE_BASE_URL is the older name, kept for one release.
SERVER = ("CODEWIRE_API_URL", "CODEWIRE_SERVER_URL", "CODEWIRE_BASE_URL")
DOTENV_FILES = (".env.local", ".env")
_DOTENV_VARIABLES = frozenset((API_KEY, JWT_TOKEN, *ORGANIZATION, *SERVER))


@dataclass(frozen=True)
class Settings:
    # The API key or user token sent as the bearer; never shown or logged.
    bearer: str = field(repr=False)
    credential: Literal["api key", "user token"]
    organization_id: str
    api_url: str
    # Things to report once, such as a server variable ignored in a .env file.
    warnings: tuple[str, ...] = ()


def resolve_settings(
    *,
    api_key: str | None,
    jwt_token: str | None,
    organization_id: str | None,
    api_url: str | None,
    environ: Mapping[str, str],
    cwd: Path,
) -> Settings:
    """Resolve the settings.

    The credential comes as a unit from the highest source that sets a key or
    a token: code, the environment, then ``.env.local`` and ``.env`` in
    ``cwd``. A key or token in a lower source is ignored and reported. The
    organization comes from the highest source at or above the credential's
    that sets one; failing that, from the highest source below it, which is
    reported. The server comes from code or the environment, never a file.

    Raises ``ValueError`` before any request when there is no credential, or
    a user token has no organization. Messages never contain a key or token.
    """
    files = [_read_dotenv(cwd / name) for name in DOTENV_FILES]
    found: list[str] = []
    for path, values in files:
        for variable in SERVER:
            if variable in values:
                found.append(
                    f"ignored {variable} in {path}: the server is never read "
                    f"from a .env file; set {variable} in the environment or "
                    "pass api_url"
                )

    def source(name: str, values: Mapping[str, str]) -> _Source:
        return _Source(
            name,
            values.get(API_KEY) or None,
            values.get(JWT_TOKEN) or None,
            _first(values.get(variable) for variable in ORGANIZATION),
            next((variable for variable in ORGANIZATION if values.get(variable)), None),
        )

    ordered = [
        _Source("code", api_key or None, jwt_token or None, organization_id or None),
        source("the environment", environ),
        *(source(str(path), values) for path, values in files),
    ]
    url = (
        _first((api_url, *(environ.get(variable) for variable in SERVER)))
        or DEFAULT_API_URL
    ).rstrip("/")

    chosen = next(
        (index for index, each in enumerate(ordered) if each.api_key or each.jwt_token),
        None,
    )
    if chosen is None:
        raise ValueError(
            f"no credentials: set {API_KEY} or {JWT_TOKEN}, "
            "or pass api_key or jwt_token to Codewire()"
        )
    credential = ordered[chosen]
    for lower in ordered[chosen + 1:]:
        for variable, value in ((API_KEY, lower.api_key), (JWT_TOKEN, lower.jwt_token)):
            if value:
                found.append(
                    f"ignored {variable} in {lower.name}: the credential "
                    f"comes from {credential.name}"
                )
    organization = _first(each.organization_id for each in ordered[: chosen + 1]) or ""
    if not organization:
        below = next((each for each in ordered[chosen + 1:] if each.organization_id), None)
        if below is not None:
            organization = below.organization_id
            found.append(
                f"used {below.organization_variable} in {below.name}: the "
                f"credential in {credential.name} sets no organization"
            )
    if credential.api_key:
        return Settings(credential.api_key, "api key", organization, url, tuple(found))
    if not organization:
        raise ValueError(
            f"a user token needs an organization: set {ORGANIZATION[0]} "
            "or pass organization_id to Codewire()"
        )
    return Settings(credential.jwt_token, "user token", organization, url, tuple(found))


@dataclass(frozen=True)
class _Source:
    """What one source sets; empty values count as unset."""

    name: str
    api_key: str | None = field(repr=False)
    jwt_token: str | None = field(repr=False)
    organization_id: str | None
    # The variable that set organization_id, for a source other than code.
    organization_variable: str | None = None


def _first(values) -> str | None:
    for value in values:
        if value:
            return value
    return None


def _read_dotenv(path: Path) -> tuple[Path, dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return path, {}
    except (OSError, UnicodeDecodeError) as error:
        reason = (error.strerror if isinstance(error, OSError) else "not UTF-8") or "read failed"
        raise ValueError(f"cannot read {path}: {reason}") from None
    return path, parse_dotenv(text, str(path))


_EXPORT = re.compile(r"^export\s")
_COMMENT = re.compile(r"\s#")


def parse_dotenv(text: str, path: str) -> dict[str, str]:
    """Read ``KEY=VALUE`` lines, ``#`` comments, an optional ``export `` and
    single or double quotes, keeping only the Codewire settings variables.

    Other lines are skipped unread, since the file usually belongs to other
    tools too.
    """
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _EXPORT.match(line):
            line = line[len("export"):].lstrip()
        name, equals, value = line.partition("=")
        name = name.strip()
        if not equals or name not in _DOTENV_VARIABLES:
            continue
        value = value.strip()
        if value[:1] in ("'", '"'):
            end = value.find(value[0], 1)
            if end < 0:
                raise ValueError(f"{path}:{number}: {name} has no closing quote")
            value = value[1:end]
        else:
            comment = _COMMENT.search(value)
            if comment:
                value = value[: comment.start()].rstrip()
        values[name] = value
    return values


_reported: set[str] = set()


def report_once(messages: tuple[str, ...]) -> None:
    """Report each message once per process, as a ``UserWarning``."""
    for message in messages:
        if message in _reported:
            continue
        _reported.add(message)
        warnings.warn(message, UserWarning, stacklevel=3)
