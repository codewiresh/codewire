"""Local VM support for the Codewire Python SDK.

Shells out to the ``cw`` CLI's ``--output json`` interface. Mirrors the remote
``environments`` surface so callers can swap ``client.environments`` for
``client.local`` with minimal changes. Requires the ``cw`` binary on PATH
(or ``$CW_BIN`` pointing at it).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


class LocalError(RuntimeError):
    """Raised when a ``cw`` subprocess fails or emits malformed JSON."""


@dataclass
class LocalPort:
    host_port: int
    guest_port: int
    label: str = ""


@dataclass
class LocalMount:
    source: str
    target: str
    readonly: bool = False


@dataclass
class LocalSpecPort:
    host_port: int | None = None
    guest_port: int | None = None
    port: int | None = None
    label: str = ""


@dataclass
class LocalSpecMount:
    source: str
    target: str = ""
    readonly: bool = False


@dataclass
class LocalSpec:
    """Input for ``cw env --local create --spec``. Mirrors codewire.yaml."""

    preset: str = ""
    image: str = ""
    install: str = ""
    startup: str = ""
    env: dict[str, str] = field(default_factory=dict)
    ports: list[LocalSpecPort] = field(default_factory=list)
    mounts: list[LocalSpecMount] = field(default_factory=list)
    cpu: int = 0
    memory: int = 0
    disk: int = 0
    agent: str = ""
    secret_project: str = ""
    include_org_secrets: bool | None = None
    include_user_secrets: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the shape expected by ``cw env --local create --spec``."""

        body: dict[str, Any] = {}
        if self.preset:
            body["preset"] = self.preset
        if self.image:
            body["image"] = self.image
        if self.install:
            body["install"] = self.install
        if self.startup:
            body["startup"] = self.startup
        if self.env:
            body["env"] = dict(self.env)
        if self.ports:
            body["ports"] = [
                {
                    k: v
                    for k, v in {
                        "host_port": p.host_port,
                        "guest_port": p.guest_port,
                        "port": p.port,
                        "label": p.label,
                    }.items()
                    if v not in (None, "", 0)
                }
                for p in self.ports
            ]
        if self.mounts:
            body["mounts"] = [
                {
                    "source": m.source,
                    "target": m.target or None,
                    "readonly": m.readonly or None,
                }
                for m in self.mounts
            ]
        if self.cpu:
            body["cpu"] = self.cpu
        if self.memory:
            body["memory"] = self.memory
        if self.disk:
            body["disk"] = self.disk
        if self.agent:
            body["agent"] = self.agent
        if self.secret_project:
            body["secret_project"] = self.secret_project
        if self.include_org_secrets is not None:
            body["include_org_secrets"] = self.include_org_secrets
        if self.include_user_secrets is not None:
            body["include_user_secrets"] = self.include_user_secrets
        return body


@dataclass
class LocalExecResult:
    exit_code: int
    stdout: str
    stderr: str


class LocalInstance:
    """A persisted local VM. Mirrors the ``Environment`` wrapper surface."""

    def __init__(self, service: "LocalService", data: dict[str, Any]):
        self._service = service
        self._data = data

    # -- properties mirroring the JSON shape ----------------------------------

    @property
    def name(self) -> str:
        return self._data["name"]

    @property
    def backend(self) -> str:
        return self._data.get("backend", "")

    @property
    def status(self) -> str:
        return self._data.get("status", "")

    @property
    def runtime_name(self) -> str:
        return self._data.get("runtime_name", "")

    @property
    def repo_path(self) -> str:
        return self._data.get("repo_path", "")

    @property
    def workdir(self) -> str:
        return self._data.get("workdir", "")

    @property
    def ports(self) -> list[dict[str, Any]]:
        return list(self._data.get("ports") or [])

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        self._service.start(self.name)

    def stop(self) -> None:
        self._service.stop(self.name)

    def remove(self) -> None:
        self._service.remove(self.name)

    def exec(
        self,
        *,
        command: list[str],
        working_dir: str | None = None,
    ) -> LocalExecResult:
        return self._service.exec(
            self.name, command=command, working_dir=working_dir
        )

    def wait_ready(self, timeout: float = 300, interval: float = 1.0) -> None:
        """Poll ``cw env --local info`` until running or terminal."""

        deadline = time.monotonic() + timeout
        while True:
            fresh = self._service.get(self.name)
            self._data = fresh._data
            status = (self.status or "").lower()
            if status == "running":
                return
            if status in {"error", "missing"}:
                raise LocalError(
                    f"local instance {self.name!r} entered state {status!r}"
                )
            if time.monotonic() >= deadline:
                raise LocalError(
                    f"timed out waiting for local instance {self.name!r}"
                )
            time.sleep(interval)


class LocalService:
    """Local VM surface. Constructed once and attached to :class:`Codewire`."""

    def __init__(self, cw_bin: str | None = None):
        self._cw_bin_override = cw_bin
        self._resolved_bin: str | None = None

    # -- binary resolution ----------------------------------------------------

    def bin(self) -> str:
        """Return the path to the ``cw`` binary, resolving via override, env,
        and PATH in that order. Raises :class:`LocalError` if unresolved."""

        if self._resolved_bin:
            return self._resolved_bin
        if self._cw_bin_override:
            self._resolved_bin = self._cw_bin_override
            return self._resolved_bin
        override = os.environ.get("CW_BIN", "").strip()
        if override:
            self._resolved_bin = override
            return override
        found = shutil.which("cw")
        if not found:
            raise LocalError(
                "cw CLI not found on PATH; install from https://codewire.sh/install "
                "or set CW_BIN"
            )
        self._resolved_bin = found
        return found

    # -- lifecycle ------------------------------------------------------------

    def create(
        self,
        spec: LocalSpec | dict[str, Any],
        *,
        backend: str,
        name: str | None = None,
        path: str | None = None,
        wait: bool = False,
        wait_timeout: float = 300,
    ) -> LocalInstance:
        """Create a new local instance from ``spec`` using ``backend``."""

        if not backend:
            raise ValueError("backend is required")
        spec_dict = spec.to_dict() if isinstance(spec, LocalSpec) else dict(spec)
        args = [
            "env",
            "--local",
            "create",
            "--output",
            "json",
            "--backend",
            backend,
            "--spec",
            "-",
        ]
        if name:
            args += ["--name", name]
        if path:
            args += ["--path", path]
        out = self._run(args, stdin=json.dumps(spec_dict).encode("utf-8"))
        instance = LocalInstance(self, json.loads(out))
        if wait and instance.status.lower() != "running":
            instance.wait_ready(timeout=wait_timeout)
        return instance

    def list(self) -> list[LocalInstance]:
        out = self._run(["env", "--local", "list", "--output", "json"])
        return [LocalInstance(self, row) for row in json.loads(out)]

    def get(self, name: str) -> LocalInstance:
        out = self._run(["env", "--local", "info", "--output", "json", name])
        return LocalInstance(self, json.loads(out))

    def start(self, name: str) -> None:
        self._run(["env", "--local", "start", "--output", "json", name])

    def stop(self, name: str) -> None:
        self._run(["env", "--local", "stop", "--output", "json", name])

    def remove(self, name: str) -> None:
        self._run(["env", "--local", "rm", "--output", "json", name])

    def exec(
        self,
        name: str,
        *,
        command: list[str],
        working_dir: str | None = None,
    ) -> LocalExecResult:
        if not command:
            raise ValueError("command is required")
        args = ["run", "--no-tty", name]
        if working_dir:
            args += ["--workdir", working_dir]
        args.append("--")
        args.extend(command)
        out = self._run(args)
        return LocalExecResult(
            exit_code=0,
            stdout=out,
            stderr="",
        )

    # -- subprocess plumbing --------------------------------------------------

    def _run(
        self,
        args: Iterable[str],
        *,
        stdin: bytes | None = None,
    ) -> str:
        """Invoke ``cw <args...>`` and return stdout. Raises :class:`LocalError`
        on non-zero exit with the captured stderr as message."""

        cmd = [self.bin(), *list(args)]
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise LocalError(
                f"{' '.join(cmd)} exited {result.returncode}: {stderr}"
            )
        return result.stdout.decode("utf-8")
