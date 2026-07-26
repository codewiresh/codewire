"""Mesh API client for the Codewire Python SDK.

Mirrors the Go ``codewire.MeshClient`` surface: Networks, Nodes, Groups,
Credentials, and KV. The mesh speaks its own HTTP API distinct from the
platform — construct with :class:`MeshClient` and a mesh URL + auth token.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

import httpx

from codewire.errors import CodewireError


# -- Types --------------------------------------------------------------------


@dataclass
class MeshNetwork:
    id: str
    created_at: str
    node_count: int = 0
    invite_count: int = 0


@dataclass
class MeshNode:
    name: str
    network_id: str = ""
    peer_url: str = ""
    connected: bool = False


@dataclass
class MeshEnrollment:
    id: str
    network_id: str
    enrollment_token: str
    uses_remaining: int
    expires_at: str
    node_name: str = ""


@dataclass
class MeshNodeCredentials:
    node_token: str
    node_name: str
    network_id: str
    enrollment_id: str = ""


@dataclass
class MeshKVEntry:
    key: str
    value: str = ""


@dataclass
class MeshGroupMember:
    network_id: str
    group_name: str
    node_name: str
    session_name: str
    created_at: str


@dataclass
class MeshGroupPolicy:
    network_id: str
    group_name: str
    messages_policy: str
    debug_policy: str


@dataclass
class MeshGroup:
    network_id: str
    name: str
    created_at: str
    created_by: str = ""
    members: list[MeshGroupMember] | None = None
    policy: MeshGroupPolicy | None = None


@dataclass
class MeshRuntimeCredential:
    credential: str
    network_id: str
    subject_kind: str
    subject_id: str
    expires_at: str


@dataclass
class MeshVerifierKey:
    key_id: str
    algorithm: str
    public_key: str


@dataclass
class MeshVerifierBundle:
    network_id: str
    issuer: str
    keys: list[MeshVerifierKey]
    version: int
    expires_at: str


@dataclass
class MeshSenderDelegation:
    delegation: str
    network_id: str
    source_node: str
    expires_at: str
    from_session_id: int | None = None
    from_session_name: str = ""
    audience_node: str = ""


# -- HTTP plumbing ------------------------------------------------------------


class _MeshHttp:
    """Thin HTTP wrapper that handles auth header selection and error shape.

    The mesh uses two auth modes:
    - Client auth: Bearer on the client's auth token (most endpoints).
    - Node auth: Bearer on a node token passed per-call (delegation issuance).
    - Public: no Authorization header (enrollment redemption).
    """

    def __init__(
        self,
        base_url: str,
        auth_token: str,
        *,
        timeout: float = 30,
        http_client: httpx.Client | None = None,
    ):
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                base_url=self._base_url, timeout=timeout
            )
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        token: str | None = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)
        bearer = self._auth_token if token is None else token
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if body is not None and raw_body is None:
            headers.setdefault("Content-Type", "application/json")
        elif content_type:
            headers["Content-Type"] = content_type
        resp = self._client.request(
            method,
            path,
            json=body if raw_body is None else None,
            content=raw_body,
            headers=headers,
        )
        if resp.status_code >= 400:
            detail = resp.text.strip() or resp.reason_phrase
            raise CodewireError(resp.status_code, detail, resp.headers.get("x-request-id", ""))
        return resp

    def json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        token: str | None = None,
    ) -> Any:
        resp = self.request(method, path, body=body, token=token)
        if resp.status_code == 204:
            return None
        if not resp.content:
            return None
        return resp.json()


# -- Services -----------------------------------------------------------------


class MeshNetworks:
    def __init__(self, http: _MeshHttp):
        self._http = http

    def create(self, network_id: str) -> None:
        """Create or claim a network."""
        self._http.json(
            "POST", "/api/v1/networks", body={"network_id": network_id}
        )

    def list(self) -> list[MeshNetwork]:
        rows = self._http.json("GET", "/api/v1/networks") or []
        return [MeshNetwork(**row) for row in rows]


class MeshNodes:
    def __init__(self, http: _MeshHttp):
        self._http = http

    def list(self, network_id: str) -> list[MeshNode]:
        rows = self._http.json(
            "GET", f"/api/v1/nodes?network_id={quote(network_id, safe='')}"
        ) or []
        return [MeshNode(**row) for row in rows]

    def revoke(self, network_id: str, node_name: str) -> None:
        self._http.json(
            "DELETE",
            f"/api/v1/nodes/{quote(node_name, safe='')}?network_id={quote(network_id, safe='')}",
        )

    def create_enrollment(
        self,
        network_id: str,
        node_name: str,
        *,
        uses: int = 1,
        ttl: str | None = None,
    ) -> MeshEnrollment:
        body: dict[str, Any] = {
            "network_id": network_id,
            "node_name": node_name,
            "uses": uses,
        }
        if ttl:
            body["ttl"] = ttl
        data = self._http.json("POST", "/api/v1/node-enrollments", body=body)
        return MeshEnrollment(**data)

    def redeem_enrollment(
        self, enrollment_token: str, node_name: str
    ) -> MeshNodeCredentials:
        """Redeem an enrollment token to register a node. No auth required."""
        data = self._http.json(
            "POST",
            "/api/v1/node-enrollments/redeem",
            body={
                "enrollment_token": enrollment_token,
                "node_name": node_name,
            },
            token="",
        )
        return MeshNodeCredentials(**data)


class MeshGroups:
    def __init__(self, http: _MeshHttp):
        self._http = http

    def create(self, network_id: str, name: str) -> MeshGroup:
        data = self._http.json(
            "POST",
            "/api/v1/groups",
            body={"network_id": network_id, "name": name},
        )
        return _group_from_dict(data)

    def list(self, network_id: str) -> list[MeshGroup]:
        rows = self._http.json(
            "GET",
            f"/api/v1/groups?network_id={quote(network_id, safe='')}",
        ) or []
        return [_group_from_dict(row) for row in rows]

    def get(self, network_id: str, name: str) -> MeshGroup:
        data = self._http.json(
            "GET",
            f"/api/v1/groups/{quote(name, safe='')}?network_id={quote(network_id, safe='')}",
        )
        return _group_from_dict(data)

    def delete(self, network_id: str, name: str) -> None:
        self._http.json(
            "DELETE",
            f"/api/v1/groups/{quote(name, safe='')}?network_id={quote(network_id, safe='')}",
        )

    def add_member(
        self,
        network_id: str,
        group_name: str,
        node_name: str,
        session_name: str,
    ) -> MeshGroupMember:
        data = self._http.json(
            "POST",
            f"/api/v1/groups/{quote(group_name, safe='')}/members",
            body={
                "network_id": network_id,
                "node_name": node_name,
                "session_name": session_name,
            },
        )
        return MeshGroupMember(**data)

    def remove_member(
        self,
        network_id: str,
        group_name: str,
        node_name: str,
        session_name: str,
    ) -> None:
        path = (
            f"/api/v1/groups/{quote(group_name, safe='')}/members"
            f"?network_id={quote(network_id, safe='')}"
            f"&node_name={quote(node_name, safe='')}"
            f"&session_name={quote(session_name, safe='')}"
        )
        self._http.json("DELETE", path)

    def set_policy(
        self,
        network_id: str,
        group_name: str,
        messages_policy: str,
        debug_policy: str,
    ) -> MeshGroupPolicy:
        data = self._http.json(
            "PUT",
            f"/api/v1/groups/{quote(group_name, safe='')}/policy",
            body={
                "network_id": network_id,
                "messages_policy": messages_policy,
                "debug_policy": debug_policy,
            },
        )
        return MeshGroupPolicy(**data)


class MeshCredentials:
    def __init__(self, http: _MeshHttp):
        self._http = http

    def issue_runtime_credential(
        self, network_id: str
    ) -> MeshRuntimeCredential:
        data = self._http.json(
            "POST",
            f"/api/v1/network-auth/runtime/client?network_id={quote(network_id, safe='')}",
        )
        return MeshRuntimeCredential(**data)

    def fetch_verifier_bundle(self, network_id: str) -> MeshVerifierBundle:
        data = self._http.json(
            "GET",
            f"/api/v1/network-auth/bundle?network_id={quote(network_id, safe='')}",
        )
        keys = [MeshVerifierKey(**k) for k in data.get("keys", [])]
        return MeshVerifierBundle(
            network_id=data["network_id"],
            issuer=data["issuer"],
            keys=keys,
            version=int(data.get("version", 0)),
            expires_at=data.get("expires_at", ""),
        )

    def issue_node_runtime_credential(
        self, node_token: str
    ) -> MeshRuntimeCredential:
        """Runtime credential using node auth instead of client auth."""
        data = self._http.json(
            "POST", "/api/v1/network-auth/runtime/node", token=node_token
        )
        return MeshRuntimeCredential(**data)

    def issue_sender_delegation(
        self,
        node_token: str,
        source_node: str,
        *,
        from_session_id: int | None = None,
        from_session_name: str = "",
        verbs: Iterable[str] | None = None,
        audience_node: str = "",
    ) -> MeshSenderDelegation:
        body: dict[str, Any] = {
            "source_node": source_node,
            "verbs": list(verbs or []),
        }
        if from_session_id is not None:
            body["from_session_id"] = from_session_id
        if from_session_name:
            body["from_session_name"] = from_session_name
        if audience_node:
            body["audience_node"] = audience_node
        data = self._http.json(
            "POST",
            "/api/v1/network-auth/delegation/node",
            body=body,
            token=node_token,
        )
        return MeshSenderDelegation(**data)


class MeshKV:
    def __init__(self, http: _MeshHttp):
        self._http = http

    def set(
        self,
        network_id: str,
        namespace: str,
        key: str,
        value: bytes | str,
        *,
        ttl: str | None = None,
    ) -> None:
        path = (
            f"/api/v1/kv/{quote(namespace, safe='')}/{quote(key, safe='')}"
            f"?network_id={quote(network_id, safe='')}"
        )
        raw = value.encode("utf-8") if isinstance(value, str) else value
        headers = {"X-TTL": ttl} if ttl else None
        self._http.request(
            "PUT",
            path,
            raw_body=raw,
            content_type="application/octet-stream",
            extra_headers=headers,
        )

    def get(self, network_id: str, namespace: str, key: str) -> bytes:
        path = (
            f"/api/v1/kv/{quote(namespace, safe='')}/{quote(key, safe='')}"
            f"?network_id={quote(network_id, safe='')}"
        )
        resp = self._http.request("GET", path)
        return resp.content

    def list(
        self, network_id: str, namespace: str, prefix: str = ""
    ) -> list[MeshKVEntry]:
        path = (
            f"/api/v1/kv/{quote(namespace, safe='')}"
            f"?prefix={quote(prefix, safe='')}"
            f"&network_id={quote(network_id, safe='')}"
        )
        rows = self._http.json("GET", path) or []
        return [MeshKVEntry(**row) for row in rows]

    def delete(self, network_id: str, namespace: str, key: str) -> None:
        path = (
            f"/api/v1/kv/{quote(namespace, safe='')}/{quote(key, safe='')}"
            f"?network_id={quote(network_id, safe='')}"
        )
        self._http.json("DELETE", path)


def _group_from_dict(data: dict[str, Any]) -> MeshGroup:
    members = [
        MeshGroupMember(**m) for m in (data.get("members") or [])
    ] or None
    policy_data = data.get("policy")
    policy = MeshGroupPolicy(**policy_data) if policy_data else None
    return MeshGroup(
        network_id=data["network_id"],
        name=data["name"],
        created_at=data.get("created_at", ""),
        created_by=data.get("created_by", ""),
        members=members,
        policy=policy,
    )


# -- Client -------------------------------------------------------------------


class MeshClient:
    """Client for the Codewire mesh API.

    The mesh speaks a separate HTTP API from the platform; construct this with
    a mesh URL + auth token (not the Codewire API key).
    """

    def __init__(
        self,
        mesh_url: str,
        auth_token: str,
        *,
        timeout: float = 30,
        http_client: httpx.Client | None = None,
    ):
        self._http = _MeshHttp(
            mesh_url,
            auth_token,
            timeout=timeout,
            http_client=http_client,
        )
        self.networks = MeshNetworks(self._http)
        self.nodes = MeshNodes(self._http)
        self.groups = MeshGroups(self._http)
        self.credentials = MeshCredentials(self._http)
        self.kv = MeshKV(self._http)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "MeshClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
