"""A hosted Sandbox's audit log (#6189) over the generated Connect service.

A user's session or an API key reads it. Organization owners and admins read
every Sandbox's events, a deleted Sandbox's included; a member reads those of
each Sandbox they can open now.

Every enum in an event is its proto value name without the enum's prefix, in
lower case: ``"access"``, ``"ssh"``, ``"out_of_credit"``. The unspecified
value is ``""``, and a value this SDK does not know yet is ``"unknown"``;
neither fails a read.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Literal, TypedDict

from codewire._context import ConnectContext
from codewire.v1 import audit_pb2 as pb
from codewire.v1.audit_connect import AuditServiceClientSync

AuditEventKind = Literal["access", "lifecycle", "policy", "refused", "credentials"]


class AuditEnvironment(TypedDict):
    id: str
    name: str
    deleted: bool


class AuditPolicyRevision(TypedDict):
    name: str
    revision: int


class AuditUser(TypedDict):
    id: str
    email: str
    # "owner", "admin", "member" or "staff".
    role: str


class AuditApiKey(TypedDict):
    id: str
    name: str


class AuditActor(TypedDict, total=False):
    """Who did it, as they were when it happened: exactly one key, or none
    for an actor this SDK does not know yet. ``platform`` is the platform's
    own action and ``sandbox`` what the Sandbox's workload caused; each is
    an empty dict."""

    user: AuditUser
    api_key: AuditApiKey
    platform: dict
    sandbox: dict


class AuditAccess(TypedDict):
    # "terminal", "ssh", "exec", "desktop" or "preview".
    surface: str
    client_ip: str


class AuditSize(TypedDict):
    vcpu: int
    memory_mib: int


# ``action`` is "created", "started", "stopped", "restarted", "resized",
# "snapshot_taken" or "deleted". ``reason`` is why the platform did it, such
# as "idle", and "" when a person did. ``from`` and ``to`` are the sizes of a
# resize, None otherwise. ``idle_stop_seconds`` is, for an idle stop, the idle
# timeout the Sandbox had then; 0 when not known. ``from`` is a keyword, so
# these use the functional form.
AuditLifecycle = TypedDict("AuditLifecycle", {
    "action": str,
    "reason": str,
    "preset": str,
    "from_snapshot": str,
    "from": AuditSize | None,
    "to": AuditSize | None,
    "snapshot": str,
    "idle_stop_seconds": int,
})


# ``action`` is "selected", "edited", "enforcing" or "failed_closed".
AuditPolicyChange = TypedDict("AuditPolicyChange", {
    "action": str,
    "from": str,
    "to": str,
    "policy": str,
    "from_revision": int,
    "to_revision": int,
    "added": list[str],
    "removed": list[str],
    "revision": int,
    "failure_code": str,
})


class AuditRefusal(TypedDict):
    destination: str
    withheld: bool
    address: str
    # None for DNS.
    port: int | None
    # "dns", "tcp" or "udp".
    protocol: str
    reason: str
    source: str
    policy: str
    revision: int
    # The first revision of the selected policy that allows it, when its
    # current revision does; None otherwise.
    allowed_since_revision: int | None


class AuditRefusalOverflow(TypedDict):
    """An hour's refusals past its 1,000 subjects, counted together; the
    event's ``count`` is the refusals."""

    # How many more subjects were refused that hour.
    subjects: int
    # True past 1,000 more, which are not counted exactly.
    at_least: bool


class AuditCredentials(TypedDict):
    # "attached", "detached" or "used".
    action: str
    provider: str
    name: str
    host: str
    withheld: bool


class AuditEvent(TypedDict):
    """One event: exactly one of ``access``, ``lifecycle``, ``policy``,
    ``refused``, ``refused_overflow`` or ``credentials`` is set and the others
    are None. ``kind`` names it, ``"refused"`` for both refusal keys."""

    id: str
    kind: str
    # RFC 3339: when it began, and when it ended or None while a session is
    # open.
    first: str | None
    last: str | None
    count: int
    actor: AuditActor
    access: AuditAccess | None
    lifecycle: AuditLifecycle | None
    policy: AuditPolicyChange | None
    refused: AuditRefusal | None
    credentials: AuditCredentials | None
    refused_overflow: AuditRefusalOverflow | None


class AuditEventPage(TypedDict):
    environment: AuditEnvironment
    # The selected network policy at its current revision; None when the
    # environment selects none.
    policy: AuditPolicyRevision | None
    events: list[AuditEvent]
    # Empty when nothing is older.
    next_cursor: str
    # A grouped answer's subjects past its 1,000, and those an hour's
    # overflow event counted.
    left_out: int


def _enum(enum, value: int, prefix: str) -> str:
    if value == 0:
        return ""
    known = enum.DESCRIPTOR.values_by_number.get(value)
    if known is None:
        return "unknown"
    return known.name.removeprefix(prefix).lower()


def _kinds(kinds: Sequence[str]) -> list[int]:
    values = pb.AuditEventKind.DESCRIPTOR.values_by_name
    result = []
    for kind in kinds:
        value = values.get("AUDIT_EVENT_KIND_" + kind.upper()) if kind else None
        if value is None or value.number == 0:
            raise ValueError(f"unknown audit event kind {kind!r}")
        result.append(value.number)
    return result


def _timestamp(message, field: str) -> str | None:
    return getattr(message, field).ToJsonString() if message.HasField(field) else None


def _size(message, field: str) -> AuditSize | None:
    if not message.HasField(field):
        return None
    value = getattr(message, field)
    return {"vcpu": value.vcpu, "memory_mib": value.memory_mib}


def _actor(value: pb.AuditActor) -> AuditActor:
    arm = value.WhichOneof("actor")
    if arm == "user":
        return {"user": {"id": value.user.id, "email": value.user.email,
                         "role": _enum(pb.AuditRole, value.user.role, "AUDIT_ROLE_")}}
    if arm == "api_key":
        return {"api_key": {"id": value.api_key.id, "name": value.api_key.name}}
    if arm in ("platform", "sandbox"):
        return {arm: {}}
    return {}


def _lifecycle(value: pb.AuditLifecycle) -> AuditLifecycle:
    return {
        "action": _enum(pb.AuditLifecycle.Action, value.action, "ACTION_"),
        "reason": _enum(pb.AuditPlatformReason, value.reason, "AUDIT_PLATFORM_REASON_"),
        "preset": value.preset,
        "from_snapshot": value.from_snapshot,
        "from": _size(value, "from"),
        "to": _size(value, "to"),
        "snapshot": value.snapshot,
        "idle_stop_seconds": value.idle_stop_seconds,
    }


def _policy(value: pb.AuditPolicyChange) -> AuditPolicyChange:
    return {
        "action": _enum(pb.AuditPolicyChange.Action, value.action, "ACTION_"),
        "from": getattr(value, "from"),
        "to": value.to,
        "policy": value.policy,
        "from_revision": value.from_revision,
        "to_revision": value.to_revision,
        "added": list(value.added),
        "removed": list(value.removed),
        "revision": value.revision,
        "failure_code": value.failure_code,
    }


def _refusal(value: pb.AuditRefusal) -> AuditRefusal:
    return {
        "destination": value.destination,
        "withheld": value.withheld,
        "address": value.address,
        "port": value.port if value.HasField("port") else None,
        "protocol": _enum(pb.AuditProtocol, value.protocol, "AUDIT_PROTOCOL_"),
        "reason": value.reason,
        "source": value.source,
        "policy": value.policy,
        "revision": value.revision,
        "allowed_since_revision": (
            value.allowed_since_revision if value.HasField("allowed_since_revision") else None),
    }


def _credentials(value: pb.AuditCredentials) -> AuditCredentials:
    return {
        "action": _enum(pb.AuditCredentials.Action, value.action, "ACTION_"),
        "provider": value.provider,
        "name": value.name,
        "host": value.host,
        "withheld": value.withheld,
    }


def _event(value: pb.AuditEvent) -> AuditEvent:
    detail = value.WhichOneof("detail")
    return {
        "id": value.id,
        "kind": _enum(pb.AuditEventKind, value.kind, "AUDIT_EVENT_KIND_"),
        "first": _timestamp(value, "first"),
        "last": _timestamp(value, "last"),
        "count": value.count,
        "actor": _actor(value.actor),
        "access": ({"surface": _enum(pb.AuditSurface, value.access.surface, "AUDIT_SURFACE_"),
                    "client_ip": value.access.client_ip} if detail == "access" else None),
        "lifecycle": _lifecycle(value.lifecycle) if detail == "lifecycle" else None,
        "policy": _policy(value.policy) if detail == "policy" else None,
        "refused": _refusal(value.refused) if detail == "refused" else None,
        "credentials": _credentials(value.credentials) if detail == "credentials" else None,
        "refused_overflow": ({"subjects": value.refused_overflow.subjects,
                              "at_least": value.refused_overflow.at_least}
                             if detail == "refused_overflow" else None),
    }


def _page(response: pb.ListAuditEventsResponse) -> AuditEventPage:
    if not response.HasField("environment"):
        raise RuntimeError("audit response omitted environment")
    environment = response.environment
    return {
        "environment": {"id": environment.id, "name": environment.name,
                        "deleted": environment.deleted},
        "policy": ({"name": response.policy.name, "revision": response.policy.revision}
                   if response.HasField("policy") else None),
        "events": [_event(event) for event in response.events],
        "next_cursor": response.next_cursor,
        "left_out": response.left_out,
    }


class Audit:
    """A hosted Sandbox's audit log (``cw audit``)."""

    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(AuditServiceClientSync)

    def list_audit_events(self, *, environment_id: str | None = None,
                          environment_name: str | None = None,
                          kinds: Sequence[AuditEventKind] = (),
                          since: datetime | None = None, until: datetime | None = None,
                          limit: int = 0, cursor: str = "",
                          group_by_subject: bool = False) -> AuditEventPage:
        """One page of an environment's events, newest first by when each
        began. Name the environment by exactly one of ``environment_id`` or
        ``environment_name``; only an ID names a deleted one. ``kinds`` empty
        is every kind; ``since`` None is 7 days ago and ``until`` None now;
        ``limit`` 0 is 100. ``group_by_subject`` answers one event per kind
        and subject for the whole range, with no cursor."""
        if (environment_id is None) == (environment_name is None):
            raise ValueError("name the environment by exactly one of environment_id or environment_name")
        request = pb.ListAuditEventsRequest(
            org_id=self._context.resolve_org_id(), kinds=_kinds(kinds), limit=limit,
            cursor=cursor, group_by_subject=group_by_subject)
        if environment_id is not None:
            request.environment_id = environment_id
        else:
            request.environment_name = environment_name
        if since is not None:
            request.since.FromDatetime(since)
        if until is not None:
            request.until.FromDatetime(until)
        return _page(self._context.unary(self._client.list_audit_events, request))

    def close(self) -> None:
        self._client.close()
