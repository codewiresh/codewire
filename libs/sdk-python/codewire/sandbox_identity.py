"""Sandbox identity's records (#4663) over the generated Connect service.

Each Sandbox's identity groups, the organization's registered audiences, and
the switches that stop minting. Changing any of them is for organization
owners and admins. Nothing here issues a token.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, TypedDict

from codewire._context import ConnectContext
from codewire.v1 import sandbox_identity_pb2 as pb
from codewire.v1.sandbox_identity_connect import SandboxIdentityServiceClientSync


class EnvironmentIdentityGroups(TypedDict):
    """A Sandbox's groups, sorted; a token names each as ``<org id>:<group>``."""

    environment_id: str
    groups: list[str]
    # Bumped on every change; 0 for a Sandbox whose groups were never set.
    version: int
    # RFC 3339, or None for a Sandbox whose groups were never set.
    updated_at: str | None


# "unknown" is a reason this SDK does not know yet; it never fails a read.
GroupUserReason = Literal["creator", "owner_grant", "operator_grant", "organization_admin", "unknown"]


class IdentityGroupUser(TypedDict):
    """A member who can run code in a Sandbox, and so use its groups."""

    user_id: str
    email: str
    reason: GroupUserReason


class SetEnvironmentIdentityGroupsResult(TypedDict):
    groups: EnvironmentIdentityGroups
    previous_groups: list[str]
    # False when the new set equals the old one.
    changed: bool
    # Everyone who can run code in the Sandbox; every process in it can use
    # its groups too.
    can_run_code: list[IdentityGroupUser]


class IdentityAudience(TypedDict):
    """A verifier the organization registered, in its canonical form."""

    org_id: str
    audience: str
    # None: every group. Otherwise only these; empty sees none but ``all``.
    visible_groups: list[str] | None
    lifetime_seconds: int
    claim_created_by: bool
    claim_environment_name: bool
    file_name: str | None
    version: int
    created_by: str
    created_at: str | None


_REASONS: dict[int, GroupUserReason] = {
    pb.IDENTITY_GROUP_USER_REASON_CREATOR: "creator",
    pb.IDENTITY_GROUP_USER_REASON_OWNER_GRANT: "owner_grant",
    pb.IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT: "operator_grant",
    pb.IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN: "organization_admin",
}


def _groups(response) -> EnvironmentIdentityGroups:
    if not response.HasField("groups"):
        raise RuntimeError("sandbox identity response omitted groups")
    value = response.groups
    return {
        "environment_id": value.environment_id,
        "groups": list(value.groups),
        "version": value.version,
        "updated_at": value.updated_at.ToJsonString() if value.HasField("updated_at") else None,
    }


def _user(value: pb.IdentityGroupUser) -> IdentityGroupUser:
    return {"user_id": value.user_id, "email": value.email,
            "reason": _REASONS.get(value.reason, "unknown")}


def _audience(value: pb.IdentityAudience) -> IdentityAudience:
    return {
        "org_id": value.org_id,
        "audience": value.audience,
        "visible_groups": list(value.visible_groups.names) if value.HasField("visible_groups") else None,
        "lifetime_seconds": value.lifetime.seconds if value.HasField("lifetime") else 600,
        "claim_created_by": value.claim_created_by,
        "claim_environment_name": value.claim_environment_name,
        "file_name": value.file_name if value.HasField("file_name") else None,
        "version": value.version,
        "created_by": value.created_by,
        "created_at": value.created_at.ToJsonString() if value.HasField("created_at") else None,
    }


class SandboxIdentity:
    """Groups, audiences and the stop switches (``cw identity``)."""

    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(SandboxIdentityServiceClientSync)

    def get_groups(self, environment_id: str) -> EnvironmentIdentityGroups:
        return _groups(self._context.unary(
            self._client.get_environment_identity_groups,
            pb.GetEnvironmentIdentityGroupsRequest(
                org_id=self._context.resolve_org_id(), environment_id=environment_id),
        ))

    def set_groups(self, environment_id: str, groups: Sequence[str]) -> SetEnvironmentIdentityGroupsResult:
        """Replaces a Sandbox's groups; an empty list removes them all."""
        response = self._context.unary(
            self._client.set_environment_identity_groups,
            pb.SetEnvironmentIdentityGroupsRequest(
                org_id=self._context.resolve_org_id(), environment_id=environment_id,
                groups=list(groups)),
        )
        return {
            "groups": _groups(response),
            "previous_groups": list(response.previous_groups),
            "changed": response.changed,
            "can_run_code": [_user(user) for user in response.can_run_code],
        }

    def register_audience(self, audience: str, *, visible_groups: Sequence[str] | None = None,
                          lifetime_seconds: int | None = None, claim_created_by: bool = False,
                          claim_environment_name: bool = False,
                          file_name: str | None = None) -> IdentityAudience:
        """``visible_groups`` None sees every group; ``lifetime_seconds`` None is 600."""
        request = pb.RegisterIdentityAudienceRequest(
            org_id=self._context.resolve_org_id(), audience=audience,
            claim_created_by=claim_created_by, claim_environment_name=claim_environment_name)
        if visible_groups is not None:
            request.visible_groups.names.extend(visible_groups)
            request.visible_groups.SetInParent()
        if lifetime_seconds is not None:
            request.lifetime.seconds = lifetime_seconds
            request.lifetime.SetInParent()
        if file_name is not None:
            request.file_name = file_name
        response = self._context.unary(self._client.register_identity_audience, request)
        if not response.HasField("audience"):
            raise RuntimeError("sandbox identity response omitted audience")
        return _audience(response.audience)

    def list_audiences(self) -> list[IdentityAudience]:
        response = self._context.unary(
            self._client.list_identity_audiences,
            pb.ListIdentityAudiencesRequest(org_id=self._context.resolve_org_id()),
        )
        return [_audience(value) for value in response.audiences]

    def remove_audience(self, audience: str) -> str:
        """Returns the canonical audience removed."""
        return self._context.unary(
            self._client.remove_identity_audience,
            pb.RemoveIdentityAudienceRequest(org_id=self._context.resolve_org_id(), audience=audience),
        ).audience

    def stop_minting(self, environment_id: str | None = None) -> bool:
        """One Sandbox, or the whole organization without one. False when it
        was already stopped."""
        return self._context.unary(
            self._client.stop_identity_minting,
            pb.StopIdentityMintingRequest(org_id=self._context.resolve_org_id(),
                                          environment_id=environment_id or ""),
        ).changed

    def resume_minting(self, environment_id: str | None = None) -> bool:
        """One Sandbox, or the organization without one. False when it was
        not stopped."""
        return self._context.unary(
            self._client.resume_identity_minting,
            pb.ResumeIdentityMintingRequest(org_id=self._context.resolve_org_id(),
                                            environment_id=environment_id or ""),
        ).changed

    def close(self) -> None:
        self._client.close()
