"""An organization's network policies (#4000) over the generated Connect service.

The deployment must turn platform network policies on; while it is off, every
method raises the normal CodewireError for UNAVAILABLE.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, TypedDict

from codewire._context import ConnectContext
from codewire.v1 import network_policy_pb2 as pb
from codewire.v1.network_policy_connect import NetworkPolicyServiceClientSync


class NetworkPolicyRule(TypedDict):
    """An exact name, a ``*.`` pattern or a public CIDR, and its TCP ports."""

    target: str
    ports: list[int]


class NetworkPolicy(TypedDict):
    """One immutable revision. A local VM's policy with the same rules has the
    same digest."""

    id: str
    org_id: str
    name: str
    revision: int
    current_revision: int
    rules: list[NetworkPolicyRule]
    digest: str
    created_by: str


# "unknown" is a state this SDK does not know yet; it never fails a read.
EnforcementState = Literal["not_enforced", "enforced", "enforcing", "failed_closed", "unknown"]


class EnvironmentNetworkPolicy(TypedDict):
    """What an environment selects, and what its runtime enforces."""

    reference: str
    name: str
    revision: int
    digest: str
    enforcement: EnforcementState
    enforced_revision: int
    enforced_digest: str
    # RFC 3339, or None while nothing enforces the selection.
    enforced_at: str | None


_ENFORCEMENT: dict[int, EnforcementState] = {
    pb.NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED: "not_enforced",
    pb.NETWORK_POLICY_ENFORCEMENT_ENFORCED: "enforced",
    pb.NETWORK_POLICY_ENFORCEMENT_ENFORCING: "enforcing",
    pb.NETWORK_POLICY_ENFORCEMENT_FAILED_CLOSED: "failed_closed",
}


def _selector(policy: str | dict[str, str]) -> pb.NetworkPolicySelector:
    """A policy by name, or by ``{"id": ...}``."""
    if isinstance(policy, str):
        return pb.NetworkPolicySelector(name=policy)
    return pb.NetworkPolicySelector(id=policy["id"])


def _rules(rules: Sequence[NetworkPolicyRule]) -> list[pb.NetworkPolicyRule]:
    return [pb.NetworkPolicyRule(target=rule["target"], ports=rule["ports"]) for rule in rules]


def _policy(response) -> NetworkPolicy:
    if not response.HasField("policy"):
        raise RuntimeError("network policy response omitted policy")
    value = response.policy
    return {
        "id": value.id,
        "org_id": value.org_id,
        "name": value.name,
        "revision": value.revision,
        "current_revision": value.current_revision,
        "rules": [{"target": rule.target, "ports": list(rule.ports)} for rule in value.rules],
        "digest": value.digest,
        "created_by": value.created_by,
    }


def environment_network_policy(value: pb.EnvironmentNetworkPolicy) -> EnvironmentNetworkPolicy:
    return {
        "reference": value.reference,
        "name": value.name,
        "revision": value.revision,
        "digest": value.digest,
        "enforcement": _ENFORCEMENT.get(value.enforcement, "unknown"),
        "enforced_revision": value.enforced_revision,
        "enforced_digest": value.enforced_digest,
        "enforced_at": value.enforced_at.ToJsonString() if value.HasField("enforced_at") else None,
    }


class NetworkPolicies:
    """Owners and admins create, change and delete; members read and select."""

    def __init__(self, context: ConnectContext):
        self._context = context
        self._client = context.transport.client(NetworkPolicyServiceClientSync)

    def create(self, name: str, allow: Sequence[NetworkPolicyRule],
               *, from_policy: str | dict[str, str] | None = None) -> NetworkPolicy:
        """Revision 1: ``from_policy``'s current rules, or none, plus ``allow``."""
        request = pb.CreateNetworkPolicyRequest(
            org_id=self._context.resolve_org_id(), name=name, allow=_rules(allow))
        if from_policy is not None:
            # `from` is a Python keyword, so the field is reached by name.
            getattr(request, "from").CopyFrom(_selector(from_policy))
        return _policy(self._context.unary(self._client.create_network_policy, request))

    def list(self) -> list[NetworkPolicy]:
        response = self._context.unary(
            self._client.list_network_policies,
            pb.ListNetworkPoliciesRequest(org_id=self._context.resolve_org_id()),
        )
        return [_policy(pb.GetNetworkPolicyResponse(policy=value)) for value in response.policies]

    def get(self, policy: str | dict[str, str], *, revision: int = 0) -> NetworkPolicy:
        """Zero means the current revision."""
        return _policy(self._context.unary(
            self._client.get_network_policy,
            pb.GetNetworkPolicyRequest(org_id=self._context.resolve_org_id(),
                                       policy=_selector(policy), revision=revision),
        ))

    def update(self, policy: str | dict[str, str], *,
               allow: Sequence[NetworkPolicyRule] = (), remove: Sequence[str] = (),
               expected_revision: int = 0) -> NetworkPolicy:
        """A new revision. With ``expected_revision``, a concurrent change is
        refused rather than lost."""
        return _policy(self._context.unary(
            self._client.update_network_policy,
            pb.UpdateNetworkPolicyRequest(
                org_id=self._context.resolve_org_id(), policy=_selector(policy),
                allow=_rules(allow), remove=list(remove), expected_revision=expected_revision),
        ))

    def delete(self, policy: str | dict[str, str]) -> NetworkPolicy:
        """Refused while an environment selects it; returns it as it was."""
        return _policy(self._context.unary(
            self._client.delete_network_policy,
            pb.DeleteNetworkPolicyRequest(org_id=self._context.resolve_org_id(),
                                          policy=_selector(policy)),
        ))

    def select(self, environment_id: str, reference: str) -> EnvironmentNetworkPolicy:
        """``hosted-default`` removes the selection."""
        response = self._context.unary(
            self._client.update_environment_network_policy,
            pb.UpdateEnvironmentNetworkPolicyRequest(
                org_id=self._context.resolve_org_id(), environment_id=environment_id,
                network_policy=reference),
        )
        if not response.HasField("network_policy"):
            raise RuntimeError("network policy response omitted network_policy")
        return environment_network_policy(response.network_policy)

    def close(self) -> None:
        self._client.close()
