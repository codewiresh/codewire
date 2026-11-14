import type {
  EnvironmentNetworkPolicy as ProtoEnvironmentNetworkPolicy,
  NetworkPolicy as ProtoNetworkPolicy,
} from "@codewire/proto-ts/gen/codewire/v1/network_policy_pb";
import { NetworkPolicyEnforcement } from "@codewire/proto-ts/gen/codewire/v1/network_policy_pb";
import type { NetworkPolicyClient } from "./transport.js";
import { mapConnectError } from "./types.js";

/** One allow rule: an exact name, a `*.` pattern or a public CIDR, and its TCP ports. */
export interface NetworkPolicyRule {
  target: string;
  ports: number[];
}

/** One immutable revision of an organization's network policy (#4000). */
export interface NetworkPolicy {
  id: string;
  org_id: string;
  name: string;
  revision: number;
  current_revision: number;
  rules: NetworkPolicyRule[];
  /** Lowercase hex SHA-256; a local VM's policy with the same rules has the same digest. */
  digest: string;
  created_at?: Date;
  created_by: string;
}

/** `unknown` is a state this SDK does not know yet; it never fails a read. */
export type NetworkPolicyEnforcementState = "not_enforced" | "enforced" | "enforcing" | "failed_closed" | "unknown";

/** What an environment selects, and what its runtime enforces. */
export interface EnvironmentNetworkPolicy {
  /** `open`, `locked`, `hosted-default` or `platform:id:UUID`. */
  reference: string;
  name: string;
  /** The stored policy's current revision; 0 for a built-in. */
  revision: number;
  digest: string;
  enforcement: NetworkPolicyEnforcementState;
  enforced_revision: number;
  enforced_digest: string;
  enforced_at?: Date;
}

/** A policy by name, or by `{ id }`. */
export type NetworkPolicySelector = string | { id: string };

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error("orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID");
  }
  return orgId;
}

function selector(value: NetworkPolicySelector) {
  return typeof value === "string"
    ? { selector: { case: "name" as const, value } }
    : { selector: { case: "id" as const, value: value.id } };
}

function fromPolicy(policy: ProtoNetworkPolicy | undefined): NetworkPolicy {
  if (!policy) throw new Error("network policy response omitted policy");
  return {
    id: policy.id,
    org_id: policy.orgId,
    name: policy.name,
    revision: policy.revision,
    current_revision: policy.currentRevision,
    rules: policy.rules.map((rule) => ({ target: rule.target, ports: [...rule.ports] })),
    digest: policy.digest,
    created_at: policy.createdAt ? new Date(Number(policy.createdAt.seconds) * 1000) : undefined,
    created_by: policy.createdBy,
  };
}

const ENFORCEMENT: Record<number, NetworkPolicyEnforcementState> = {
  [NetworkPolicyEnforcement.NOT_ENFORCED]: "not_enforced",
  [NetworkPolicyEnforcement.ENFORCED]: "enforced",
  [NetworkPolicyEnforcement.ENFORCING]: "enforcing",
  [NetworkPolicyEnforcement.FAILED_CLOSED]: "failed_closed",
};

export function fromEnvironmentNetworkPolicy(policy: ProtoEnvironmentNetworkPolicy): EnvironmentNetworkPolicy {
  const enforcement = ENFORCEMENT[policy.enforcement] ?? "unknown";
  return {
    reference: policy.reference,
    name: policy.name,
    revision: policy.revision,
    digest: policy.digest,
    enforcement,
    enforced_revision: policy.enforcedRevision,
    enforced_digest: policy.enforcedDigest,
    enforced_at: policy.enforcedAt ? new Date(Number(policy.enforcedAt.seconds) * 1000) : undefined,
  };
}

/** An organization's network policies (`cw policy --cloud`). The deployment
 * must turn them on; otherwise every method fails as unavailable. */
export class NetworkPolicies {
  constructor(
    private client: NetworkPolicyClient,
    private orgId: string,
  ) {}

  /** A new policy at revision 1: `from`'s current rules, or none, plus `allow`. */
  async create(name: string, allow: NetworkPolicyRule[], from?: NetworkPolicySelector): Promise<NetworkPolicy> {
    try {
      const response = await this.client.createNetworkPolicy({
        orgId: resolveOrgId(this.orgId),
        name,
        from: from === undefined ? undefined : selector(from),
        allow,
      });
      return fromPolicy(response.policy);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** The organization's policies at their current revisions, by name. */
  async list(): Promise<NetworkPolicy[]> {
    try {
      const response = await this.client.listNetworkPolicies({ orgId: resolveOrgId(this.orgId) });
      return response.policies.map(fromPolicy);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** A policy at `revision`, or at its current revision. */
  async get(policy: NetworkPolicySelector, revision = 0): Promise<NetworkPolicy> {
    try {
      const response = await this.client.getNetworkPolicy({
        orgId: resolveOrgId(this.orgId),
        policy: selector(policy),
        revision,
      });
      return fromPolicy(response.policy);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** A new revision: the current rules plus `allow`, minus the rules for
   * `remove`. With `expectedRevision`, a concurrent change is refused. */
  async update(
    policy: NetworkPolicySelector,
    change: { allow?: NetworkPolicyRule[]; remove?: string[]; expectedRevision?: number },
  ): Promise<NetworkPolicy> {
    try {
      const response = await this.client.updateNetworkPolicy({
        orgId: resolveOrgId(this.orgId),
        policy: selector(policy),
        allow: change.allow ?? [],
        remove: change.remove ?? [],
        expectedRevision: change.expectedRevision ?? 0,
      });
      return fromPolicy(response.policy);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Deletes a policy no environment selects; returns it as it was. */
  async delete(policy: NetworkPolicySelector): Promise<NetworkPolicy> {
    try {
      const response = await this.client.deleteNetworkPolicy({
        orgId: resolveOrgId(this.orgId),
        policy: selector(policy),
      });
      return fromPolicy(response.policy);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Selects an environment's policy; `hosted-default` removes the selection. */
  async select(environmentId: string, reference: string): Promise<EnvironmentNetworkPolicy> {
    try {
      const response = await this.client.updateEnvironmentNetworkPolicy({
        orgId: resolveOrgId(this.orgId),
        environmentId,
        networkPolicy: reference,
      });
      if (!response.networkPolicy) throw new Error("network policy response omitted network_policy");
      return fromEnvironmentNetworkPolicy(response.networkPolicy);
    } catch (error) {
      throw mapConnectError(error);
    }
  }
}
