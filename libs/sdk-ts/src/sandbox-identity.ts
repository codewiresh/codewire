import {
  EnvironmentIdentityGroupsSchema,
  IdentityAudienceGroupsSchema,
  IdentityAudienceSchema,
  IdentityGroupUserReason,
  IdentityGroupUserSchema,
  type EnvironmentIdentityGroups as ProtoEnvironmentIdentityGroups,
  type IdentityAudience as ProtoIdentityAudience,
  type IdentityGroupUser as ProtoIdentityGroupUser,
} from "@codewire/proto-ts/gen/codewire/v1/sandbox_identity_pb";
import type { SandboxIdentityClient } from "./transport.js";
import { mapConnectError } from "./types.js";

/** A Sandbox's identity groups, sorted; a token names each as `<org id>:<group>`. */
export interface EnvironmentIdentityGroups {
  environment_id: string;
  groups: string[];
  /** Bumped on every change; 0 for a Sandbox whose groups were never set. */
  version: number;
  updated_at?: Date;
}

/** `unknown` is a reason this SDK does not know yet; it never fails a read. */
export type IdentityGroupUserReasonName = "creator" | "owner_grant" | "operator_grant" | "organization_admin" | "unknown";

/** A member who can run code in a Sandbox, and so use its groups. */
export interface IdentityGroupUser {
  user_id: string;
  email: string;
  reason: IdentityGroupUserReasonName;
}

export interface SetEnvironmentIdentityGroupsResult {
  groups: EnvironmentIdentityGroups;
  previous_groups: string[];
  /** False when the new set equals the old one. */
  changed: boolean;
  /** Everyone who can run code in the Sandbox; every process in it can use its groups too. */
  can_run_code: IdentityGroupUser[];
}

/** A verifier the organization registered. */
export interface IdentityAudience {
  org_id: string;
  /** The canonical form. */
  audience: string;
  /** Absent: every group. Otherwise only these, and an empty list sees none but `all`. */
  visible_groups?: string[];
  lifetime_seconds: number;
  claim_created_by: boolean;
  claim_environment_name: boolean;
  file_name?: string;
  version: number;
  created_by: string;
  created_at?: Date;
}

export interface RegisterIdentityAudienceOptions {
  /** Only these of a Sandbox's groups; absent is every group. */
  visibleGroups?: string[];
  /** 60 to 600; absent is 600. */
  lifetimeSeconds?: number;
  claimCreatedBy?: boolean;
  claimEnvironmentName?: boolean;
  fileName?: string;
}

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error("organizationId is required — pass organizationId in ClientOptions or set CODEWIRE_ORGANIZATION_ID");
  }
  return orgId;
}

function date(timestamp: { seconds: bigint; nanos: number } | undefined): Date | undefined {
  return timestamp ? new Date(Number(timestamp.seconds) * 1000 + Math.floor(timestamp.nanos / 1_000_000)) : undefined;
}

export function fromIdentityGroups(groups: ProtoEnvironmentIdentityGroups | undefined): EnvironmentIdentityGroups {
  if (!groups) throw new Error("sandbox identity response omitted groups");
  return {
    environment_id: groups.environmentId,
    groups: [...groups.groups],
    version: Number(groups.version),
    updated_at: date(groups.updatedAt),
  };
}

const REASONS: Record<number, IdentityGroupUserReasonName> = {
  [IdentityGroupUserReason.CREATOR]: "creator",
  [IdentityGroupUserReason.OWNER_GRANT]: "owner_grant",
  [IdentityGroupUserReason.OPERATOR_GRANT]: "operator_grant",
  [IdentityGroupUserReason.ORGANIZATION_ADMIN]: "organization_admin",
};

export function fromIdentityGroupUser(user: ProtoIdentityGroupUser): IdentityGroupUser {
  return { user_id: user.userId, email: user.email, reason: REASONS[user.reason] ?? "unknown" };
}

export function fromIdentityAudience(audience: ProtoIdentityAudience | undefined): IdentityAudience {
  if (!audience) throw new Error("sandbox identity response omitted audience");
  return {
    org_id: audience.orgId,
    audience: audience.audience,
    visible_groups: audience.visibleGroups ? [...audience.visibleGroups.names] : undefined,
    lifetime_seconds: audience.lifetime ? Number(audience.lifetime.seconds) : 600,
    claim_created_by: audience.claimCreatedBy,
    claim_environment_name: audience.claimEnvironmentName,
    file_name: audience.fileName,
    version: Number(audience.version),
    created_by: audience.createdBy,
    created_at: date(audience.createdAt),
  };
}

function assertDescriptorCoverage(
  name: string,
  fields: ReadonlyArray<{ number: number; name: string }>,
  expected: string[],
): void {
  if (fields.length !== expected.length || fields.some((field, index) => field.name !== expected[index])) {
    throw new Error(`codewire: sandbox identity ${name} converter does not cover every descriptor field`);
  }
}

/** Throws when a future sandbox identity proto field lacks an SDK mapping. */
export function assertSandboxIdentityConverterCoverage(): void {
  assertDescriptorCoverage("groups", EnvironmentIdentityGroupsSchema.fields, [
    "environment_id", "groups", "version", "updated_at",
  ]);
  assertDescriptorCoverage("group user", IdentityGroupUserSchema.fields, ["user_id", "email", "reason"]);
  assertDescriptorCoverage("audience groups", IdentityAudienceGroupsSchema.fields, ["names"]);
  assertDescriptorCoverage("audience", IdentityAudienceSchema.fields, [
    "org_id", "audience", "visible_groups", "lifetime", "claim_created_by", "claim_environment_name",
    "file_name", "version", "created_by", "created_at",
  ]);
}

/** Sandbox identity's records (`cw identity`): each Sandbox's groups, the
 * organization's registered audiences, and the switches that stop minting.
 * Changing any of them is for organization owners and admins. */
export class SandboxIdentity {
  constructor(
    private client: SandboxIdentityClient,
    private orgId: string,
  ) {}

  async getGroups(environmentId: string): Promise<EnvironmentIdentityGroups> {
    try {
      const response = await this.client.getEnvironmentIdentityGroups({
        orgId: resolveOrgId(this.orgId),
        environmentId,
      });
      return fromIdentityGroups(response.groups);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Replaces a Sandbox's groups; an empty list removes them all. */
  async setGroups(environmentId: string, groups: string[]): Promise<SetEnvironmentIdentityGroupsResult> {
    try {
      const response = await this.client.setEnvironmentIdentityGroups({
        orgId: resolveOrgId(this.orgId),
        environmentId,
        groups,
      });
      return {
        groups: fromIdentityGroups(response.groups),
        previous_groups: [...response.previousGroups],
        changed: response.changed,
        can_run_code: response.canRunCode.map(fromIdentityGroupUser),
      };
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  async registerAudience(audience: string, options: RegisterIdentityAudienceOptions = {}): Promise<IdentityAudience> {
    try {
      const response = await this.client.registerIdentityAudience({
        orgId: resolveOrgId(this.orgId),
        audience,
        visibleGroups: options.visibleGroups === undefined ? undefined : { names: options.visibleGroups },
        lifetime: options.lifetimeSeconds === undefined
          ? undefined
          : { seconds: BigInt(options.lifetimeSeconds), nanos: 0 },
        claimCreatedBy: options.claimCreatedBy ?? false,
        claimEnvironmentName: options.claimEnvironmentName ?? false,
        fileName: options.fileName,
      });
      return fromIdentityAudience(response.audience);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  async listAudiences(): Promise<IdentityAudience[]> {
    try {
      const response = await this.client.listIdentityAudiences({ orgId: resolveOrgId(this.orgId) });
      return response.audiences.map(fromIdentityAudience);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Removes a registration; returns the canonical audience removed. */
  async removeAudience(audience: string): Promise<string> {
    try {
      const response = await this.client.removeIdentityAudience({ orgId: resolveOrgId(this.orgId), audience });
      return response.audience;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Stops minting for one Sandbox, or the whole organization without one.
   * Returns false when it was already stopped. */
  async stopMinting(environmentId?: string): Promise<boolean> {
    try {
      const response = await this.client.stopIdentityMinting({
        orgId: resolveOrgId(this.orgId),
        environmentId: environmentId ?? "",
      });
      return response.changed;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Resumes minting for one Sandbox, or the organization without one.
   * Returns false when it was not stopped. */
  async resumeMinting(environmentId?: string): Promise<boolean> {
    try {
      const response = await this.client.resumeIdentityMinting({
        orgId: resolveOrgId(this.orgId),
        environmentId: environmentId ?? "",
      });
      return response.changed;
    } catch (error) {
      throw mapConnectError(error);
    }
  }
}
