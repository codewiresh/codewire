import type {
  AccessProfile as ProtoAccessProfile,
  EnvironmentAccessProfileBinding as ProtoBinding,
} from "@codewire/proto-ts/gen/codewire/v1/access_profile_pb";
import type { AccessProfileClient } from "./transport.js";
import { mapConnectError } from "./types.js";

/** Metadata-only reference. Duplicate capability slots are invalid. */
export interface AccessProfileEntry {
  capability_slot: string;
  credential_id: string;
}

/** One immutable personal profile revision; no protected material. Every
 * profile includes the account's one GitHub connection; GitHub is never an entry. */
export interface AccessProfile {
  id: string;
  name: string;
  /** Lossless uint64; never convert this CAS coordinate to number. */
  revision: bigint;
  entries: AccessProfileEntry[];
}

/** Exact selection, not an access grant or proof of runtime readiness. */
export interface EnvironmentAccessProfileBinding {
  environment_id: string;
  access_profile_id: string;
  access_profile_revision: bigint;
}

export interface EnvironmentAccessProfile {
  binding?: EnvironmentAccessProfileBinding;
  personal_credentials_confirmed: boolean;
}

function revision(value: bigint): bigint {
  if (typeof value !== "bigint" || value <= 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error("access profile revision must be a positive uint64 bigint");
  }
  return value;
}

function toEntries(entries: readonly AccessProfileEntry[]) {
  const slots = new Set<string>();
  return entries.map((entry) => {
    if (entry.capability_slot === "github") {
      throw new Error("every profile includes the account's GitHub connection; it is never an entry");
    }
    if (slots.has(entry.capability_slot)) {
      throw new Error("duplicate access profile capability slot");
    }
    slots.add(entry.capability_slot);
    return { capabilitySlot: entry.capability_slot, credentialId: entry.credential_id };
  });
}

function fromProfile(profile: ProtoAccessProfile | undefined): AccessProfile {
  if (!profile) throw new Error("access profile response omitted access_profile");
  return {
    id: profile.id,
    name: profile.name,
    revision: revision(profile.revision),
    entries: profile.entries.map((entry) => ({
      capability_slot: entry.capabilitySlot,
      credential_id: entry.credentialId,
    })),
  };
}

function fromBinding(binding: ProtoBinding): EnvironmentAccessProfileBinding {
  return {
    environment_id: binding.environmentId,
    access_profile_id: binding.accessProfileId,
    access_profile_revision: revision(binding.accessProfileRevision),
  };
}

/** Authenticated-user personal profiles. Organization API keys cannot manage
 * this account resource; supply the existing user OAuth bearer to Codewire.
 * All methods are material-free and never refresh a stale CAS automatically. */
export class AccessProfiles {
  constructor(private client: AccessProfileClient) {}

  /** Consume every page using the server's default page size. */
  async list(): Promise<AccessProfile[]> {
    try {
      const profiles: AccessProfile[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listAccessProfiles({ pageToken });
        profiles.push(...response.accessProfiles.map(fromProfile));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return profiles;
    } catch (error) { throw mapConnectError(error); }
  }

  /** Omitted revision selects current; a supplied revision is exact. */
  async get(id: string, exactRevision?: bigint): Promise<AccessProfile> {
    try {
      const response = await this.client.getAccessProfile({
        selector: { case: "accessProfileId", value: id },
        revision: exactRevision === undefined ? undefined : revision(exactRevision),
      });
      return fromProfile(response.accessProfile);
    } catch (error) { throw mapConnectError(error); }
  }

  async getByName(name: string, exactRevision?: bigint): Promise<AccessProfile> {
    try {
      const response = await this.client.getAccessProfile({
        selector: { case: "name", value: name },
        revision: exactRevision === undefined ? undefined : revision(exactRevision),
      });
      return fromProfile(response.accessProfile);
    } catch (error) { throw mapConnectError(error); }
  }

  async create(name: string, entries: readonly AccessProfileEntry[]): Promise<AccessProfile> {
    try {
      const response = await this.client.createAccessProfile({ name, entries: toEntries(entries) });
      return fromProfile(response.accessProfile);
    } catch (error) { throw mapConnectError(error); }
  }

  /** Replace the entire entry set, including an explicitly empty set. */
  async update(id: string, expectedRevision: bigint, entries: readonly AccessProfileEntry[]): Promise<AccessProfile> {
    try {
      const response = await this.client.updateAccessProfile({
        accessProfileId: id, expectedRevision: revision(expectedRevision), entries: toEntries(entries),
      });
      return fromProfile(response.accessProfile);
    } catch (error) { throw mapConnectError(error); }
  }

  /** Relabel at the observed current revision and name; a stale view is
   * rejected. No revision is published, the entries are unchanged and Sandbox
   * bindings stay pinned. */
  async rename(id: string, expectedRevision: bigint, expectedName: string, name: string): Promise<AccessProfile> {
    try {
      const response = await this.client.renameAccessProfile({
        accessProfileId: id, expectedRevision: revision(expectedRevision), expectedName, name,
      });
      return fromProfile(response.accessProfile);
    } catch (error) { throw mapConnectError(error); }
  }

  async delete(id: string, expectedRevision: bigint): Promise<void> {
    try {
      await this.client.deleteAccessProfile({ accessProfileId: id, expectedRevision: revision(expectedRevision) });
    } catch (error) { throw mapConnectError(error); }
  }

  async getEnvironmentBinding(environmentId: string): Promise<EnvironmentAccessProfile> {
    try {
      const response = await this.client.getEnvironmentAccessProfile({ environmentId });
      return {
        binding: response.binding ? fromBinding(response.binding) : undefined,
        personal_credentials_confirmed: response.personalCredentialsConfirmed,
      };
    } catch (error) { throw mapConnectError(error); }
  }

}
