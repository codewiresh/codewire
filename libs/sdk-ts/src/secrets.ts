import { fromProtoSecretMetadata } from "./convert.js";
import type { SecretClient } from "./transport.js";
import { mapConnectError } from "./types.js";
import type { SecretMetadata } from "./types.js";

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error(
      "orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID",
    );
  }
  return orgId;
}

export class Secrets {
  constructor(
    private client: SecretClient,
    private orgId: string,
  ) {}

  /** List organization secrets. */
  async list(): Promise<SecretMetadata[]> {
    try {
      const secrets: SecretMetadata[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listSecrets({
          orgId: resolveOrgId(this.orgId),
          pageToken,
        });
        secrets.push(...response.secrets.map(fromProtoSecretMetadata));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return secrets;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Set an organization secret. */
  async set(key: string, value: string): Promise<void> {
    try {
      await this.client.setSecret({
        orgId: resolveOrgId(this.orgId),
        key,
        value,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete an organization secret. */
  async delete(key: string): Promise<void> {
    try {
      await this.client.deleteSecret({ orgId: resolveOrgId(this.orgId), key });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Rename an organization secret key. */
  async rename(oldKey: string, newKey: string): Promise<void> {
    try {
      await this.client.renameSecret({
        orgId: resolveOrgId(this.orgId),
        key: oldKey,
        newKey,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List user-scoped secrets. */
  async listUser(): Promise<SecretMetadata[]> {
    try {
      const secrets: SecretMetadata[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listUserSecrets({ pageToken });
        secrets.push(...response.secrets.map(fromProtoSecretMetadata));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return secrets;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Set a user-scoped secret. */
  async setUser(key: string, value: string): Promise<void> {
    try {
      await this.client.setUserSecret({ key, value });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete a user-scoped secret. */
  async deleteUser(key: string): Promise<void> {
    try {
      await this.client.deleteUserSecret({ key });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Rename a user-scoped secret key. */
  async renameUser(oldKey: string, newKey: string): Promise<void> {
    try {
      await this.client.renameUserSecret({ key: oldKey, newKey });
    } catch (error) {
      throw mapConnectError(error);
    }
  }
}
