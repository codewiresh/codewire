import type { ApiKeyClient } from "./transport.js";
import type {
  APIKeyData,
  CreateAPIKeyRequest,
  CreateAPIKeyResponse,
} from "./types.js";
import {
  fromProtoAPIKey,
  fromProtoCreateAPIKeyResponse,
} from "./convert.js";
import { mapConnectError } from "./types.js";

export class APIKeys {
  constructor(
    private client: ApiKeyClient,
    private orgId: string,
  ) {}

  private resolveOrgId(): string {
    if (!this.orgId) {
      throw new Error(
        "orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID",
      );
    }
    return this.orgId;
  }

  /** Create a new API key. */
  async create(body: CreateAPIKeyRequest): Promise<CreateAPIKeyResponse> {
    try {
      return fromProtoCreateAPIKeyResponse(
        await this.client.createApiKey({
          orgId: this.resolveOrgId(),
          name: body.name ?? "",
          scopes: body.scopes ?? [],
          expiresInDays: body.expires_in_days ?? undefined,
        }),
      );
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List all API keys. */
  async list(): Promise<APIKeyData[]> {
    try {
      const keys: APIKeyData[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listApiKeys({
          orgId: this.resolveOrgId(),
          pageToken,
        });
        keys.push(...response.apiKeys.map(fromProtoAPIKey));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return keys;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Update an API key. */
  async update(
    keyId: string,
    body: { disabled?: boolean },
  ): Promise<APIKeyData> {
    try {
      const response = await this.client.updateApiKey({
        orgId: this.resolveOrgId(),
        keyId,
        disabled: body.disabled,
      });
      if (!response.apiKey) {
        throw new Error("API key response omitted api_key");
      }
      return fromProtoAPIKey(response.apiKey);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete an API key. */
  async delete(keyId: string): Promise<void> {
    try {
      await this.client.deleteApiKey({
        orgId: this.resolveOrgId(),
        keyId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }
}
