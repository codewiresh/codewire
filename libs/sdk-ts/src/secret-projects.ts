import {
  fromProtoSecretMetadata,
  fromProtoSecretProject,
} from "./convert.js";
import type { SecretClient } from "./transport.js";
import { mapConnectError } from "./types.js";
import type {
  CreateSecretProjectRequest,
  SecretMetadata,
  SecretProject,
  SetProjectSecretRequest,
} from "./types.js";

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error(
      "orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID",
    );
  }
  return orgId;
}

export class SecretProjects {
  constructor(
    private client: SecretClient,
    private orgId: string,
  ) {}

  /** Create a new secret project. */
  async create(body: CreateSecretProjectRequest): Promise<SecretProject> {
    try {
      const response = await this.client.createSecretProject({
        orgId: resolveOrgId(this.orgId),
        name: body.name,
      });
      if (!response.secretProject) {
        throw new Error("secret project response omitted secret_project");
      }
      return fromProtoSecretProject(response.secretProject);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List all secret projects. */
  async list(): Promise<SecretProject[]> {
    try {
      const projects: SecretProject[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listSecretProjects({
          orgId: resolveOrgId(this.orgId),
          pageToken,
        });
        projects.push(...response.secretProjects.map(fromProtoSecretProject));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return projects;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete a secret project. */
  async delete(projectId: string): Promise<void> {
    try {
      await this.client.deleteSecretProject({
        orgId: resolveOrgId(this.orgId),
        secretProjectId: projectId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List secrets in a project. */
  async listSecrets(projectId: string): Promise<SecretMetadata[]> {
    try {
      const secrets: SecretMetadata[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listProjectSecrets({
          orgId: resolveOrgId(this.orgId),
          secretProjectId: projectId,
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

  /** Set a secret in a project. */
  async setSecret(
    projectId: string,
    body: SetProjectSecretRequest,
  ): Promise<void> {
    try {
      await this.client.setProjectSecret({
        orgId: resolveOrgId(this.orgId),
        secretProjectId: projectId,
        key: body.key,
        value: body.value,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete a secret from a project. */
  async deleteSecret(projectId: string, key: string): Promise<void> {
    try {
      await this.client.deleteProjectSecret({
        orgId: resolveOrgId(this.orgId),
        secretProjectId: projectId,
        key,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Rename a secret key in a project. */
  async renameSecret(
    projectId: string,
    oldKey: string,
    newKey: string,
  ): Promise<void> {
    try {
      await this.client.renameProjectSecret({
        orgId: resolveOrgId(this.orgId),
        secretProjectId: projectId,
        key: oldKey,
        newKey,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }
}
