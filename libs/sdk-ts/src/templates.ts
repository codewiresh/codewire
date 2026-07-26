import {
  fromProtoPreset,
  toProtoCreatePresetRequest,
  toProtoUpdatePresetRequest,
} from "./convert.js";
import type { PresetClient, SecretClient } from "./transport.js";
import { mapConnectError } from "./types.js";
import type {
  CreateTemplateRequest,
  TemplateData,
  UpdateTemplateRequest,
} from "./types.js";

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error(
      "orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID",
    );
  }
  return orgId;
}

export class Templates {
  constructor(
    private presets: PresetClient,
    private secrets: SecretClient,
    private orgId: string,
  ) {}

  /** Create a new preset. */
  async create(body: CreateTemplateRequest): Promise<TemplateData> {
    try {
      const orgId = resolveOrgId(this.orgId);
      const response = await this.presets.createPreset(
        toProtoCreatePresetRequest(
          orgId,
          body,
          await this.resolveSecretProjectId(body.secret_project, false),
        ),
      );
      if (!response.preset) throw new Error("preset response omitted preset");
      return fromProtoPreset(response.preset);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List presets. */
  async list(): Promise<TemplateData[]> {
    try {
      const presets: TemplateData[] = [];
      let pageToken = "";
      do {
        const response = await this.presets.listPresets({
          orgId: resolveOrgId(this.orgId),
          pageToken,
        });
        presets.push(...response.presets.map(fromProtoPreset));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return presets;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Get a preset by ID. */
  async get(presetId: string): Promise<TemplateData> {
    try {
      const response = await this.presets.getPreset({
        orgId: resolveOrgId(this.orgId),
        presetId,
      });
      if (!response.preset) throw new Error("preset response omitted preset");
      return fromProtoPreset(response.preset);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Update a preset. */
  async update(
    presetId: string,
    body: UpdateTemplateRequest,
  ): Promise<TemplateData> {
    try {
      const orgId = resolveOrgId(this.orgId);
      const response = await this.presets.updatePreset(
        toProtoUpdatePresetRequest(
          orgId,
          presetId,
          body,
          await this.resolveSecretProjectId(body.secret_project, true),
        ),
      );
      if (!response.preset) throw new Error("preset response omitted preset");
      return fromProtoPreset(response.preset);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete a preset. */
  async delete(presetId: string): Promise<void> {
    try {
      await this.presets.deletePreset({
        orgId: resolveOrgId(this.orgId),
        presetId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  private async resolveSecretProjectId(
    selection: string | null | undefined,
    update: boolean,
  ): Promise<string | undefined> {
    if (selection === undefined) return undefined;
    if (selection === null || selection === "") return update ? "" : undefined;

    const orgId = resolveOrgId(this.orgId);
    let pageToken = "";
    do {
      const response = await this.secrets.listSecretProjects({ orgId, pageToken });
      const project = response.secretProjects.find(
        (candidate) => candidate.id === selection || candidate.name === selection,
      );
      if (project) return project.id;
      pageToken = response.nextPageToken;
    } while (pageToken !== "");
    throw new Error(`codewire: secret project not found: ${selection}`);
  }
}
