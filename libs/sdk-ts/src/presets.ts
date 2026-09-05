import {
  fromProtoPreset,
  toProtoCreatePresetRequest,
  toProtoUpdatePresetRequest,
} from "./convert.js";
import type { PresetClient } from "./transport.js";
import { mapConnectError } from "./types.js";
import type {
  CreatePresetRequest,
  PresetData,
  UpdatePresetRequest,
} from "./types.js";

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error(
      "orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID",
    );
  }
  return orgId;
}

export class Presets {
  constructor(
    private presets: PresetClient,
    private orgId: string,
  ) {}

  /** Create a new preset. */
  async create(body: CreatePresetRequest): Promise<PresetData> {
    try {
      const orgId = resolveOrgId(this.orgId);
      const response = await this.presets.createPreset(
        toProtoCreatePresetRequest(orgId, body),
      );
      if (!response.preset) throw new Error("preset response omitted preset");
      return fromProtoPreset(response.preset);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List presets. */
  async list(): Promise<PresetData[]> {
    try {
      const presets: PresetData[] = [];
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
  async get(presetId: string): Promise<PresetData> {
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
    body: UpdatePresetRequest,
  ): Promise<PresetData> {
    try {
      const orgId = resolveOrgId(this.orgId);
      const response = await this.presets.updatePreset(
        toProtoUpdatePresetRequest(orgId, presetId, body),
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
}
