import { fromProtoFileEntry } from "./convert.js";
import type { FileClient } from "./transport.js";
import { mapConnectError } from "./types.js";
import type { FileEntry } from "./types.js";

const uploadChunkSize = 32 * 1024;

export class Files {
  constructor(
    private client: FileClient,
    private uploadClient: FileClient,
    private orgId: string,
    private environmentId: string,
  ) {}

  /** List files in the environment at the given path. */
  async list(dirPath?: string): Promise<FileEntry[]> {
    try {
      const entries: FileEntry[] = [];
      let pageToken = "";
      do {
        const response = await this.client.listFiles({
          orgId: this.orgId,
          environmentId: this.environmentId,
          path: dirPath ?? "",
          pageToken,
        });
        entries.push(...response.entries.map(fromProtoFileEntry));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return entries;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Upload a file through FileService's typed client stream. */
  async upload(src: Uint8Array, remotePath: string): Promise<void> {
    try {
      await this.uploadClient.uploadFile(this.uploadRequests(src, remotePath));
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Download a file through FileService's typed server stream. */
  async download(remotePath: string): Promise<ArrayBuffer> {
    try {
      const chunks: Uint8Array[] = [];
      let length = 0;
      for await (const response of this.client.downloadFile({
        orgId: this.orgId,
        environmentId: this.environmentId,
        path: remotePath,
      })) {
        if (response.payload.case === "chunk") {
          chunks.push(response.payload.value);
          length += response.payload.value.byteLength;
        }
      }
      const data = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        data.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return data.buffer;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  private async *uploadRequests(src: Uint8Array, remotePath: string) {
    yield {
      payload: {
        case: "header" as const,
        value: {
          orgId: this.orgId,
          environmentId: this.environmentId,
          path: remotePath,
        },
      },
    };
    for (let offset = 0; offset < src.byteLength; offset += uploadChunkSize) {
      yield {
        payload: {
          case: "chunk" as const,
          value: src.slice(offset, offset + uploadChunkSize),
        },
      };
    }
  }
}
