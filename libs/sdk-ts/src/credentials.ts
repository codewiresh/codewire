import {
  CredentialSchema,
  CredentialAuthenticationKind,
  CredentialStatus,
  EnrollCodexRequestSchema,
  SshPublicKeySchema,
  GithubRepositorySchema,
  ListGithubRepositoriesRequestSchema,
  ListGithubRepositoriesResponseSchema,
  type Credential as ProtoCredential,
  type EnrollCodexResponse,
} from "@codewire/proto-ts/gen/codewire/v1/credential_pb";
import type { CredentialClient, CredentialMutationClient, GithubRepositoryClient } from "./transport.js";
import { mapConnectError } from "./types.js";

/** Personal platform metadata. No provider token or protected-store reference. */
export interface Credential {
  id: string;
  name: string;
  provider: string;
  authentication_kind:
    | "oauth"
    | "api_key"
    | "access_token"
    | "github_app"
    | "ssh_key";
  account_hint?: string;
  status: "active" | "revoked" | "expired" | "refresh_failed";
  /** Hard credential-use deadline, not provider access-token expiry. */
  expires_at_unix?: bigint;
  revocation_generation: bigint;
  /** Public registration data for an SSH identity; never private key bytes. */
  ssh_public_key?: SshPublicKey;
}

export interface SshPublicKey {
  openssh: string;
  fingerprint: string;
}

/** Allowlisted repository metadata, never provider JSON or a checkout grant. */
export interface GithubRepository {
  repository_id: string;
  full_name: string;
  default_branch: string;
  clone_url: string;
  is_private: boolean;
  archived: boolean;
  disabled: boolean;
}

export interface GithubRepositoryPage {
  repositories: GithubRepository[];
  next_page_token: string;
}

export interface CodexEnrollmentOptions {
  signal?: AbortSignal;
  /** Reconnect one exact existing identity; supply both fields or neither. */
  credential_id?: string;
  expected_revocation_generation?: bigint;
}

/** The one-time code is for the requesting user, never routine logs. */
export interface CodexDeviceChallenge {
  verification_url: string;
  user_code: string;
  expires_at_unix: bigint;
}

export type CodexEnrollmentEvent =
  | { type: "challenge"; challenge: CodexDeviceChallenge }
  | { type: "credential"; credential: Credential };

/** Missing acknowledgement does not prove that the credential was not stored. */
export class EnrollmentOutcomeUnknownError extends Error {
  constructor() {
    super("Codex enrollment acknowledgement is unknown; reconcile the credential by name before retrying");
    this.name = "EnrollmentOutcomeUnknownError";
  }
}

// Leave bounded room for request admission/cleanup around the server's original
// 15-minute enrollment. This changes no ordinary RPC or transport default.
const ENROLLMENT_TIMEOUT_MS = 16 * 60 * 1000;

function generation(value: bigint): bigint {
  if (typeof value !== "bigint" || value <= 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error("credential revision must be a positive uint64 bigint");
  }
  return value;
}

function assertFields(
  name: string,
  fields: readonly { number: number; name: string }[],
  expected: ReadonlyMap<number, string>,
): void {
  if (fields.length !== expected.size) {
    throw new Error(`${name} converter covers ${expected.size} descriptor fields, expected ${fields.length}`);
  }
  for (const field of fields) {
    if (expected.get(field.number) !== field.name) {
      throw new Error(`${name} converter does not cover descriptor field ${field.name}`);
    }
  }
}

/** Throws when credential metadata or Codex reconnect gains an unmapped field. */
export function assertCredentialConverterCoverage(): void {
  assertFields("GitHub repository", GithubRepositorySchema.fields, new Map([
    [1, "repository_id"], [2, "full_name"], [3, "default_branch"], [4, "clone_url"],
    [5, "is_private"], [6, "archived"], [7, "disabled"],
  ]));
  assertFields("GitHub repository request", ListGithubRepositoriesRequestSchema.fields, new Map([
    [1, "profile_id"], [2, "profile_revision"], [3, "page_size"], [4, "page_token"],
  ]));
  assertFields("GitHub repository response", ListGithubRepositoriesResponseSchema.fields, new Map([
    [1, "repositories"], [2, "next_page_token"],
  ]));
  assertFields("credential", CredentialSchema.fields, new Map([
    [1, "id"], [2, "name"], [3, "provider"], [4, "authentication_kind"],
    [5, "account_hint"], [6, "status"], [7, "expires_at_unix"],
    [8, "revocation_generation"], [9, "ssh_public_key"],
  ]));
  assertFields("SSH public key", SshPublicKeySchema.fields, new Map([
    [1, "openssh"], [2, "fingerprint"],
  ]));
  assertFields("Codex enrollment", EnrollCodexRequestSchema.fields, new Map([
    [1, "name"], [2, "credential_id"], [3, "expected_revocation_generation"],
  ]));
}

function fromCredential(value: ProtoCredential | undefined): Credential {
  if (!value) throw new Error("credential response omitted credential");
  const kinds = {
    [CredentialAuthenticationKind.OAUTH]: "oauth",
    [CredentialAuthenticationKind.API_KEY]: "api_key",
    [CredentialAuthenticationKind.ACCESS_TOKEN]: "access_token",
    [CredentialAuthenticationKind.GITHUB_APP]: "github_app",
    [CredentialAuthenticationKind.SSH_KEY]: "ssh_key",
  } as const;
  const authentication_kind = kinds[value.authenticationKind as keyof typeof kinds];
  const statuses = {
    [CredentialStatus.ACTIVE]: "active", [CredentialStatus.REVOKED]: "revoked",
    [CredentialStatus.EXPIRED]: "expired", [CredentialStatus.REFRESH_FAILED]: "refresh_failed",
  } as const;
  const status = statuses[value.status as keyof typeof statuses];
  if (!authentication_kind || !status) {
    throw new Error("credential response contains unsupported metadata");
  }
  if (
    (authentication_kind === "ssh_key") !== (value.sshPublicKey !== undefined)
  ) {
    throw new Error(
      "credential response must contain SSH public metadata exactly for SSH credentials",
    );
  }
  return {
    id: value.id, name: value.name, provider: value.provider, authentication_kind,
    account_hint: value.accountHint,
    status,
    expires_at_unix: value.expiresAtUnix,
    revocation_generation: generation(value.revocationGeneration),
    ssh_public_key: value.sshPublicKey
      ? {
          openssh: value.sshPublicKey.openssh,
          fingerprint: value.sshPublicKey.fingerprint,
        }
      : undefined,
  };
}

/** Account-scoped credentials; supply a user OAuth bearer, not an organization
 * API key. Enrollment/lifecycle require OAuth even when metadata permits a
 * session. These methods never choose delivery mode or retry mutations. */
export class Credentials {
  constructor(private client: CredentialClient, private mutations: CredentialMutationClient,
    private repositories?: GithubRepositoryClient) {}

  /** Fetch one page without silently advancing the selected profile revision. */
  async listGithubRepositories(
    profileId: string, profileRevision: bigint, pageSize = 50, pageToken = "",
  ): Promise<GithubRepositoryPage> {
    generation(profileRevision);
    if (!profileId || !Number.isInteger(pageSize) || pageSize < 0 || pageSize > 100 || pageToken.length > 128) {
      throw new Error("invalid GitHub repository selection or page");
    }
    if (!this.repositories) throw new Error("GitHub repository client is not configured");
    try {
      const response = await this.repositories.listGithubRepositories({ profileId, profileRevision, pageSize, pageToken });
      return {
        repositories: response.repositories.map((value) => ({
          repository_id: value.repositoryId, full_name: value.fullName, default_branch: value.defaultBranch,
          clone_url: value.cloneUrl, is_private: value.isPrivate, archived: value.archived, disabled: value.disabled,
        })),
        next_page_token: response.nextPageToken,
      };
    } catch (error) { throw mapConnectError(error); }
  }

  async list(): Promise<Credential[]> {
    try {
      const result: Credential[] = [];
      const seen = new Set<string>();
      let pageToken = "";
      do {
        if (seen.has(pageToken)) throw new Error("credential pagination repeated a cursor");
        seen.add(pageToken);
        const response = await this.client.listCredentials({ pageToken });
        result.push(...response.credentials.map(fromCredential));
        pageToken = response.nextPageToken;
      } while (pageToken);
      return result;
    } catch (error) { throw mapConnectError(error); }
  }

  async get(id: string): Promise<Credential> {
    try {
      return fromCredential((await this.client.getCredential({ selector: { case: "credentialId", value: id } })).credential);
    } catch (error) { throw mapConnectError(error); }
  }

  async getByName(name: string): Promise<Credential> {
    try {
      return fromCredential((await this.client.getCredential({ selector: { case: "name", value: name } })).credential);
    } catch (error) { throw mapConnectError(error); }
  }

  /** Consume the challenge immediately, then committed metadata. Breaking the
   * loop closes the original stream. Use signal to cancel a pending read.
   * Cancellation never proves rollback: reconcile by name before retrying. */
  async *enrollCodex(
    name: string,
    options: CodexEnrollmentOptions = {},
  ): AsyncGenerator<CodexEnrollmentEvent> {
    const credentialId = options.credential_id;
    const expectedGeneration = options.expected_revocation_generation;
    if ((credentialId === undefined) !== (expectedGeneration === undefined)) {
      throw new Error(
        "Codex reconnect requires credential_id and expected_revocation_generation together",
      );
    }
    if (credentialId !== undefined && credentialId.length === 0) {
      throw new Error("Codex reconnect credential_id must not be empty");
    }
    const reconnectGeneration = expectedGeneration === undefined
      ? undefined
      : generation(expectedGeneration);
    const cancellation = new AbortController();
    let challenged = false;
    let iterator: AsyncIterator<EnrollCodexResponse> | undefined;
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => {
      closing ??= (async () => {
        cancellation.abort();
        try {
          // Connect 2.1.2 deliberately omits return()/throw() on this iterable.
          // Its deadline cleanup runs only after next() observes EOF/rejection.
          // Drain the same iterator after abort, including when the consumer
          // is paused at a yield. Concurrent exit paths share this one promise.
          if (iterator) while (!(await iterator.next()).done) { /* discard remaining metadata */ }
        } catch { /* expected cancellation completes transport cleanup */ }
      })();
      return closing;
    };
    const cancel = () => { void close(); };
    options.signal?.addEventListener("abort", cancel, { once: true });
    if (options.signal?.aborted) cancel();
    try {
      if (cancellation.signal.aborted) throw new EnrollmentOutcomeUnknownError();
      const stream = this.mutations.enrollCodex({
        name,
        credentialId,
        expectedRevocationGeneration: reconnectGeneration,
      }, {
        signal: cancellation.signal, timeoutMs: ENROLLMENT_TIMEOUT_MS,
      });
      iterator = stream[Symbol.asyncIterator]();
      for (;;) {
        const next = await iterator.next();
        if (cancellation.signal.aborted) throw new EnrollmentOutcomeUnknownError();
        if (next.done) break;
        const response = next.value;
        if (response.event.case === "challenge" && !challenged) {
          const value = response.event.value;
          if (!value.verificationUrl || !value.userCode || value.expiresAtUnix === 0n) {
            throw new EnrollmentOutcomeUnknownError();
          }
          challenged = true;
          yield { type: "challenge", challenge: {
            verification_url: value.verificationUrl, user_code: value.userCode,
            expires_at_unix: value.expiresAtUnix,
          } };
        } else if (response.event.case === "credential" && challenged) {
          const credential = fromCredential(response.event.value);
          // Finish transport ownership before exposing the terminal event;
          // callers need not ask for another item to release its deadline.
          await close();
          yield { type: "credential", credential };
          return;
        } else {
          throw new EnrollmentOutcomeUnknownError();
        }
      }
      throw new EnrollmentOutcomeUnknownError();
    } catch {
      // Neither a transport exception nor a malformed/missing acknowledgement
      // authorizes logout or blind retry. Do not retain response/credential data.
      throw new EnrollmentOutcomeUnknownError();
    } finally {
      await close();
      options.signal?.removeEventListener("abort", cancel);
    }
  }

  async revoke(id: string, expectedGeneration: bigint): Promise<Credential> {
    try {
      return fromCredential((await this.mutations.revokeCredential({
        credentialId: id, expectedRevocationGeneration: generation(expectedGeneration),
      })).credential);
    } catch (error) { throw mapConnectError(error); }
  }

  /** Forget one already-revoked, unreferenced record; not provider logout. */
  async delete(id: string, expectedGeneration: bigint): Promise<void> {
    try {
      await this.mutations.deleteCredential({ credentialId: id, expectedRevocationGeneration: generation(expectedGeneration) });
    } catch (error) { throw mapConnectError(error); }
  }
}
