import {
  CredentialAuthenticationKind,
  CredentialStatus,
  type Credential as ProtoCredential,
  type EnrollCodexResponse,
} from "@codewire/proto-ts/gen/codewire/v1/credential_pb";
import type { CredentialClient, CredentialMutationClient } from "./transport.js";
import { mapConnectError } from "./types.js";

/** Personal platform metadata. No provider token or protected-store reference. */
export interface Credential {
  id: string;
  name: string;
  provider: string;
  authentication_kind: "oauth" | "api_key" | "access_token" | "github_app";
  account_hint?: string;
  status: "active" | "revoked" | "expired" | "refresh_failed";
  /** Hard credential-use deadline, not provider access-token expiry. */
  expires_at_unix?: bigint;
  revocation_generation: bigint;
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

function fromCredential(value: ProtoCredential | undefined): Credential {
  if (!value) throw new Error("credential response omitted credential");
  const kinds = {
    [CredentialAuthenticationKind.OAUTH]: "oauth",
    [CredentialAuthenticationKind.API_KEY]: "api_key",
    [CredentialAuthenticationKind.ACCESS_TOKEN]: "access_token",
    [CredentialAuthenticationKind.GITHUB_APP]: "github_app",
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
  return {
    id: value.id, name: value.name, provider: value.provider, authentication_kind,
    account_hint: value.accountHint,
    status,
    expires_at_unix: value.expiresAtUnix,
    revocation_generation: generation(value.revocationGeneration),
  };
}

/** Account-scoped credentials; supply a user OAuth bearer, not an organization
 * API key. Enrollment/lifecycle require OAuth even when metadata permits a
 * session. These methods never choose delivery mode or retry mutations. */
export class Credentials {
  constructor(private client: CredentialClient, private mutations: CredentialMutationClient) {}

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
  async *enrollCodex(name: string, options: { signal?: AbortSignal } = {}): AsyncGenerator<CodexEnrollmentEvent> {
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
      const stream = this.mutations.enrollCodex({ name }, {
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
