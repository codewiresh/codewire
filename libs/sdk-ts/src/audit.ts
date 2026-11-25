import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  AuditAccessSchema,
  AuditActorSchema,
  AuditApiKeySchema,
  AuditCredentialsSchema,
  AuditCredentials_Action,
  AuditEnvironmentSchema,
  AuditEventKind,
  AuditEventSchema,
  AuditLifecycleSchema,
  AuditLifecycle_Action,
  AuditPlatformReason,
  AuditPlatformSchema,
  AuditPolicyChangeSchema,
  AuditPolicyChange_Action,
  AuditPolicyRevisionSchema,
  AuditProtocol,
  AuditRefusalOverflowSchema,
  AuditRefusalSchema,
  AuditRole,
  AuditSandboxSchema,
  AuditSizeSchema,
  AuditSurface,
  AuditUserSchema,
  ListAuditEventsResponseSchema,
  file_codewire_v1_audit,
  type AuditActor as ProtoAuditActor,
  type AuditEvent as ProtoAuditEvent,
  type AuditSize as ProtoAuditSize,
  type ListAuditEventsRequest as ProtoListAuditEventsRequest,
  type ListAuditEventsResponse as ProtoListAuditEventsResponse,
} from "@codewire/proto-ts/gen/codewire/v1/audit_pb";
import type { AuditClient } from "./transport.js";
import { mapConnectError } from "./types.js";

// Every enum in an audit event is its proto value name without the enum's
// prefix, in lower case: "access", "ssh", "out_of_credit". The unspecified
// value is "", and a value this SDK does not know yet is "unknown"; neither
// fails a read.

export type AuditEventKindName = "access" | "lifecycle" | "policy" | "refused" | "credentials";

/** One environment's events. Name it by exactly one of `environmentId` or
 * `environmentName`; only an ID names a deleted one. */
export interface ListAuditEventsOptions {
  environmentId?: string;
  environmentName?: string;
  /** None means every kind. */
  kinds?: AuditEventKindName[];
  /** Absent is 7 days ago; at most 90 days ago. */
  since?: Date;
  /** Absent is now. */
  until?: Date;
  /** Absent or 0 is 100; more than 1,000 is refused. */
  limit?: number;
  /** A previous page's `next_cursor`. */
  cursor?: string;
  /** One event per kind and subject for the whole range, with no cursor. */
  groupBySubject?: boolean;
}

export interface AuditEnvironment {
  id: string;
  name: string;
  deleted: boolean;
}

export interface AuditPolicyRevision {
  name: string;
  revision: number;
}

export interface AuditUser {
  id: string;
  email: string;
  /** "owner", "admin", "member" or "staff". */
  role: string;
}

export interface AuditApiKey {
  id: string;
  name: string;
}

/** Who did it, as they were when it happened: exactly one key, or none for
 * an actor this SDK does not know yet. `platform` is the platform's own
 * action and `sandbox` what the Sandbox's workload caused. */
export interface AuditActor {
  user?: AuditUser;
  api_key?: AuditApiKey;
  platform?: Record<string, never>;
  sandbox?: Record<string, never>;
}

export interface AuditAccess {
  /** "terminal", "ssh", "exec", "desktop" or "preview". */
  surface: string;
  client_ip: string;
}

export interface AuditSize {
  vcpu: number;
  memory_mib: number;
}

export interface AuditLifecycle {
  /** "created", "started", "stopped", "restarted", "resized", "snapshot_taken" or "deleted". */
  action: string;
  /** Why the platform did it, such as "idle"; "" when a person did. */
  reason: string;
  preset: string;
  from_snapshot: string;
  /** Resized: the sizes before and after. */
  from?: AuditSize;
  to?: AuditSize;
  snapshot: string;
  /** Stopped for being idle: the idle timeout the Sandbox had then; 0 when not known. */
  idle_stop_seconds: number;
}

export interface AuditPolicyChange {
  /** "selected", "edited", "enforcing" or "failed_closed". */
  action: string;
  from: string;
  to: string;
  policy: string;
  from_revision: number;
  to_revision: number;
  added: string[];
  removed: string[];
  revision: number;
  failure_code: string;
}

export interface AuditRefusal {
  destination: string;
  withheld: boolean;
  address: string;
  /** Absent for DNS. */
  port?: number;
  /** "dns", "tcp" or "udp". */
  protocol: string;
  reason: string;
  source: string;
  policy: string;
  revision: number;
  /** The first revision of the selected policy that allows it, when its current revision does. */
  allowed_since_revision?: number;
}

/** An hour's refusals past its 1,000 subjects, counted together; the event's `count` is the refusals. */
export interface AuditRefusalOverflow {
  /** How many more subjects were refused that hour. */
  subjects: number;
  /** True past 1,000 more, which are not counted exactly. */
  at_least: boolean;
}

export interface AuditCredentials {
  /** "attached", "detached" or "used". */
  action: string;
  provider: string;
  name: string;
  host: string;
  withheld: boolean;
}

/** One event: exactly one of `access`, `lifecycle`, `policy`, `refused`,
 * `refused_overflow` or `credentials` is set, and `kind` names it
 * ("refused" for both refusal fields). */
export interface AuditEvent {
  id: string;
  kind: string;
  /** When it began. */
  first?: Date;
  /** When it ended; absent while a session is open. */
  last?: Date;
  count: number;
  actor: AuditActor;
  access?: AuditAccess;
  lifecycle?: AuditLifecycle;
  policy?: AuditPolicyChange;
  refused?: AuditRefusal;
  credentials?: AuditCredentials;
  refused_overflow?: AuditRefusalOverflow;
}

export interface AuditEventPage {
  environment: AuditEnvironment;
  /** The selected network policy at its current revision; absent when it selects none. */
  policy?: AuditPolicyRevision;
  events: AuditEvent[];
  /** Empty when nothing is older. */
  next_cursor: string;
  /** A grouped answer's subjects past its 1,000, and those an hour's overflow event counted. */
  left_out: number;
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

/** Exported for the tests, which check it names every value. */
export function auditEnumName(enumObject: Record<number, string>, value: number): string {
  if (value === 0) return "";
  const name = enumObject[value];
  return typeof name === "string" ? name.toLowerCase() : "unknown";
}

function auditEventKinds(kinds: string[]): AuditEventKind[] {
  return kinds.map((kind) => {
    const value = (AuditEventKind as unknown as Record<string, unknown>)[kind.toUpperCase()];
    if (kind === "" || typeof value !== "number" || value === 0) {
      throw new Error(`codewire: unknown audit event kind ${JSON.stringify(kind)}`);
    }
    return value as AuditEventKind;
  });
}

function fromAuditSize(size: ProtoAuditSize | undefined): AuditSize | undefined {
  return size ? { vcpu: size.vcpu, memory_mib: Number(size.memoryMib) } : undefined;
}

function fromAuditActor(actor: ProtoAuditActor | undefined): AuditActor {
  switch (actor?.actor.case) {
    case "user": {
      const user = actor.actor.value;
      return { user: { id: user.id, email: user.email, role: auditEnumName(AuditRole, user.role) } };
    }
    case "apiKey":
      return { api_key: { id: actor.actor.value.id, name: actor.actor.value.name } };
    case "platform":
      return { platform: {} };
    case "sandbox":
      return { sandbox: {} };
    default:
      return {};
  }
}

export function fromAuditEvent(event: ProtoAuditEvent): AuditEvent {
  const result: AuditEvent = {
    id: event.id,
    kind: auditEnumName(AuditEventKind, event.kind),
    first: date(event.first),
    last: date(event.last),
    count: Number(event.count),
    actor: fromAuditActor(event.actor),
  };
  const detail = event.detail;
  switch (detail.case) {
    case "access":
      result.access = { surface: auditEnumName(AuditSurface, detail.value.surface), client_ip: detail.value.clientIp };
      break;
    case "lifecycle": {
      const value = detail.value;
      result.lifecycle = {
        action: auditEnumName(AuditLifecycle_Action, value.action),
        reason: auditEnumName(AuditPlatformReason, value.reason),
        preset: value.preset,
        from_snapshot: value.fromSnapshot,
        from: fromAuditSize(value.from),
        to: fromAuditSize(value.to),
        snapshot: value.snapshot,
        idle_stop_seconds: value.idleStopSeconds,
      };
      break;
    }
    case "policy": {
      const value = detail.value;
      result.policy = {
        action: auditEnumName(AuditPolicyChange_Action, value.action),
        from: value.from,
        to: value.to,
        policy: value.policy,
        from_revision: value.fromRevision,
        to_revision: value.toRevision,
        added: [...value.added],
        removed: [...value.removed],
        revision: value.revision,
        failure_code: value.failureCode,
      };
      break;
    }
    case "refused": {
      const value = detail.value;
      result.refused = {
        destination: value.destination,
        withheld: value.withheld,
        address: value.address,
        port: value.port,
        protocol: auditEnumName(AuditProtocol, value.protocol),
        reason: value.reason,
        source: value.source,
        policy: value.policy,
        revision: value.revision,
        allowed_since_revision: value.allowedSinceRevision,
      };
      break;
    }
    case "refusedOverflow":
      result.refused_overflow = { subjects: Number(detail.value.subjects), at_least: detail.value.atLeast };
      break;
    case "credentials": {
      const value = detail.value;
      result.credentials = {
        action: auditEnumName(AuditCredentials_Action, value.action),
        provider: value.provider,
        name: value.name,
        host: value.host,
        withheld: value.withheld,
      };
      break;
    }
  }
  return result;
}

export function fromAuditEventPage(response: ProtoListAuditEventsResponse): AuditEventPage {
  if (!response.environment) throw new Error("audit response omitted environment");
  const { id, name, deleted } = response.environment;
  return {
    environment: { id, name, deleted },
    policy: response.policy ? { name: response.policy.name, revision: response.policy.revision } : undefined,
    events: response.events.map(fromAuditEvent),
    next_cursor: response.nextCursor,
    left_out: Number(response.leftOut),
  };
}

function assertDescriptorCoverage(
  name: string,
  fields: ReadonlyArray<{ number: number; name: string }>,
  expected: string[],
): void {
  if (fields.length !== expected.length || fields.some((field, index) => field.name !== expected[index])) {
    throw new Error(`codewire: audit ${name} converter does not cover every descriptor field`);
  }
}

/** Throws when a future audit proto field or message lacks an SDK mapping.
 * ListAuditEventsRequest is the one message it never converts. */
export function assertAuditConverterCoverage(): void {
  const converted = 16;
  if (file_codewire_v1_audit.messages.length - 1 !== converted) {
    throw new Error(`codewire: audit converter covers ${converted} messages, audit.proto has ${file_codewire_v1_audit.messages.length - 1} besides the request`);
  }
  assertDescriptorCoverage("page", ListAuditEventsResponseSchema.fields, [
    "environment", "policy", "events", "next_cursor", "left_out",
  ]);
  assertDescriptorCoverage("environment", AuditEnvironmentSchema.fields, ["id", "name", "deleted"]);
  assertDescriptorCoverage("policy revision", AuditPolicyRevisionSchema.fields, ["name", "revision"]);
  assertDescriptorCoverage("event", AuditEventSchema.fields, [
    "id", "kind", "first", "last", "count", "actor", "access", "lifecycle", "policy", "refused", "credentials",
    "refused_overflow",
  ]);
  assertDescriptorCoverage("actor", AuditActorSchema.fields, ["user", "api_key", "platform", "sandbox"]);
  assertDescriptorCoverage("user", AuditUserSchema.fields, ["id", "email", "role"]);
  assertDescriptorCoverage("API key", AuditApiKeySchema.fields, ["id", "name"]);
  assertDescriptorCoverage("platform", AuditPlatformSchema.fields, []);
  assertDescriptorCoverage("sandbox", AuditSandboxSchema.fields, []);
  assertDescriptorCoverage("access", AuditAccessSchema.fields, ["surface", "client_ip"]);
  assertDescriptorCoverage("size", AuditSizeSchema.fields, ["vcpu", "memory_mib"]);
  assertDescriptorCoverage("lifecycle", AuditLifecycleSchema.fields, [
    "action", "reason", "preset", "from_snapshot", "from", "to", "snapshot", "idle_stop_seconds",
  ]);
  assertDescriptorCoverage("policy change", AuditPolicyChangeSchema.fields, [
    "action", "from", "to", "policy", "from_revision", "to_revision", "added", "removed", "revision", "failure_code",
  ]);
  assertDescriptorCoverage("refusal", AuditRefusalSchema.fields, [
    "destination", "withheld", "address", "port", "protocol", "reason", "source", "policy", "revision",
    "allowed_since_revision",
  ]);
  assertDescriptorCoverage("refusal overflow", AuditRefusalOverflowSchema.fields, ["subjects", "at_least"]);
  assertDescriptorCoverage("credentials", AuditCredentialsSchema.fields, ["action", "provider", "name", "host", "withheld"]);
}

/** A hosted Sandbox's audit log (`cw audit`). A user's session or an API key
 * reads it; organization owners and admins read every Sandbox's events, a
 * member those of each Sandbox they can open now. */
export class Audit {
  constructor(
    private client: AuditClient,
    private orgId: string,
  ) {}

  /** One page of an environment's events, newest first by when each began. */
  async listAuditEvents(options: ListAuditEventsOptions): Promise<AuditEventPage> {
    try {
      const hasId = options.environmentId !== undefined;
      if (hasId === (options.environmentName !== undefined)) {
        throw new Error("codewire: an audit read names its environment by exactly one of environmentId or environmentName");
      }
      const environment: ProtoListAuditEventsRequest["environment"] = hasId
        ? { case: "environmentId", value: options.environmentId! }
        : { case: "environmentName", value: options.environmentName! };
      const response = await this.client.listAuditEvents({
        orgId: resolveOrgId(this.orgId),
        environment,
        kinds: auditEventKinds(options.kinds ?? []),
        since: options.since === undefined ? undefined : timestampFromDate(options.since),
        until: options.until === undefined ? undefined : timestampFromDate(options.until),
        limit: options.limit ?? 0,
        cursor: options.cursor ?? "",
        groupBySubject: options.groupBySubject ?? false,
      });
      return fromAuditEventPage(response);
    } catch (error) {
      throw mapConnectError(error);
    }
  }
}
