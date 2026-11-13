# Connect error model

This document records the six decisions (D1 to D6) that define the one error
contract every Connect surface shares. The `connect_error` and `error`
modules of `codewire-server-core` and [PROTO-STYLE.md](PROTO-STYLE.md) cite
them by number. PROTO-STYLE.md has the summary for someone writing or
calling an RPC. This document states each rule and the reason for it.

## Background

Every service raises one error type, `codewire_server_core::AppError`. Over
plain HTTP it renders as a JSON envelope with `status`, `title`, `detail`,
an optional `errors` list for validation failures (each with a JSON-pointer
`path` and a `message`), and optional `code`, `hint` and `request_id`.

A Connect error is one of the 16 canonical codes, a message, and a list of
typed protobuf detail messages. The decisions below say how the first shape
maps onto the second.

## D1: `google.rpc` detail types, vendored

Error details use `google.rpc.BadRequest`, `google.rpc.ErrorInfo` and
`google.rpc.RetryInfo`. No Codewire-specific detail type exists. The needed
files are vendored under `proto/google/rpc/` (`error_details.proto`,
`code.proto`, `status.proto`) with their upstream license header and a
provenance comment.

Reason: every Connect and gRPC tool already understands these types. The
files are vendored, not fetched, because the build uses local `buf` plugins
only and must work without network access. The vendored set stays minimal.
A future Codewire-owned detail type belongs in a `codewire` package, never
in the vendored files.

## D2: Status to code mapping

One mapping serves all services. `ConnectError::from_app_error` implements
it.

| HTTP status | Connect code | Details attached |
|---|---|---|
| 400 malformed request | `invalid_argument` | none |
| 400 valid request missing required configuration or a lifecycle prerequisite | `failed_precondition` | none |
| 422 validation | `invalid_argument` | `BadRequest.field_violations` |
| 401 | `unauthenticated` | none |
| 403 (including non-member organization access and the admin check) | `permission_denied` | `ErrorInfo` |
| 404 | `not_found` | none |
| 409 conflict | `already_exists` for a create collision; `failed_precondition` for a lifecycle-state conflict (for example, stop on a deleting environment) | `ErrorInfo.reason` |
| 429 | `resource_exhausted` | `RetryInfo.retry_delay` |
| 502 or 503, upstream or daemon unavailable | `unavailable` | `RetryInfo` where a retry is sane |
| 504 server-enforced deadline | `deadline_exceeded` | none |
| any other 5xx, and everything unmapped | `internal` | none |

Rules that go with the table:

- The table is total by fallback, not by enumeration. Anything unmapped
  renders as `internal`.
- The second row is `AppError::Precondition`. It keeps HTTP 400 on the
  plain HTTP surface and renders `failed_precondition` over Connect.
- The machine-readable `code` of an error takes precedence over its HTTP
  status for a small closed set of reasons. Lifecycle-state and
  organization-selection reasons (such as `invalid_state` and
  `environment_protected`) and `credit_exhausted` render
  `failed_precondition`. Quota reasons (`quota_exceeded`,
  `resource_limit_exceeded`) render `resource_exhausted`. The set is the
  match in `connect_code_for`.
- A 409 is a lifecycle-state conflict only when its `code` is in the list
  in `is_state_conflict_reason`. Every other 409 is `already_exists`.
- `RetryInfo` is attached only where the producer knows the delay, through
  `ConnectError::with_retry_delay`. The mapping never fabricates one.
- `deadline_exceeded` is produced by server-enforced deadlines, including
  the bounded credential resolution in the Connect auth layer. `aborted`
  is reserved for optimistic-concurrency conflicts and has no producer yet.

Reason: clients branch on the code and the typed details, never on message
text, so the mapping must be the same for every service.

## D3: Field paths

`BadRequest.FieldViolation.field` uses dotted paths such as `spec.name` and
`ports[0].target`. They are converted from the envelope's JSON pointers
(`/spec/name`, `/ports/0/target`). The body root (`/`) maps to an empty
`field`, and the violation description carries the message. One function
does the conversion: `json_pointer_to_field_path`.

Reason: dotted paths are the `google.rpc.BadRequest` convention, and one
conversion function keeps both renderers in step.

## D4: `code`, `hint` and `request_id` survive in `ErrorInfo`

`ErrorInfo.domain` is `codewire.sh`. `ErrorInfo.reason` carries the
envelope's optional `code` in upper snake case (`session_expired` becomes
`SESSION_EXPIRED`). `ErrorInfo.metadata` carries `hint` and `request_id`,
each only when present. When an error has none of the three, no `ErrorInfo`
is attached. When it has a `hint` or `request_id` but no `code`, `reason`
is empty. The `x-request-id` response header is unchanged.

Reason: clients and support tooling already depend on these three fields.
Carrying them in a standard detail type keeps them available without a
custom message.

## D5: Polling hints are response fields

Environment read responses carry an explicit
`google.protobuf.Duration poll_interval` field. No `Retry-After` header is
used for polling.

Reason: a typed contract should not hide data that clients depend on in a
transport header.

## D6: One error type, two renderers

Services keep the single `AppError` type. It renders the HTTP envelope
(`error` module) and the Connect error (`connect_error` module) from the
same accessors. Handlers raise an `AppError` and never construct Connect
codes or details by hand.

Reason: with one source, the HTTP and Connect surfaces cannot disagree
about the same failure.
