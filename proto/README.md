# Service contracts

Canonical home for Connect-RPC / protobuf contracts: internal
service-to-service surfaces and the client-facing `codewire.*` packages
(Connect-RPC migration, `docs/plans/connect-rpc/`). Every surface gets a
versioned schema here; implementations are generated from these files,
which makes swapping a service's implementation language invisible to
its callers.

**Authoring rules — layout, naming, pagination, `NO_SIDE_EFFECTS`,
stability postures, codegen — live in
[`docs/dev/PROTO-STYLE.md`](../docs/dev/PROTO-STYLE.md) (canonical).**

## Layout

```
proto/
├── buf.yaml               # buf v2 module config (lint: STANDARD, breaking: FILE)
├── buf.gen.yaml           # codegen config for internal packages (local plugins)
├── buf.gen.codewire.yaml  # codegen config for the client-facing codewire/** packages
├── buf.gen.google-rpc-ts.yaml # TypeScript vendored google.rpc detail schemas
├── buf.gen.google-rpc-python.yaml # Python vendored google.rpc detail schemas
├── google/rpc/            # vendored googleapis error-model protos (see below)
├── <service>/v1/          # one package per service, versioned (internal contracts)
└── codewire/**/v1/        # client-facing contract packages (Connect-RPC migration)
```

Generated Go clients for both internal and client-facing packages live in the
standalone `libs/gen-go/` module and are checked in. The client-facing
`codewire.*` packages (`docs/plans/connect-rpc/`) additionally generate into
`libs/gen-python/` and `packages/codewire-proto-ts/src/gen/` (checked in), and
are compiled for Rust at build time by `crates/codewire-proto`.

## Contracts

| Package | Service | Consumers |
|---|---|---|
| `coordinator.v1` | `CoordinatorService` — tailnet coordinate (WireGuard key exchange). Production transport is currently WebSocket+JSON with field names matching these messages; the schema is the source of truth for the wire shapes. | CLI, environment sidecars, desktop |

`libs/gateway-proto/proto/` holds the Rust-consumed daemon/gateway protocol.
It has no independent Go module or generated Go copy. New client-facing
contracts go here.

## Vendored third-party protos

`google/rpc/{error_details,code,status}.proto` are vendored verbatim from
[googleapis](https://github.com/googleapis/googleapis) at commit
`bb9551666256aa929ffe1bbe7ad17db1342f0214` (Apache-2.0; upstream license
headers retained, provenance comment added after each header). They define
the well-known error detail types (`google.rpc.BadRequest`,
`google.rpc.ErrorInfo`, `google.rpc.RetryInfo`, …) used by the Connect
error model (`docs/plans/connect-rpc/01-error-model.md`, D1). They are
vendored — not pulled from the BSR — because CI is restricted-network and
this module uses no remote dependencies or plugins.

Rules for the vendored files:

- Never hand-edit them. To update, re-copy the files from a newer upstream
  commit and update the provenance comments and the commit hash above, in
  a dedicated PR.
- They are exempt from `buf lint` (upstream predates buf's STANDARD rules)
  via the `lint.ignore` entry in `buf.yaml`; `buf breaking` still covers
  them.
- They are excluded from codegen in `buf.gen.yaml`: canonical generated
  code for `google.rpc` already ships in the Go ecosystem (for example Go's
  `google.golang.org/genproto`), so generating a Go copy here would duplicate
  types. TypeScript and Python decode `ConnectError` details with checked-in
  generated copies: `buf.gen.google-rpc-ts.yaml` emits
  `packages/codewire-proto-ts/src/gen/google/rpc/` through the pinned local
  `protoc-gen-es` plugin, while `buf.gen.google-rpc-python.yaml` emits
  `libs/gen-python/google/rpc/` through pinned protoc built-ins. The Python
  SDK stages the latter into its wheel; neither generated representation is a
  second contract source.
- If a surface needs a Codewire-owned error detail type not expressible via
  `google.rpc.*`, it gets added to the owning Codewire package with its own
  ADR note — do not extend the vendored files.

## Workflow

```sh
make proto-tools        # install pinned generators (Go plugins, Python venv)
make proto-lint         # buf lint
make proto-generate     # regenerate all checked-in codegen templates
make proto-drift-check  # CI gate: fails if generated code is stale
```

The TypeScript generator (`protoc-gen-es`) comes from `bun install`
(pinned in the root `package.json` devDependencies).

Breaking changes are checked with `buf breaking` against `main`
(`cd proto && buf breaking --against '../.git#branch=main,subdir=proto'`).
