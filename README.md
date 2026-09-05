# Codewire

Agent-ready sandbox environments. Open source under AGPL-3.0-only.

## What it is

Codewire orchestrates sandbox environments on Kubernetes via the `agent-sandbox` CRD operator. Each environment is a long-lived development environment that users or AI agents can SSH into, exec inside, transfer files into, and tunnel ports through.

This repository contains the control plane, dashboard, CLI, SDKs, and generated API types for that stack.

## Repo layout

```
apps/
  cli/         cw packaging, installers, charts, and release metadata
  dashboard/   Playwright contract and Rust/Zola production image
  docs/        Zola documentation source
  ios/         native iOS client

libs/
  gateway-proto/      internal gateway/daemon Connect contract
  gen-go/, gen-python/  generated public Connect clients
  sdk-go/, sdk-ts/, sdk-python/  public language SDKs
  tailnet/            bounded Tailscale interoperability support

crates/        Rust workspace for services, web UI, CLI, desktop, and shared clients
packages/      shared design assets and generated TypeScript Connect schemas
deployments/   k8s manifests + kustomize overlays
docs/          stable docs + planning notes
```

## Quick start

### Local kind control plane

```bash
# Interactive development cluster
make up

# Separate isolated Rust-owned product gate
make e2e-kind
```

The interactive local kind ingress listens on `http://127.0.0.1:8080`; the e2e
gate creates and deletes its own cluster. Use `docs/dev/KIND-E2E.md` for the
full local cluster workflow.

### Local sandbox environment (CLI)

On Linux/x86_64, the native developer preview runs Cloud Hypervisor directly
through KVM. It requires usable `/dev/kvm` and `/dev/vhost-vsock` devices plus
the reviewed Cloud Hypervisor v53, Linux 6.18.48 LTS, and Codewire guest-root
artifacts under `~/.cache/codewire/local-vmm-v1/artifacts` with the sibling lock at
`~/.cache/codewire/local-vmm-v1/artifacts.lock.json`. The preview never
downloads or substitutes those artifacts at runtime.

```bash
# Build the CLI
cargo build -p codewire-cli-bin --bin cw

# Auto-clone a clean Git root, or copy an ordinary directory once.
./target/debug/cw env create --local \
  --name codewire-dev \
  --cpu 2 \
  --memory 8GB \
  --path .

# Creation selects it, so enter it without a platform login or target argument.
./target/debug/cw shell

# Run a durable non-interactive session and manage the same VM.
./target/debug/cw run -- uname -a
./target/debug/cw env info --local codewire-dev
./target/debug/cw env stop --local codewire-dev
./target/debug/cw env start --local codewire-dev
./target/debug/cw env restart --local codewire-dev

# CPU and memory apply on restart; the persistent ext4 disk grows offline.
./target/debug/cw env resize --local codewire-dev \
  --cpu 4 --memory 16GB --disk 40GB --yes

# Read-only inventory: this never adopts, repairs, or deletes an orphan.
./target/debug/cw doctor local
./target/debug/cw env rm --local codewire-dev --yes
```

Familiar resource inputs are binary quantities: `8GB` of memory allocates 8192
MiB, and `2048MB` of disk resolves to 2 GiB. `GiB`/`MiB` and their shorter
`Gi`/`Mi` spellings also work, and suffixes are case-insensitive.

An exact clean Git root becomes an independent clone of its checked-out commit;
host hooks, credential helpers, embedded remote credentials, unrelated refs,
and later host changes do not enter the VM. An ordinary directory becomes an
environment-owned point-in-time copy. Use `--path-mode clone` or
`--path-mode copy` to override automatic classification; direct host access is
never inferred from `--path`. The primary workspace runs directly in the
canonical Codewire OCI workspace image beneath trusted guest init and runc;
Docker does not own it. A `codewire.yaml` may combine portable `repositories`
with local `mounts` using `mode: copy`; relative mount sources resolve from the
configuration file, and each becomes an environment-owned point-in-time copy.
Multi-repository entries use the same normalized project model as the platform.
`image` in `codewire.yaml` and `--image` select any valid OCI workspace image. A
`ports` entry with `port` declares a guest application port. A `host_port` and
`guest_port` pair also publishes it for the VM lifetime on the host loopback
address only:

```yaml
ports:
  - host_port: 18080
    guest_port: 8080
```

Native local environments join Mesh only when `--network NAME` is explicit or
a selected network is confirmed; `--no-network` always disables attachment.
Use `cw network use NAME --auto-connect` to make the selected network the
durable no-prompt default for new local and platform environments at the
matching Mesh origin and organization; running `cw network use NAME` without
that flag restores confirmation. Native local creation with no selected network
starts neither Mesh transport nor platform access. Once attachment is selected,
native local and platform creation fail instead of silently creating a
disconnected environment when enrollment cannot be completed.
`cw mesh up` provides the standalone offline/self-hosted coordinator used by
the product smoke. The host owns Mesh identity and transport, and the VM sees
only admitted TCP streams for its declared application ports. Access profiles
select material-free credential grants whose protected values remain in the
isolated host broker. Credential and access-profile commands treat a bare
selector as a name. Use `name:<name>` for a name that resembles selector syntax,
`id:<canonical-uuid>` for a record ID, and `user/<name>` for an exact
scope-qualified access-profile reference. Malformed prefixes are rejected.
Preset, install/startup, environment, agent-installation,
and secret options still fail explicitly while the remaining Forgejo #1910
slices are completed. Repository, copy-mount, and direct-mount skills are
captured into immutable environment-owned generations at create time and on
explicit skill refresh. An owner-only SQLite WAL is the authoritative
supervisor state. Preview JSON is not imported, and older SQLite schemas are
unsupported. Lifecycle effects are journaled, disk shrink is rejected, and
delete moves the environment tree to an operation-specific trash generation
before removing only known runtime files.

Developers with artifacts staged outside the default cache can point the CLI
at them and run the complete product smoke:

```bash
export CODEWIRE_NATIVE_ARTIFACT_ROOT=/absolute/path/to/artifacts
export CODEWIRE_NATIVE_ARTIFACT_LOCK=/absolute/path/to/artifacts.lock.json
cargo build -p codewire-cli-bin --bin cw \
  -p codewire-mesh --bin codewire-mesh \
  -p codewire-derp --bin codewire-derp
cargo build -p codewire-local-vmm \
  --bin codewire-local-codex-bridge-smoke \
  --bin codewire-local-public-data-smoke \
  --bin codewire-local-state-probe
mkdir -p .tmp
chmod 0700 .tmp

scripts/ci/verify/smoke-native-local-environment.sh \
  --cw-bin "$PWD/target/debug/cw" \
  --mesh-bin "$PWD/target/debug/codewire-mesh" \
  --derp-bin "$PWD/target/debug/codewire-derp" \
  --data-plane-smoke-bin "$PWD/target/debug/codewire-local-public-data-smoke" \
  --credential-bridge-smoke-bin "$PWD/target/debug/codewire-local-codex-bridge-smoke" \
  --state-probe-bin "$PWD/target/debug/codewire-local-state-probe" \
  --artifact-root "$CODEWIRE_NATIVE_ARTIFACT_ROOT" \
  --artifact-lock "$CODEWIRE_NATIVE_ARTIFACT_LOCK" \
  --scratch-parent "$PWD/.tmp"
```

The native smoke verifies that repository, copy-mount, and direct-mount skill
inputs remain immutable until an explicit refresh, are projected read-only in
the guest, and preserve executable helper modes.

The native local supervisor is the only supported local environment owner:

```bash
./target/debug/cw env create --local \
  --name native-local \
  --image workspace \
  --path .

# Resize a native environment. A terminal shows the current-to-desired plan,
# active-session warning, and a default-no confirmation before the restart.
./target/debug/cw env resize --local native-local --cpu 6 --memory 12Gi --disk 120Gi

# Automation must provide explicit resources and --yes.
./target/debug/cw env resize --local native-local --cpu 6 --yes --output json
```

`cw env resize ENV` resolves the placement when it is unambiguous. Native and
platform resize both restore a running VM after applying changes without
recreating the environment, and disk growth cannot be reversed. Native VMs use
whole CPU cores and perform ext4 growth while stopped.

### Local database and dashboard loop

```bash
make dev           # Start local Postgres
make db-init       # Apply the baseline schema
make web           # Run the dashboard dev server
```

### SDK tests

```bash
make test-sdk      # Typecheck + unit tests across Go, Python, TypeScript SDKs
```

## Architecture (one-paragraph)

The **control plane** (`codewire`) accepts API requests, manages environment lifecycle, integrates with Kubernetes via the `agent-sandbox` CRD, handles billing, and exposes OIDC. Each running environment is a pod containing a workspace container + a **gateway** sidecar; the gateway routes SSH/SCP/SFTP from outside the cluster to a **daemon** running alongside user code. Gateway↔daemon talks over Connect-RPC. The web dashboard and the `cw` CLI are first-class clients of the control plane.

## Status

Codewire is pre-1.0. The OSS surface is stable enough to run and contribute against but breaking changes can land between releases. Architectural direction and current work tracked in [docs/plans/](docs/plans/) and on the issue tracker.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — stable architecture summary
- [docs/GLOSSARY.md](docs/GLOSSARY.md) — canonical terms
- [docs/dev/CODEWIRE-APP-GUIDE.md](docs/dev/CODEWIRE-APP-GUIDE.md) — internal engineering guide
- [docs/plans/](docs/plans/) — design proposals + in-flight architecture work

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

Codewire is licensed under AGPL-3.0-only. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
