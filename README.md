# Codewire

Isolated development environments for developers and AI coding agents.
Open source under AGPL-3.0-only.

Codewire runs each environment in its own hardware-virtualized VM with its own
kernel, keeps durable terminal and agent sessions inside it, and lets you reach
it by shell, SSH, file transfer, browser terminal and preview URLs. The same
`cw` CLI drives three placements: a hosted sandbox on the Codewire platform, a
local VM on your own Linux or Apple Silicon machine, and a trusted session on
your host. This repository holds the platform services, the dashboard, the
CLI, the local VM runtime and the SDKs.

## Install

```sh
curl -fsSL https://get.codewire.sh | sh
```

It redirects to the installer, which you can also fetch directly:

```sh
curl -fsSL https://codewire.sh/install.sh | sh
```

The installer needs only a POSIX shell, `curl` and a SHA-256 tool. It
downloads the stable release for your platform (Linux x86_64/arm64, macOS
Apple Silicon/Intel), checks it against the release's `SHA256SUMS`, and
installs it as a managed `cw` that `cw upgrade` keeps current with signed
releases from `releases.codewire.sh`. See
[docs/dev/CLI-MANAGED-INSTALL.md](docs/dev/CLI-MANAGED-INSTALL.md).

From a checkout, `make cli-install` builds and installs the same way.
`cargo build -p codewire-cli-bin --bin cw` gives an unmanaged development
binary at `target/debug/cw`. Building from source needs a Rust toolchain
(`rustup`) and `protoc`, the Protocol Buffers compiler, on `PATH` (or `PROTOC`
set to its path):

```sh
sudo apt-get install protobuf-compiler   # Debian/Ubuntu
sudo pacman -S protobuf                  # Arch
brew install protobuf                    # macOS
```

## Quick start

A local VM needs no account. On Linux it runs Cloud Hypervisor on KVM; on an
Apple Silicon Mac it uses Virtualization.framework.

```sh
cw setup --local                       # install the pinned VM runtime
cw create --local --name my-app --path .
cw shell                               # creation selected my-app
cw run claude                          # Claude Code in my-app; Ctrl-B, then D detaches
cw run -- cargo test                   # a durable session; cw ls, cw attach
cw stop --local my-app
```

`--path .` mounts the folder live in the VM; dependency and build folders
(`node_modules`, `target`, `.venv` by default) stay on the VM disk.

A hosted sandbox:

```sh
cw setup                               # sign in, pick an organization
cw create --name my-app --image workspace
cw shell my-app
cw run --in my-app --name lead --agent codex --detach --prompt 'Review this repo'
cw inbox my-app --session lead
```

`cw --help` groups every command; `cw init` writes a `codewire.yaml` that
either placement can use.

## How it works

- **Control plane.** Rust services behind one shared chassis
  (`crates/codewire-server-core`): identity and OIDC (`codewire-idp`),
  environment lifecycle (`codewire-orchestration`, a Temporal worker and the
  Kubernetes sandbox client), billing (`codewire-billing`), the credential
  broker (`codewire-credential-service`), the tailnet coordinator, DERP and
  UDP relays, and Codewire Mesh. PostgreSQL holds product state; Temporal runs
  lifecycle workflows. The dashboard (`crates/codewire-dashboard-web`) is
  server-rendered HTML with HTMX.
- **Hosted environment.** One Pod per environment, created through the
  kubernetes-sigs `agent-sandbox` CRDs and scheduled with a RuntimeClass:
  `commodity` is Kata Containers with Cloud Hypervisor; `confidential` is Kata
  with QEMU-SNP on eligible hosts. The Pod holds a `workspace` container and a
  guest-local `dind` container. The workspace runs `cw __hosted-daemon`.
- **Daemon.** The daemon is the in-environment control plane: exec, PTY and
  file RPCs for sessions, an SSH server (with SFTP and SCP) on port 2222, and
  the environment's tailnet peer. Orchestration binds it, records its host
  key, and relays its credential bridge to the broker so provider secrets stay
  outside the sandbox. There is no sidecar or gateway.
- **Access.** `cw` reaches a hosted environment over WireGuard: direct UDP
  first, then the UDP relay, then DERP, and finally a WebSocket SSH proxy
  through orchestration. `cw setup ssh` lets OpenSSH, VS Code and `rsync`
  use the same path.
- **Local VM.** `cw` supervises the VM on your machine with the same guest
  daemon and workspace image; secrets and provider credentials stay in a host
  broker and reach the VM only as bounded capabilities.

## Repository layout

```text
apps/cli/        cw installer, packaging and release metadata
apps/dashboard/  dashboard image and browser tests
apps/docs/       documentation site (codewire.sh/docs)
crates/          Rust workspace: services, daemon, CLI, local VM runtime, dashboard
deployments/     Kubernetes manifests, kustomize overlays, Docker images
images/          workspace and runtime OCI images
libs/            SDKs (TypeScript, Go, Python) and generated clients
packages/        design system and generated TypeScript schemas
proto/           Connect-RPC contract source
docs/            architecture, glossary and developer docs
```

## Documentation

- [User guide](https://codewire.sh/docs)
- [Architecture](docs/ARCHITECTURE.md) and [glossary](docs/GLOSSARY.md)
- [Local VMs on Linux](docs/dev/LINUX-LOCAL-VMS.md) and [on macOS](docs/dev/MACOS-CLI.md)
- [Sessions and agent orchestration](docs/dev/CLI-ORCHESTRATION.md)
- [Sandbox daemon](docs/dev/SANDBOX-DAEMON.md), [networking](docs/dev/DERP-STUN.md),
  [secrets and credentials](docs/dev/SECRETS-AND-CREDENTIALS.md)
- [Local development](docs/dev/LOCAL-DEV.md), [contributing](CONTRIBUTING.md)
  and the [docs index](docs/README.md)

## Status

Codewire is pre-1.0. Breaking changes can land between releases.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

Codewire is licensed under AGPL-3.0-only. See [LICENSE](LICENSE).
