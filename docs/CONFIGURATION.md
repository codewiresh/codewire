# Configuration reference

A Codewire deployment names its own registries and hosts. The product ships no
default that points at one operator's infrastructure: when a required value is
missing, the service that needs it refuses to start, and its error names the
variable and this page.

Services read these values from their environment. In the Kubernetes
manifests (`deployments/k8s`), the `codewire-config` ConfigMap carries most of
them, and each overlay sets its own values. CI and release workflows take their
settings from repository Actions variables; see
[dev/CI-CONFIGURATION.md](dev/CI-CONFIGURATION.md).

## Runtime images

Orchestration renders every Sandbox from three images: the workspace image,
the daemon (support) image, and the Docker-in-Docker image. The workspace
digest is the published pin in `crates/codewire-workspace-image`. The DinD image
is Docker's official image, pinned by digest in the source. The deployment
chooses where the workspace and daemon images are pulled from.

| Variable | Required | Meaning | Example |
|---|---|---|---|
| `CODEWIRE_WORKSPACE_IMAGE_REPOSITORY` | Required by orchestration | The repository the default workspace image is pulled from, with no tag or digest. Orchestration appends the pinned digest. `cw` and the dashboard send the same digest at its public mirror, `ghcr.io/codewiresh/workspace`, and orchestration resolves it to this repository. The public mirror is itself a valid value. | `registry.example.com/codewire/workspace` |
| `CODEWIRE_APPROVED_IMAGE_REGISTRIES` | Required by orchestration | Comma-separated registry prefixes, each ending in `/` and with no spaces, that the runtime-node image cache may hold digest-pinned images from. The image cache admission policy reads the same value, so the two always approve the same registries. An image from any other registry is never cached. | `registry.example.com/,docker.io/library/` |
| `SANDBOX_DAEMON_IMAGE` | Required by orchestration | The support image every workspace runs its daemon from. Pin it by digest: a Start then re-pins an existing Sandbox's daemon to it, but only from an image in the same repository. | `registry.example.com/codewire/daemon@sha256:<digest>` |

### Where the manifests set them

- `CODEWIRE_WORKSPACE_IMAGE_REPOSITORY` and `SANDBOX_DAEMON_IMAGE` are keys of
  the `codewire-config` ConfigMap. Base `config.env` leaves the repository
  empty, so every overlay must set it.
- `CODEWIRE_APPROVED_IMAGE_REGISTRIES` is the only key of the
  `codewire-image-registries` ConfigMap in orchestration's namespace
  (`deployments/k8s/orchestration/image-registries.yaml`). Orchestration reads
  it into its environment. The image cache `ValidatingAdmissionPolicyBinding`
  names the same ConfigMap as its parameter (`paramRef`), and denies every
  image cache write when the ConfigMap is missing. Its name carries no hash
  suffix, so a changed value reaches orchestration only after its Pods
  restart. The policy applies the new value at once.

### Local clusters

The Kind overlays (`deployments/k8s/overlays/local-kind*` and
`tests/e2e/kind`) pull the workspace image from its public mirror:

```text
CODEWIRE_WORKSPACE_IMAGE_REPOSITORY=ghcr.io/codewiresh/workspace
CODEWIRE_APPROVED_IMAGE_REGISTRIES=ghcr.io/codewiresh/,docker.io/library/
```

`make kind-runtime-images` preloads that image into every node.

The process-level harnesses (`scripts/dev/dev-stack.sh` and the integration and
rehearsal runners) use `registry.example.invalid`, a reserved name that never
resolves.
