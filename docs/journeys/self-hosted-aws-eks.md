# Self-hosting Codewire on Amazon EKS

A self-hosted Codewire deployment on Amazon EKS (#6706) is done when an
operator deploys the CloudFormation stack and Helm release in their own AWS
account, signs in as the first administrator, enrolls a host, runs the full
environment lifecycle, verifies empty, failure and recovery states, and tears
the stack down with no orphaned AWS resources. This file is that walk. The
format is in [README.md](README.md).

The surface is a real non-production AWS account running the Phase 1
`ControlPlaneOnly` stack (`Minimal` profile, `DeletionProtection=false`,
enrolled Linux KVM host running `cw host run`). Phase 2 adds `aws-kms` KEK
wrapping for `credential-service` and `EksKvmStandard` bare-metal `.metal`
sandbox nodes; those steps are listed separately below.

## Where the walk stands

Updated 2026-11-28. Written before the CloudFormation template and Helm
prerequisites (#6706); every step is not yet observed.

| ID | What | AWS EKS (`ControlPlaneOnly`) |
| --- | --- | --- |
| `eks-stack-deploy` | Deploy CloudFormation stack and inspect outputs | not yet observed |
| `eks-helm-bootstrap` | Bootstrap cluster controllers, Helm release and TLS | not yet observed |
| `eks-first-admin` | Create first admin and verify invite-only sign-up | not yet observed |
| `eks-host-lifecycle` | Enroll host and run create, run, stop, start and rm | not yet observed |
| `eks-empty-failure-recovery` | Verify empty, offline-host, pod-restart and RDS-reconnect states | not yet observed |
| `eks-imds-isolation` | Verify IMDSv2 hop-limit=1 blocks Pod access to EC2 metadata | not yet observed |
| `eks-clean-teardown` | Drain LoadBalancers/PVCs and delete stack with zero orphans | not yet observed |
| `eks-kms-credentials` | Phase 2: `aws-kms` KEK wrapping for orchestration and credential-service | not yet observed |
| `eks-kvm-standard` | Phase 2: `EksKvmStandard` `.metal` node group and VM sandbox lifecycle | not yet observed |

## Before the walk

- Use a dedicated non-production AWS account and a Route53 hosted zone you
  control (or prepare a BYO TLS certificate and DNS records).
- Isolate CLI state from any existing sign-in with `CW_CONFIG_DIR`, for
  example `CW_CONFIG_DIR="$(mktemp -d)"`.
- Record the exact `codewire/codewire` commit SHA, AWS region, Kubernetes
  version, RDS engine version, and `cw version` with every observation.
- Run with `DeletionProtection=false` for disposable verification stacks, and
  confirm the AWS account has zero remaining NLBs, ENIs, or EBS volumes
  created by the stack after teardown.

## Phase 1: Control plane on EKS with enrolled hosts

### `eks-stack-deploy`: deploy CloudFormation stack and inspect outputs

- **Entry points:** `aws cloudformation deploy` or AWS CloudFormation console.
- **States to exercise:** clean stack creation with `CreateVpc=true`,
  `DeploymentProfile=Minimal`, `SandboxComputeMode=ControlPlaneOnly`, and
  `SecretKekMode=SecretsManagerLocalKeyring`; invalid CIDR or missing required
  parameter fails validation before resource creation.
- **Driving it:**
  1. Stack template and deploy command: no command yet (#6706).
  2. Inspect stack outputs (`ClusterName`, `RdsEndpoint`, `KmsKeyArn`,
     `SecretsPrefixArn`, `ValuesParameterName`, `InstallCommand`).
- **Proof:** CloudFormation stack reaches `CREATE_COMPLETE`; RDS PostgreSQL 17
  instance reports `PubliclyAccessible=false` and `StorageEncrypted=true`; EKS
  control plane reports version `1.33+` with secrets encryption enabled on the
  stack KMS key; all node Launch Templates show `HttpTokens=required` and
  `HttpPutResponseHopLimit=1`.
- **Gotchas:** Ensure `AllowedApiCidrs` includes the workstation IP running
  the bootstrap step, or run bootstrap from inside the VPC.
- **Observed:** not yet observed.

### `eks-helm-bootstrap`: bootstrap cluster controllers, Helm release and TLS

- **Entry points:** EKS bootstrap script and `helm upgrade --install` using
  `deployments/helm/codewire`.
- **States to exercise:** fresh bootstrap on an empty cluster; idempotent
  second run produces no unintended changes or downtime; missing stack output
  or unreachable cluster fails with a clear error.
- **Driving it:**
  1. Run the bootstrap installer from the stack outputs: no command yet
     (#6706).
  2. Check Envoy Gateway, AWS Load Balancer Controller, External Secrets
     Operator, `cert-manager`, Temporal, and Codewire Pods are `Ready`.
  3. Request `https://<domain>/healthz` and `https://<domain>/readyz`.
- **Proof:** `https://<domain>/healthz` and `https://<domain>/readyz` return
  HTTP `200` over valid TLS issued for `<domain>` (and wildcard
  `*.preview.<domain>` when Route53 DNS-01 is enabled); ExternalSecret objects
  report `SecretSynced`; re-running the bootstrap installer exits `0`.
- **Gotchas:** Wait for DNS-01 ACME propagation before testing TLS; verify
  the NLB target group health checks pass on the Envoy Gateway pods.
- **Observed:** not yet observed.

### `eks-first-admin`: create first admin and verify invite-only sign-up

- **Entry points:** post-install admin bootstrap Job, dashboard web UI, and
  `cw login`.
- **States to exercise:** first admin creation; uninvited sign-up lands in
  disabled/waiting state (`IDP_SIGNUP=invite-only`); re-running admin
  bootstrap refuses to create a second admin; `cw login --server
  https://<domain>` completes device flow.
- **Driving it:**
  1. Read the first admin setup output / invite link from the bootstrap Job.
  2. Sign in to `https://<domain>` as admin and create the first organization
     at `/organizations/new`.
  3. Attempt uninvited sign-up in a private browser session and verify it
     reports the account is waiting for admin approval.
  4. Run `cw login --server https://<domain>` and `cw whoami`.
- **Proof:** Dashboard shows the signed-in admin and new organization;
  uninvited account appears Disabled under Admin → Manage account access;
  `cw whoami` prints the admin account against `https://<domain>` with zero
  requests to `codewire.sh`.
- **Gotchas:** Without SMTP/SES configured, copy one-time invite links from
  the organization Members page.
- **Observed:** not yet observed.

### `eks-host-lifecycle`: enroll host and run create, run, stop, start and rm

- **Entry points:** `cw host enroll`, `cw host provide`, `cw host run`,
  `cw create --on host:<name>`, `cw run`, `cw stop`, `cw start`, `cw rm`.
- **States to exercise:** full environment lifecycle over the EKS Envoy
  Gateway HTTP/2 gRPC `HostAgentService` and `EnvironmentSessionService`
  routes.
- **Driving it:**
  1. On a Linux KVM host (or Apple Silicon Mac), run `cw host enroll --name
     eks-walk`, `cw host provide --max-vms 2`, and `cw host run`.
  2. Verify `cw hosts` shows `eks-walk` online.
  3. Run `cw create --on host:eks-walk --name demo`, `cw run demo -- uname -a`,
     `cw stop demo`, `cw start demo`, `cw run demo -- echo ok`, and
     `cw rm demo`.
- **Proof:** Each command exits `0`; `cw run demo -- uname -a` prints the
  guest Linux kernel; workspace state persists across stop and start;
  `cw ls` no longer lists `demo` after `cw rm demo`.
- **Gotchas:** Keep `cw host run` active during the walk; remove the host
  with `cw host leave --yes` before teardown.
- **Observed:** not yet observed.

### `eks-empty-failure-recovery`: verify empty, offline-host, pod-restart and RDS-reconnect states

- **Entry points:** `cw hosts`, `cw create`, `kubectl rollout restart`.
- **States to exercise:**
  - empty state: before any host is enrolled, `cw hosts` reports no hosts and
    `cw create` fails with a clear placement message;
  - failure state: stop `cw host run`, wait for the host heartbeat timeout
    (45 s), confirm `cw hosts` shows offline and `cw create --on
    host:eks-walk` fails cleanly;
  - recovery state: restart `cw host run`, confirm host returns online;
    restart `codewire-orchestration` and `codewire-idp` deployments via
    `kubectl rollout restart`, confirm existing admin, org, and host remain
    intact and `cw whoami` / `cw hosts` succeed after rollout.
- **Driving it:** Execute each of the three states above in sequence using
  `cw` and `kubectl`.
- **Proof:** Empty and offline creates exit non-zero with actionable error
  text; after deployment restarts, `kubectl rollout status` succeeds and
  previously enrolled host returns online with zero data loss.
- **Gotchas:** Do not confuse Kubernetes readiness transition (5–15 s) with
  a permanent error; wait for `kubectl rollout status` to complete.
- **Observed:** not yet observed.

### `eks-imds-isolation`: verify IMDSv2 hop-limit=1 blocks Pod access to EC2 metadata

- **Entry points:** ephemeral diagnostic Pod scheduled on an EKS worker node.
- **States to exercise:** HTTP token request (`PUT
  http://169.254.169.254/latest/api/token`) from a Pod network namespace.
- **Driving it:**
  1. Run a temporary non-privileged Pod in a test namespace attempting to
     fetch an IMDSv2 token from `169.254.169.254` with a 3-second timeout.
  2. Delete the temporary Pod.
- **Proof:** The request times out or fails with no HTTP 200 and no token
  returned, confirming `HttpPutResponseHopLimit=1` blocks Pod IMDS access
  while EKS Pod Identity still works for authorized ServiceAccounts.
- **Gotchas:** Run with `hostNetwork: false` (default Pod networking).
- **Observed:** not yet observed.

### `eks-clean-teardown`: drain LoadBalancers/PVCs and delete stack with zero orphans

- **Entry points:** uninstall script and `aws cloudformation delete-stack`.
- **States to exercise:** draining Kubernetes LoadBalancer Services and PVCs
  before deleting the CloudFormation stack so AWS NLB ENIs and EBS volumes do
  not stall VPC deletion.
- **Driving it:**
  1. Run `cw host leave --yes` on the enrolled host.
  2. Run the uninstall and stack deletion flow: no command yet (#6706).
  3. Query EC2 load balancers, network interfaces, and EBS volumes tagged for
     the cluster name.
- **Proof:** CloudFormation stack reaches `DELETE_COMPLETE` without manual
  ENI cleanup; AWS CLI queries return zero remaining NLBs, security groups, or
  EBS volumes for the deleted stack.
- **Gotchas:** Stacks deployed with `DeletionProtection=true` intentionally
  retain RDS, KMS, and Secrets Manager KEK secrets; this step tests
  `DeletionProtection=false`.
- **Observed:** not yet observed.

## Phase 2: AWS KMS KEK & bare-metal KVM sandboxes (future)

### `eks-kms-credentials`: `aws-kms` KEK wrapping for orchestration and credential-service

- **Entry points:** `SecretKekMode=AwsKms`, `cw credentials`, private `--repo`
  create.
- **States to exercise:** tenant secret and credential DEK wrap/unwrap via
  AWS KMS using EKS Pod Identity with zero static KEK files in Kubernetes
  Secrets; CloudTrail records KMS `Encrypt`/`Decrypt` calls scoped to the
  stack key.
- **Driving it:** no command yet (#6706 Phase 2).
- **Proof:** `codewire-credential-service` reaches `Ready` without OpenBao;
  storing a secret and cloning a private repo succeed; revoking the KMS key
  grant fails closed.
- **Gotchas:** Requires the Phase 2 `aws-kms` `KekProvider` implementation in
  `crates/codewire-protected-store`.
- **Observed:** not yet observed.

### `eks-kvm-standard`: `EksKvmStandard` `.metal` node group and VM sandbox lifecycle

- **Entry points:** `SandboxComputeMode=EksKvmStandard`, `cw create`
  (Kubernetes placement).
- **States to exercise:** `.metal` node group scale-up (`c7i.metal-24xl`),
  `codewire.sh/kvm` advertisement via `cw-kvm-device-plugin`, `standard` VM
  sandbox create/run/stop/start/rm with GP3 EBS PVC, and scale-down to 0.
- **Driving it:** no command yet (#6706 Phase 2, depends on #5602 and public
  GHCR runtime image mirrors).
- **Proof:** Sandbox Pod schedules onto the tainted `.metal` node using
  `runtimeClassName: standard`, boots a KVM VM, passes egress lockdown checks,
  and persists workspace files across stop and start.
- **Gotchas:** `.metal` instances incur substantial hourly cost; scale
  `MetalDesiredSize=0` immediately after verification.
- **Observed:** not yet observed.
