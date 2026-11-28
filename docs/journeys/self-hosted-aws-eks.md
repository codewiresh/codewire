# Self-hosting Codewire on Amazon EKS

A self-hosted Codewire deployment on Amazon EKS (#6706) is done when an
operator deploys `deployments/aws-eks/template.yaml` and runs
`deployments/aws-eks/install.sh` in their own AWS account, verifies the Nitro
nested-KVM node pool (`/dev/kvm` and Cloud Hypervisor boot), signs in as the
first administrator, runs the environment lifecycle, verifies empty, failure
and recovery states, and tears the stack down via
`deployments/aws-eks/uninstall.sh` with no orphaned AWS resources. This file is
that walk. The format is in [README.md](README.md).

The default surface is a real non-production AWS account running the default
`EksKvmStandard` stack (`Minimal` profile, `1x m7i.4xlarge` Nitro nested-KVM
self-managed ASG, `DeletionProtection=false`, ~$880–$940/mo steady state,
ephemeral run torn down immediately after observation). `ControlPlaneOnly`
remains tested via the enrolled-host steps below.

## Where the walk stands

Updated 2026-11-28. Template, bootstrap scripts, and static CI checks are in
tree; live AWS verification is not yet observed.

| ID | What | AWS EKS (`EksKvmStandard` default) |
| --- | --- | --- |
| `eks-stack-deploy` | Deploy CloudFormation stack and inspect outputs | not yet observed |
| `eks-nitro-nested-kvm` | Verify Nitro nested-KVM `/dev/kvm`, AccessEntry join, and Cloud Hypervisor boot | not yet observed |
| `eks-helm-bootstrap` | Bootstrap cluster controllers, Helm release and TLS | not yet observed |
| `eks-first-admin` | Create first admin and verify invite-only sign-up | not yet observed |
| `eks-host-lifecycle` | Enroll host and run create, run, stop, start and rm | not yet observed |
| `eks-empty-failure-recovery` | Verify empty, offline-host, pod-restart and RDS-reconnect states | not yet observed |
| `eks-imds-isolation` | Verify IMDSv2 hop-limit=1 blocks Pod access to EC2 metadata | not yet observed |
| `eks-clean-teardown` | Drain LoadBalancers/PVCs and delete stack with zero orphans | not yet observed |
| `eks-kvm-standard` | End-to-end `standard` VM sandbox lifecycle (after GHCR runtime mirrors) | not yet observed |
| `eks-kms-credentials` | Phase 2: `aws-kms` KEK wrapping for orchestration and credential-service | not yet observed |

## Before the walk

- Use a dedicated non-production AWS account and a Route53 hosted zone you
  control (or prepare a BYO TLS certificate and DNS records).
- Isolate CLI state from any existing sign-in with `CW_CONFIG_DIR`, for
  example `CW_CONFIG_DIR="$(mktemp -d)"`.
- Record the exact `codewire/codewire` commit SHA, AWS region, Kubernetes
  version, `KvmInstanceType`, RDS engine version, and `cw version` with every
  observation.
- Run with `DeletionProtection=false` for disposable verification stacks, and
  confirm the AWS account has zero remaining NLBs, ENIs, or EBS volumes
  created by the stack after teardown.

## Phase 1: EKS stack, Nitro nested-KVM, control plane & enrolled hosts

### `eks-stack-deploy`: deploy CloudFormation stack and inspect outputs

- **Entry points:** `aws cloudformation deploy` with
  `deployments/aws-eks/template.yaml` or AWS CloudFormation console.
- **States to exercise:** clean stack creation with default
  `SandboxComputeMode=EksKvmStandard`, `KvmInstanceType=m7i.4xlarge`,
  `CreateVpc=true`, `DeploymentProfile=Minimal`, and
  `SecretKekMode=SecretsManagerLocalKeyring`; invalid CIDR or missing required
  parameter fails validation before resource creation.
- **Driving it:**
  1. Run:
     ```sh
     aws cloudformation deploy \
       --region <region> \
       --stack-name codewire-eks-walk \
       --template-file deployments/aws-eks/template.yaml \
       --capabilities CAPABILITY_IAM \
       --parameter-overrides \
         ClusterName=codewire-walk \
         DomainName=<domain> \
         HostedZoneId=<zone-id> \
         AllowedApiCidrs="<your-ip>/32" \
         DeletionProtection=false
     ```
  2. Inspect stack outputs (`ClusterName`, `RdsEndpoint`, `KmsKeyArn`,
     `SecretsPrefix`, `ValuesParameterName`, `InstallCommand`).
- **Proof:** CloudFormation stack reaches `CREATE_COMPLETE`; RDS PostgreSQL 17
  instance reports `PubliclyAccessible=false` and `StorageEncrypted=true`; EKS
  control plane reports version `1.33+` with secrets encryption enabled on the
  stack KMS key; both Launch Templates show `HttpTokens=required` and
  `HttpPutResponseHopLimit=1`; `KvmNodeLaunchTemplate` shows
  `CpuOptions.NestedVirtualization=enabled` and resolved dynamic SSM AL2023
  AMI.
- **Gotchas:** Ensure `AllowedApiCidrs` includes the workstation IP running
  the bootstrap step, or run bootstrap from inside the VPC.
- **Observed:** not yet observed.

### `eks-nitro-nested-kvm`: verify Nitro nested-KVM `/dev/kvm`, AccessEntry join, and Cloud Hypervisor boot

- **Entry points:** `kubectl get nodes`, EC2 instance attributes, Cloud
  Hypervisor smoke on the self-managed KVM ASG node.
- **States to exercise:** self-managed ASG node (`m7i.4xlarge`) joins EKS via
  `KvmNodeAccessEntry` (`Type: EC2_LINUX`) with label
  `node.codewire.sh/purpose=sandbox-runtime` and taint
  `node.codewire.sh/runtime-candidate=true:NoSchedule`; `/dev/kvm` is present
  and Cloud Hypervisor boots a minimal guest VM cleanly under AWS Nitro nested
  virtualization; changing `KvmInstanceType` via stack update rolls the ASG
  cleanly.
- **Driving it:**
  1. Run `kubectl get nodes -l node.codewire.sh/purpose=sandbox-runtime -o wide`
     and confirm the `m7i.4xlarge` node is `Ready` with taint
     `node.codewire.sh/runtime-candidate=true:NoSchedule`.
  2. Verify `/dev/kvm` exists on the KVM node and run a Cloud Hypervisor boot
     smoke check on that node.
- **Proof:** Node is `Ready` via EKS Access Entry with no manual `aws-auth`
  edits; `/dev/kvm` is openable (`kvm` ioctl version check succeeds) and Cloud
  Hypervisor boots a guest kernel to userspace cleanly on Nitro nested-KVM.
- **Gotchas:** EKS Managed Node Groups can strip
  `CpuOptions.NestedVirtualization`; confirm the KVM node belongs to
  `KvmNodeAutoScalingGroup` and reports `NestedVirtualization: enabled` via
  `aws ec2 describe-instances`.
- **Observed:** not yet observed.

### `eks-helm-bootstrap`: bootstrap cluster controllers, Helm release and TLS

- **Entry points:** `deployments/aws-eks/install.sh` and `helm upgrade
  --install` using `deployments/helm/codewire`.
- **States to exercise:** fresh bootstrap on an empty cluster; idempotent
  second run produces no unintended changes or downtime; missing stack output
  or unreachable cluster fails with a clear error.
- **Driving it:**
  1. Run:
     ```sh
     ./deployments/aws-eks/install.sh \
       --stack-name codewire-eks-walk \
       --region <region> \
       --acme-email <email> \
       --admin-email <admin-email>
     ```
  2. Point DNS for `<domain>` and `*.preview.<domain>` at the Envoy Gateway
     NLB printed by `install.sh`.
  3. Check Envoy Gateway, AWS Load Balancer Controller, External Secrets
     Operator, `cert-manager`, Temporal, and Codewire Pods are `Ready`.
  4. Request `https://<domain>/healthz` and `https://<domain>/readyz`.
- **Proof:** `https://<domain>/healthz` and `https://<domain>/readyz` return
  HTTP `200` over valid TLS issued for `<domain>` (and wildcard
  `*.preview.<domain>` when Route53 DNS-01 is enabled); ExternalSecret objects
  report `SecretSynced`; re-running `deployments/aws-eks/install.sh` exits `0`.
- **Gotchas:** Wait for DNS-01 ACME propagation before testing TLS; verify
  the NLB target group health checks pass on the Envoy Gateway pods.
- **Observed:** not yet observed.

### `eks-first-admin`: create first admin and verify invite-only sign-up

- **Entry points:** `Job/codewire-admin-bootstrap`, dashboard web UI, and
  `cw login`.
- **States to exercise:** first admin creation; uninvited sign-up lands in
  disabled/waiting state (`IDP_SIGNUP=invite-only`); re-running admin
  bootstrap refuses to create a second admin; `cw login --server
  https://<domain>` completes device flow.
- **Driving it:**
  1. Confirm `Job/codewire-admin-bootstrap` succeeded and retrieve the
     generated password from Secrets Manager (`codewire/<cluster>/admin-bootstrap`).
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

- **Entry points:** `deployments/aws-eks/uninstall.sh` and
  `aws cloudformation delete-stack`.
- **States to exercise:** draining Kubernetes Gateways, LoadBalancer Services,
  and PVCs before deleting the CloudFormation stack so AWS NLB ENIs and EBS
  volumes do not stall VPC deletion.
- **Driving it:**
  1. Run `cw host leave --yes` on the enrolled host.
  2. Run:
     ```sh
     ./deployments/aws-eks/uninstall.sh \
       --stack-name codewire-eks-walk \
       --region <region> \
       --delete-stack
     ```
  3. Query EC2 load balancers, network interfaces, and EBS volumes tagged for
     the cluster name.
- **Proof:** CloudFormation stack reaches `DELETE_COMPLETE` without manual
  ENI cleanup; AWS CLI queries return zero remaining NLBs, security groups, or
  EBS volumes for the deleted stack.
- **Gotchas:** Stacks deployed with `DeletionProtection=true` intentionally
  retain RDS, KMS, and Secrets Manager KEK secrets; this step tests
  `DeletionProtection=false`.
- **Observed:** not yet observed.

## Follow-up: In-cluster `standard` sandboxes & AWS KMS KEK

### `eks-kvm-standard`: end-to-end `standard` VM sandbox lifecycle

- **Entry points:** `SandboxComputeMode=EksKvmStandard`, `cw create`
  (Kubernetes placement).
- **States to exercise:** `codewire.sh/kvm` advertisement via
  `cw-kvm-device-plugin`, `standard` VM sandbox create/run/stop/start/rm with
  encrypted GP3 EBS PVC on the Nitro nested-KVM node (`m7i.4xlarge`), and
  vertical upgrade via `KvmInstanceType`.
- **Driving it:** no command yet (awaits public `ghcr.io/codewiresh/*` mirrors
  for `pod-runtime`, `workspace-disk`, `egress`, and `kvm-device-plugin` plus
  `#5602` chart toggles).
- **Proof:** Sandbox Pod schedules onto the tainted KVM ASG node using
  `runtimeClassName: standard`, boots a KVM VM, passes egress lockdown checks,
  and persists workspace files across stop and start.
- **Gotchas:** Scale `KvmDesiredSize=0` or tear down disposable verification
  stacks immediately after testing.
- **Observed:** not yet observed.

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
