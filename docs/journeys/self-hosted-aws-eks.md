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

Updated 2026-11-28. First live AWS EKS verification ran in `us-east-1` from
`c61b29ed1a` plus the PR 4 fixes (9 bugs caught and fixed live in
`template.yaml`, `install.sh`, `values-eks.yaml.tmpl`, `orchestration.yaml`,
`temporal.yaml`, and `gateway.yaml`). Stack deploy, Nitro nested-KVM L2
execution, IMDSv2 hop-limit isolation, controller/ESO/RDS-TLS/Temporal/IdP/
Dashboard/Billing/Envoy-Gateway routing, first-admin bootstrap/sign-in/
invite-only sign-up, and zero-leak teardown are observed; public NLB ingress,
`codewire-orchestration` `local-keyring` readiness, and `cw` enrolled-host
lifecycle await an ELB-enabled verification account and the next GHCR release
tag (`>= v0.4.42`, after `#6685`).

| ID | What | AWS EKS (`EksKvmStandard` default) |
| --- | --- | --- |
| `eks-stack-deploy` | Deploy CloudFormation stack and inspect outputs | observed (2026-11-28, `us-east-1`, `m7i.xlarge` under 8-vCPU account quota) |
| `eks-nitro-nested-kvm` | Verify Nitro nested-KVM `/dev/kvm`, AccessEntry join, and KVM L2 execution | observed (2026-11-28, `m7i.xlarge`, `KVM_RUN` L2 guest `'OK'` -> `KVM_EXIT_HLT`; full Cloud Hypervisor boot awaits GHCR runtime mirrors) |
| `eks-helm-bootstrap` | Bootstrap cluster controllers, Helm release and TLS | partially observed (2026-11-28; ESO, RDS PG 17.9 TLS, Temporal, IdP, Billing, Dashboard, Envoy Gateway HTTPS `200`/`204`/`301` verified; public NLB blocked by new-account ELB restriction, orchestration `local-keyring` awaits `>= v0.4.42` GHCR tag) |
| `eks-first-admin` | Create first admin and verify invite-only sign-up | partially observed (2026-11-28; bootstrap Job, second-admin refusal, admin sign-in `200`, uninvited sign-up `202` `accessPending:true` verified via Envoy Gateway HTTPS; `cw login` awaits public NLB + `>= v0.4.42`) |
| `eks-host-lifecycle` | Enroll host and run create, run, stop, start and rm | not yet observed (awaits public NLB + `>= v0.4.42` GHCR release) |
| `eks-empty-failure-recovery` | Verify empty, offline-host, pod-restart and RDS-reconnect states | partially observed (2026-11-28; `codewire-idp` rollout restart + RDS TLS reconnect verified; `cw hosts` offline/recovery awaits `eks-host-lifecycle`) |
| `eks-imds-isolation` | Verify IMDSv2 hop-limit=1 blocks Pod access to EC2 metadata | observed (2026-11-28; `curl` timed out after 3001 ms, `HTTP 000`) |
| `eks-clean-teardown` | Drain LoadBalancers/PVCs and delete stack with zero orphans | observed (2026-11-28; `DELETE_COMPLETE` in 624s, zero leaked AWS resources) |
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
- **Observed:** 2026-11-28 on real AWS (`us-east-1`, base commit `c61b29ed1a`,
  `cw v0.4.26`). Stack `codewire-eks-walk-6706` reached `CREATE_COMPLETE`
  (`SandboxComputeMode=EksKvmStandard`, `DeploymentProfile=Minimal`,
  `DeletionProtection=false`, `HostedZoneId=""`). Verified EKS `1.33`
  (`v1.33.13-eks-9adbfea`) `ACTIVE` with KMS `secrets` encryption and CIDR-scoped
  public API + private API; RDS PostgreSQL `17.9` (`db.t4g.medium`)
  `PubliclyAccessible=false`, `StorageEncrypted=true` on the stack KMS CMK;
  both Launch Templates enforced `HttpTokens=required` and
  `HttpPutResponseHopLimit=1`; dynamic SSM AL2023 AMI resolved to
  `ami-099a88fd7c697e35b`. The disposable dev account had an 8-vCPU On-Demand
  Standard quota (`L-1216C47A`), so 4-vCPU Nitro nested-virt types
  (`m7i.xlarge`/`m8i.xlarge`/`c7i.xlarge`/`c8i.xlarge`) were added to
  `KvmInstanceType.AllowedValues` (keeping `m7i.4xlarge` default) and the KVM
  ASG launched `m7i.xlarge` with `CpuOptions.NestedVirtualization=enabled`.

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
- **Observed:** 2026-11-28 on real AWS (`us-east-1`, `m7i.xlarge`,
  AL2023 `6.12.115-140.210.amzn2023.x86_64`, `containerd://2.3.7`). Self-managed
  ASG node joined EKS 1.33 via `KvmNodeAccessEntry` (`Type: EC2_LINUX`) in 69 s
  with labels `node.codewire.sh/purpose=sandbox-runtime,codewire.sh/node-pool=kvm-sandbox`
  and taint `node.codewire.sh/runtime-candidate=true:NoSchedule` (zero `aws-auth`
  edits). Live probe pod verified `/dev/kvm` exists (`0666`), all 4 vCPUs expose
  `vmx`, containerd config sets `device_ownership_from_security_context = true`
  under `[plugins.'io.containerd.cri.v1.runtime']` (template updated from
  containerd 1.x `grpc.v1.cri`), and `KVM_GET_API_VERSION=12` +
  `KVM_CREATE_VM` + `KVM_RUN` executed a real-mode x86 L2 guest to
  `KVM_EXIT_HLT` with serial output `'OK'`. Full Cloud Hypervisor guest kernel
  boot awaits public runtime image mirrors (`eks-kvm-standard`).

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
- **Observed:** partially observed 2026-11-28 (`us-east-1`, `HostedZoneId=""`
  with BYO self-signed TLS Secrets, `--image-tag v0.4.41`). Live bootstrap
  caught and fixed 9 real defects: GHCR has no `:latest` tag (fixed `install.sh`
  to resolve latest `v*` tag or require `--image-tag`); `orchestration.env`
  hardcoded `TEMPORAL_HOST_PORT` to `temporal-system` (added
  `orchestration.temporalHostPort`); `install.sh` omitted `codewire-sandboxes`
  namespace, its required `codewire.sh/resource-type=sandbox` +
  `codewire.sh/runtime-scope=shared` labels, and the
  `codewire-orchestration-internal-roots` ConfigMap; `values-eks.yaml.tmpl`
  omitted `SANDBOX_DAEMON_IMAGE` and `SANDBOX_NAMESPACE`; `temporal.yaml` used
  only `SQL_TLS_ENABLED` instead of `POSTGRES_TLS_ENABLED` + `SQL_TLS_ENABLED`
  / `SQL_HOST_VERIFICATION` for RDS `rds.force_ssl=1`; Envoy Gateway v1.3.2
  rejected `Backend` references without `extensionApis.enableBackend=true` and
  rejected `maxStreamDuration`/`streamIdleTimeout`/`clientSelectors[].path`/
  `Distinct` local CIDRMatch in `BackendTrafficPolicy`. After fixes, verified
  live: all 4 controllers `deployed`, all 5 `ExternalSecret` objects
  `SecretSynced` via namespace-scoped `SecretStore` + EKS Pod Identity,
  `Job/codewire-database-init` `Complete` (3 s) against RDS PG 17.9 over TLS,
  `codewire-temporal`, `codewire-idp`, `codewire-billing`, and
  `codewire-dashboard` `1/1 Running`, `HTTPRoute/codewire-apex` `Accepted=True`
  + `ResolvedRefs=True`, `BackendTrafficPolicy/codewire-long-lived`
  `Accepted=True`, Envoy Gateway HTTPS `GET /healthz` (`204`),
  `GET /.well-known/openid-configuration` (`200`), `GET /.well-known/jwks.json`
  (`200`), `GET /` (`200`), and HTTP→HTTPS `301` redirect. Not yet observed:
  public AWS NLB provisioning (the fresh dev account returned AWS account-level
  `OperationNotPermitted: This AWS account currently does not support creating
  load balancers`), Route53 DNS-01 ACME issuance, and `codewire-orchestration`
  `local-keyring` readiness (`v0.4.41` predates `#6685`; requires next release
  tag `>= v0.4.42`).

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
- **Observed:** partially observed 2026-11-28 (`us-east-1`, `--image-tag
  v0.4.41`). `Job/codewire-admin-bootstrap` reached `Complete` (6 s) logging
  `created the admin admin@codewire-walk.test`; a second `create-admin` Job
  exited cleanly with `this server already has an admin; nothing changed`.
  Through Envoy Gateway HTTPS: `GET /api/auth/sign-up/mode` returned `200`
  (`{"mode":"invite-only","reason":false}`), `POST /api/auth/sign-in` for the
  bootstrapped admin returned `200` (`is_admin: true`, session created), and
  uninvited `POST /api/auth/sign-up` returned `202` (`"accessPending": true`,
  `is_admin: false`). Browser org creation and `cw login` / `cw whoami` await
  an ELB-enabled account and `>= v0.4.42` GHCR release.

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
- **Observed:** partially observed 2026-11-28 (`us-east-1`).
  `kubectl -n codewire rollout restart deployment/codewire-idp` rolled cleanly
  to `1/1 Running` and reconnected to RDS PostgreSQL 17.9 over TLS with the
  bootstrapped admin intact. Empty-host and offline-host `cw` checks await
  `eks-host-lifecycle`.

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
- **Observed:** 2026-11-28 (`us-east-1`). Non-privileged Pod (`hostNetwork:
  false`) running `curl -sS -m 3 -X PUT http://169.254.169.254/latest/api/token
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'` timed out after 3001 ms
  (`curl_exit=28`, `HTTP_CODE=000`, zero bytes returned), while EKS Pod Identity
  worked for `ebs-csi-controller-sa`, `external-secrets`, and
  `aws-load-balancer-controller`.

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
- **Observed:** 2026-11-28 (`us-east-1`).
  `./deployments/aws-eks/uninstall.sh --stack-name codewire-eks-walk-6706
  --region us-east-1 --delete-stack` uninstalled releases and reached
  CloudFormation `DELETE_COMPLETE` in 624 s with zero manual ENI cleanup.
  Post-delete AWS CLI audit confirmed zero remaining EKS clusters, EC2
  instances, Auto Scaling Groups, NLBs, NAT Gateways, EIPs, EBS volumes, RDS
  instances, non-default VPCs, or ENIs; the intentionally retained disposable
  RDS snapshot, 5 Secrets Manager secrets, and KMS CMK were explicitly deleted
  or scheduled for 7-day deletion.

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
