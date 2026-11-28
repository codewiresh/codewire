# Self-hosting Codewire on Amazon EKS

> **Status:** Specification and outline written ahead of implementation
> (#6706). The CloudFormation template, EKS Helm values, and bootstrap scripts
> land in follow-up pull requests; see
> [docs/journeys/self-hosted-aws-eks.md](journeys/self-hosted-aws-eks.md) for
> the acceptance walk.

Deploy a self-hosted Codewire platform on Amazon EKS in your own AWS account
using one CloudFormation template for AWS infrastructure and the official
[Codewire Helm chart](../deployments/helm/codewire/README.md) for Kubernetes
workloads.

For single-machine self-hosting without Kubernetes, see
[docs/SELF-HOSTING.md](SELF-HOSTING.md).

## Deployment modes

Codewire separates where the **control plane** runs from where **sandboxes**
run. Two EKS deployment modes are controlled by the `SandboxComputeMode`
CloudFormation parameter:

| Mode | Control plane | Where sandboxes run | AWS compute footprint | Status |
| --- | --- | --- | --- | --- |
| **`ControlPlaneOnly` (default)** | Small x86\_64 EKS managed node group (e.g. 2x `t3.large`) | Enrolled hosts (`cw host run` on Linux KVM, Apple Silicon Macs, or standalone EC2 `.metal`), and future direct EC2 placement (#4120) | No `.metal` EKS nodes required | Phase 1 (#6706) |
| **`EksKvmStandard` (opt-in)** | System node group + tainted `.metal` EKS managed node group (`c7i.metal-24xl` / `m7i.metal-24xl`) | In-cluster Kubernetes VM sandboxes (`standard` runtime profile, `/dev/kvm` via `cw-kvm-device-plugin`) | Requires EC2 `.metal` nodes | Phase 2 (after #5602 and GHCR image mirrors) |

Regular EC2 instances on AWS Nitro do not expose `/dev/kvm`. Keeping
`ControlPlaneOnly` as the default avoids unexpected bare-metal charges while
providing the full Codewire control plane on EKS. Diagnostic `runc` sandboxes
remain disabled by default.

## Architecture overview

CloudFormation owns all AWS infrastructure, EKS cluster resources, managed
add-ons, and IAM boundaries; `deployments/helm/codewire` owns all Kubernetes
application resources.

- **Networking & VPC:** Optional new multi-AZ VPC (`CreateVpc=true`, public
  subnets for NLB/NAT Gateway, private subnets for EKS nodes and RDS, free S3
  VPC Gateway Endpoint) or bring-your-own VPC and subnets (`CreateVpc=false`).
- **EKS Cluster (Kubernetes 1.33+):** Managed add-ons `vpc-cni` (with eBPF
  `ENABLE_NETWORK_POLICY=true`), `coredns`, `kube-proxy`,
  `aws-ebs-csi-driver`, and `eks-pod-identity-agent`. Every controller and
  workload AWS role uses **EKS Pod Identity** with least-privilege scoping.
- **Database (RDS PostgreSQL 17):** Private subnet deployment, KMS-encrypted
  GP3 storage, custom parameter group (`max_locks_per_transaction=1024`,
  `rds.force_ssl=1`), hosting `codewire`, `temporal`, and
  `temporal_visibility` databases (`pgcrypto` extension built in).
- **Temporal:** Self-hosted in-cluster backed by RDS (`TemporalMode=InCluster`,
  default) or external Temporal Cloud (`TemporalMode=External`).
- **Ingress, TLS & Wildcard DNS:** AWS NLB TCP passthrough (`:443`, plus
  optional `:3478/UDP` STUN and `:41641/UDP` UDP relay when direct access is
  enabled) fronting in-cluster **Envoy Gateway** (Gateway API) with
  `cert-manager` issuing public and wildcard `*.preview.<domain>` certificates
  via Route53 DNS-01 (or BYO TLS Secret) plus internal cluster CAs.
- **Secrets & KEK Management:** Dedicated stack AWS KMS CMK (auto-rotation
  enabled) encrypting EKS Secrets, RDS, EBS, and AWS Secrets Manager.
  - Phase 1 default (`SecretsManagerLocalKeyring`): Secrets Manager + External
    Secrets Operator (ESO) syncs `SESSION_SECRET`, RDS credentials,
    `idp-signing-keks/v1`, and `tenant-keks/v1` into Kubernetes Secrets for
    `CODEWIRE_SECRET_KEK_PROVIDER=local-keyring`.
  - Phase 2 (`AwsKms`): Native AWS KMS DEK wrapping/unwrapping via EKS Pod
    Identity for both `orchestration` and `credential-service`.
  - Optional (`ExternalOpenBao`): Connect to an existing OpenBao/Vault cluster.
- **No unused S3 bucket:** Codewire has no S3 object-storage runtime
  dependency; workspace storage uses encrypted GP3 EBS PVCs and EBS CSI
  VolumeSnapshots.

## Security invariants

- **IMDS isolation:** Every EC2 Launch Template enforces IMDSv2 with
  `HttpTokens: required` and `HttpPutResponseHopLimit: 1`, preventing Pods
  from accessing EC2 instance metadata (`169.254.169.254`).
- **Data protection:** `DeletionPolicy: Retain` protects the KMS CMK, RDS
  instance, and KEK Secrets Manager secrets when `DeletionProtection=true`.
  Losing the tenant KEK permanently loses stored tenant secrets.
- **Invite-only sign-up & no hosted defaults:** `IDP_SIGNUP=invite-only` by
  default; no fallback to `codewire.sh`.
- **Audit-IP integrity:** NLB preserves client source IP (`externalTrafficPolicy:
  Local` / Proxy Protocol v2) so backend services never trust spoofed
  `X-Forwarded-For` headers.

## Planned deployment layout

The implementation PRs for #6706 add:

1. Helm chart self-host prerequisites in `deployments/helm/codewire`
   (`local-keyring` KEK mount, optional Temporal, Gateway API routes, and
   database/admin bootstrap Jobs).
2. A single self-contained CloudFormation template, idempotent bootstrap
   installer, safe teardown script, and static CI checks (`cfn-lint`, repo
   policy checks, and Helm render matrix tests).
3. Live end-to-end verification recorded in
   [docs/journeys/self-hosted-aws-eks.md](journeys/self-hosted-aws-eks.md).
