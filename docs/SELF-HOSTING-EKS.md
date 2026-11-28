# Self-hosting Codewire on Amazon EKS

Deploy a self-hosted Codewire platform on Amazon EKS in your own AWS account
using the single self-contained CloudFormation template
([deployments/aws-eks/template.yaml](../deployments/aws-eks/template.yaml)) for
AWS infrastructure and the cloud-agnostic
[Codewire Helm chart](../deployments/helm/codewire/README.md) for Kubernetes
workloads (#6706).

For single-machine self-hosting without Kubernetes, see
[docs/SELF-HOSTING.md](SELF-HOSTING.md). For the end-to-end acceptance walk,
see [docs/journeys/self-hosted-aws-eks.md](journeys/self-hosted-aws-eks.md).

## Deployment modes

Codewire separates where the **control plane** runs from where **sandboxes**
run. Two EKS deployment modes are controlled by the `SandboxComputeMode`
CloudFormation parameter:

| Mode | Control plane | KVM sandbox pool | Estimated monthly baseline (us-east-1) |
| --- | --- | --- | --- |
| **`EksKvmStandard` (default)** | Small x86\_64 EKS managed node group (`2x t3.large`) | Self-managed EC2 Auto Scaling Group (`1x m7i.4xlarge` default with AWS Nitro `CpuOptions.NestedVirtualization: enabled`, $0 surcharge; upgradeable up to `.metal`) | **~$880–$940/mo** (`m7i.4xlarge`) |
| **`ControlPlaneOnly` (opt-in)** | Small x86\_64 EKS managed node group (`2x t3.large`) | None (sandboxes run on enrolled hosts via `cw host run`, or future direct EC2 placement #4120) | **~$290–$320/mo** (`Minimal`) / ~$550–$750/mo (`HA`) |

Because EKS Managed Node Groups can strip `CpuOptions.NestedVirtualization`,
the KVM pool is provisioned as a **Self-Managed EC2 Auto Scaling Group** with a
hardened Launch Template, a dynamic SSM Public Parameter AL2023 AMI
(`EksAl2023AmiId`, zero hardcoded regional AMI IDs), AL2023 `NodeConfig`
userdata (`device_ownership_from_security_context = true`), and a dedicated
`AWS::EKS::AccessEntry` (`Type: EC2_LINUX`).

### Seamless KVM upgrade path

Upgrade vertically or horizontally at any time via a CloudFormation stack
update on `KvmInstanceType` and `KvmMinSize` / `KvmDesiredSize` / `KvmMaxSize`:

- Entry / smaller: `m7i.2xlarge`, `m8i.2xlarge`, `c7i.2xlarge`, `c8i.2xlarge`
- Default sweet spot (~$700–$1,000/mo total): **`m7i.4xlarge`**, `m8i.4xlarge`,
  `c7i.4xlarge`, `c8i.4xlarge`, `r7i.4xlarge`, `r8i.4xlarge`
- High density: `m7i.8xlarge`, `m8i.8xlarge`, `c7i.8xlarge`, `c8i.8xlarge`,
  `m7i.16xlarge`, `m8i.16xlarge`
- Bare metal: `c7i.metal-24xl`, `m7i.metal-24xl`, `c8i.metal-24xl`,
  `m8i.metal-24xl` (the template automatically omits
  `CpuOptions.NestedVirtualization` when a `.metal` type is selected)

Diagnostic `runc` sandboxes remain disabled by default.

## Architecture overview

CloudFormation owns all AWS infrastructure, EKS cluster resources, managed
add-ons, and IAM boundaries. `deployments/helm/codewire` remains 100%
cloud-agnostic (zero AWS annotations, IAM, or CRDs in the chart, with every
container image parameterized under `images.*` for regular Kubernetes clusters
and registry mirrors); all AWS/EKS wiring lives in `deployments/aws-eks/`.

- **Networking & VPC:** Optional 2-AZ VPC (`CreateVpc=true`, public subnets for
  NLB/NAT Gateway, private subnets for EKS nodes and RDS, free S3 VPC Gateway
  Endpoint) or bring-your-own VPC and subnets (`CreateVpc=false`).
- **EKS Cluster (Kubernetes 1.33+):** Managed add-ons `vpc-cni` (with eBPF
  `enableNetworkPolicy: "true"`), `coredns`, `kube-proxy`,
  `aws-ebs-csi-driver`, and `eks-pod-identity-agent`. Every controller uses
  least-privilege **EKS Pod Identity**.
- **Database (RDS PostgreSQL 17):** Private subnet deployment, KMS-encrypted
  GP3 storage, custom parameter group (`max_locks_per_transaction=1024`,
  `rds.force_ssl=1`), hosting `codewire`, `temporal`, and
  `temporal_visibility` databases (`pgcrypto` extension built in).
- **Temporal:** Self-hosted in-cluster backed by RDS (`TemporalMode=InCluster`,
  default) or external Temporal Cloud (`TemporalMode=External`).
- **Ingress, TLS & Wildcard DNS:** AWS NLB TCP passthrough (`:443`,
  `externalTrafficPolicy: Local` for audit-IP integrity) fronting in-cluster
  **Envoy Gateway** (Gateway API) with `cert-manager` issuing public and
  wildcard `*.preview.<domain>` certificates via Route53 DNS-01 (or BYO TLS
  Secret) plus a namespace-local internal CA Issuer.
- **Secrets & KEK Management:** Dedicated stack AWS KMS CMK (auto-rotation
  enabled, `DeletionPolicy: Retain`) encrypting EKS Secrets, RDS, EBS, and AWS
  Secrets Manager.
  - Phase 1 default (`SecretsManagerLocalKeyring`): Secrets Manager + External
    Secrets Operator (ESO) syncs `SESSION_SECRET`, RDS credentials,
    `idp-signing-keks/v1`, and `tenant-keks/v1` into Kubernetes Secrets for
    `orchestration.localKeyring.enabled=true` (`CODEWIRE_SECRET_KEK_PROVIDER=local-keyring`).
  - Phase 2 (`AwsKms`): Native AWS KMS DEK wrapping/unwrapping via EKS Pod
    Identity for both `orchestration` and `credential-service`.
  - Optional (`ExternalOpenBao`): Connect to an existing OpenBao/Vault cluster.
- **No unused S3 bucket:** Codewire has no S3 object-storage runtime
  dependency; workspace storage uses encrypted GP3 EBS PVCs and EBS CSI
  VolumeSnapshots.

## Quick start

1. Deploy the AWS CloudFormation stack:

   ```sh
   aws cloudformation deploy \
     --region us-east-1 \
     --stack-name codewire-eks \
     --template-file deployments/aws-eks/template.yaml \
     --capabilities CAPABILITY_IAM \
     --parameter-overrides \
       ClusterName=codewire \
       DomainName=codewire.example.com \
       HostedZoneId=Z0123456789ABCDEF \
       AllowedApiCidrs="$(curl -s https://checkip.amazonaws.com)/32"
   ```

   Pass `SandboxComputeMode=ControlPlaneOnly` to skip the KVM Auto Scaling
   Group and run sandboxes exclusively on enrolled hosts (`cw host run`).

2. Bootstrap cluster controllers and deploy Codewire via Helm:

   ```sh
   ./deployments/aws-eks/install.sh \
     --stack-name codewire-eks \
     --region us-east-1 \
     --acme-email ops@example.com \
     --admin-email admin@example.com
   ```

3. Point DNS for `<DomainName>` and `*.preview.<DomainName>` (and
   `derp.<DomainName>` when `EnableDirectAccess=true`) at the Envoy Gateway NLB
   printed by `install.sh`.

4. Tear down safely (for disposable stacks deployed with
   `DeletionProtection=false`):

   ```sh
   ./deployments/aws-eks/uninstall.sh \
     --stack-name codewire-eks \
     --region us-east-1 \
     --delete-stack
   ```

## Security invariants

- **IMDS isolation:** Every EC2 Launch Template (system and KVM pools) enforces
  IMDSv2 with `HttpTokens: required` and `HttpPutResponseHopLimit: 1`,
  preventing Pods from reaching EC2 instance metadata (`169.254.169.254`).
- **Data protection:** `DeletionPolicy: Retain` protects the KMS CMK and KEK
  Secrets Manager secrets, and `DeletionPolicy: Snapshot` +
  `DeletionProtection` protect RDS. Losing the tenant KEK permanently loses
  stored tenant secrets.
- **Invite-only sign-up & no hosted defaults:** `IDP_SIGNUP=invite-only` by
  default; no fallback to `codewire.sh`.
- **Audit-IP integrity:** NLB preserves client source IP
  (`externalTrafficPolicy: Local`) so backend services never trust spoofed
  `X-Forwarded-For` headers.

## In-cluster KVM runtime prerequisites

The CloudFormation stack provisions the Nitro nested-KVM node pool, AL2023
containerd ownership setting, and `agentSandbox` CRDs out of the box. Running
live `standard` VM sandboxes inside EKS additionally requires:

- public `ghcr.io/codewiresh/*` mirrors for `pod-runtime`, `workspace-disk`,
  `egress`, and `kvm-device-plugin` (tracked under #5602 / #6706);
- live Nitro nested-KVM Cloud Hypervisor verification recorded in
  [docs/journeys/self-hosted-aws-eks.md](journeys/self-hosted-aws-eks.md).
