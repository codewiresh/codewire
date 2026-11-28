# Self-hosted Codewire on Amazon EKS (CloudFormation)

Official AWS CloudFormation template and Helm bootstrap for deploying a
self-hosted Codewire platform on Amazon EKS (#6706).

See [docs/SELF-HOSTING-EKS.md](../../docs/SELF-HOSTING-EKS.md) for the
architecture overview and
[docs/journeys/self-hosted-aws-eks.md](../../docs/journeys/self-hosted-aws-eks.md)
for the acceptance walk.

## Files

- `template.yaml` — Single self-contained CloudFormation stack (< 51 KB;
  deploys directly without an S3 nested-template bucket). Provisions VPC (or
  uses an existing VPC), KMS CMK, Secrets Manager credentials/KEKs, RDS
  PostgreSQL 17, EKS 1.33+ with managed add-ons (`vpc-cni` with NetworkPolicy,
  `aws-ebs-csi-driver`, `eks-pod-identity-agent`), hardened Launch Templates
  (`IMDSv2` `HttpPutResponseHopLimit=1`), dynamic SSM Public Parameter AL2023
  AMI (zero hardcoded regional AMI IDs), system managed node group,
  self-managed KVM sandbox Auto Scaling Group (`EksKvmStandard` default,
  `1x m7i.4xlarge` with AWS Nitro `CpuOptions.NestedVirtualization: enabled`
  targeting ~$880–$940/mo total, upgradeable up to `.metal`), EKS Access Entry
  (`EC2_LINUX`), and least-privilege EKS Pod Identity associations.
- `install.sh` — Idempotent bootstrap script reading CloudFormation stack
  outputs, installing pinned cluster controllers (`aws-load-balancer-controller`,
  `external-secrets`, `cert-manager`, `envoy-gateway`), syncing stack secrets,
  and deploying the cloud-agnostic `deployments/helm/codewire` chart.
- `uninstall.sh` — Drains Gateways, LoadBalancer Services, and PVCs before
  deleting the CloudFormation stack so AWS NLB ENIs and EBS volumes do not
  orphan.
- `values-eks.yaml.tmpl` — EKS values overlay rendered by `install.sh` for
  `deployments/helm/codewire`.

## Quick start

1. Deploy the AWS infrastructure stack (default `EksKvmStandard` with
   `1x m7i.4xlarge` Nitro nested-KVM node + `Minimal` control plane,
   ~$880–$940/mo; pass `SandboxComputeMode=ControlPlaneOnly` for enrolled hosts
   only at ~$290–$320/mo):

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

2. Bootstrap cluster controllers and deploy Codewire:

   ```sh
   ./deployments/aws-eks/install.sh \
     --stack-name codewire-eks \
     --region us-east-1 \
     --acme-email ops@example.com \
     --admin-email admin@example.com
   ```

3. Scale or upgrade KVM sandbox capacity at any time via stack update
   (`m7i.2xlarge` → `m7i.4xlarge`/`m8i.4xlarge` → `m8i.8xlarge`/`m8i.16xlarge`
   → `c7i.metal-24xl`/`m7i.metal-24xl`; `.metal` automatically omits
   `CpuOptions.NestedVirtualization`):

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
       AllowedApiCidrs="$(curl -s https://checkip.amazonaws.com)/32" \
       KvmInstanceType=m8i.8xlarge \
       KvmDesiredSize=2
   ```

4. Tear down safely (when `DeletionProtection=false`):

   ```sh
   ./deployments/aws-eks/uninstall.sh \
     --stack-name codewire-eks \
     --region us-east-1 \
     --delete-stack
   ```
