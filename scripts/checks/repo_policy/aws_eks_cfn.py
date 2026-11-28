"""Static security and schema policy check for deployments/aws-eks/template.yaml (#6706).

Validates the self-hosted Amazon EKS CloudFormation template and bootstrap
scripts without requiring AWS credentials:
- valid CloudFormation top-level structure and size under 51,200 bytes (direct upload);
- every EC2 LaunchTemplate enforces IMDSv2 (`HttpTokens: required`,
  `HttpPutResponseHopLimit: 1`) and KMS-encrypted EBS volumes;
- every RDS DBInstance has `PubliclyAccessible: false`, `StorageEncrypted: true`,
  `KmsKeyId`, safe `DeletionPolicy` (`Snapshot` or `Retain`), and parameter group
  enforcing `rds.force_ssl: "1"` and `max_locks_per_transaction: "1024"`;
- KMS CMK has `EnableKeyRotation: true` and `DeletionPolicy: Retain` +
  `UpdateReplacePolicy: Retain`;
- every Secrets Manager Secret sets `KmsKeyId` and retains on delete/replace;
- EKS cluster enables KMS `secrets` encryption and `EndpointPrivateAccess: true`;
- `vpc-cni` add-on enables `enableNetworkPolicy: "true"`;
- stack-owned IAM roles for Secrets Manager, KMS, and Route53 never grant
  wildcard `Resource: "*"` on secrets, KMS keys, or Route53 hosted zones;
- bootstrap script pins every cluster controller Helm chart version.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import yaml

from .shared import ROOT, argparse, report

TEMPLATE_PATH = "deployments/aws-eks/template.yaml"
INSTALL_SCRIPT_PATH = "deployments/aws-eks/install.sh"
MAX_DIRECT_UPLOAD_BYTES = 51_200


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that preserves CloudFormation short-form intrinsic tags."""


def _cfn_tag_constructor(tag_name: str):
    def _construct(loader: yaml.SafeLoader, node: yaml.Node) -> dict[str, Any]:
        if isinstance(node, yaml.ScalarNode):
            value: Any = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        elif isinstance(node, yaml.MappingNode):
            value = loader.construct_mapping(node, deep=True)
        else:
            value = None
        return {tag_name: value}

    return _construct


for _short, _fn in (
    ("!Ref", "Ref"),
    ("!Sub", "Fn::Sub"),
    ("!GetAtt", "Fn::GetAtt"),
    ("!If", "Fn::If"),
    ("!Equals", "Fn::Equals"),
    ("!Not", "Fn::Not"),
    ("!And", "Fn::And"),
    ("!Or", "Fn::Or"),
    ("!Join", "Fn::Join"),
    ("!Split", "Fn::Split"),
    ("!Select", "Fn::Select"),
    ("!GetAZs", "Fn::GetAZs"),
    ("!Cidr", "Fn::Cidr"),
    ("!Base64", "Fn::Base64"),
    ("!FindInMap", "Fn::FindInMap"),
    ("!ImportValue", "Fn::ImportValue"),
    ("!Condition", "Condition"),
    ("!Transform", "Fn::Transform"),
    ("!ToJsonString", "Fn::ToJsonString"),
):
    _CfnLoader.add_constructor(_short, _cfn_tag_constructor(_fn))


def parse_cfn(text: str) -> dict[str, Any]:
    parsed = yaml.load(text, Loader=_CfnLoader)
    if not isinstance(parsed, dict):
        raise ValueError("CloudFormation template did not parse to a mapping")
    return parsed


def _iter_iam_statements(role_props: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for policy in role_props.get("Policies") or []:
        pname = policy.get("PolicyName", "<unnamed>")
        doc = policy.get("PolicyDocument") or {}
        stmts = doc.get("Statement") or []
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            out.append((pname, stmt))
    return out


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def validate_template(doc: dict[str, Any], raw_bytes: int, raw_text: str = "") -> list[str]:
    failures: list[str] = []

    if doc.get("AWSTemplateFormatVersion") != "2010-09-09":
        failures.append("AWSTemplateFormatVersion must be '2010-09-09'")
    if raw_bytes > MAX_DIRECT_UPLOAD_BYTES:
        failures.append(
            f"template size {raw_bytes} bytes exceeds direct-upload limit ({MAX_DIRECT_UPLOAD_BYTES} bytes)"
        )
    if re.search(r"\bami-[0-9a-f]{8,17}\b", raw_text):
        failures.append("hardcoded regional EC2 AMI ID (ami-*) is forbidden; use SSM Public Parameter")
    for section in ("Parameters", "Resources", "Outputs"):
        if not isinstance(doc.get(section), dict) or not doc[section]:
            failures.append(f"missing or empty top-level section {section}")

    params_sec: dict[str, Any] = doc.get("Parameters") or {}
    if isinstance(params_sec, dict):
        ami_param = params_sec.get("EksAl2023AmiId") or {}
        if ami_param.get("Type") != "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>":
            failures.append(
                "EksAl2023AmiId must have Type 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>'"
            )
        mode_param = params_sec.get("SandboxComputeMode") or {}
        if mode_param.get("Default") != "EksKvmStandard":
            failures.append("SandboxComputeMode must default to 'EksKvmStandard'")
        kvm_type = params_sec.get("KvmInstanceType") or {}
        if kvm_type.get("Default") not in {"m7i.4xlarge", "m8i.4xlarge"}:
            failures.append("KvmInstanceType must default to m7i.4xlarge or m8i.4xlarge")

    resources: dict[str, Any] = doc.get("Resources") or {}
    if not isinstance(resources, dict):
        return failures

    kms_keys = 0
    eks_clusters = 0
    rds_instances = 0
    launch_templates = 0
    vpc_cni_addons = 0
    pg_param_groups = 0
    kvm_asgs = 0
    kvm_access_entries = 0
    nested_virt_lt = False

    for logical_id, res in resources.items():
        if not isinstance(res, dict):
            failures.append(f"resource {logical_id} is not a mapping")
            continue
        rtype = res.get("Type")
        props = res.get("Properties") or {}

        if rtype == "AWS::KMS::Key":
            kms_keys += 1
            if props.get("EnableKeyRotation") is not True:
                failures.append(f"{logical_id}: EnableKeyRotation must be true")
            if res.get("DeletionPolicy") != "Retain" or res.get("UpdateReplacePolicy") != "Retain":
                failures.append(f"{logical_id}: KMS key must set DeletionPolicy and UpdateReplacePolicy to Retain")

        elif rtype == "AWS::SecretsManager::Secret":
            if not props.get("KmsKeyId"):
                failures.append(f"{logical_id}: Secret must specify KmsKeyId")
            if res.get("DeletionPolicy") != "Retain" or res.get("UpdateReplacePolicy") != "Retain":
                failures.append(f"{logical_id}: Secret must set DeletionPolicy and UpdateReplacePolicy to Retain")
            if logical_id in {"IdpSigningKekSecret", "TenantKekSecret"}:
                gen = props.get("GenerateSecretString") or {}
                excluded = set(str(gen.get("ExcludeCharacters") or ""))
                missing_non_hex = sorted(set("ghijklmnopqrstuvwxyz") - excluded)
                if (
                    gen.get("PasswordLength") != 64
                    or gen.get("ExcludePunctuation") is not True
                    or gen.get("ExcludeUppercase") is not True
                    or missing_non_hex
                ):
                    failures.append(
                        f"{logical_id}: KekKeyring::load requires [0-9a-f]{{64}} "
                        "(PasswordLength=64, ExcludePunctuation=true, ExcludeUppercase=true, "
                        "ExcludeCharacters covering g-z)"
                    )

        elif rtype == "AWS::EC2::LaunchTemplate":
            launch_templates += 1
            data = props.get("LaunchTemplateData") or {}
            meta = data.get("MetadataOptions") or {}
            if meta.get("HttpTokens") != "required":
                failures.append(f"{logical_id}: MetadataOptions.HttpTokens must be 'required'")
            if meta.get("HttpPutResponseHopLimit") != 1:
                failures.append(f"{logical_id}: MetadataOptions.HttpPutResponseHopLimit must be 1")
            bdms = data.get("BlockDeviceMappings") or []
            if not bdms:
                failures.append(f"{logical_id}: must declare encrypted EBS BlockDeviceMappings")
            for bdm in bdms:
                ebs = (bdm or {}).get("Ebs") or {}
                if ebs.get("Encrypted") is not True or not ebs.get("KmsKeyId"):
                    failures.append(f"{logical_id}: EBS volume must set Encrypted: true and KmsKeyId")
            cpu_opts = data.get("CpuOptions")
            if isinstance(cpu_opts, dict):
                if_branch = cpu_opts.get("Fn::If")
                if (
                    isinstance(if_branch, list)
                    and len(if_branch) == 3
                    and any(
                        isinstance(branch, dict) and branch.get("NestedVirtualization") == "enabled"
                        for branch in if_branch[1:]
                    )
                ):
                    nested_virt_lt = True
                elif cpu_opts.get("NestedVirtualization") == "enabled":
                    nested_virt_lt = True

        elif rtype == "AWS::AutoScaling::AutoScalingGroup":
            kvm_asgs += 1

        elif rtype == "AWS::EKS::AccessEntry":
            if props.get("Type") == "EC2_LINUX":
                kvm_access_entries += 1

        elif rtype == "AWS::RDS::DBParameterGroup":
            pg_param_groups += 1
            params = props.get("Parameters") or {}
            if str(params.get("rds.force_ssl")) != "1":
                failures.append(f"{logical_id}: rds.force_ssl must be '1'")
            if str(params.get("max_locks_per_transaction")) != "1024":
                failures.append(f"{logical_id}: max_locks_per_transaction must be '1024'")

        elif rtype == "AWS::RDS::DBInstance":
            rds_instances += 1
            if props.get("PubliclyAccessible") is not False:
                failures.append(f"{logical_id}: RDS PubliclyAccessible must be false")
            if props.get("StorageEncrypted") is not True or not props.get("KmsKeyId"):
                failures.append(f"{logical_id}: RDS StorageEncrypted must be true with KmsKeyId")
            if res.get("DeletionPolicy") not in {"Retain", "Snapshot"}:
                failures.append(f"{logical_id}: RDS DeletionPolicy must be Snapshot or Retain")

        elif rtype == "AWS::EKS::Cluster":
            eks_clusters += 1
            enc = props.get("EncryptionConfig") or []
            has_secrets_enc = any(
                isinstance(item, dict)
                and "secrets" in (item.get("Resources") or [])
                and bool((item.get("Provider") or {}).get("KeyArn"))
                for item in enc
            )
            if not has_secrets_enc:
                failures.append(f"{logical_id}: EKS EncryptionConfig must encrypt secrets with KMS")
            vpc_cfg = props.get("ResourcesVpcConfig") or {}
            if vpc_cfg.get("EndpointPrivateAccess") is not True:
                failures.append(f"{logical_id}: EKS EndpointPrivateAccess must be true")

        elif rtype == "AWS::EKS::Addon" and props.get("AddonName") == "vpc-cni":
            vpc_cni_addons += 1
            cfg_raw = props.get("ConfigurationValues") or "{}"
            try:
                cfg = json.loads(cfg_raw)
            except json.JSONDecodeError:
                failures.append(f"{logical_id}: vpc-cni ConfigurationValues is not valid JSON")
                cfg = {}
            if str(cfg.get("enableNetworkPolicy")).lower() != "true":
                failures.append(f"{logical_id}: vpc-cni must set enableNetworkPolicy=true")

        elif rtype == "AWS::IAM::Role":
            for pname, stmt in _iter_iam_statements(props):
                actions = [str(a).lower() for a in _as_list(stmt.get("Action"))]
                resources_list = _as_list(stmt.get("Resource"))
                if "*" in resources_list:
                    sensitive = [
                        a
                        for a in actions
                        if a.startswith(("secretsmanager:", "kms:", "route53:"))
                    ]
                    if sensitive:
                        failures.append(
                            f"{logical_id}/{pname}: wildcard Resource '*' is forbidden for {sensitive}"
                        )

    if kms_keys < 1:
        failures.append("template must define an AWS::KMS::Key")
    if eks_clusters < 1:
        failures.append("template must define an AWS::EKS::Cluster")
    if rds_instances < 1:
        failures.append("template must define an AWS::RDS::DBInstance")
    if pg_param_groups < 1:
        failures.append("template must define an AWS::RDS::DBParameterGroup")
    if launch_templates < 1:
        failures.append("template must define at least one AWS::EC2::LaunchTemplate")
    if vpc_cni_addons < 1:
        failures.append("template must define the vpc-cni AWS::EKS::Addon")
    if kvm_asgs < 1:
        failures.append("template must provision KVM sandbox nodes via AWS::AutoScaling::AutoScalingGroup")
    if kvm_access_entries < 1:
        failures.append("template must define an AWS::EKS::AccessEntry with Type EC2_LINUX for KVM ASG nodes")
    if not nested_virt_lt:
        failures.append("KVM LaunchTemplate must enable CpuOptions.NestedVirtualization for non-.metal instances")

    return failures


def validate_install_script(text: str) -> list[str]:
    failures: list[str] = []
    required_pins = (
        "AWS_LB_CONTROLLER_CHART_VERSION",
        "EXTERNAL_SECRETS_CHART_VERSION",
        "CERT_MANAGER_CHART_VERSION",
        "ENVOY_GATEWAY_CHART_VERSION",
    )
    for var in required_pins:
        if not re.search(rf'^readonly\s+{var}="[^"]+"', text, re.MULTILINE):
            failures.append(f"{INSTALL_SCRIPT_PATH}: missing pinned readonly {var}")
    if re.search(r"\bClusterSecretStore\b", text):
        failures.append(
            f"{INSTALL_SCRIPT_PATH}: unscoped ClusterSecretStore is forbidden; "
            "use a namespace-scoped SecretStore in ${NAMESPACE}"
        )
    if "kind: SecretStore" not in text:
        failures.append(f"{INSTALL_SCRIPT_PATH}: must declare a namespace-scoped SecretStore")
    if "wait --for=condition=Ready externalsecret --all" not in text:
        failures.append(f"{INSTALL_SCRIPT_PATH}: must wait for ExternalSecrets Ready before Helm install")
    return failures


def self_test() -> list[str]:
    failures: list[str] = []
    baseline = parse_cfn((ROOT / TEMPLATE_PATH).read_text(encoding="utf-8"))

    # 1. Hop-limit regression must fail.
    broken_imds = copy.deepcopy(baseline)
    broken_imds["Resources"]["SystemNodeLaunchTemplate"]["Properties"]["LaunchTemplateData"]["MetadataOptions"][
        "HttpPutResponseHopLimit"
    ] = 2
    if not validate_template(broken_imds, 1000):
        failures.append("self-test: HttpPutResponseHopLimit=2 was not rejected")

    # 2. Public RDS must fail.
    broken_rds = copy.deepcopy(baseline)
    broken_rds["Resources"]["DbInstance"]["Properties"]["PubliclyAccessible"] = True
    if not validate_template(broken_rds, 1000):
        failures.append("self-test: PubliclyAccessible=true on RDS was not rejected")

    # 3. Wildcard SecretsManager IAM must fail.
    broken_iam = copy.deepcopy(baseline)
    broken_iam["Resources"]["ExternalSecretsRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0][
        "Resource"
    ] = "*"
    if not validate_template(broken_iam, 1000):
        failures.append("self-test: wildcard Resource '*' for secretsmanager was not rejected")

    # 4. Missing KMS rotation must fail.
    broken_kms = copy.deepcopy(baseline)
    broken_kms["Resources"]["CodewireKmsKey"]["Properties"]["EnableKeyRotation"] = False
    if not validate_template(broken_kms, 1000):
        failures.append("self-test: EnableKeyRotation=false was not rejected")

    # 5. Missing install.sh pin must fail.
    if not validate_install_script("#!/usr/bin/env bash\n"):
        failures.append("self-test: unpinned install.sh was not rejected")

    # 6. Hardcoded regional AMI ID must fail.
    if not validate_template(baseline, 1000, raw_text="ImageId: ami-0123456789abcdef0\n"):
        failures.append("self-test: hardcoded ami-* ID was not rejected")

    # 7. Missing NestedVirtualization on KVM LaunchTemplate must fail.
    broken_nv = copy.deepcopy(baseline)
    broken_nv["Resources"]["KvmNodeLaunchTemplate"]["Properties"]["LaunchTemplateData"].pop("CpuOptions", None)
    if not validate_template(broken_nv, 1000):
        failures.append("self-test: missing CpuOptions.NestedVirtualization was not rejected")

    # 8. Non-hex KEK generator (missing ExcludeUppercase / g-z) must fail.
    broken_kek = copy.deepcopy(baseline)
    broken_kek["Resources"]["TenantKekSecret"]["Properties"]["GenerateSecretString"].pop("ExcludeUppercase", None)
    if not validate_template(broken_kek, 1000):
        failures.append("self-test: non-hex TenantKekSecret generator was not rejected")

    # 9. Unscoped ClusterSecretStore in install.sh must fail.
    bad_install = (ROOT / INSTALL_SCRIPT_PATH).read_text(encoding="utf-8").replace(
        "kind: SecretStore", "kind: ClusterSecretStore"
    )
    if not validate_install_script(bad_install):
        failures.append("self-test: unscoped ClusterSecretStore in install.sh was not rejected")

    return failures


def check_aws_eks_cfn(args: argparse.Namespace) -> int:
    if getattr(args, "self_test", False):
        if report("aws eks cfn", self_test()):
            return 1
        print("aws eks cfn: OK (self-test)")
        return 0

    template_file = ROOT / TEMPLATE_PATH
    install_file = ROOT / INSTALL_SCRIPT_PATH
    failures: list[str] = []

    if not template_file.exists():
        failures.append(f"missing {TEMPLATE_PATH}")
    else:
        raw = template_file.read_bytes()
        try:
            doc = parse_cfn(raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{TEMPLATE_PATH}: failed to parse YAML: {exc}")
        else:
            failures.extend(validate_template(doc, len(raw), raw.decode("utf-8")))

    if not install_file.exists():
        failures.append(f"missing {INSTALL_SCRIPT_PATH}")
    else:
        failures.extend(validate_install_script(install_file.read_text(encoding="utf-8")))

    if report("aws eks cfn", failures):
        return 1
    print(f"aws eks cfn: OK ({TEMPLATE_PATH}, {len(template_file.read_bytes())} bytes)")
    return 0
