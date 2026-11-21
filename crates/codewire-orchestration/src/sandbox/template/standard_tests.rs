//! The `standard` workspace Pod against its contract: `SPEC.md` section 4,
//! "The `standard` profile" in `docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`,
//! and the settings `cw __pod-runtime` reads.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;

const NAMESPACE: &str = "dev-sandboxes";
const RUNTIME_IMAGE: &str = "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const IMAGE_DISK: &str = "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222";
const IMAGE_DISK_ID: &str = "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";
const BUILD_ID: &str = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";
const WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:5555555555555555555555555555555555555555555555555555555555555555";
const ENVIRONMENT_ID: &str = "be31063a-8ec8-46d5-aa17-75cda1729370";
const ORGANIZATION_ID: &str = "0b6f0c55-3a9e-4f3e-9c55-9f6a3c1d2e7f";

fn runtime() -> StandardRuntime {
    StandardRuntime::parse(
        RUNTIME_IMAGE,
        &format!("{IMAGE_DISK} {IMAGE_DISK_ID} {BUILD_ID} {WORKSPACE_IMAGE}"),
    )
    .unwrap()
    .unwrap()
}

fn egress() -> HostedEgressTemplate {
    crate::egress::gateway_check::assume_verified();
    HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: "2".into(),
        gateway: GatewayPeer {
            namespace: "gateway-proxies".into(),
            gateway_name: "public".into(),
            gateway_namespace: "gateway".into(),
            port: 10443,
        },
        derp_tls_port: 8443,
        gateway_addr: "10.44.0.43:443".into(),
        derp_addr: "derp.codewire-dev.sh=10.44.0.84:8443".into(),
        cluster_dns_ip: "10.44.0.10".into(),
    }
}

fn opts() -> TemplateOpts {
    TemplateOpts {
        name: "tmpl-standard".into(),
        environment_id: ENVIRONMENT_ID.into(),
        organization_id: ORGANIZATION_ID.into(),
        image: "registry.example.invalid/codewire/workspace@sha256:6666666666666666666666666666666666666666666666666666666666666666".into(),
        support_image: TEST_SUPPORT_IMAGE.into(),
        runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
        workspace_binding_url: "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087".into(),
        server_namespace: "dev".into(),
        cpu_millicores: 1500,
        memory_mib: 4096,
        disk_gib: 20,
        workspace_storage_class: "example-workspace-class".into(),
        hosted_egress: Some(egress()),
        standard_runtime: Some(runtime()),
        ..Default::default()
    }
}

fn pod(template: &Value) -> &Value {
    &template["spec"]["podTemplate"]["spec"]
}

fn workspace(template: &Value) -> &Value {
    &pod(template)["containers"][0]
}

fn env(template: &Value) -> BTreeMap<String, Value> {
    workspace(template)["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let value = entry
                .get("value")
                .cloned()
                .unwrap_or_else(|| entry["valueFrom"].clone());
            (entry["name"].as_str().unwrap().to_owned(), value)
        })
        .collect()
}

#[test]
fn a_standard_workspace_is_one_unprivileged_container_of_the_runtime_image() {
    let template = render_sandbox_template(NAMESPACE, &opts());
    let pod = pod(&template);
    let containers = pod["containers"].as_array().unwrap();
    assert_eq!(containers.len(), 1, "one container, and no dind");
    let workspace = &containers[0];
    assert_eq!(workspace["name"], "workspace");
    assert_eq!(workspace["image"], RUNTIME_IMAGE);
    // The image's own entrypoint, which admission pins.
    assert!(workspace.get("command").is_none() && workspace.get("args").is_none());
    assert!(pod.get("initContainers").is_none());
    assert_eq!(pod["runtimeClassName"], "standard");
    assert_eq!(
        pod["securityContext"],
        json!({
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "runAsNonRoot": true,
            "fsGroup": 1000,
            "fsGroupChangePolicy": "OnRootMismatch",
            "seccompProfile": { "type": "RuntimeDefault" },
        })
    );
    assert_eq!(
        workspace["securityContext"],
        json!({ "allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"] } })
    );
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["terminationGracePeriodSeconds"], 60);
    // The Pod resolves nothing.
    assert_eq!(pod["dnsPolicy"], "None");
    assert_eq!(
        workspace["readinessProbe"]["exec"]["command"][2],
        "test -f /codewire/run/daemon/ready"
    );
}

#[test]
fn a_standard_workspace_mounts_only_its_claim_its_image_disk_its_tokens_and_roots() {
    let template = render_sandbox_template(NAMESPACE, &opts());
    let pod = pod(&template);
    let volumes: BTreeMap<&str, &Value> = pod["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|volume| (volume["name"].as_str().unwrap(), volume))
        .collect();
    assert_eq!(
        volumes.keys().copied().collect::<Vec<_>>(),
        [
            "codewire-run",
            "image-disk",
            "orchestration-internal-roots",
            "workspace-binding-identity",
            "workspace-egress-identity",
        ]
    );
    assert_eq!(
        volumes["image-disk"]["image"],
        json!({ "reference": IMAGE_DISK, "pullPolicy": "IfNotPresent" })
    );
    assert_eq!(volumes["codewire-run"]["emptyDir"]["medium"], "Memory");
    let mounts: BTreeMap<&str, &Value> = workspace(&template)["volumeMounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mount| (mount["mountPath"].as_str().unwrap(), mount))
        .collect();
    assert_eq!(mounts["/state"]["name"], "workspace");
    assert_eq!(
        *mounts["/image"],
        json!({ "name": "image-disk", "mountPath": "/image", "readOnly": true })
    );
    assert_eq!(mounts["/codewire/run"]["name"], "codewire-run");
    // No TUN: the VM has no network device.
    assert!(!template.to_string().contains("egress-devnet"));
    // The claim is a filesystem: the VM's disks are files on it.
    let claim = &template["spec"]["volumeClaimTemplates"][0]["spec"];
    assert_eq!(claim["resources"]["requests"]["storage"], "20Gi");
    assert!(claim.get("volumeMode").is_none());
}

#[test]
fn a_standard_workspace_requests_the_users_size_and_limits_hold_its_vm_process() {
    let template = render_sandbox_template(NAMESPACE, &opts());
    let resources = &workspace(&template)["resources"];
    assert_eq!(resources["requests"]["cpu"], "1500m");
    assert_eq!(resources["requests"]["memory"], "4096Mi");
    assert_eq!(resources["limits"]["cpu"], "2500m");
    assert_eq!(resources["limits"]["memory"], "5120Mi");
    assert_eq!(resources["limits"]["codewire.sh/kvm"], "1");
    assert!(resources["requests"].get("codewire.sh/kvm").is_none());
}

#[test]
fn a_standard_workspace_hands_cw_pod_runtime_its_settings_by_their_names() {
    let template = render_sandbox_template(NAMESPACE, &opts());
    let env = env(&template);
    for (name, value) in [
        ("CODEWIRE_VM_VCPUS", "2"),
        ("CODEWIRE_VM_MEMORY_MIB", "4096"),
        // 20 GiB less 7%, 256 MiB and the 4 GiB root disk, whole MiB.
        ("CODEWIRE_VM_STATE_DISK_MIB", "14694"),
        ("CODEWIRE_WORKSPACE_IMAGE", WORKSPACE_IMAGE),
        ("CODEWIRE_IMAGE_DISK_ID", IMAGE_DISK_ID),
        ("CODEWIRE_IMAGE_DISK_BUILD_ID", BUILD_ID),
        (
            "CODEWIRE_POD_PLATFORM_PEERS",
            "10.44.0.89:8089,10.44.0.87:8087,10.44.0.43:443,10.44.0.84:8443",
        ),
        // The daemon's own, as a Kata broker workspace gets them.
        ("CODEWIRE_DERP_ADDR", "derp.codewire-dev.sh=10.44.0.84:8443"),
        ("CODEWIRE_EGRESS_STREAM_ADDR", "10.44.0.89:8089"),
        ("CODEWIRE_WORKSPACE_SHIM_ADDR", "0.0.0.0:7777"),
    ] {
        assert_eq!(env[name], value, "{name}");
    }
    assert_eq!(
        env["CODEWIRE_POD_UID"],
        json!({ "fieldRef": { "fieldPath": "metadata.uid" } })
    );
    // Docker is the guest's own.
    assert!(!env.contains_key("DOCKER_HOST"));
}

#[test]
fn a_standard_workspace_is_identity_free() {
    let opts = opts();
    let text = render_sandbox_template(NAMESPACE, &opts).to_string();
    for forbidden in [
        "CODEWIRE_ENVIRONMENT_ID",
        "codewire.sh/environment-id",
        ENVIRONMENT_ID,
        ORGANIZATION_ID,
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn a_standard_rendering_is_refused_without_its_network_its_runtime_or_a_size_its_vm_takes() {
    assert!(opts().validate_standard_runtime().is_ok());
    let refused = |opts: TemplateOpts| opts.validate_standard_runtime().is_err();
    assert!(refused(TemplateOpts {
        hosted_egress: None,
        ..opts()
    }));
    assert!(refused(TemplateOpts {
        standard_runtime: None,
        ..opts()
    }));
    assert!(refused(TemplateOpts {
        disk_gib: 7,
        ..opts()
    }));
    assert!(
        TemplateOpts {
            disk_gib: 8,
            ..opts()
        }
        .validate_standard_runtime()
        .is_ok()
    );
    assert!(refused(TemplateOpts {
        cpu_millicores: 32_001,
        ..opts()
    }));
    assert!(refused(TemplateOpts {
        memory_mib: 65_537,
        ..opts()
    }));
    for peer in [
        "127.0.0.1:8089",
        "169.254.169.254:80",
        "codewire-egress:8089",
    ] {
        let mut egress = egress();
        egress.stream_addr = peer.into();
        assert!(
            refused(TemplateOpts {
                hosted_egress: Some(egress),
                ..opts()
            }),
            "{peer}"
        );
    }
    // Another profile is not this check's to refuse.
    assert!(
        TemplateOpts {
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            standard_runtime: None,
            ..opts()
        }
        .validate_standard_runtime()
        .is_ok()
    );
}

#[test]
fn standard_runtime_settings_are_both_or_neither_and_pinned_by_digest() {
    assert_eq!(StandardRuntime::parse("", " "), Ok(None));
    let line = format!("{IMAGE_DISK} {IMAGE_DISK_ID} {BUILD_ID} {WORKSPACE_IMAGE}");
    assert!(
        StandardRuntime::parse(RUNTIME_IMAGE, &line)
            .unwrap()
            .is_some()
    );
    for (image, disk) in [
        (RUNTIME_IMAGE, String::new()),
        ("", line.clone()),
        ("registry.example.invalid/codewire/runtime:1", line.clone()),
        (
            RUNTIME_IMAGE,
            format!("{IMAGE_DISK} {IMAGE_DISK_ID} {BUILD_ID}"),
        ),
        (
            RUNTIME_IMAGE,
            format!(
                "{IMAGE_DISK} {} {BUILD_ID} {WORKSPACE_IMAGE}",
                IMAGE_DISK_ID.to_uppercase()
            ),
        ),
        (
            RUNTIME_IMAGE,
            format!(
                "{IMAGE_DISK} {IMAGE_DISK_ID} {BUILD_ID} registry.example.invalid/codewire/workspace:1"
            ),
        ),
    ] {
        assert!(
            StandardRuntime::parse(image, &disk).is_err(),
            "{image} {disk}"
        );
    }
}

/// The template the class's admission rule is tested against
/// (`scripts/ci/verify/kyverno-pods-from-goldens.py`).
#[test]
fn a_standard_template_matches_its_golden_file() {
    crate::test_golden::assert_golden(
        "standard-sandboxtemplate.golden.json",
        &render_sandbox_template(NAMESPACE, &opts()),
    );
}
