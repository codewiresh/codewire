use k8s_openapi::api::core::v1::{
    EnvVar, EnvVarSource, ObjectFieldSelector, PersistentVolumeClaimVolumeSource, PodSpec,
    PodStatus, ProjectedVolumeSource, ServiceAccountTokenProjection, Volume, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
use serde_json::json;

use super::*;
use std::collections::BTreeMap;

use codewire_daemon_proto::{SANDBOX_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod};
use kube::api::DynamicObject;

use crate::sandbox::LABEL_OPERATION_GENERATION;

const POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const SANDBOX_UID: &str = "5a4db0c5-6d1e-4b0f-9b3c-2f0e7c1d9a11";
const WORKSPACE_IMAGE: &str = "registry.example.test/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const INIT_IMAGE: &str = "registry.example.test/codewire/daemon@sha256:2222222222222222222222222222222222222222222222222222222222222222";
const DIND_IMAGE: &str = "docker.io/library/docker:28-dind";
const DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// The facts a driver reads off `pod`.
fn facts(pod: &Pod) -> crate::runtime::MemberFacts {
    crate::runtime::kubernetes::observation::member_facts(pod).unwrap()
}

/// The facts a driver reads off `sandbox`.
fn runtime_of(sandbox: &DynamicObject) -> crate::runtime::RuntimeFacts {
    crate::runtime::kubernetes::observation::runtime_facts(sandbox).unwrap()
}

fn env(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: Some(value.into()),
        ..Default::default()
    }
}

fn container(name: &str, image: &str, env: Vec<EnvVar>) -> Container {
    Container {
        name: name.into(),
        image: Some(image.into()),
        env: Some(env),
        ..Default::default()
    }
}

fn status(name: &str, image_id: &str) -> ContainerStatus {
    ContainerStatus {
        name: name.into(),
        image_id: image_id.into(),
        ..Default::default()
    }
}

fn legacy_pod(workspace_env: Vec<EnvVar>) -> Pod {
    Pod {
        metadata: ObjectMeta {
            uid: Some(POD_UID.into()),
            labels: Some(BTreeMap::from([(
                LABEL_OPERATION_GENERATION.into(),
                "7".into(),
            )])),
            owner_references: Some(vec![OwnerReference {
                api_version: "agents.x-k8s.io/v1beta1".into(),
                kind: "Sandbox".into(),
                name: "sandbox".into(),
                uid: SANDBOX_UID.into(),
                controller: Some(true),
                ..Default::default()
            }]),
            ..Default::default()
        },
        spec: Some(PodSpec {
            service_account_name: Some(SANDBOX_SERVICE_ACCOUNT.into()),
            containers: vec![
                container("workspace", WORKSPACE_IMAGE, workspace_env),
                container("dind", DIND_IMAGE, Vec::new()),
            ],
            init_containers: Some(vec![container(
                "codewire-daemon-init",
                INIT_IMAGE,
                Vec::new(),
            )]),
            volumes: Some(vec![Volume {
                name: "workspace".into(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: "workspace-sandbox".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: Some(PodStatus {
            container_statuses: Some(vec![
                status("workspace", WORKSPACE_IMAGE),
                status(
                    "dind",
                    "docker.io/library/docker@sha256:4444444444444444444444444444444444444444444444444444444444444444",
                ),
            ]),
            init_container_statuses: Some(vec![status(
                "codewire-daemon-init",
                &format!("sha256:{}", "2".repeat(64)),
            )]),
            ..Default::default()
        }),
    }
}

fn github_clients() -> &'static str {
    codewire_access::ManagedCredentialClients::from_profile_slots(["github"])
        .unwrap()
        .encode()
}

fn token_env() -> Vec<EnvVar> {
    vec![env(DAEMON_AUTH_TOKEN_ENV, "synthetic-environment-token")]
}

fn sandbox() -> DynamicObject {
    serde_json::from_value(json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": { "name": "sandbox", "uid": SANDBOX_UID },
        "spec": { "podTemplate": { "spec": {
            "containers": [
                { "name": "workspace", "image": WORKSPACE_IMAGE },
                { "name": "dind", "image": DIND_IMAGE },
            ],
            "initContainers": [
                { "name": "codewire-daemon-init", "image": INIT_IMAGE },
            ],
        } } },
    }))
    .unwrap()
}

fn binding_volume(audience: &str) -> Volume {
    Volume {
        name: WORKSPACE_BINDING_VOLUME.into(),
        projected: Some(ProjectedVolumeSource {
            sources: Some(vec![VolumeProjection {
                service_account_token: Some(ServiceAccountTokenProjection {
                    audience: Some(audience.into()),
                    expiration_seconds: Some(600),
                    path: "token".into(),
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn the_credential_scope_follows_what_the_pod_was_rendered_with() {
    assert_eq!(
        credential_scope(&facts(&legacy_pod(token_env()))),
        Some(WorkspaceCredentialScope::Environment)
    );

    let mut binding = legacy_pod(Vec::new());
    binding
        .spec
        .as_mut()
        .unwrap()
        .volumes
        .as_mut()
        .unwrap()
        .push(binding_volume(WORKSPACE_BINDING_TOKEN_AUDIENCE));
    assert_eq!(
        credential_scope(&facts(&binding)),
        Some(WorkspaceCredentialScope::Pod)
    );

    // Both, neither, or a binding volume for another audience: refused.
    let mut both = legacy_pod(token_env());
    both.spec
        .as_mut()
        .unwrap()
        .volumes
        .as_mut()
        .unwrap()
        .push(binding_volume(WORKSPACE_BINDING_TOKEN_AUDIENCE));
    assert_eq!(credential_scope(&facts(&both)), None);
    assert_eq!(credential_scope(&facts(&legacy_pod(Vec::new()))), None);
    let mut wrong_audience = legacy_pod(Vec::new());
    wrong_audience
        .spec
        .as_mut()
        .unwrap()
        .volumes
        .as_mut()
        .unwrap()
        .push(binding_volume(
            codewire_daemon_proto::CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
        ));
    assert_eq!(credential_scope(&facts(&wrong_audience)), None);
}

#[test]
fn a_legacy_pod_records_what_it_was_rendered_with() {
    let mut rendered = token_env();
    rendered.extend([
        env(GENERATION_ENV, "6"),
        env(PROJECTION_SHA256_ENV, DIGEST),
        env(MANAGED_CLIENTS_ENV, github_clients()),
    ]);
    assert_eq!(
        environment_scope_capture(&facts(&legacy_pod(rendered))),
        Some(CapturedBootstrap {
            operation_generation: 6,
            projection_selection_sha256: Some(DIGEST.into()),
            managed_credential_clients: github_clients().into(),
        })
    );
    // Without a projection there is no generation variable: the converged
    // generation label stands in, with no digest and no managed client.
    assert_eq!(
        environment_scope_capture(&facts(&legacy_pod(token_env()))),
        Some(CapturedBootstrap {
            operation_generation: 7,
            projection_selection_sha256: None,
            managed_credential_clients: codewire_access::ManagedCredentialClients::default()
                .encode()
                .to_owned(),
        })
    );
}

#[test]
fn ambiguous_or_malformed_rendered_values_are_refused() {
    let from_field = EnvVar {
        name: MANAGED_CLIENTS_ENV.into(),
        value_from: Some(EnvVarSource {
            field_ref: Some(ObjectFieldSelector {
                field_path: "metadata.name".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    for invalid in [
        vec![env(GENERATION_ENV, "6"), env(GENERATION_ENV, "6")],
        vec![env(GENERATION_ENV, "0")],
        vec![env(GENERATION_ENV, "six")],
        vec![env(PROJECTION_SHA256_ENV, &"AB".repeat(32))],
        vec![env(PROJECTION_SHA256_ENV, "abc")],
        vec![env(MANAGED_CLIENTS_ENV, "not-a-client")],
        vec![from_field],
    ] {
        let mut rendered = token_env();
        rendered.extend(invalid);
        assert_eq!(
            environment_scope_capture(&facts(&legacy_pod(rendered))),
            None
        );
    }
}

#[test]
fn images_must_equal_the_sandbox_template_and_pinned_digests() {
    let sandbox = sandbox();
    assert!(images_match(
        &runtime_of(&sandbox),
        &facts(&legacy_pod(token_env()))
    ));

    let mut retagged = legacy_pod(token_env());
    retagged.spec.as_mut().unwrap().containers[1].image =
        Some("docker.io/library/docker:27-dind".into());
    assert!(!images_match(&runtime_of(&sandbox), &facts(&retagged)));

    let mut extra = legacy_pod(token_env());
    extra
        .spec
        .as_mut()
        .unwrap()
        .containers
        .push(container("sidecar", DIND_IMAGE, Vec::new()));
    assert!(!images_match(&runtime_of(&sandbox), &facts(&extra)));

    let mut other_init = legacy_pod(token_env());
    other_init.spec.as_mut().unwrap().init_containers = Some(Vec::new());
    assert!(!images_match(&runtime_of(&sandbox), &facts(&other_init)));

    // A pinned reference whose running digest differs is a stale member.
    let mut stale = legacy_pod(token_env());
    stale
        .status
        .as_mut()
        .unwrap()
        .container_statuses
        .as_mut()
        .unwrap()[0]
        .image_id = format!("registry.example.test/codewire/workspace@sha256:{DIGEST}");
    assert!(!images_match(&runtime_of(&sandbox), &facts(&stale)));

    let mut unreported = legacy_pod(token_env());
    unreported.status.as_mut().unwrap().init_container_statuses = None;
    assert!(!images_match(&runtime_of(&sandbox), &facts(&unreported)));
}

#[test]
fn the_pod_must_still_be_the_observed_incarnation_and_mount_the_resolved_pvc() {
    let pod = legacy_pod(token_env());
    assert!(member_still_observed(&facts(&pod), POD_UID, SANDBOX_UID));
    assert!(!member_still_observed(
        &facts(&pod),
        SANDBOX_UID,
        SANDBOX_UID
    ));
    assert!(!member_still_observed(&facts(&pod), POD_UID, POD_UID));
    let mut terminating = legacy_pod(token_env());
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert!(!member_still_observed(
        &facts(&terminating),
        POD_UID,
        SANDBOX_UID
    ));
    let mut other_account = legacy_pod(token_env());
    other_account.spec.as_mut().unwrap().service_account_name = Some("default".into());
    assert!(!member_still_observed(
        &facts(&other_account),
        POD_UID,
        SANDBOX_UID
    ));

    let resolved = WorkspacePvc::Claim {
        name: "workspace-sandbox".into(),
        uid: POD_UID.into(),
        bound: true,
    };
    assert!(volume_matches(&facts(&pod), &resolved));
    assert!(!volume_matches(&facts(&pod), &WorkspacePvc::VolumeLess));
    assert!(!volume_matches(
        &facts(&pod),
        &WorkspacePvc::Claim {
            name: "workspace-sandbox".into(),
            uid: POD_UID.into(),
            bound: false,
        }
    ));
    assert!(!volume_matches(
        &facts(&pod),
        &WorkspacePvc::Claim {
            name: "workspace-other".into(),
            uid: POD_UID.into(),
            bound: true,
        }
    ));
    let mut volume_less = legacy_pod(token_env());
    volume_less.spec.as_mut().unwrap().volumes = None;
    assert!(volume_matches(
        &facts(&volume_less),
        &WorkspacePvc::VolumeLess
    ));
}

#[test]
fn record_results_are_closed_categories() {
    for (result, label) in [
        (RecordResult::Recorded, "recorded"),
        (RecordResult::Unchanged, "unchanged"),
        (RecordResult::NotReady, "not_ready"),
        (RecordResult::Denied, "denied"),
        (RecordResult::Conflict, "conflict"),
        (RecordResult::Unavailable, "unavailable"),
    ] {
        assert_eq!(result.as_str(), label);
    }
}

#[test]
fn a_failing_environment_backs_off_exponentially_and_success_clears_it() {
    let mut backoffs = Backoffs::default();
    let start = Instant::now();
    assert!(backoffs.ready("env", start));
    backoffs.observe("env", RecordResult::Denied, start);
    assert!(!backoffs.ready("env", start + BACKOFF_BASE - Duration::from_secs(1)));
    assert!(backoffs.ready("env", start + BACKOFF_BASE));
    // Each further failure doubles the wait, up to the cap.
    let mut expected = BACKOFF_BASE;
    for result in [
        RecordResult::Unavailable,
        RecordResult::NotReady,
        RecordResult::Conflict,
    ] {
        backoffs.observe("env", result, start);
        expected = (expected * 2).min(BACKOFF_MAX);
        assert!(!backoffs.ready("env", start + expected - Duration::from_secs(1)));
        assert!(backoffs.ready("env", start + expected));
    }
    for _ in 0..40 {
        backoffs.observe("env", RecordResult::Denied, start);
    }
    assert!(backoffs.ready("env", start + BACKOFF_MAX));
    // Other environments are unaffected, and success forgets the failures.
    assert!(backoffs.ready("other", start));
    backoffs.observe("env", RecordResult::Unchanged, start);
    assert!(backoffs.ready("env", start));
    backoffs.observe("env", RecordResult::Denied, start);
    backoffs.observe("env", RecordResult::Recorded, start);
    assert!(backoffs.ready("env", start));
}

#[test]
fn the_backoff_table_stays_bounded() {
    let mut backoffs = Backoffs::default();
    let start = Instant::now();
    for index in 0..MAX_BACKOFF_ENTRIES + 10 {
        backoffs.observe(&format!("env-{index}"), RecordResult::Denied, start);
    }
    assert_eq!(backoffs.0.len(), MAX_BACKOFF_ENTRIES);
    // Expired entries make room again.
    backoffs.observe("late", RecordResult::Denied, start + BACKOFF_MAX);
    assert!(backoffs.0.len() <= MAX_BACKOFF_ENTRIES && backoffs.0.contains_key("late"));
}

fn environment_binding(generation: i64, digest: Option<&str>, clients: &str) -> EnvironmentBinding {
    EnvironmentBinding {
        pod_uid: POD_UID.into(),
        operation_generation: generation,
        projection_selection_sha256: digest.map(str::to_owned),
        managed_credential_clients: clients.into(),
        credential_scope: WorkspaceCredentialScope::Pod,
    }
}

/// Design §12: a bound identity-free runtime is stale when its binding row,
/// not its (absent) Pod environment, differs from the current template
/// options. The generation matters only while a projection is selected,
/// exactly as for the rendered check.
#[test]
fn a_bound_runtime_is_stale_only_when_its_captured_bootstrap_differs() {
    let none = codewire_access::ManagedCredentialClients::default();
    let github = codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap();
    let mut opts = crate::runtime::RenderingIdentity {
        environment_id: String::new(),
        organization_id: String::new(),
        operation_generation: 7,
        projection_selection_sha256: None,
        managed_credential_clients: none,
        source_snapshot_id: None,
        confidential_storage_manifest_uri: String::new(),
    };
    // No projection: a relabelled generation is still current.
    assert!(binding_bootstrap_current(
        &environment_binding(3, None, none.encode()),
        &opts
    ));
    assert!(!binding_bootstrap_current(
        &environment_binding(7, None, github.encode()),
        &opts
    ));
    assert!(!binding_bootstrap_current(
        &environment_binding(7, Some(DIGEST), none.encode()),
        &opts
    ));
    // A selected projection binds digest, clients and generation.
    let digest = [0x33; 32];
    opts.projection_selection_sha256 = Some(digest);
    opts.managed_credential_clients = github;
    assert!(binding_bootstrap_current(
        &environment_binding(7, Some(DIGEST), github.encode()),
        &opts
    ));
    assert!(!binding_bootstrap_current(
        &environment_binding(6, Some(DIGEST), github.encode()),
        &opts
    ));
    assert!(!binding_bootstrap_current(
        &environment_binding(7, None, github.encode()),
        &opts
    ));
    assert!(!binding_bootstrap_current(
        &environment_binding(7, Some(&"44".repeat(32)), github.encode()),
        &opts
    ));
    assert!(!binding_bootstrap_current(
        &environment_binding(7, Some(DIGEST), none.encode()),
        &opts
    ));
}

#[test]
fn enforced_refusals_are_value_blind_closed_categories() {
    for refused in [
        BindRefused::Denied("images"),
        BindRefused::BoundElsewhere,
        BindRefused::NotConverged,
        BindRefused::PodChanged,
        BindRefused::ChainUnverified,
    ] {
        let text = refused.to_string();
        assert!(
            !text.contains(POD_UID) && !text.contains(SANDBOX_UID),
            "{text}"
        );
    }
    let debug = format!("{:?}", environment_binding(7, Some(DIGEST), "v2:0"));
    assert!(!debug.contains(DIGEST));
}

#[test]
fn early_bind_polls_fast_only_while_a_warm_adoption_can_converge() {
    assert_eq!(early_bind_poll(Duration::ZERO), EARLY_BIND_FAST_POLL);
    assert_eq!(
        early_bind_poll(EARLY_BIND_FAST_WINDOW - Duration::from_millis(1)),
        EARLY_BIND_FAST_POLL
    );
    assert_eq!(early_bind_poll(EARLY_BIND_FAST_WINDOW), EARLY_BIND_POLL);
    assert_eq!(early_bind_poll(Duration::from_secs(30)), EARLY_BIND_POLL);
    assert!(EARLY_BIND_FAST_POLL < EARLY_BIND_POLL);
}

/// A confidential workspace Pod (B2c) as the controller creates it from the
/// rendering: the SEV-SNP runtime, the daemon copied by an init container
/// into an emptyDir, a block-mode RWOP claim and the measured anchors.
fn confidential_pod_and_sandbox() -> (Pod, DynamicObject) {
    use crate::sandbox::template::{
        RUNTIME_PROFILE_CONFIDENTIAL, TemplateOpts, render_sandbox_template,
    };
    let opts = TemplateOpts {
        name: "workspace-confidential".into(),
        image: WORKSPACE_IMAGE.into(),
        support_image: INIT_IMAGE.into(),
        dind_image: DIND_IMAGE.into(),
        runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
        environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
        workspace_binding_url: "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087"
                    .into(),
        measured_binding_roots:
            "-----BEGIN CERTIFICATE-----\nMIIBsynthetic\n-----END CERTIFICATE-----\n".into(),
        confidential_storage_manifest_uri: "kbs:///default/codewire-storage-manifests/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        disk_gib: 20,
        kata_coco_init_data_enabled: true,
        kata_coco_kbs_url: "https://kbs.example.test".into(),
        server_namespace: "dev".into(),
        ..Default::default()
    };
    let rendered = render_sandbox_template("dev-sandboxes", &opts);
    let mut spec = rendered["spec"]["podTemplate"]["spec"].clone();
    // The controller adds the workspace claim from the claim template.
    spec["volumes"].as_array_mut().unwrap().push(json!({
        "name": "workspace",
        "persistentVolumeClaim": { "claimName": "workspace-sandbox" },
    }));
    let mut pod = legacy_pod(Vec::new());
    pod.spec = Some(serde_json::from_value(spec.clone()).unwrap());
    let sandbox = serde_json::from_value(json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": { "name": "sandbox", "uid": SANDBOX_UID },
        "spec": { "podTemplate": { "spec": rendered["spec"]["podTemplate"]["spec"].clone() } },
    }))
    .unwrap();
    (pod, sandbox)
}

#[test]
fn a_confidential_pod_binds_with_pod_scope_like_a_standard_one() {
    let (pod, sandbox) = confidential_pod_and_sandbox();
    let spec = pod.spec.as_ref().unwrap();
    assert_eq!(spec.runtime_class_name.as_deref(), Some("confidential"));
    // The binding token and no environment token: Pod scope, which 8087
    // binds, records a host key for and serves access to.
    assert_eq!(
        credential_scope(&facts(&pod)),
        Some(WorkspaceCredentialScope::Pod)
    );
    // The init container's support image counts like any other image, and the
    // kubelet-reported digests must match the pinned references.
    assert!(images_match(&runtime_of(&sandbox), &facts(&pod)));
    let mut substituted = pod.clone();
    substituted.spec.as_mut().unwrap().init_containers.as_mut().unwrap()[0].image = Some(
        "registry.example.test/codewire/gateway@sha256:5555555555555555555555555555555555555555555555555555555555555555"
            .into(),
    );
    assert!(!images_match(&runtime_of(&sandbox), &facts(&substituted)));
    // A block-mode claim attached as a device still resolves by its volume.
    assert!(volume_matches(
        &facts(&pod),
        &WorkspacePvc::Claim {
            name: "workspace-sandbox".into(),
            uid: POD_UID.into(),
            bound: true,
        }
    ));
    assert!(member_still_observed(&facts(&pod), POD_UID, SANDBOX_UID));
    // A confidential Pod that still carried the environment token would be
    // ambiguous and refused, never bound.
    let mut both = pod.clone();
    both.spec.as_mut().unwrap().containers[0]
        .env
        .as_mut()
        .unwrap()
        .push(env(DAEMON_AUTH_TOKEN_ENV, "synthetic-environment-token"));
    assert_eq!(credential_scope(&facts(&both)), None);
}
