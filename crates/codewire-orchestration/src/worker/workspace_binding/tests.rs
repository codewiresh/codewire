use k8s_openapi::api::core::v1::{
    EnvVar, EnvVarSource, ObjectFieldSelector, PersistentVolumeClaimVolumeSource, PodSpec,
    PodStatus, ProjectedVolumeSource, ServiceAccountTokenProjection, Volume, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
use serde_json::json;

use super::*;

const POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const SANDBOX_UID: &str = "5a4db0c5-6d1e-4b0f-9b3c-2f0e7c1d9a11";
const WORKSPACE_IMAGE: &str = "registry.example.test/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const INIT_IMAGE: &str = "registry.example.test/codewire/gateway@sha256:2222222222222222222222222222222222222222222222222222222222222222";
const DIND_IMAGE: &str = "docker.io/library/docker:28-dind";
const DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";

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
        credential_scope(&legacy_pod(token_env())),
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
        credential_scope(&binding),
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
    assert_eq!(credential_scope(&both), None);
    assert_eq!(credential_scope(&legacy_pod(Vec::new())), None);
    let mut wrong_audience = legacy_pod(Vec::new());
    wrong_audience
        .spec
        .as_mut()
        .unwrap()
        .volumes
        .as_mut()
        .unwrap()
        .push(binding_volume(
            codewire_gateway_proto::CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
        ));
    assert_eq!(credential_scope(&wrong_audience), None);
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
        environment_scope_capture(&legacy_pod(rendered)),
        Some(CapturedBootstrap {
            operation_generation: 6,
            projection_selection_sha256: Some(DIGEST.into()),
            managed_credential_clients: github_clients().into(),
        })
    );
    // Without a projection there is no generation variable: the converged
    // generation label stands in, with no digest and no managed client.
    assert_eq!(
        environment_scope_capture(&legacy_pod(token_env())),
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
        assert_eq!(environment_scope_capture(&legacy_pod(rendered)), None);
    }
}

#[test]
fn images_must_equal_the_sandbox_template_and_pinned_digests() {
    let sandbox = sandbox();
    assert!(images_match(&sandbox, &legacy_pod(token_env())));

    let mut retagged = legacy_pod(token_env());
    retagged.spec.as_mut().unwrap().containers[1].image =
        Some("docker.io/library/docker:27-dind".into());
    assert!(!images_match(&sandbox, &retagged));

    let mut extra = legacy_pod(token_env());
    extra
        .spec
        .as_mut()
        .unwrap()
        .containers
        .push(container("sidecar", DIND_IMAGE, Vec::new()));
    assert!(!images_match(&sandbox, &extra));

    let mut other_init = legacy_pod(token_env());
    other_init.spec.as_mut().unwrap().init_containers = Some(Vec::new());
    assert!(!images_match(&sandbox, &other_init));

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
    assert!(!images_match(&sandbox, &stale));

    let mut unreported = legacy_pod(token_env());
    unreported.status.as_mut().unwrap().init_container_statuses = None;
    assert!(!images_match(&sandbox, &unreported));
}

#[test]
fn the_pod_must_still_be_the_observed_incarnation_and_mount_the_resolved_pvc() {
    let pod = legacy_pod(token_env());
    assert!(pod_still_observed(&pod, POD_UID, SANDBOX_UID));
    assert!(!pod_still_observed(&pod, SANDBOX_UID, SANDBOX_UID));
    assert!(!pod_still_observed(&pod, POD_UID, POD_UID));
    let mut terminating = legacy_pod(token_env());
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert!(!pod_still_observed(&terminating, POD_UID, SANDBOX_UID));
    let mut other_account = legacy_pod(token_env());
    other_account.spec.as_mut().unwrap().service_account_name = Some("default".into());
    assert!(!pod_still_observed(&other_account, POD_UID, SANDBOX_UID));

    let resolved = WorkspacePvc::Claim {
        name: "workspace-sandbox".into(),
        uid: POD_UID.into(),
        bound: true,
    };
    assert!(pvc_matches(&pod, &resolved));
    assert!(!pvc_matches(&pod, &WorkspacePvc::VolumeLess));
    assert!(!pvc_matches(
        &pod,
        &WorkspacePvc::Claim {
            name: "workspace-sandbox".into(),
            uid: POD_UID.into(),
            bound: false,
        }
    ));
    assert!(!pvc_matches(
        &pod,
        &WorkspacePvc::Claim {
            name: "workspace-other".into(),
            uid: POD_UID.into(),
            bound: true,
        }
    ));
    let mut volume_less = legacy_pod(token_env());
    volume_less.spec.as_mut().unwrap().volumes = None;
    assert!(pvc_matches(&volume_less, &WorkspacePvc::VolumeLess));
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
    let mut opts = crate::sandbox::template::TemplateOpts {
        operation_generation: 7,
        managed_credential_clients: none,
        ..Default::default()
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
