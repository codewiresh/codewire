//! Exercise cleanup without a successful creation-time template lookup.

use super::*;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use serde_json::json;
use std::sync::{Arc, Mutex};

type Objects = BTreeMap<(String, String), Value>;

fn fixture(
    list_failure: bool,
    retain_owned: bool,
    replace_owned: bool,
) -> (SandboxClient, Arc<Mutex<Objects>>) {
    let mut initial = BTreeMap::new();
    for (plural, kind) in [
        ("sandboxtemplates", "SandboxTemplate"),
        ("sandboxwarmpools", "SandboxWarmPool"),
    ] {
        for environment in ["env-test", "env-foreign"] {
            let name = format!("{plural}-{environment}");
            initial.insert((plural.into(), name.clone()), json!({
                "apiVersion": super::super::EXTENSIONS_API_VERSION, "kind": kind,
                "metadata": {"name":name, "namespace":"dev-sandboxes", "uid":format!("uid-{name}"),
                    "labels":{LABEL_ENV_ID:environment}}
            }));
        }
    }
    let objects = Arc::new(Mutex::new(initial));
    let stored = objects.clone();
    let service = Router::new().fallback(move |request: Request<Body>| {
        let stored = stored.clone();
        async move {
            let uri = request.uri().clone();
            let method = request.method().clone();
            let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
            let body: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
            let path: Vec<_> = uri.path().split('/').filter(|part| !part.is_empty()).collect();
            assert!(path.contains(&"dev-sandboxes"), "cleanup escaped its namespace");
            let list = method == Method::GET && uri.query().is_some();
            let mut objects = stored.lock().unwrap();
            let (status, body) = if method == Method::POST {
                // Create: the fallback stores the object under its plural.
                let key = (path[path.len()-1].to_owned(), body["metadata"]["name"].as_str().unwrap().to_owned());
                match objects.entry(key) {
                    std::collections::btree_map::Entry::Occupied(_) => (StatusCode::CONFLICT, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"AlreadyExists","code":409})),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(body.clone());
                        (StatusCode::CREATED, body)
                    }
                }
            } else if list {
                let plural = *path.last().unwrap();
                if plural == "sandboxwarmpools" {
                    assert!(uri.query().unwrap().contains("labelSelector=codewire.sh%2Fenvironment-id%3Denv-test"));
                }
                // Identity-free templates carry no label: templates are
                // listed whole, and cleanup selects its own.
                if plural == "sandboxtemplates" {
                    assert!(!uri.query().unwrap().contains("labelSelector"));
                }
                if list_failure && plural == "sandboxtemplates" {
                    (StatusCode::FORBIDDEN, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}))
                } else {
                    // PVCs and templates are listed unfiltered: cleanup matches them itself.
                    let items: Vec<_> = objects.iter().filter(|((resource, _), value)| resource == plural && (matches!(plural, "persistentvolumeclaims" | "sandboxtemplates") || value["metadata"]["labels"][LABEL_ENV_ID] == "env-test")).map(|(_, value)| value.clone()).collect();
                    (StatusCode::OK, json!({"apiVersion":"v1","kind":"List","metadata":{},"items":items}))
                }
            } else {
                let key = (path[path.len()-2].to_owned(), path[path.len()-1].to_owned());
                if method == Method::DELETE && objects.contains_key(&key) {
                    assert!(!key.1.ends_with("env-foreign"), "cleanup selected a foreign environment");
                    if replace_owned {
                        let replacement = objects.get_mut(&key).unwrap();
                        replacement["metadata"]["uid"] = "foreign-replacement-uid".into();
                        replacement["metadata"]["labels"][LABEL_ENV_ID] = "env-foreign".into();
                    }
                    if body.pointer("/preconditions/uid").is_some_and(|uid| uid != &objects[&key]["metadata"]["uid"]) {
                        (StatusCode::CONFLICT, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Conflict","code":409}))
                    } else {
                        if !retain_owned { objects.remove(&key); }
                        (StatusCode::OK, json!({"apiVersion":"v1","kind":"Status","status":"Success","code":200}))
                    }
                } else if let Some(value) = objects.get(&key) {
                    (StatusCode::OK, value.clone())
                } else {
                    (StatusCode::NOT_FOUND, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}))
                }
            };
            Response::builder().status(status).header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()
        }
    });
    (
        SandboxClient::new(Client::new(service, "default"), "dev-sandboxes"),
        objects,
    )
}

#[tokio::test]
async fn cleanup_without_template_hint_discovers_owned_objects_and_preserves_foreign_objects() {
    let (client, objects) = fixture(false, false, false);
    let before = client
        .environment_residue("env-test", "", None, false)
        .await
        .unwrap();
    assert_eq!(
        before.resources,
        [
            "SandboxTemplate/sandboxtemplates-env-test",
            "SandboxWarmPool/sandboxwarmpools-env-test"
        ]
    );
    client
        .delete_environment_resources("env-test", "", None, false, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(
        client
            .environment_residue("env-test", "", None, false)
            .await
            .unwrap()
            .is_empty()
    );
    let retained = objects.lock().unwrap();
    assert_eq!(retained.len(), 2);
    assert!(
        retained
            .keys()
            .all(|(_, name)| name.ends_with("env-foreign"))
    );
}

#[tokio::test]
async fn cleanup_discovery_failure_and_retained_objects_cannot_prove_absence() {
    let (client, _) = fixture(true, false, false);
    assert!(
        client
            .environment_residue("env-test", "", None, false)
            .await
            .is_err()
    );
    assert!(
        client
            .delete_environment_resources("env-test", "", None, false, Duration::from_millis(1))
            .await
            .is_err()
    );
    let (client, _) = fixture(false, true, false);
    let error = client
        .delete_environment_resources("env-test", "", None, false, Duration::from_millis(1))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("timeout waiting for environment")
    );
}

#[tokio::test]
async fn cleanup_uid_fence_preserves_a_foreign_replacement() {
    let (client, objects) = fixture(false, false, true);
    assert!(
        client
            .delete_environment_resources("env-test", "", None, false, Duration::from_secs(1))
            .await
            .is_err()
    );
    let objects = objects.lock().unwrap();
    assert_eq!(objects.len(), 4);
    assert!(
        objects
            .values()
            .any(|value| value["metadata"]["uid"] == "foreign-replacement-uid")
    );
}

#[tokio::test]
async fn cleanup_name_hint_cannot_adopt_a_foreign_template() {
    let (client, objects) = fixture(false, false, false);
    assert!(
        client
            .environment_residue("env-test", "", Some("sandboxtemplates-env-foreign"), false)
            .await
            .is_err()
    );
    assert_eq!(objects.lock().unwrap().len(), 4);
}

fn insert_template(objects: &Arc<Mutex<Objects>>, name: &str) {
    objects.lock().unwrap().insert(
        ("sandboxtemplates".into(), name.into()),
        json!({"apiVersion": super::super::EXTENSIONS_API_VERSION, "kind": "SandboxTemplate",
            "metadata": {"name": name, "namespace": "dev-sandboxes", "uid": format!("uid-{name}")}}),
    );
}

/// #2831: destroy removes the environment's identity-free template (no
/// environment label) by its own name, even when the hint derived from the
/// preset's current image names another template, as after the preset's
/// image changed, or there is no hint, as after its configuration was
/// removed. Templates of other environments and shared pool templates stay,
/// and destroying again, with the template gone, succeeds.
#[tokio::test]
async fn destroy_removes_the_identity_free_template_whatever_its_preset_now_names() {
    for hint in [None, Some("codewire-workspace-sha256-0ce0c5eb-env-test")] {
        let (client, objects) = fixture(false, false, false);
        for name in [
            "workspace-env-test",
            "workspace-env-foreign",
            "cw-pool-500m-1024mi-5gi-0a1b2c3d",
        ] {
            insert_template(&objects, name);
        }
        let residue = client
            .environment_residue("env-test", "", hint, false)
            .await
            .unwrap();
        assert!(
            residue
                .resources
                .contains(&"SandboxTemplate/workspace-env-test".to_owned())
        );
        for _ in 0..2 {
            client
                .delete_environment_resources("env-test", "", hint, false, Duration::from_secs(1))
                .await
                .unwrap();
        }
        assert!(
            client
                .environment_residue("env-test", "", hint, false)
                .await
                .unwrap()
                .is_empty()
        );
        let remaining = objects.lock().unwrap();
        let templates: Vec<&str> = remaining
            .keys()
            .filter(|(resource, _)| resource == "sandboxtemplates")
            .map(|(_, name)| name.as_str())
            .collect();
        assert_eq!(
            templates,
            [
                "cw-pool-500m-1024mi-5gi-0a1b2c3d",
                "sandboxtemplates-env-foreign",
                "workspace-env-foreign"
            ]
        );
    }
}

/// Design §12: destroy's storage proof also counts the recorded workspace PVC
/// UID, so a restore-born PVC the fork has not adopted yet (no owner, no
/// environment label, only the tracking label) is deleted and proven gone. A
/// PVC with another UID is never selected by the recorded UID.
#[tokio::test]
async fn destroy_proves_the_recorded_workspace_pvc_gone_even_before_adoption() {
    let (client, objects) = fixture(false, false, false);
    for (name, uid) in [
        ("workspace-restored", "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c"),
        (
            "workspace-unrelated",
            "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d",
        ),
    ] {
        objects.lock().unwrap().insert(
            ("persistentvolumeclaims".into(), name.into()),
            json!({"apiVersion":"v1","kind":"PersistentVolumeClaim",
                "metadata":{"name":name,"namespace":"dev-sandboxes","uid":uid,
                    "labels":{"agents.x-k8s.io/sandbox-name-hash":"d0258436"}}}),
        );
    }
    let recorded = Some("9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c");
    let unscoped = client
        .environment_residue("env-test", "", None, false)
        .await
        .unwrap();
    assert!(
        !unscoped
            .resources
            .iter()
            .any(|resource| resource.starts_with("PersistentVolumeClaim/"))
    );
    let residue = client
        .environment_residue_with_recorded_storage("env-test", "", None, false, recorded)
        .await
        .unwrap();
    assert!(
        residue
            .resources
            .contains(&"PersistentVolumeClaim/workspace-restored".to_owned())
    );
    assert!(
        !residue
            .resources
            .contains(&"PersistentVolumeClaim/workspace-unrelated".to_owned())
    );
    client
        .delete_environment_resources_with_recorded_storage(
            "env-test",
            "",
            None,
            false,
            recorded,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    let remaining = objects.lock().unwrap();
    assert!(
        !remaining.contains_key(&("persistentvolumeclaims".into(), "workspace-restored".into()))
    );
    assert!(remaining.contains_key(&(
        "persistentvolumeclaims".into(),
        "workspace-unrelated".into()
    )));
}

fn insert_bridge(objects: &Arc<Mutex<Objects>>, environment: &str) {
    let name = warm_member_daemon_bridge_name(environment);
    objects.lock().unwrap().insert(
        ("networkpolicies".into(), name.clone()),
        json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
            "metadata":{"name":name,"namespace":"dev-sandboxes","uid":format!("uid-{name}"),
                "labels":{LABEL_ENV_ID:environment}}}),
    );
}

fn has_bridge(objects: &Arc<Mutex<Objects>>, environment: &str) -> bool {
    objects.lock().unwrap().contains_key(&(
        "networkpolicies".into(),
        warm_member_daemon_bridge_name(environment),
    ))
}

/// Program #2238 C6 (#2434): both bridge halves are environment residue and
/// leave with the gateway stack, which stop, destroy and every cleanup path
/// delete; a cold re-claim deletes them by name. Another environment's
/// bridge is never touched.
#[tokio::test]
async fn warm_member_bridge_is_residue_and_leaves_with_the_access_stack() {
    let (client, objects) = fixture(false, false, false);
    insert_bridge(&objects, "env-test");
    insert_bridge(&objects, "env-foreign");
    let residue = client
        .environment_residue("env-test", "", None, false)
        .await
        .unwrap();
    assert!(
        residue
            .resources
            .contains(&"NetworkPolicy/cw-daemon-warm-env-test".to_owned()),
        "the bridge is not residue: {:?}",
        residue.resources
    );
    client.delete_access_stack("env-test").await.unwrap();
    assert!(!has_bridge(&objects, "env-test"));
    assert!(has_bridge(&objects, "env-foreign"));

    insert_bridge(&objects, "env-test");
    client.delete_warm_member_bridge("env-test").await.unwrap();
    assert!(!has_bridge(&objects, "env-test"));
    // NotFound is success.
    client.delete_warm_member_bridge("env-test").await.unwrap();

    insert_bridge(&objects, "env-test");
    client
        .delete_environment_resources("env-test", "", None, false, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(!has_bridge(&objects, "env-test"));
    assert!(has_bridge(&objects, "env-foreign"));
}

/// The bridge is created only through the renderer: a recorded Sandbox UID
/// that is not a canonical UUID writes nothing, and unmanaged network
/// policies are left alone.
#[tokio::test]
async fn warm_member_bridge_applies_the_daemon_half_for_a_canonical_uid_only() {
    const ENVIRONMENT: &str = "be31063a-8ec8-46d5-aa17-75cda1729370";
    const SANDBOX: &str = "0b6f4a52-5d1e-4c2a-9a4e-3f1d2c7b8e90";
    let (client, objects) = fixture(false, false, false);
    let opts = TemplateOpts {
        environment_id: ENVIRONMENT.into(),
        organization_id: "org-test".into(),
        operation_generation: 7,
        server_namespace: "dev".into(),
        ..Default::default()
    };
    assert!(
        client
            .ensure_warm_member_bridge(&opts, "d0258436")
            .await
            .is_err()
    );
    let unmanaged = TemplateOpts {
        network_policy_management: "Unmanaged".into(),
        ..opts.clone()
    };
    client
        .ensure_warm_member_bridge(&unmanaged, SANDBOX)
        .await
        .unwrap();
    assert!(!has_bridge(&objects, ENVIRONMENT));
    client
        .ensure_warm_member_bridge(&opts, SANDBOX)
        .await
        .unwrap();
    assert!(has_bridge(&objects, ENVIRONMENT));
    let daemon = objects.lock().unwrap()[&(
        "networkpolicies".into(),
        warm_member_daemon_bridge_name(ENVIRONMENT),
    )]
        .clone();
    assert_eq!(
        daemon["spec"]["podSelector"],
        json!({"matchLabels": {"agents.x-k8s.io/sandbox-uid": SANDBOX, "codewire.sh/type": "workspace"}})
    );
}
