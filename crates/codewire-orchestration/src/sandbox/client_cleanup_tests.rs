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
            let (status, body) = if list {
                let plural = *path.last().unwrap();
                if matches!(plural, "sandboxtemplates" | "sandboxwarmpools") {
                    assert!(uri.query().unwrap().contains("labelSelector=codewire.sh%2Fenvironment-id%3Denv-test"));
                }
                if list_failure && plural == "sandboxtemplates" {
                    (StatusCode::FORBIDDEN, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}))
                } else {
                    let items: Vec<_> = objects.iter().filter(|((resource, _), value)| resource == plural && value["metadata"]["labels"][LABEL_ENV_ID] == "env-test").map(|(_, value)| value.clone()).collect();
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
