//! Pool-born Claim reads and the cold re-claim (Program #2238 C3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, Response, StatusCode};
use serde_json::json;

use super::*;

const NS: &str = "dev-sandboxes";
const ENV: &str = "3d6bb495-efac-419f-bf3a-91696e7c7ca4";
const CLAIM_UID: &str = "c0ffee00-efac-419f-bf3a-91696e7c7ca4";
const SANDBOX_UID: &str = "5a4db0c5-efac-419f-bf3a-91696e7c7ca4";
const POOL: &str = "cw-pool-1000m-4096mi-10gi-78909fe3";
const MEMBER: &str = "cw-pool-1000m-4096mi-10gi-78909fe3-x7k2p";

fn claim_path() -> String {
    format!("/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NS}/sandboxclaims/sandbox-{ENV}")
}

fn sandbox_path() -> String {
    format!("/apis/agents.x-k8s.io/v1beta1/namespaces/{NS}/sandboxes/{MEMBER}")
}

#[derive(Clone, Default)]
struct Api {
    objects: Arc<Mutex<HashMap<String, Value>>>,
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Api {
    fn pool_born(pool: &str) -> Self {
        let api = Self::default();
        api.objects.lock().unwrap().insert(
            claim_path(),
            json!({
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                "metadata": {"name": format!("sandbox-{ENV}"), "namespace": NS, "uid": CLAIM_UID,
                    "resourceVersion": "3", "finalizers": ["codewire.sh/deletion-protection", "other/keep"]},
                "spec": {"warmPoolRef": {"name": pool}},
                "status": {"sandbox": {"name": MEMBER}},
            }),
        );
        api.objects.lock().unwrap().insert(
            sandbox_path(),
            json!({
                "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                "metadata": {"name": MEMBER, "namespace": NS, "uid": SANDBOX_UID,
                    "ownerReferences": [{"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                        "kind": "SandboxClaim", "name": format!("sandbox-{ENV}"), "uid": CLAIM_UID,
                        "controller": true}]},
                "spec": {},
            }),
        );
        api
    }

    fn client(&self) -> SandboxClient {
        let api = self.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let api = api.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                api.requests
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone(), body.clone()));
                let mut objects = api.objects.lock().unwrap();
                let found = match method.as_str() {
                    "GET" => objects.get(&path).cloned(),
                    "DELETE" => {
                        let uid = objects
                            .get(&path)
                            .map(|object| object["metadata"]["uid"].clone());
                        match uid {
                            Some(uid) if body["preconditions"]["uid"] != uid => {
                                return status(StatusCode::CONFLICT, "Conflict");
                            }
                            _ => objects.remove(&path),
                        }
                    }
                    "PATCH" => {
                        let object = objects.get_mut(&path);
                        match object {
                            Some(object) => {
                                assert_eq!(body[0]["op"], "test");
                                assert_eq!(body[0]["path"], "/metadata/uid");
                                if body[0]["value"] != object["metadata"]["uid"] {
                                    return status(StatusCode::UNPROCESSABLE_ENTITY, "Invalid");
                                }
                                assert_eq!(body[1]["path"], "/metadata/finalizers");
                                object["metadata"]["finalizers"] = body[1]["value"].clone();
                                Some(object.clone())
                            }
                            None => None,
                        }
                    }
                    _ => None,
                };
                match found {
                    Some(object) => Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(object.to_string()))
                        .unwrap(),
                    None => status(StatusCode::NOT_FOUND, "NotFound"),
                }
            }
        });
        SandboxClient::new(Client::new(service, "default"), NS)
    }

    fn mutations(&self) -> Vec<(String, String, Value)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _, _)| method != "GET")
            .cloned()
            .collect()
    }
}

fn status(code: StatusCode, reason: &str) -> Response<Body> {
    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":reason,"code":code.as_u16()})
                .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn only_the_recorded_pool_born_claim_is_observed() {
    let api = Api::pool_born(POOL);
    let client = api.client();
    let observed = client.pool_born_claim(ENV, CLAIM_UID).await.unwrap();
    assert_eq!(
        observed,
        Some(PoolBornClaim {
            claim_uid: CLAIM_UID.into(),
            pool: POOL.into(),
            sandbox: Some((MEMBER.into(), SANDBOX_UID.into())),
        })
    );
    // A replaced Claim, or one that selects its environment shadow, is not.
    assert_eq!(
        client.pool_born_claim(ENV, SANDBOX_UID).await.unwrap(),
        None
    );
    let shadow = Api::pool_born("shadow-pool-workspace-3d6bb495-efac-419f-bf3a-91696e7c7ca4");
    assert_eq!(
        shadow
            .client()
            .pool_born_claim(ENV, CLAIM_UID)
            .await
            .unwrap(),
        None
    );
    // A Sandbox some other controller owns is refused.
    api.objects
        .lock()
        .unwrap()
        .get_mut(&sandbox_path())
        .unwrap()["metadata"]["ownerReferences"][0]["uid"] = json!("another-claim");
    assert!(client.pool_born_claim(ENV, CLAIM_UID).await.is_err());
    assert!(api.mutations().is_empty(), "observation never writes");
}

#[tokio::test]
async fn the_cold_reclaim_deletes_the_sandbox_and_claim_each_by_uid() {
    let api = Api::pool_born(POOL);
    let client = api.client();
    let observed = client
        .pool_born_claim(ENV, CLAIM_UID)
        .await
        .unwrap()
        .unwrap();
    client
        .delete_pool_born_claim(ENV, &observed, Duration::from_secs(5))
        .await
        .unwrap();
    let mutations = api.mutations();
    assert_eq!(mutations.len(), 3, "{mutations:?}");
    assert_eq!(mutations[0].0, "DELETE");
    assert_eq!(mutations[0].1, sandbox_path());
    assert_eq!(mutations[0].2["preconditions"]["uid"], SANDBOX_UID);
    assert_eq!(mutations[1].0, "PATCH");
    assert_eq!(mutations[1].2[1]["value"], json!(["other/keep"]));
    assert_eq!(mutations[2].0, "DELETE");
    assert_eq!(mutations[2].1, claim_path());
    assert_eq!(mutations[2].2["preconditions"]["uid"], CLAIM_UID);
    assert!(api.objects.lock().unwrap().is_empty());

    // A Claim replaced after the observation is never deleted or patched.
    let api = Api::pool_born(POOL);
    let client = api.client();
    let mut stale = client
        .pool_born_claim(ENV, CLAIM_UID)
        .await
        .unwrap()
        .unwrap();
    stale.claim_uid = "c0ffee00-0000-419f-bf3a-91696e7c7ca4".into();
    stale.sandbox = None;
    client
        .delete_pool_born_claim(ENV, &stale, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(api.mutations().is_empty());
    assert!(api.objects.lock().unwrap().contains_key(&claim_path()));
}
