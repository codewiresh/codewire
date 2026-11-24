use std::collections::HashSet;

use axum::body::Body;
use axum::http::{Request, Response};
use serde_json::json;

use super::*;

const NAMESPACE: &str = "dev-sandboxes";

/// The sandbox namespace's Pods through `client`.
pub(super) fn pods(client: kube::Client) -> Api<Pod> {
    Api::namespaced(client, NAMESPACE)
}

/// An API server that answers every request with `status`.
pub(super) fn failing(status: u16) -> kube::Client {
    kube::Client::new(
        tower::service_fn(move |_: Request<kube::client::Body>| async move {
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(status)
                    .body(Body::from(
                        json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": status})
                            .to_string(),
                    ))
                    .unwrap(),
            )
        }),
        NAMESPACE,
    )
}

fn page(uids: &[&str], next: Option<&str>) -> String {
    json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "PartialObjectMetadataList",
        "metadata": {"continue": next.unwrap_or_default()},
        "items": uids.iter().map(|uid| json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadata",
            "metadata": {"name": format!("pod-{uid}"), "namespace": NAMESPACE, "uid": uid},
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

/// An API server with two pages of Pods; the second page's request fails
/// with `second_status` when it is not 200.
fn paged(second_status: u16) -> kube::Client {
    kube::Client::new(
        tower::service_fn(move |request: Request<kube::client::Body>| async move {
            let query = request.uri().query().unwrap_or_default().to_owned();
            let response = if query.contains("continue=next") {
                if second_status == 200 {
                    Response::builder().body(Body::from(page(&["uid-c"], None)))
                } else {
                    Response::builder().status(second_status).body(Body::from(
                        json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": second_status})
                            .to_string(),
                    ))
                }
            } else {
                Response::builder().body(Body::from(page(&["uid-a", "uid-b"], Some("next"))))
            };
            Ok::<_, std::convert::Infallible>(response.unwrap())
        }),
        NAMESPACE,
    )
}

/// Every page is read, and the UIDs of all of them are the list.
#[tokio::test]
async fn the_list_reads_every_page() {
    let uids = live_pod_uids(&pods(paged(200))).await.unwrap();
    let expected: HashSet<String> = ["uid-a", "uid-b", "uid-c"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(uids, expected);
}

/// A failed page, an expired continuation (410) included, fails the whole
/// list, so a sweep never deletes from part of it.
#[tokio::test]
async fn a_failed_page_fails_the_whole_list() {
    for status in [500, 410, 403] {
        assert!(
            live_pod_uids(&pods(paged(status))).await.is_err(),
            "{status}"
        );
        assert!(
            live_pod_uids(&pods(failing(status))).await.is_err(),
            "{status}"
        );
    }
}
