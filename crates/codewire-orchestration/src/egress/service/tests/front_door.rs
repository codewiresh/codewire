//! `FrontDoorSession` (#4001): the Pod is checked before any relay work, the
//! session joins only its live binding's current epoch, and the epoch's
//! refusals reach cw-egress by their code alone.

use base64::engine::general_purpose::STANDARD;
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::Status;
use uuid::Uuid;

use super::*;
use crate::front_door::{BindingKey, FrontDoorEpochs, Join, Joined, Registration};
use crate::worker::environment_auth::WorkspaceCredentialScope;

const ENVIRONMENT: &str = "4b0f9a3e-2c41-4d7a-9a51-6f1f8d2b7c10";
const GENERATION: i64 = 5;
const GUEST_FRAME: &[u8] = b"\0\0\0\x03one";
const HOST_FRAME: &[u8] = b"\0\0\0\x03two";

struct Bound;

#[async_trait]
impl BindingStore for Bound {
    async fn live_binding(
        &self,
        pod_uid: &str,
        namespace: &str,
        pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(
            (pod_uid == GUEST_UID && namespace == SANDBOXES && pod_name == GUEST).then(|| {
                LiveBinding {
                    environment_id: ENVIRONMENT.into(),
                    pod_uid: GUEST_UID.into(),
                    namespace: SANDBOXES.into(),
                    pod_name: GUEST.into(),
                    claim_uid: "claim".into(),
                    sandbox_uid: "sandbox".into(),
                    operation_generation: GENERATION,
                    projection_selection_sha256: Some("ab".repeat(32)),
                    managed_credential_clients: String::new(),
                    credential_scope: WorkspaceCredentialScope::Pod,
                    environment_generation: 1,
                    isolation_tier: "standard".into(),
                    working_directory: String::new(),
                    defaults: None,
                }
            }),
        )
    }
}

fn key() -> BindingKey {
    BindingKey {
        environment_id: Uuid::parse_str(ENVIRONMENT).unwrap(),
        pod_uid: GUEST_UID.into(),
        generation: u64::try_from(GENERATION).unwrap(),
    }
}

fn open() -> Value {
    json!({"open": named_guest()})
}

fn bridge(frame: &[u8]) -> Value {
    json!({"bridge": STANDARD.encode(frame)})
}

/// Every message of a session that sends `frames`, ending with its
/// end-of-stream message.
async fn session(app: axum::Router, frames: &[Value]) -> Vec<Value> {
    let mut body = Vec::new();
    for frame in frames {
        let payload = serde_json::to_vec(frame).unwrap();
        body.push(0_u8);
        body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&payload);
    }
    let request = Request::post("/codewire.internal.v1.EgressService/FrontDoorSession")
        .header("content-type", "application/connect+json")
        .header(AUTHORIZATION, format!("Bearer {}", token()))
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
        .await
        .expect("the session ends")
        .unwrap()
        .to_bytes();
    let mut messages = Vec::new();
    let mut rest = &bytes[..];
    while rest.len() >= 5 {
        let length = frame_len(rest);
        messages.push(serde_json::from_slice(&rest[5..5 + length]).unwrap());
        rest = &rest[5 + length..];
    }
    messages
}

/// A registered epoch for `key`, and the joins it is asked.
fn epoch(
    front_doors: &Arc<FrontDoorEpochs>,
    key: BindingKey,
) -> (Registration, mpsc::Receiver<Join>) {
    let (joins, asked) = mpsc::channel(1);
    (front_doors.register(key, joins), asked)
}

fn refused(messages: &[Value]) -> &str {
    messages.last().unwrap()["error"]["code"]
        .as_str()
        .unwrap_or("none")
}

#[tokio::test]
async fn a_session_joins_its_pods_current_epoch_and_carries_frames_unchanged() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let epoch = tokio::spawn(async move {
        let Join { frames, reply } = asked.recv().await.unwrap();
        let joined = Joined {
            frames: futures::stream::iter([Ok(HOST_FRAME.to_vec())]).boxed(),
            session: CancellationToken::new().drop_guard(),
        };
        assert!(reply.send(Ok(joined)).is_ok());
        frames.collect::<Vec<_>>().await
    });
    let messages = session(
        app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
        &[open(), bridge(GUEST_FRAME)],
    )
    .await;
    assert_eq!(messages[0], json!({"attached": {}}), "{messages:?}");
    assert_eq!(messages[1], bridge(HOST_FRAME), "{messages:?}");
    assert_eq!(refused(&messages), "none", "{messages:?}");
    let guest = epoch.await.unwrap();
    assert_eq!(guest.len(), 1);
    assert_eq!(guest[0].as_ref().unwrap(), GUEST_FRAME);
}

#[tokio::test]
async fn a_pod_on_another_node_is_refused_before_any_relay_work() {
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| pod.spec.as_mut().unwrap().node_name = Some("runtime-b".into()));
    });
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(
        app_with(&cluster, Arc::new(Bound), Some(front_doors)),
        &[open()],
    )
    .await;
    assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
    assert!(asked.try_recv().is_err(), "the epoch was never asked");
}

#[tokio::test]
async fn a_pod_named_with_another_uid_is_refused_before_any_relay_work() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(
        app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
        &[json!({"open": {"podUid": "1d0c2b9a-0000-4000-8000-000000000000", "podName": GUEST}})],
    )
    .await;
    assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
    assert!(asked.try_recv().is_err(), "the epoch was never asked");
}

#[tokio::test]
async fn an_unbound_pod_is_refused_and_no_epoch_is_asked() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(
        app_with(&Cluster::healthy(), Arc::new(Unbound), Some(front_doors)),
        &[open()],
    )
    .await;
    assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
    assert!(asked.try_recv().is_err());
}

#[tokio::test]
async fn a_session_opens_first_and_only_once() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let app = || {
        app_with(
            &Cluster::healthy(),
            Arc::new(Bound),
            Some(Arc::clone(&front_doors)),
        )
    };
    let messages = session(app(), &[bridge(GUEST_FRAME)]).await;
    assert_eq!(refused(&messages), "failed_precondition", "{messages:?}");
    assert!(asked.try_recv().is_err());

    // A second open reaches the epoch as the end of the guest's frames.
    let epoch = tokio::spawn(async move {
        let Join { frames, reply } = asked.recv().await.unwrap();
        let joined = Joined {
            frames: futures::stream::empty().boxed(),
            session: CancellationToken::new().drop_guard(),
        };
        assert!(reply.send(Ok(joined)).is_ok());
        frames.collect::<Vec<_>>().await
    });
    session(app(), &[open(), bridge(GUEST_FRAME), open()]).await;
    let guest = epoch.await.unwrap();
    assert_eq!(guest[0].as_ref().unwrap(), GUEST_FRAME);
    assert_eq!(
        guest[1].as_ref().unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
}

#[tokio::test]
async fn without_an_epoch_for_the_pods_current_binding_cw_egress_retries() {
    // None at all, or only one for the binding's previous generation, which
    // the relay is about to replace.
    for registered in [
        None,
        Some(BindingKey {
            generation: 4,
            ..key()
        }),
    ] {
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let registered = registered.map(|key| epoch(&front_doors, key));
        let messages = session(
            app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
            &[open()],
        )
        .await;
        assert_eq!(refused(&messages), "unavailable", "{messages:?}");
        if let Some((_epoch, mut asked)) = registered {
            assert!(asked.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn an_epochs_refusal_reaches_cw_egress_by_its_code_alone() {
    for (status, code) in [
        (Status::already_exists("broker detail"), "already_exists"),
        (
            Status::permission_denied("broker detail"),
            "permission_denied",
        ),
        (Status::internal("broker detail"), "unavailable"),
    ] {
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let (_epoch, mut asked) = epoch(&front_doors, key());
        let epoch = tokio::spawn(async move {
            let Join { reply, .. } = asked.recv().await.unwrap();
            assert!(reply.send(Err(status)).is_ok());
        });
        let messages = session(
            app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
            &[open()],
        )
        .await;
        epoch.await.unwrap();
        assert_eq!(refused(&messages), code, "{messages:?}");
        assert!(
            !serde_json::to_string(&messages)
                .unwrap()
                .contains("broker detail"),
            "{messages:?}"
        );
    }
}

#[tokio::test]
async fn an_unlabelled_or_ending_pod_is_refused_before_any_relay_work() {
    for edit in [
        (|pod: &mut Pod| {
            pod.metadata
                .labels
                .as_mut()
                .unwrap()
                .remove(EGRESS_MODE_LABEL);
        }) as fn(&mut Pod),
        |pod: &mut Pod| {
            pod.metadata.deletion_timestamp =
                Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
                ))
        },
    ] {
        let cluster = Cluster::healthy().with(|cluster| cluster.edit_guest(edit));
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let (_epoch, mut asked) = epoch(&front_doors, key());
        let messages = session(
            app_with(&cluster, Arc::new(Bound), Some(front_doors)),
            &[open()],
        )
        .await;
        assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
        assert!(asked.try_recv().is_err(), "the epoch was never asked");
    }
}

#[tokio::test]
async fn the_relays_session_ends_when_cw_egress_stops_reading() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let session_ended = CancellationToken::new();
    let ended = session_ended.clone();
    tokio::spawn(async move {
        let Join { reply, .. } = asked.recv().await.unwrap();
        let joined = Joined {
            // A session that would serve for ever.
            frames: futures::stream::pending().boxed(),
            session: session_ended.drop_guard(),
        };
        assert!(reply.send(Ok(joined)).is_ok());
    });
    let request = Request::post("/codewire.internal.v1.EgressService/FrontDoorSession")
        .header("content-type", "application/connect+json")
        .header(AUTHORIZATION, format!("Bearer {}", token()))
        .body(Body::from({
            let payload = serde_json::to_vec(&open()).unwrap();
            let mut body = vec![0_u8];
            body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&payload);
            body
        }))
        .unwrap();
    let response = app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors))
        .oneshot(request)
        .await
        .unwrap();
    let mut body = response.into_body();
    // The attached frame arrives; then cw-egress goes away.
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .unwrap();
    assert!(first.is_some());
    assert!(!ended.is_cancelled());
    drop(body);
    tokio::time::timeout(Duration::from_secs(5), ended.cancelled())
        .await
        .expect("the relay's session ended with the stream");
}

#[tokio::test]
async fn a_relay_that_fails_mid_session_ends_it_cleanly() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    tokio::spawn(async move {
        let Join { reply, .. } = asked.recv().await.unwrap();
        let joined = Joined {
            frames: futures::stream::iter([
                Ok(HOST_FRAME.to_vec()),
                Err(Status::unavailable("broker detail")),
            ])
            .boxed(),
            session: CancellationToken::new().drop_guard(),
        };
        assert!(reply.send(Ok(joined)).is_ok());
    });
    let messages = session(
        app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
        &[open()],
    )
    .await;
    assert_eq!(messages[1], bridge(HOST_FRAME), "{messages:?}");
    assert_eq!(refused(&messages), "unavailable", "{messages:?}");
    assert!(
        !serde_json::to_string(&messages)
            .unwrap()
            .contains("broker detail")
    );
}
