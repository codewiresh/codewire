//! Real manager + inherited capability RPC + authenticated ingress + shared
//! frame driver. Git/bundle production is the existing synthetic child seam;
//! this does not claim a real provider checkout or Linux hardware acceptance.

use super::*;
use crate::{
    PlatformCredentialBinding, PlatformCredentialConnector, PlatformCredentialInput,
    PlatformCredentialOutput, RepositoryPlatformAccess,
};
use codewire_access::{AccessProfileId, EnvironmentId};
use codewire_daemon_proto::codewire::bridge::v1 as bridge;
use futures::{StreamExt as _, future::BoxFuture};
use tokio::time::Instant;

struct Closed(Arc<AtomicBool>);
impl Drop for Closed {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Connector {
    expected: RepositoryPlatformAccess,
    seen: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    withhold_end: bool,
}

impl PlatformCredentialConnector for Connector {
    fn connect(
        &self,
        binding: PlatformCredentialBinding,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<PlatformCredentialOutput, Status>> {
        assert_eq!(binding, self.expected.binding);
        assert_eq!(ready.environment_id, self.expected.environment_id.as_str());
        assert_eq!(ready.environment_generation, 1);
        assert_eq!(
            ready.protocol_version,
            codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        );
        assert!(Instant::now() < deadline);
        let seen = Arc::clone(&self.seen);
        let closed = Closed(Arc::clone(&self.closed));
        let withhold_end = self.withhold_end;
        Box::pin(async move {
            let output = futures::stream::unfold(
                (input, std::collections::VecDeque::new(), closed),
                move |(mut input, mut queued, closed)| {
                    let seen = Arc::clone(&seen);
                    async move {
                        if queued.is_empty() {
                            if withhold_end && seen.load(Ordering::Acquire) {
                                // The peer remains open forever. Only the
                                // retained local owner may terminate it.
                                std::future::pending::<()>().await;
                            }
                            let frame = input.next().await?.unwrap();
                            let Some(bridge::credential_bridge_guest_message::Payload::Request(
                                request,
                            )) = frame.payload
                            else {
                                panic!("only repository HTTP requests are admitted");
                            };
                            assert_eq!(request.capability_slot, "github");
                            assert_eq!(request.route, "github-https");
                            assert_eq!(request.path, "/codewire/codewire.git/info/refs");
                            assert_eq!(request.query, "service=git-upload-pack");
                            assert!(
                                request.headers.iter().all(|header| !header
                                    .name
                                    .eq_ignore_ascii_case("authorization"))
                            );
                            seen.store(true, Ordering::Release);
                            use bridge::credential_bridge_host_message::Payload;
                            queued.extend([
                                Payload::ResponseStart(bridge::CredentialBridgeResponseStart {
                                    request_id: request.request_id.clone(),
                                    status_code: 200,
                                    headers: Vec::new(),
                                }),
                                Payload::ResponseBody(bridge::CredentialBridgeResponseBody {
                                    request_id: request.request_id.clone(),
                                    data: b"PACK".to_vec(),
                                }),
                            ]);
                            if !withhold_end {
                                queued.push_back(Payload::ResponseEnd(
                                    bridge::CredentialBridgeResponseEnd {
                                        request_id: request.request_id,
                                    },
                                ));
                            }
                        }
                        Some((
                            Ok(bridge::CredentialBridgeHostMessage {
                                payload: queued.pop_front(),
                            }),
                            (input, queued, closed),
                        ))
                    }
                },
            );
            Ok(Box::pin(output) as PlatformCredentialOutput)
        })
    }
}

fn fixture(
    withhold_end: bool,
) -> (
    Fixture,
    RepositoryPlatformAccess,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
) {
    let mut fixture = Fixture::new();
    // This selected ID deliberately does not exist in the local authority.
    fixture.request.profile_id = AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap();
    fixture.request.profile_revision = 9;
    let selected = RepositoryPlatformAccess {
        environment_id: EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap(),
        environment_generation: 1,
        binding: PlatformCredentialBinding {
            config_directory: fixture._temp.path().join("platform"),
            server_url: "https://platform.invalid".into(),
            selection_sha256: [17; 32],
            selection: codewire_project::PlatformProjectionSelection {
                creator: "synthetic-owner".into(),
                organization: "synthetic-org".into(),
                organization_selected: false,
                user_selected: false,
                project_id: None,
                profile: Some((fixture.request.profile_id.to_string(), 9)),
                ordinary_keys: Default::default(),
                reserved_keys: ["CODEX_HOME".into()].into(),
            },
        },
    };
    let seen = Arc::new(AtomicBool::new(false));
    let closed = Arc::new(AtomicBool::new(false));
    Arc::get_mut(&mut fixture.manager)
        .unwrap()
        .platform_connector = Some(Arc::new(Connector {
        expected: selected.clone(),
        seen: Arc::clone(&seen),
        closed: Arc::clone(&closed),
        withhold_end,
    }));
    (fixture, selected, seen, closed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn platform_checkout_uses_exact_create_identity_and_never_the_local_profile_store() {
    let (mut fixture, selected, seen, closed) = fixture(false);
    let manager = Arc::clone(&fixture.manager);
    let request = fixture.request.clone();
    let waiter = tokio::spawn(async move { manager.prepare(request, Some(selected)).await });
    let child = fixture.child().await;
    assert!(seen.load(Ordering::Acquire));
    let staging = child.staging.clone();
    drop(child.exit_gate);
    let prepared = tokio::time::timeout(Duration::from_secs(3), waiter)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        closed.load(Ordering::Acquire),
        "owned bridge must close before output admission"
    );
    assert_eq!(prepared.metadata.branch, "main");
    assert!(prepared.metadata.bundle_size > 0);
    drop(prepared);
    fixture.shutdown().await;
    assert!(!staging.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_waiter_during_platform_body_drains_all_local_owners_without_bundle_admission() {
    let (mut fixture, selected, seen, closed) = fixture(true);
    let manager = Arc::clone(&fixture.manager);
    let request = fixture.request.clone();
    let waiter = tokio::spawn(async move { manager.prepare(request, Some(selected)).await });
    let mut child = tokio::time::timeout(Duration::from_secs(3), fixture.started.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), &mut child.streaming)
        .await
        .unwrap()
        .unwrap();
    assert!(seen.load(Ordering::Acquire));
    assert!(!closed.load(Ordering::Acquire));
    assert!(
        matches!(
            child.leased.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "response has no terminal frame"
    );
    waiter.abort();
    assert!(waiter.await.err().unwrap().is_cancelled());
    // Observe completion without sending manager shutdown: request drop alone
    // must trigger the retained child/channel/ingress cleanup.
    let drained = tokio::time::timeout(
        Duration::from_secs(3),
        Arc::clone(&fixture.manager.jobs).acquire_many_owned(MAX_REPOSITORY_JOBS),
    )
    .await
    .unwrap()
    .unwrap();
    drop(drained);
    assert!(
        closed.load(Ordering::Acquire),
        "request drop joins local bridge even while its remote peer stays open"
    );
    assert_reaped(&child);
    assert_eq!(
        fixture.manager.jobs.available_permits(),
        MAX_REPOSITORY_JOBS as usize
    );
    fixture.shutdown().await;
}
