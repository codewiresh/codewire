use super::*;
use crate::credential_bridge::CredentialBridge;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

pub(crate) fn config(root: &Path) -> crate::Config {
    for name in ["state", "home", "workspace"] {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root.join(name))
            .unwrap();
    }
    crate::Config {
        listen_addr: String::new(),
        workspace_root: root.join("workspace"),
        home_root: root.join("home"),
        mount_roots: Vec::new(),
        auth_token: crate::DaemonAuthToken::new("synthetic-host-control-owner").unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        launch_projection: None,
        host: Some(crate::HostConfig {
            state_root: root.join("state"),
        }),
        session_working_dir: None,
    }
}

pub(crate) fn scope() -> Scope {
    Scope {
        environment_id: Uuid::from_u128(1).to_string(),
        org_id: "synthetic-org".into(),
        network_id: "synthetic-network".into(),
        caller_key: [1; 32],
        target_key: [2; 32],
        grant_id: Uuid::from_u128(2).to_string(),
        grant_revision: 1,
    }
}

pub(crate) fn grant(scope: &Scope, expected_book_revision: u64) -> v1::HostControlPutGrantRequest {
    v1::HostControlPutGrantRequest {
        expected_book_revision,
        grant: Some(v1::HostControlGrant {
            environment_id: scope.environment_id.clone(),
            grant_id: scope.grant_id.clone(),
            org_id: scope.org_id.clone(),
            network_id: scope.network_id.clone(),
            caller_key: scope.caller_key.to_vec(),
            target_key: scope.target_key.to_vec(),
            revision: 0,
            revoked: false,
            verbs: vec![1, 2, 3, 4],
        }),
    }
}

pub(crate) fn launch(id: u128, scope: &Scope, script: &str) -> Mutation {
    Mutation::from_wire(v1::HostControlMutationRequest {
        request_id: Uuid::from_u128(id).to_string(),
        scope: Some(scope.to_wire()),
        operation: Some(v1::host_control_mutation_request::Operation::Launch(
            v1::HostControlLaunch {
                command: vec!["/bin/sh".into(), "-c".into(), script.into()],
                ..Default::default()
            },
        )),
    })
    .unwrap()
}

pub(crate) fn input(
    id: u128,
    scope: &Scope,
    session: &str,
    generation: u64,
    data: &[u8],
) -> Mutation {
    Mutation::from_wire(v1::HostControlMutationRequest {
        request_id: Uuid::from_u128(id).to_string(),
        scope: Some(scope.to_wire()),
        operation: Some(v1::host_control_mutation_request::Operation::Input(
            v1::HostControlInput {
                session_id: session.into(),
                expected_launch_generation: generation,
                data: data.into(),
            },
        )),
    })
    .unwrap()
}

pub(crate) fn stop(id: u128, scope: &Scope, session: &str, generation: u64) -> Mutation {
    Mutation::from_wire(v1::HostControlMutationRequest {
        request_id: Uuid::from_u128(id).to_string(),
        scope: Some(scope.to_wire()),
        operation: Some(v1::host_control_mutation_request::Operation::Stop(
            v1::HostControlStop {
                session_id: session.into(),
                expected_launch_generation: generation,
            },
        )),
    })
    .unwrap()
}

/// A host engine whose host bounds are all HANG, not the product's one-second
/// cleanup steps, five-second dispatch, ten-second shutdown and three-second
/// RPC join: no test here is about them, and a stalled CI slot spent them, so
/// a confirmed stop read as unknown.
pub(crate) fn host_engine(config: &crate::Config) -> SessionEngine {
    SessionEngine::with_host_bounds(
        config,
        CredentialBridge::new(None),
        crate::durable_session::HostBounds::all(HANG),
    )
}

pub(crate) async fn owner(root: &Path) -> (Owner, SessionEngine) {
    owner_with(root, crate::durable_session::HostBounds::all(HANG)).await
}

/// [`owner`] with `bounds` in place of the all-HANG host bounds, for a test
/// whose subject is one of them.
pub(crate) async fn owner_with(
    root: &Path,
    bounds: crate::durable_session::HostBounds,
) -> (Owner, SessionEngine) {
    let config = config(root);
    let engine = SessionEngine::with_host_bounds(&config, CredentialBridge::new(None), bounds);
    let owner = Owner::new(
        &config,
        HostControlBinding::new(scope().environment_id).unwrap(),
        engine.clone(),
    )
    .await
    .unwrap();
    owner.put_grant(grant(&scope(), 0)).await.unwrap();
    (owner, engine)
}

/// Bounds a wait on an event, so a hang fails instead of stalling the run.
/// It is never the expected duration: the condition is the event, and a slow
/// CI slot can stall a process for seconds (#3309).
const HANG: Duration = Duration::from_secs(60);

pub(crate) async fn settled(owner: &Owner, request: &Mutation) -> Receipt {
    tokio::time::timeout(HANG, async {
        loop {
            let receipt = owner
                .observe(&request.request_id, &request.scope)
                .await
                .unwrap();
            if !receipt.unsettled() {
                return receipt;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

/// Mutates and returns the request's outcome. The RPC answers with the
/// receipt it has after its RPC join bound, which on a stalled slot can still be
/// unsettled; the outcome is then the settled receipt (#3309).
async fn outcome(owner: &Owner, request: Mutation) -> Receipt {
    let receipt = owner.mutate(request.clone()).await.unwrap();
    if receipt.unsettled() {
        settled(owner, &request).await
    } else {
        receipt
    }
}

async fn finish(owner: &Owner, engine: &SessionEngine) {
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

/// Reopen the store in the same process after its previous owner was dropped.
/// A daemon restart releases the owner lock with its process; here the last
/// clone of the dropped owner can still be releasing it, so a busy lock is
/// retried until that release. A store that stays unreadable still fails the
/// test, after HANG.
async fn reopen_owner(config: &crate::Config, engine: &SessionEngine) -> Owner {
    let deadline = tokio::time::Instant::now() + HANG;
    loop {
        match Owner::new(
            config,
            HostControlBinding::new(scope().environment_id).unwrap(),
            engine.clone(),
        )
        .await
        {
            Ok(owner) => return owner,
            Err(Error::Storage) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("reopen host control owner: {error:?}"),
        }
    }
}

#[tokio::test]
async fn host_control_duplicate_launch_input_and_stop_have_one_effect() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = owner(temp.path()).await;
    let marker = temp.path().join("effects");
    let request = launch(
        3,
        &scope(),
        &format!(
            "printf launch\\n >> '{}'; while read value; do printf '%s\\n' \"$value\" >> '{}'; done",
            marker.display(),
            marker.display()
        ),
    );
    let mut joins = Vec::new();
    for _ in 0..8 {
        let owner = owner.clone();
        let request = request.clone();
        joins.push(tokio::spawn(async move { outcome(&owner, request).await }));
    }
    for task in joins {
        assert_eq!(
            task.await.unwrap().phase,
            v1::HostControlRequestPhase::Completed as i32
        );
    }
    let launched = owner.observe(&request.request_id, &scope()).await.unwrap();
    let written = input(4, &scope(), &launched.session_id, 1, b"only-once\n");
    let first = owner.mutate(written.clone()).await.unwrap();
    assert!(first.input_acknowledged);
    assert!(
        owner
            .mutate(written.clone())
            .await
            .unwrap()
            .input_acknowledged
    );
    tokio::time::timeout(HANG, async {
        loop {
            if std::fs::read_to_string(&marker).is_ok_and(|bytes| bytes.contains("only-once")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let stopped = stop(5, &scope(), &launched.session_id, 1);
    let first = outcome(&owner, stopped.clone()).await;
    assert_eq!(
        first.phase,
        v1::HostControlRequestPhase::Completed as i32,
        "{first:?}: {:?}",
        engine.get(&launched.session_id).await
    );
    assert!(!first.cleanup_unknown);
    assert_eq!(owner.mutate(stopped).await.unwrap().phase, first.phase);
    let bytes = std::fs::read_to_string(marker).unwrap();
    assert_eq!(bytes.matches("launch").count(), 1);
    assert_eq!(bytes.matches("only-once").count(), 1);
    let changed = launch(3, &scope(), "exit 17");
    assert!(matches!(owner.mutate(changed).await, Err(Error::Conflict)));
    finish(&owner, &engine).await;
}

#[tokio::test]
async fn host_control_origin_filters_local_sessions_and_other_grants() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = owner(temp.path()).await;
    let local = engine
        .launch(v1::LaunchSessionRequest {
            command: vec!["/bin/true".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    let request = launch(3, &scope(), "sleep 60");
    let controlled = owner.mutate(request).await.unwrap();
    assert!(matches!(
        owner.get(&scope(), &local.session_id).await,
        Err(Error::Denied)
    ));
    assert_eq!(owner.list(&scope()).await.unwrap().len(), 1);
    let mut other = scope();
    other.grant_id = Uuid::from_u128(9).to_string();
    owner.put_grant(grant(&other, 1)).await.unwrap();
    assert!(matches!(
        owner.get(&other, &controlled.session_id).await,
        Err(Error::Denied)
    ));
    let refused = owner
        .mutate(stop(4, &other, &controlled.session_id, 1))
        .await
        .unwrap();
    assert_eq!(refused.phase, v1::HostControlRequestPhase::Rejected as i32);
    assert_eq!(
        engine.get(&controlled.session_id).await.unwrap().state,
        v1::SessionLifecycleState::Running as i32
    );
    finish(&owner, &engine).await;
}

#[tokio::test]
async fn host_control_missing_grant_zero_generation_and_foreign_environment_have_no_records() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = owner(temp.path()).await;
    let mut foreign = scope();
    foreign.environment_id = Uuid::from_u128(8).to_string();
    assert!(matches!(
        owner.mutate(launch(3, &foreign, "exit 0")).await,
        Err(Error::Denied)
    ));
    let mut unknown = scope();
    unknown.grant_id = Uuid::from_u128(7).to_string();
    assert!(matches!(
        owner.mutate(launch(4, &unknown, "exit 0")).await,
        Err(Error::Denied)
    ));
    let wire = v1::HostControlMutationRequest {
        request_id: Uuid::from_u128(5).to_string(),
        scope: Some(scope().to_wire()),
        operation: Some(v1::host_control_mutation_request::Operation::Stop(
            v1::HostControlStop {
                session_id: format!("session-{}", Uuid::from_u128(6)),
                expected_launch_generation: 0,
            },
        )),
    };
    assert!(matches!(Mutation::from_wire(wire), Err(Error::Invalid)));
    assert!(engine.list().await.unwrap().is_empty());
    finish(&owner, &engine).await;
}

#[tokio::test]
async fn host_control_receipt_loss_is_unknown_and_never_relaunches_after_reload() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = owner(temp.path()).await;
    owner.0.state.lock().await.store.fail_next_finish = true;
    let request = launch(3, &scope(), "printf receipt-lost; exit 0");
    let receipt = owner.mutate(request.clone()).await.unwrap();
    assert_eq!(receipt.phase, v1::HostControlRequestPhase::Unknown as i32);
    assert!(!receipt.input_acknowledged);
    tokio::time::timeout(HANG, async {
        loop {
            let record = engine.get(&receipt.session_id).await.unwrap();
            if record.state == v1::SessionLifecycleState::Exited as i32
                && record.output_end_offset == 12
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    finish(&owner, &engine).await;
    drop(owner);
    drop(engine);
    let config = config(temp.path());
    let engine = host_engine(&config);
    let owner = reopen_owner(&config, &engine).await;
    let observed = owner.observe(&request.request_id, &scope()).await.unwrap();
    assert_eq!(observed.reason, "recovered_unknown");
    assert_eq!(
        owner.mutate(request).await.unwrap().phase,
        v1::HostControlRequestPhase::Unknown as i32
    );
    let output = engine
        .read_output(v1::ReadSessionOutputRequest {
            session_id: observed.session_id,
            offset: 0,
            limit: 1024,
            allow_history_gap: false,
        })
        .await
        .unwrap();
    let bytes = output
        .chunks
        .into_iter()
        .flat_map(|chunk| chunk.data)
        .collect::<Vec<_>>();
    assert_eq!(bytes, b"receipt-lost");
    finish(&owner, &engine).await;
}

#[tokio::test]
async fn host_control_authorization_and_service_are_host_only() {
    use v1::host_control_service_server::HostControlService as Rpc;
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let engine = host_engine(&config);
    let service = HostControlService::new(
        &config,
        HostControlBinding::new(scope().environment_id).unwrap(),
        engine.clone(),
    )
    .await
    .unwrap();
    let missing = service
        .get_host_control_info(tonic::Request::new(v1::HostControlInfoRequest {}))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::Unauthenticated);
    let mut request = tonic::Request::new(v1::HostControlInfoRequest {});
    request.metadata_mut().insert(
        codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER,
        "synthetic-host-control-owner".parse().unwrap(),
    );
    let info = service
        .get_host_control_info(request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.environment_id, scope().environment_id);
    assert_eq!(info.protocol_version, HOST_CONTROL_PROTOCOL);
    let owner = service.owner();
    drop(service);
    finish(&owner, &engine).await;
    drop(owner);
    let mut nonhost = config.clone();
    nonhost.host = None;
    assert!(matches!(
        Owner::new(
            &nonhost,
            HostControlBinding::new(scope().environment_id).unwrap(),
            SessionEngine::new(&nonhost, CredentialBridge::new(None))
        )
        .await,
        Err(Error::Denied)
    ));
}

#[tokio::test]
async fn host_control_service_pages_large_actual_records_without_drop_or_truncation() {
    use prost::Message;
    use v1::host_control_service_server::HostControlService as Rpc;
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let engine = host_engine(&config);
    let service = HostControlService::new(
        &config,
        HostControlBinding::new(scope().environment_id).unwrap(),
        engine.clone(),
    )
    .await
    .unwrap();
    let owner = service.owner();
    owner.put_grant(grant(&scope(), 0)).await.unwrap();
    for id in 3..11 {
        let mut command = vec!["/bin/true".into()];
        command.extend(vec!["x".repeat(4096); 15]);
        let request = Mutation::from_wire(v1::HostControlMutationRequest {
            request_id: Uuid::from_u128(id).to_string(),
            scope: Some(scope().to_wire()),
            operation: Some(v1::host_control_mutation_request::Operation::Launch(
                v1::HostControlLaunch {
                    command,
                    ..Default::default()
                },
            )),
        })
        .unwrap();
        let result = outcome(&owner, request).await;
        assert_eq!(result.phase, v1::HostControlRequestPhase::Completed as i32);
    }
    // Wait for the actual short children and their terminal metadata before
    // comparing record bytes across pages; pagination itself never rewrites.
    tokio::time::timeout(HANG, async {
        loop {
            if engine
                .list()
                .await
                .unwrap()
                .iter()
                .all(|record| record.state == v1::SessionLifecycleState::Exited as i32)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let expected = owner.list(&scope()).await.unwrap();
    let mut collected = Vec::new();
    let mut after = String::new();
    let mut pages = 0;
    loop {
        let mut request = tonic::Request::new(v1::HostControlReadRequest {
            scope: Some(scope().to_wire()),
            after_session_id: after.clone(),
            page_limit: 8,
            ..Default::default()
        });
        request.metadata_mut().insert(
            codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER,
            "synthetic-host-control-owner".parse().unwrap(),
        );
        let response = service
            .list_host_sessions(request)
            .await
            .unwrap()
            .into_inner();
        assert!(response.encoded_len() <= 256 * 1024);
        assert!(!response.sessions.is_empty());
        assert!(
            response
                .sessions
                .iter()
                .all(|record| record.session_id > after)
        );
        if !response.next_session_id.is_empty() {
            assert_eq!(
                response.next_session_id,
                response.sessions.last().unwrap().session_id
            );
        }
        after = response.next_session_id;
        collected.extend(response.sessions);
        pages += 1;
        assert!(pages <= 8);
        if after.is_empty() {
            break;
        }
    }
    assert!(pages > 1);
    assert_eq!(collected, expected);
    finish(&owner, &engine).await;
}

#[test]
fn host_control_service_refuses_an_oversized_single_record_without_truncation() {
    let record = v1::SessionRecord {
        session_id: format!("session-{}", Uuid::from_u128(3)),
        command: vec!["x".repeat(256 * 1024)],
        launch_generation: 1,
        ..Default::default()
    };
    assert!(matches!(
        service::session_page(vec![record], "", 8),
        Err(Error::Capacity)
    ));
}

#[test]
fn host_control_abrupt_publication_cuts_recover_without_process_reissue() {
    for cut in [
        "created",
        "output",
        "metadata",
        "published",
        "parents",
        "spawned",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "host_control::tests::host_control_crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CW_HOST_CONTROL_CRASH_ROOT", temp.path())
            .env("CW_HOST_CONTROL_CRASH_CUT", cut)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77), "cut {cut}");
        if cut == "spawned" {
            assert_eq!(
                std::fs::read(temp.path().join("process-effect")).unwrap(),
                b"once"
            );
        } else {
            assert!(!temp.path().join("process-effect").exists());
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let config = config(temp.path());
                let engine = host_engine(&config);
                let owner = Owner::new(
                    &config,
                    HostControlBinding::new(scope().environment_id).unwrap(),
                    engine.clone(),
                )
                .await
                .unwrap();
                let request = crash_request(temp.path());
                let retained = owner.observe(&request.request_id, &scope()).await.unwrap();
                assert_eq!(retained.phase, v1::HostControlRequestPhase::Unknown as i32);
                assert_eq!(owner.mutate(request).await.unwrap().phase, retained.phase);
                if cut == "spawned" {
                    assert_eq!(
                        std::fs::read(temp.path().join("process-effect")).unwrap(),
                        b"once"
                    );
                } else {
                    assert!(!temp.path().join("process-effect").exists());
                }
                let sessions = engine.list().await.unwrap();
                if matches!(cut, "published" | "parents") {
                    assert_eq!(sessions.len(), 1);
                    assert_eq!(
                        sessions[0].state,
                        v1::SessionLifecycleState::Interrupted as i32
                    );
                    assert!(sessions[0].cleanup_unknown);
                } else if cut == "spawned" {
                    assert_eq!(sessions.len(), 1);
                    assert_eq!(sessions[0].state, v1::SessionLifecycleState::Exited as i32);
                    assert!(!sessions[0].cleanup_unknown);
                } else {
                    assert!(sessions.is_empty());
                }
                owner.drain().await.unwrap();
                let result = engine.shutdown().await;
                if matches!(cut, "published" | "parents") {
                    assert!(
                        matches!(
                            result,
                            Err(crate::durable_session::SessionError::Internal(_))
                        ),
                        "a recovered unconfirmed record must keep the legacy cleanup fence"
                    );
                } else {
                    result.unwrap();
                }
            });
    }
}

fn crash_request(root: &Path) -> Mutation {
    launch(
        3,
        &scope(),
        &format!("printf once >> '{}'", root.join("process-effect").display()),
    )
}

#[test]
#[ignore = "invoked only by isolated abrupt-publication parent fixture"]
fn host_control_crash_child() {
    let Some(root) = std::env::var_os("CW_HOST_CONTROL_CRASH_ROOT") else {
        panic!("private child root is required")
    };
    let root = PathBuf::from(root);
    assert!(root.is_absolute());
    let cut = match std::env::var("CW_HOST_CONTROL_CRASH_CUT").unwrap().as_str() {
        "created" => Some(store::LaunchCut::Created),
        "output" => Some(store::LaunchCut::OutputSynced),
        "metadata" => Some(store::LaunchCut::MetadataSynced),
        "published" => Some(store::LaunchCut::Published),
        "parents" => Some(store::LaunchCut::ParentSynced),
        "spawned" => None,
        _ => panic!("closed cut name"),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (owner, engine) = owner(&root).await;
            if cut.is_none() {
                // The owning engine executes the actual durable Issued +
                // published-origin + one-spawn path. Withhold only the final
                // request receipt. Observe the short child's known cleanup
                // before deliberately killing this isolated producer so the
                // parent never deletes a fixture with an unowned live actor.
                let request = crash_request(&root);
                owner.0.state.lock().await.store.register(&request).unwrap();
                let record = engine
                    .execute_host_control(owner.clone(), request)
                    .await
                    .unwrap();
                tokio::time::timeout(HANG, async {
                    loop {
                        let record = engine.get(&record.session_id).await.unwrap();
                        if record.state == v1::SessionLifecycleState::Exited as i32
                            && !record.cleanup_unknown
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                engine.shutdown().await.unwrap();
                // SAFETY: this is the exact isolated helper after the sole
                // synthetic actor has been reaped with confirmed cleanup.
                unsafe {
                    libc::_exit(77);
                }
            }
            let mut state = owner.0.state.lock().await;
            state.store.launch_cut = cut;
            state.store.crash_at_cut = true;
            drop(state);
            let _ = owner.mutate(crash_request(&root)).await;
            // The mutation answers after its RPC join bound, which a stalled
            // slot can spend before the owner's launch reaches the cut. The
            // launch goes on and the cut ends this process; HANG only turns a
            // cut that never comes into a failure.
            tokio::time::sleep(HANG).await;
            panic!("cut did not terminate the isolated producer");
        });
}
