//! Deterministic owner/transport sequencing, not a replacement for the
//! unchanged journal's actual PostgreSQL or same-Pod acceptance.
use super::*;
use crate::api::cw_runtime::{
    model::{CheckpointAcknowledgement, RuntimePhase},
    service_test_support as fixture,
};
use std::sync::{Arc, Mutex};

fn receipt_frame(correlation: &Correlation) -> Vec<u8> {
    let bytes = codewire_cw_release::identity::canonical_json(&serde_json::json!({
        "schema_version": 1,
        "correlation": correlation,
        "outcome": Outcome::Succeeded { result: ReplyBody::Cleaned },
    }))
    .unwrap();
    let mut frame = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    frame.extend(bytes);
    frame
}

fn stream_correlation() -> Correlation {
    Correlation {
        request_id: uuid::Uuid::new_v4(),
        pod_uid: uuid::Uuid::new_v4(),
        binding_sha256: "a".repeat(64),
    }
}

#[test]
fn fixed_role_has_no_caller_selected_command_environment_or_tty() {
    let start = role_start();
    assert_eq!(start.command, ["/codewire/bin/cw", "__platform-cw-runtime"]);
    assert_eq!(start.working_dir, "/home/codewire");
    assert!(start.env.is_empty());
    assert!(!start.allocate_tty && start.term.is_empty());
    assert_eq!((start.columns, start.rows), (0, 0));
}

#[tokio::test]
async fn bounded_stream_receipt_requires_exit_and_then_clean_eof() {
    let correlation = stream_correlation();
    let frame = receipt_frame(&correlation);
    let mut outputs = futures_util::stream::iter([
        Ok(DaemonRunOutput::Stdout(frame[..5].to_vec())),
        Ok(DaemonRunOutput::Stdout(frame[5..].to_vec())),
        Ok(DaemonRunOutput::Exit(0)),
    ]);
    assert_eq!(
        receive_until_exit(&mut outputs, &correlation)
            .await
            .unwrap(),
        Outcome::Succeeded {
            result: ReplyBody::Cleaned
        }
    );
    require_eof(&mut outputs).await.unwrap();
}

#[tokio::test]
async fn stdout_stderr_missing_or_wrong_exit_never_acknowledges() {
    let correlation = stream_correlation();
    let frame = receipt_frame(&correlation);
    for messages in [
        vec![Ok(DaemonRunOutput::Stdout(vec![0; wire::MAX_FRAME + 5]))],
        vec![Ok(DaemonRunOutput::Stderr(vec![0; MAX_STDERR + 1]))],
        vec![Ok(DaemonRunOutput::Stdout(frame.clone()))],
        vec![
            Ok(DaemonRunOutput::Stdout(frame.clone())),
            Ok(DaemonRunOutput::Stderr(vec![1])),
            Ok(DaemonRunOutput::Exit(0)),
        ],
        vec![
            Ok(DaemonRunOutput::Stdout(frame.clone())),
            Ok(DaemonRunOutput::Exit(3)),
        ],
        vec![Err(model::unavailable())],
    ] {
        let mut outputs = futures_util::stream::iter(messages);
        assert!(
            receive_until_exit(&mut outputs, &correlation)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn duplicate_exit_post_exit_output_loss_and_non_eof_cannot_complete_an_ack() {
    let correlation = stream_correlation();
    for extra in [
        Ok(DaemonRunOutput::Exit(0)),
        Ok(DaemonRunOutput::Stdout(vec![0])),
        Err(model::unavailable()),
    ] {
        let mut outputs = futures_util::stream::iter([
            Ok(DaemonRunOutput::Stdout(receipt_frame(&correlation))),
            Ok(DaemonRunOutput::Exit(0)),
            extra,
        ]);
        receive_until_exit(&mut outputs, &correlation)
            .await
            .unwrap();
        assert!(require_eof(&mut outputs).await.is_err());
    }
    let mut outputs = futures_util::stream::pending::<AppResult<DaemonRunOutput>>();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), require_eof(&mut outputs))
            .await
            .is_err()
    );
}

#[derive(Default)]
struct Trace {
    events: Vec<String>,
    checks: usize,
    issues: usize,
    dispatches: usize,
    acks: usize,
}
#[derive(Clone, Copy, Default)]
struct Fault {
    revoke_check: Option<usize>,
    lost_issue: bool,
    lost_ack: bool,
    unknown: bool,
    refused: bool,
    bad_receipt: bool,
}
struct Fake {
    request: RuntimeRequest,
    trace: Arc<Mutex<Trace>>,
    fault: Fault,
}
struct Permit {
    checkpoint: i32,
    effect: RuntimeEffect,
}

fn fake(action: RuntimeAction, generation: u64, fault: Fault) -> (Fake, Arc<Mutex<Trace>>) {
    let trace = Arc::new(Mutex::new(Trace::default()));
    (
        Fake {
            request: fixture::request(action, generation),
            trace: trace.clone(),
            fault,
        },
        trace,
    )
}

#[async_trait]
impl Backend for Fake {
    type Permit = Permit;
    fn request(&self) -> &RuntimeRequest {
        &self.request
    }
    async fn recheck(&mut self) -> AppResult<()> {
        let mut trace = self.trace.lock().unwrap();
        trace.checks += 1;
        trace.events.push("recheck-original-full-tuple".into());
        if self.fault.revoke_check == Some(trace.checks) {
            Err(model::unavailable())
        } else {
            Ok(())
        }
    }
    async fn issue(&mut self, effect: RuntimeEffect) -> AppResult<Permit> {
        let mut trace = self.trace.lock().unwrap();
        trace.issues += 1;
        trace
            .events
            .push(format!("issued:{}", wire::effect_name(effect)));
        self.request.phase = RuntimePhase::Issued;
        if self.fault.lost_issue {
            return Err(model::unavailable());
        }
        Ok(Permit {
            checkpoint: self.request.checkpoint + 1,
            effect,
        })
    }
    async fn dispatch(&mut self, permit: &Permit, effect: RuntimeEffect) -> Dispatch {
        assert_eq!(permit.effect, effect);
        assert_eq!(self.request.phase, RuntimePhase::Issued);
        let mut trace = self.trace.lock().unwrap();
        trace.dispatches += 1;
        trace
            .events
            .push(format!("dispatch-original-A:{}", wire::effect_name(effect)));
        drop(trace);
        if self.fault.unknown {
            return Dispatch::Unknown;
        }
        if self.fault.refused {
            return Dispatch::Refused;
        }
        if self.fault.bad_receipt {
            return Dispatch::Succeeded(ReplyBody::Cleaned);
        }
        let body = match effect {
            RuntimeEffect::Staging => ReplyBody::Staged {
                sha256: self.request.mutation.target_identity.sha256.clone(),
                size: self.request.mutation.target_identity.size,
            },
            RuntimeEffect::Cleanup => ReplyBody::Cleaned,
            RuntimeEffect::Bootstrap | RuntimeEffect::Update | RuntimeEffect::Rollback => {
                let old = expected(&self.request);
                let target = if effect == RuntimeEffect::Bootstrap {
                    self.request.mutation.bootstrap_identity.as_ref().unwrap()
                } else {
                    &self.request.mutation.target_identity
                };
                let changed = old.current.as_deref() != Some(&target.sha256);
                ReplyBody::Selected {
                    sha256: target.sha256.clone(),
                    generation: old.generation + u64::from(changed),
                    previous_sha256: if changed { old.current } else { old.previous },
                    changed,
                }
            }
        };
        Dispatch::Succeeded(body)
    }
    async fn acknowledge(&mut self, permit: &Permit, receipt: EffectReceipt) -> AppResult<()> {
        let mut trace = self.trace.lock().unwrap();
        trace.acks += 1;
        trace
            .events
            .push(format!("ack:{}", wire::effect_name(permit.effect)));
        if self.fault.lost_ack {
            return Err(model::unavailable());
        }
        self.request
            .acknowledgements
            .push(CheckpointAcknowledgement {
                checkpoint: permit.checkpoint,
                effect: permit.effect,
                receipt,
            });
        self.request.checkpoint = permit.checkpoint;
        self.request.phase = RuntimePhase::Acknowledged;
        Ok(())
    }
    async fn unknown(&mut self, _permit: &Permit) -> AppResult<RuntimeRequest> {
        self.trace
            .lock()
            .unwrap()
            .events
            .push("unknown-no-reissue".into());
        self.request.phase = RuntimePhase::Unknown;
        Ok(self.request.clone())
    }
    async fn refused(&mut self, _permit: &Permit) -> AppResult<RuntimeRequest> {
        self.trace
            .lock()
            .unwrap()
            .events
            .push("known-refusal".into());
        self.request.phase = RuntimePhase::Failed;
        Ok(self.request.clone())
    }
    async fn cancel(&mut self) -> AppResult<RuntimeRequest> {
        assert_ne!(self.request.phase, RuntimePhase::Issued);
        self.trace
            .lock()
            .unwrap()
            .events
            .push("cancel-known-partial".into());
        self.request.phase = RuntimePhase::Failed;
        Ok(self.request.clone())
    }
    async fn succeed(&mut self) -> AppResult<RuntimeRequest> {
        self.trace.lock().unwrap().events.push("settled".into());
        self.request.phase = RuntimePhase::Succeeded;
        Ok(self.request.clone())
    }
}

#[tokio::test]
async fn first_bootstrap_update_and_cleanup_each_require_fresh_check_issued_and_ack() {
    let (backend, trace) = fake(RuntimeAction::Update, 0, Fault::default());
    let result = run(backend).await.unwrap();
    assert_eq!(result.phase, RuntimePhase::Succeeded);
    assert_eq!(result.checkpoint, 4);
    assert_eq!(result.acknowledgements.len(), 4);
    let trace = trace.lock().unwrap();
    assert_eq!(
        (trace.checks, trace.issues, trace.dispatches, trace.acks),
        (5, 4, 4, 4)
    );
    for (index, name) in ["bootstrap", "staging", "update", "cleanup"]
        .iter()
        .enumerate()
    {
        assert_eq!(trace.events[index * 4], "recheck-original-full-tuple");
        assert_eq!(trace.events[index * 4 + 1], format!("issued:{name}"));
        assert_eq!(
            trace.events[index * 4 + 2],
            format!("dispatch-original-A:{name}")
        );
        assert_eq!(trace.events[index * 4 + 3], format!("ack:{name}"));
    }
    assert_eq!(expected(&result).generation, 2);
}

#[tokio::test]
async fn fresh_revocation_or_retarget_stops_before_first_issue_and_preserves_known_partial() {
    for check in [1, 2, 4] {
        let (backend, trace) = fake(
            RuntimeAction::Update,
            2,
            Fault {
                revoke_check: Some(check),
                ..Default::default()
            },
        );
        let result = run(backend).await.unwrap();
        assert_eq!(result.phase, RuntimePhase::Failed);
        let trace = trace.lock().unwrap();
        assert_eq!(trace.dispatches, check - 1);
        assert_eq!(result.acknowledgements.len(), check - 1);
        assert_eq!(trace.events.last().unwrap(), "cancel-known-partial");
    }
}

#[tokio::test]
async fn lost_issue_commit_ack_never_dispatches_cancels_or_reissues() {
    let (backend, trace) = fake(
        RuntimeAction::Update,
        2,
        Fault {
            lost_issue: true,
            ..Default::default()
        },
    );
    assert!(run(backend).await.is_err());
    let trace = trace.lock().unwrap();
    assert_eq!((trace.issues, trace.dispatches, trace.acks), (1, 0, 0));
    assert_eq!(trace.events.len(), 2);
}

#[tokio::test]
async fn lost_effect_or_receipt_or_ack_stops_without_cleanup_or_next_issue() {
    for fault in [
        Fault {
            unknown: true,
            ..Default::default()
        },
        Fault {
            bad_receipt: true,
            ..Default::default()
        },
        Fault {
            lost_ack: true,
            ..Default::default()
        },
    ] {
        let (backend, trace) = fake(RuntimeAction::Update, 2, fault);
        let result = run(backend).await;
        if fault.lost_ack {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().phase, RuntimePhase::Unknown);
        }
        let trace = trace.lock().unwrap();
        assert_eq!((trace.issues, trace.dispatches), (1, 1));
        assert!(
            trace
                .events
                .iter()
                .all(|v| !v.contains("cleanup") && !v.contains("cancel"))
        );
    }
}

#[tokio::test]
async fn exact_refusal_is_known_and_rollback_does_not_upload_or_bootstrap() {
    let (backend, trace) = fake(
        RuntimeAction::Rollback,
        2,
        Fault {
            refused: true,
            ..Default::default()
        },
    );
    assert_eq!(run(backend).await.unwrap().phase, RuntimePhase::Failed);
    assert_eq!(trace.lock().unwrap().dispatches, 1);
    let (backend, trace) = fake(RuntimeAction::Rollback, 2, Fault::default());
    let result = run(backend).await.unwrap();
    assert_eq!(result.phase, RuntimePhase::Succeeded);
    let trace = trace.lock().unwrap();
    assert_eq!(trace.dispatches, 2);
    assert!(
        trace
            .events
            .iter()
            .all(|v| !v.contains("staging") && !v.contains("bootstrap"))
    );
}

#[test]
fn sole_runtime_command_has_no_public_command_path_environment_or_credential_fields() {
    let command = role_start();
    assert_eq!(
        command.command,
        ["/codewire/bin/cw", "__platform-cw-runtime"]
    );
    assert_eq!(command.working_dir, "/home/codewire");
    assert!(command.env.is_empty());
    assert!(!command.allocate_tty);
}
