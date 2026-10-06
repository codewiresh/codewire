//! Public managed-worker checks used by the retained-Pod CW journey.
//! Every mutation has one fresh UUID, recorded before dispatch. Read-only
//! observation may wait; a failed or uncertain mutation is never replayed.

use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use codewire_client::platform_agents as rpc;
use codewire_client::{CodewireClient, ErrorCode};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(90);
const OPENAI_KEY: &str = "cwlocalopenai0123456789abcdef0123456789abcdef";
const ANTHROPIC_KEY: &str = "cwlocalanthropic0123456789abcdef0123456789abcdef";

struct Conversation {
    session: String,
    driver: String,
    generation: u64,
    kind: rpc::EnvironmentAgentKind,
    provider_sha256: String,
    provider_size: u64,
    peer: Value,
    thread: String,
    original_message: String,
    original_record: Value,
    stopped: bool,
    revoked: bool,
}

struct Continuity {
    message: String,
    turn: String,
    nonce: String,
}

pub(super) struct Journey {
    org: String,
    environment: String,
    scope: rpc::EnvironmentAgentScope,
    sessions: Vec<Conversation>,
    requests: Vec<String>,
    saved: Vec<rpc::EnvironmentAgentOperation>,
    continuity: Option<Continuity>,
    #[cfg(test)]
    caller_drop_receipt: Option<tokio::sync::oneshot::Receiver<String>>,
}

impl Journey {
    pub(super) fn validate_scope(
        &self,
        incarnation: &codewire_client::cw_runtime::EnvironmentCwRuntimeIncarnation,
        image: &codewire_client::cw_runtime::EnvironmentCwRuntimeIdentity,
    ) -> anyhow::Result<()> {
        let checksum: String = self
            .scope
            .support_image_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        ensure!(
            self.scope.incarnation.as_option() == Some(incarnation)
                && checksum == image.sha256
                && self.scope.support_image_size == image.size,
            "managed scope differs from the original ordinary runtime Pod/support image"
        );
        Ok(())
    }

    pub(super) async fn launch(
        client: &CodewireClient,
        org: &str,
        environment: &str,
        incarnation: &codewire_client::cw_runtime::EnvironmentCwRuntimeIncarnation,
        image: &codewire_client::cw_runtime::EnvironmentCwRuntimeIdentity,
    ) -> anyhow::Result<Self> {
        let info = client
            .get_environment_agent_info(rpc::GetEnvironmentAgentInfoRequest {
                org_id: org.into(),
                environment_id: environment.into(),
                ..Default::default()
            })
            .await
            .context("read original managed support")?;
        let scope = info
            .scope
            .into_option()
            .context("managed support omitted original scope")?;
        let mut journey = Self {
            org: org.into(),
            environment: environment.into(),
            scope,
            sessions: Vec::new(),
            requests: Vec::new(),
            saved: Vec::new(),
            continuity: None,
            #[cfg(test)]
            caller_drop_receipt: None,
        };
        journey.validate_scope(incarnation, image)?;
        for (index, kind) in [
            rpc::EnvironmentAgentKind::Codex,
            rpc::EnvironmentAgentKind::Codex,
            rpc::EnvironmentAgentKind::Claude,
        ]
        .into_iter()
        .enumerate()
        {
            let support = info
                .agents
                .iter()
                .find(|s| s.agent.as_known() == Some(kind))
                .context("original image omitted the required stock agent")?;
            ensure!(
                support.proxy_only_qualified
                    && support.provider_sha256.len() == 32
                    && support.provider_size > 0
                    && support.provider_version
                        == match kind {
                            rpc::EnvironmentAgentKind::Codex => "0.157.0",
                            _ => "2.1.238",
                        },
                "stock provider identity is not the selected pinned version"
            );
            let parent = journey.sessions.first();
            let operation = journey
                .mutate(
                    client,
                    rpc::mutate_environment_agent_request::Operation::Launch(Box::new(
                        rpc::EnvironmentAgentLaunch {
                            agent: kind.into(),
                            model: match kind {
                                rpc::EnvironmentAgentKind::Codex => "gpt-6.1-sol",
                                _ => "claude-sonnet-4-6",
                            }
                            .into(),
                            effort: Some("high".into()),
                            working_dir: "/workspace".into(),
                            name: format!("managed-kind-{index}-{}", Uuid::new_v4().simple()),
                            parent_session_id: parent
                                .map(|p| p.session.clone())
                                .unwrap_or_default(),
                            expected_parent_launch_generation: parent
                                .map(|p| p.generation)
                                .unwrap_or_default(),
                            expected_provider_sha256: support.provider_sha256.clone(),
                            expected_provider_size: support.provider_size,
                            expected_provider_version: support.provider_version.clone(),
                            ..Default::default()
                        },
                    )),
                    "launch",
                )
                .await?;
            ensure!(
                operation.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
                    && operation.launch_generation == 1
                    && !operation.cleanup_unknown
                    && operation.session_id == format!("session-{}", operation.driver_id),
                "original managed launch did not settle"
            );
            journey.sessions.push(Conversation {
                session: operation.session_id,
                driver: operation.driver_id,
                generation: 1,
                kind,
                provider_sha256: support
                    .provider_sha256
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                provider_size: support.provider_size,
                peer: Value::Null,
                thread: String::new(),
                original_message: String::new(),
                original_record: Value::Null,
                stopped: false,
                revoked: false,
            });
            let message = journey
                .message(client, index, "Return the fixed synthetic broker reply.")
                .await?;
            let record = journey.terminal(client, index, &message).await?;
            successful(&record, kind)?;
            journey.sessions[index].original_message = message;
            journey.sessions[index].original_record = record;
        }
        journey.parent_notifications(client).await?;
        // Capture only after native turns and parent adoption settle. These
        // immutable process identities must survive every CW selection change.
        for index in 0..journey.sessions.len() {
            let current = journey.current(client, index).await?;
            let peer = &current["peer"];
            ensure!(
                peer["identity"]["environment_id"] == environment
                    && peer["identity"]["session_id"] == journey.sessions[index].session
                    && peer["identity"]["driver_id"] == journey.sessions[index].driver
                    && peer["identity"]["driver_pid"]
                        .as_u64()
                        .is_some_and(|p| p > 0)
                    && peer["identity"]["driver_start_ticks"]
                        .as_u64()
                        .is_some_and(|p| p > 0)
                    && peer["guardian_pid"].as_u64().is_some_and(|p| p > 0)
                    && peer["guardian_start_ticks"].as_u64().is_some_and(|p| p > 0)
                    && peer["provider_pid"].as_u64().is_some_and(|p| p > 0)
                    && peer["finished_at"].is_null()
                    && peer["error"].is_null(),
                "original managed peer custody is missing"
            );
            journey.sessions[index].peer = peer.clone();
            journey.sessions[index].thread = current["driver"]["native_thread_id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .context("native conversation identity is missing")?
                .into();
            journey.sessions[index].original_record = journey
                .record(client, index, &journey.sessions[index].original_message)
                .await?;
        }
        journey.checkpoint(client, "before-bootstrap").await?;
        Ok(journey)
    }

    async fn mutate(
        &mut self,
        client: &CodewireClient,
        operation: rpc::mutate_environment_agent_request::Operation,
        action: &str,
    ) -> anyhow::Result<rpc::EnvironmentAgentOperation> {
        let id = Uuid::new_v4().to_string();
        self.requests.push(id.clone());
        println!(
            "{}",
            json!({"event":"managed-before-send", "request_id":id,
            "action":action, "environment_id":self.environment})
        );
        let saved = client
            .mutate_environment_agent(rpc::MutateEnvironmentAgentRequest {
                org_id: self.org.clone(),
                environment_id: self.environment.clone(),
                request_id: id.clone(),
                expected_scope: Some(self.scope.clone()).into(),
                operation: Some(operation),
                ..Default::default()
            })
            .await
            .context("managed mutation is uncertain; observe the recorded original UUID")?
            .operation
            .into_option()
            .context("managed mutation omitted its saved operation")?;
        validate_original(&saved, &id, &self.scope)?;
        for _ in 0..2 {
            let observed = client
                .observe_environment_agent(rpc::ObserveEnvironmentAgentRequest {
                    org_id: self.org.clone(),
                    environment_id: self.environment.clone(),
                    request_id: id.clone(),
                    ..Default::default()
                })
                .await
                .context("observe the original managed request")?
                .operation
                .into_option()
                .context("managed observation omitted its original operation")?;
            ensure!(
                observed == saved,
                "read-only observation changed the saved original outcome"
            );
        }
        self.saved.push(saved.clone());
        Ok(saved)
    }

    fn control(
        &self,
        index: usize,
        action: rpc::EnvironmentAgentAction,
        text: &str,
    ) -> rpc::EnvironmentAgentControl {
        let session = &self.sessions[index];
        rpc::EnvironmentAgentControl {
            action: action.into(),
            session_id: session.session.clone(),
            driver_id: session.driver.clone(),
            expected_launch_generation: session.generation,
            text: text.into(),
            ..Default::default()
        }
    }

    async fn action(
        &mut self,
        client: &CodewireClient,
        control: rpc::EnvironmentAgentControl,
        label: &str,
    ) -> anyhow::Result<rpc::EnvironmentAgentOperation> {
        let expected = control.clone();
        let op = self
            .mutate(
                client,
                rpc::mutate_environment_agent_request::Operation::Control(Box::new(control)),
                label,
            )
            .await?;
        validate_control(&op, &expected)?;
        Ok(op)
    }

    async fn message(
        &mut self,
        client: &CodewireClient,
        index: usize,
        text: &str,
    ) -> anyhow::Result<String> {
        let op = self
            .action(
                client,
                self.control(index, rpc::EnvironmentAgentAction::Message, text),
                "message",
            )
            .await?;
        ensure!(
            op.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
                && op.pipe_acknowledged
                && op.message_id == op.request_id,
            "managed message was not acknowledged"
        );
        Ok(op.message_id)
    }

    async fn read(
        &self,
        client: &CodewireClient,
        index: usize,
        message: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.read_at(client, index, message, self.sessions[index].generation)
            .await
    }

    async fn read_at(
        &self,
        client: &CodewireClient,
        index: usize,
        message: Option<&str>,
        generation: u64,
    ) -> anyhow::Result<Value> {
        let session = &self.sessions[index];
        let response = client
            .read_environment_agent(rpc::ReadEnvironmentAgentRequest {
                org_id: self.org.clone(),
                environment_id: self.environment.clone(),
                expected_scope: Some(self.scope.clone()).into(),
                session_id: session.session.clone(),
                driver_id: session.driver.clone(),
                expected_launch_generation: generation,
                kind: if message.is_some() {
                    rpc::EnvironmentAgentRecordKind::Message
                } else {
                    rpc::EnvironmentAgentRecordKind::Current
                }
                .into(),
                message_id: message.unwrap_or_default().into(),
                limit: 20,
                ..Default::default()
            })
            .await
            .context("read original managed record")?;
        serde_json::from_slice(&response.record_json).context("managed record is not complete JSON")
    }

    async fn current(&self, client: &CodewireClient, index: usize) -> anyhow::Result<Value> {
        self.read(client, index, None).await
    }

    async fn record(
        &self,
        client: &CodewireClient,
        index: usize,
        id: &str,
    ) -> anyhow::Result<Value> {
        self.record_at(client, index, id, self.sessions[index].generation)
            .await
    }

    async fn record_at(
        &self,
        client: &CodewireClient,
        index: usize,
        id: &str,
        generation: u64,
    ) -> anyhow::Result<Value> {
        let response = self.read_at(client, index, Some(id), generation).await?;
        let record = response
            .get("record")
            .context("managed message record is missing")?;
        ensure!(
            record["id"] == id
                && record["driver_id"] == self.sessions[index].driver
                && record["target_session_id"] == self.sessions[index].session
                && record["platform_launch_generation"] == generation,
            "managed record changed its original conversation or generation"
        );
        Ok(record.clone())
    }

    async fn terminal(
        &self,
        client: &CodewireClient,
        index: usize,
        id: &str,
    ) -> anyhow::Result<Value> {
        let end = Instant::now() + WAIT;
        loop {
            let record = self.record(client, index, id).await?;
            if matches!(
                record["state"].as_str(),
                Some("completed" | "error" | "interrupted" | "unknown")
            ) {
                return Ok(record);
            }
            ensure!(
                Instant::now() < end,
                "original native turn did not settle within its bound"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn parent_notifications(&self, client: &CodewireClient) -> anyhow::Result<()> {
        let end = Instant::now() + WAIT;
        loop {
            let current = self.current(client, 0).await?;
            let messages = current["messages"]
                .as_array()
                .context("parent inbox is missing")?;
            let mut settled = true;
            for worker in &self.sessions[1..] {
                let digest = Sha256::digest(
                    format!("codewire-agent-notification:v1:{}", worker.original_message)
                        .as_bytes(),
                );
                let mut bytes = [0; 16];
                bytes.copy_from_slice(&digest[..16]);
                let expected = uuid::Builder::from_random_bytes(bytes)
                    .into_uuid()
                    .to_string();
                let found: Vec<_> = messages
                    .iter()
                    .filter(|m| m["source"]["message_id"] == worker.original_message)
                    .collect();
                ensure!(
                    found.len() <= 1,
                    "parent adopted the same worker notification twice"
                );
                if let Some(record) = found.first() {
                    ensure!(
                        record["id"] == expected
                            && record["action"] == "notification"
                            && record["source"]["session_id"] == worker.session
                            && record["source"]["driver_id"] == worker.driver,
                        "parent notification lineage changed"
                    );
                    settled &=
                        record["state"] == "completed" && record["native_acknowledged"] == true;
                } else {
                    settled = false;
                }
            }
            if settled {
                return Ok(());
            }
            ensure!(
                Instant::now() < end,
                "parent did not accept original worker notifications"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Start before the original kernel observer and the first Store update.
    /// The 600-second fixture remains pending until this same turn is interrupted;
    /// there is no release request, replacement turn or fixed-delay success.
    pub(super) async fn begin_continuity(&mut self, client: &CodewireClient) -> anyhow::Result<()> {
        ensure!(self.continuity.is_none(), "continuity was already started");
        let nonce = Uuid::new_v4().simple().to_string()[..8].to_owned();
        let message = self.message(client, 1,
            &format!("CW_FIXTURE_UPDATE_STEERABLE {nonce}\nRemain pending through the CW selection changes.")).await?;
        let end = Instant::now() + WAIT;
        let turn = loop {
            let current = self.current(client, 1).await?;
            let record = self.record(client, 1, &message).await?;
            if current["driver"]["active_message_id"] == message
                && current["driver"]["phase"] == "busy"
                && record["state"] == "running"
                && record["native_acknowledged"] == true
                && let Some(turn) = current["driver"]["current_turn_id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
            {
                let held = Continuity {
                    message: message.clone(),
                    turn: turn.into(),
                    nonce,
                };
                validate_continuity(&self.sessions[1], &held, &current, &record)?;
                break held;
            }
            ensure!(
                Instant::now() < end,
                "the original continuity turn did not become active"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        self.continuity = Some(turn);
        // Positive dwell on the exact message/native turn, then the persistent
        // observer takes over process custody before any CW mutation.
        let dwell = Instant::now() + Duration::from_secs(2);
        loop {
            self.check_continuity(client).await?;
            if Instant::now() >= dwell {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    async fn check_continuity(&self, client: &CodewireClient) -> anyhow::Result<()> {
        let held = self
            .continuity
            .as_ref()
            .context("original continuity is missing")?;
        validate_continuity(
            &self.sessions[1],
            held,
            &self.current(client, 1).await?,
            &self.record(client, 1, &held.message).await?,
        )
    }

    pub(super) async fn checkpoint(
        &self,
        client: &CodewireClient,
        phase: &str,
    ) -> anyhow::Result<()> {
        let info = client
            .get_environment_agent_info(rpc::GetEnvironmentAgentInfoRequest {
                org_id: self.org.clone(),
                environment_id: self.environment.clone(),
                ..Default::default()
            })
            .await
            .context("recheck original managed image and Pod scope")?;
        ensure!(
            info.scope.as_option() == Some(&self.scope),
            "managed original Pod/support scope changed"
        );
        let page = client
            .list_environment_agents(rpc::ListEnvironmentAgentsRequest {
                org_id: self.org.clone(),
                environment_id: self.environment.clone(),
                expected_scope: Some(self.scope.clone()).into(),
                ..Default::default()
            })
            .await
            .context("list original managed worker processes")?;
        ensure!(
            page.next_after_session_id.is_empty() && page.sessions.len() == self.sessions.len(),
            "original managed session inventory changed"
        );
        for (index, session) in self.sessions.iter().enumerate() {
            ensure!(
                page.sessions.iter().any(|s| s.session_id == session.session
                    && s.launch_generation == session.generation),
                "original managed session disappeared"
            );
            let current = self.current(client, index).await?;
            ensure!(
                current["peer"] == session.peer
                    && current["driver"]["driver_id"] == session.driver
                    && current["driver"]["native_thread_id"] == session.thread
                    && self
                        .record(client, index, &session.original_message)
                        .await?
                        == session.original_record,
                "CW selection changed an original managed peer, conversation or completed message"
            );
        }
        self.parent_notifications(client).await?;
        if self.continuity.is_some() {
            self.check_continuity(client).await?;
        }
        println!(
            "{}",
            json!({"event":"managed-checkpoint", "phase":phase,
            "scope":self.scope, "session_count":self.sessions.len()})
        );
        Ok(())
    }

    pub(super) fn process_witness(&self) -> Value {
        Value::Array(
            self.sessions
                .iter()
                .map(|s| {
                    json!({
                        "session_id":s.session, "driver_id":s.driver, "peer":s.peer,
                        "provider_sha256":s.provider_sha256, "provider_size":s.provider_size
                    })
                })
                .collect(),
        )
    }

    pub(super) async fn controls(&mut self, client: &CodewireClient) -> anyhow::Result<()> {
        let index = 1;
        self.check_continuity(client).await?;
        let held = self
            .continuity
            .as_ref()
            .context("original continuity is missing")?;
        let message = held.message.clone();
        let turn = held.turn.clone();
        let mut steer = self.control(
            index,
            rpc::EnvironmentAgentAction::Steer,
            "Keep waiting for interruption.",
        );
        steer.expected_turn_id = Some(turn.clone());
        steer.expected_active_message_id = Some(message.clone());
        let steering = self.action(client, steer, "steer-original-turn").await?;
        ensure!(
            steering.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
                && steering.pipe_acknowledged,
            "steering did not reach the original driver"
        );
        // Native ACK occurs while the held turn is still running. Its steer
        // record settles with that turn; awaiting terminal here would deadlock.
        let end = Instant::now() + WAIT;
        loop {
            let steered = self.record(client, index, &steering.message_id).await?;
            self.check_continuity(client).await?;
            if steered["native_acknowledged"] == true {
                validate_targeted_record(&steered, &message, &turn)?;
                break;
            }
            ensure!(
                Instant::now() < end,
                "native steering did not acknowledge the original turn"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut interrupt = self.control(index, rpc::EnvironmentAgentAction::Interrupt, "");
        interrupt.expected_turn_id = Some(turn.clone());
        interrupt.expected_active_message_id = Some(message.clone());
        let interrupted = self
            .action(client, interrupt, "interrupt-original-turn")
            .await?;
        ensure!(
            interrupted.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
                && interrupted.native_acknowledged,
            "native interruption did not acknowledge the original turn"
        );
        let finished = self.terminal(client, index, &message).await?;
        ensure!(
            finished["state"] == "interrupted" && finished["turn_id"] == turn,
            "original continuity turn was replayed or completed after interruption"
        );
        let steered = self.terminal(client, index, &steering.message_id).await?;
        validate_targeted_record(&steered, &message, &turn)?;
        ensure!(
            steered["state"] == "interrupted" && steered["native_acknowledged"] == true,
            "steering did not settle with the interrupted original turn"
        );
        let interrupted_record = self
            .terminal(client, index, &interrupted.message_id)
            .await?;
        validate_targeted_record(&interrupted_record, &message, &turn)?;
        ensure!(
            interrupted_record["state"] == "completed"
                && interrupted_record["native_acknowledged"] == true,
            "interrupt record did not settle for the original turn"
        );
        println!(
            "{}",
            json!({"event":"managed-active-continuity", "message_id":message,
            "native_turn_id":turn, "nonce":self.continuity.as_ref().unwrap().nonce,
            "outcome":"interrupted-original-turn-after-A-B-A"})
        );
        self.continuity = None;
        for worker in [1, 2] {
            let id = self
                .message(
                    client,
                    worker,
                    "Return the synthetic reply after the CW rollback.",
                )
                .await?;
            successful(
                &self.terminal(client, worker, &id).await?,
                self.sessions[worker].kind,
            )?;
        }
        Ok(())
    }

    pub(super) async fn revoked(
        &mut self,
        client: &CodewireClient,
        index: usize,
    ) -> anyhow::Result<()> {
        let id = self
            .message(
                client,
                index,
                "Return a fresh reply after the selected key was revoked.",
            )
            .await?;
        let denied = self.terminal(client, index, &id).await?;
        ensure!(
            matches!(denied["state"].as_str(), Some("error" | "unknown"))
                && denied["result"].as_str().is_none_or(str::is_empty),
            "revoked selected provider fell back to a successful native reply"
        );
        let before = denied.clone();
        tokio::time::sleep(Duration::from_millis(500)).await;
        ensure!(
            self.record(client, index, &id).await? == before,
            "revoked original message was replayed or changed its terminal outcome"
        );
        let kind = self.sessions[index].kind;
        for session in &mut self.sessions {
            if session.kind == kind {
                session.revoked = true;
            }
        }
        Ok(())
    }

    pub(super) async fn stop(&mut self, client: &CodewireClient) -> anyhow::Result<()> {
        for index in (0..self.sessions.len()).rev() {
            let op = self
                .action(
                    client,
                    self.control(index, rpc::EnvironmentAgentAction::Stop, ""),
                    "stop-original-generation",
                )
                .await?;
            ensure!(
                known_stop(&op),
                "original managed family cleanup is unproven"
            );
            self.sessions[index].stopped = true;
        }
        println!(
            "{}",
            json!({"event":"managed-complete", "original_requests":self.requests,
            "claims":["pinned_stock_API_proxy_turns", "parent_notifications_once", "original_peers_CW_A_B_A",
                "native_message_steer_interrupt", "revoked_provider_denial", "known_clean_Stop"]})
        );
        Ok(())
    }

    async fn observe(
        &self,
        client: &CodewireClient,
        id: &str,
    ) -> anyhow::Result<Option<rpc::EnvironmentAgentOperation>> {
        match client
            .observe_environment_agent(rpc::ObserveEnvironmentAgentRequest {
                org_id: self.org.clone(),
                environment_id: self.environment.clone(),
                request_id: id.into(),
                ..Default::default()
            })
            .await
        {
            Ok(response) => {
                let op = response
                    .operation
                    .into_option()
                    .context("managed Observe omitted its operation")?;
                validate_original(&op, id, &self.scope)?;
                Ok(Some(op))
            }
            // The current public journal deliberately uses Conflict for absent
            // metadata. Transport, permission and all other errors still fail.
            Err(error) if error.code() == ErrorCode::AlreadyExists => Ok(None),
            Err(error) => Err(error).context("observe only the saved managed UUID"),
        }
    }

    async fn stable_observe(
        &self,
        client: &CodewireClient,
        original: &rpc::EnvironmentAgentOperation,
    ) -> anyhow::Result<()> {
        for _ in 0..2 {
            ensure!(
                self.observe(client, &original.request_id).await?.as_ref() == Some(original),
                "reconnected Observe changed or lost an original managed outcome"
            );
        }
        Ok(())
    }

    async fn historical(&self, client: &CodewireClient) -> anyhow::Result<()> {
        for (index, session) in self.sessions.iter().enumerate() {
            // A current-generation read must never be used to relabel a saved
            // gen1 message. Historical reads retain the original field value.
            ensure!(
                self.record_at(client, index, &session.original_message, 1)
                    .await?
                    == session.original_record,
                "Restart changed an original-generation completed record"
            );
        }
        Ok(())
    }

    /// Only after root's original nine pidfds are terminal and the original
    /// observer has closed normally. This starts one new lead family explicitly;
    /// it is not continuity of that family's original processes.
    pub(super) async fn restart(
        &mut self,
        client: &CodewireClient,
        reconnected: &CodewireClient,
    ) -> anyhow::Result<()> {
        ensure!(
            self.continuity.is_none() && self.sessions.iter().all(|s| s.stopped),
            "Restart requires explicit known-clean Stop of all original families"
        );
        for saved in &self.saved {
            self.stable_observe(reconnected, saved).await?;
        }
        self.historical(reconnected).await?;
        let original_generation = self.sessions[0].generation;
        let old_peer = self.sessions[0].peer.clone();
        let restarted = self
            .action(
                client,
                self.control(0, rpc::EnvironmentAgentAction::Restart, ""),
                "explicit-restart-after-original-death",
            )
            .await?;
        ensure!(
            restarted.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
                && !restarted.cleanup_unknown
                && matches!(
                    restarted.lifecycle.as_known(),
                    Some(
                        codewire_client::EnvironmentSessionState::Starting
                            | codewire_client::EnvironmentSessionState::Running
                    )
                ),
            "explicit Restart did not settle the checked next generation"
        );
        self.sessions[0].generation = original_generation
            .checked_add(1)
            .context("Restart generation overflow")?;
        self.sessions[0].stopped = false;
        let end = Instant::now() + WAIT;
        let new_peer = loop {
            let current = self.current(reconnected, 0).await?;
            if current["driver"]["phase"] == "idle"
                && current["peer"]["finished_at"].is_null()
                && current["driver"]["native_thread_id"] == self.sessions[0].thread
            {
                validate_restart_peer(&self.sessions[0], &old_peer, &current)?;
                break current["peer"].clone();
            }
            ensure!(
                Instant::now() < end,
                "restarted original conversation did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        self.sessions[0].peer = new_peer;
        self.stable_observe(reconnected, &restarted).await?;
        self.historical(reconnected).await?;

        // A fresh UUID never sent to Mutate is metadata-only and remains absent.
        let never_sent = Uuid::new_v4().to_string();
        for _ in 0..2 {
            ensure!(
                self.observe(reconnected, &never_sent).await?.is_none(),
                "Observe invented an unissued managed request"
            );
        }
        println!(
            "{}",
            json!({"event":"managed-unissued-observe","request_id":never_sent,
            "response":"already-exists","mutations":0})
        );

        // Stale mutation is sent exactly once under a new UUID. An unrelated
        // network failure must not be accepted as a generation refusal.
        let stale_id = Uuid::new_v4().to_string();
        self.requests.push(stale_id.clone());
        let mut stale = self.control(
            0,
            rpc::EnvironmentAgentAction::Message,
            "Stale generation must not run.",
        );
        stale.expected_launch_generation = original_generation;
        println!(
            "{}",
            json!({"event":"managed-before-send","request_id":stale_id,
            "action":"stale-generation-negative","environment_id":self.environment})
        );
        let refused = client
            .mutate_environment_agent(rpc::MutateEnvironmentAgentRequest {
                org_id: self.org.clone(),
                environment_id: self.environment.clone(),
                request_id: stale_id.clone(),
                expected_scope: Some(self.scope.clone()).into(),
                operation: Some(rpc::mutate_environment_agent_request::Operation::Control(
                    Box::new(stale),
                )),
                ..Default::default()
            })
            .await;
        let refused = match refused {
            Err(refused) => refused,
            Ok(_) => anyhow::bail!("stale generation was not refused before durable admission"),
        };
        ensure!(
            refused.request_id == stale_id
                && refused.source.code() == ErrorCode::AlreadyExists
                && self.observe(reconnected, &stale_id).await?.is_none(),
            "stale generation did not produce the exact pre-admission refusal"
        );
        ensure!(
            self.current(reconnected, 0).await?["peer"] == self.sessions[0].peer,
            "stale generation affected the restarted original peer"
        );
        self.historical(reconnected).await?;

        let cancelled = self.caller_cancellation(client, reconnected).await?;
        let mut stop = self.control(0, rpc::EnvironmentAgentAction::Stop, "");
        if let Some(original) = &cancelled
            && original.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Unknown)
        {
            stop.cleanup_of_request_id = Some(original.request_id.clone());
        }
        let stopped = self
            .action(client, stop, "known-clean-restarted-family-stop")
            .await?;
        ensure!(known_stop(&stopped), "restarted family cleanup is unproven");
        self.sessions[0].stopped = true;
        if let Some(original) = cancelled {
            self.stable_observe(reconnected, &original).await?;
        }
        self.stable_observe(reconnected, &stopped).await?;
        self.historical(reconnected).await?;
        println!(
            "{}",
            json!({"event":"managed-restart-complete","original_requests":self.requests,
            "generation":self.sessions[0].generation,"claims":["explicit_Restart_checked_generation",
                "retained_original_generation_history","fresh_client_observe_no_replay",
                "stale_generation_refusal","caller_drop_observed_original_UUID","known_clean_restarted_Stop"]})
        );
        Ok(())
    }

    async fn caller_cancellation(
        &mut self,
        client: &CodewireClient,
        reconnected: &CodewireClient,
    ) -> anyhow::Result<Option<rpc::EnvironmentAgentOperation>> {
        let id = Uuid::new_v4().to_string();
        self.requests.push(id.clone());
        let control = self.control(
            0,
            rpc::EnvironmentAgentAction::Message,
            "Return one fresh reply for the single caller-drop request.",
        );
        let request = rpc::MutateEnvironmentAgentRequest {
            org_id: self.org.clone(),
            environment_id: self.environment.clone(),
            request_id: id.clone(),
            expected_scope: Some(self.scope.clone()).into(),
            operation: Some(rpc::mutate_environment_agent_request::Operation::Control(
                Box::new(control.clone()),
            )),
            ..Default::default()
        };
        println!(
            "{}",
            json!({"event":"managed-before-send","request_id":id,
            "action":"single-caller-drop","environment_id":self.environment})
        );
        // This drops only the HTTP waiter. It is not a transport interception or
        // a forced lost ACK, and a fast response may win the actual race.
        #[cfg(not(test))]
        let sent = tokio::time::timeout(
            Duration::from_millis(25),
            client.mutate_environment_agent(request),
        )
        .await;
        #[cfg(test)]
        let sent = if let Some(receipt) = self.caller_drop_receipt.take() {
            // Only this fixture arms cancellation after its real server has
            // received the original UUID. Drop the same pending HTTP future;
            // no second mutation is created and no response is manufactured.
            let mutation = client.mutate_environment_agent(request);
            tokio::pin!(mutation);
            let received = tokio::time::timeout(WAIT, async {
                tokio::select! {
                    biased;
                    received = receipt => {
                        received.context("caller-drop fixture lost its original server receipt")
                    }
                    _ = &mut mutation => {
                        anyhow::bail!("caller-drop fixture mutation settled before cancellation")
                    }
                }
            })
            .await
            .context("caller-drop fixture did not receive its original UUID within bound")??;
            ensure!(
                received == id,
                "caller-drop fixture received a different UUID"
            );
            let pending = std::future::poll_fn(|context| {
                std::task::Poll::Ready(matches!(
                    std::future::Future::poll(mutation.as_mut(), context),
                    std::task::Poll::Pending
                ))
            })
            .await;
            ensure!(
                pending,
                "caller-drop fixture mutation settled before cancellation"
            );
            Err(())
        } else {
            tokio::time::timeout(
                Duration::from_millis(25),
                client.mutate_environment_agent(request),
            )
            .await
            .map_err(|_| ())
        };
        let dropped = sent.is_err();
        let response = match sent {
            Ok(Ok(response)) => Some(
                response
                    .operation
                    .into_option()
                    .context("caller-drop response omitted operation")?,
            ),
            Ok(Err(error)) => {
                ensure!(
                    error.request_id == id,
                    "caller-drop error changed its original UUID"
                );
                None
            }
            Err(_) => None,
        };
        let end = Instant::now() + WAIT;
        let mut absent = 0;
        let original = loop {
            match self.observe(reconnected, &id).await? {
                Some(op) => {
                    validate_control(&op, &control)?;
                    if matches!(
                        op.phase.as_known(),
                        Some(
                            rpc::EnvironmentAgentPhase::Completed
                                | rpc::EnvironmentAgentPhase::Rejected
                                | rpc::EnvironmentAgentPhase::Unknown
                        )
                    ) {
                        break Some(op);
                    }
                }
                None => {
                    absent += 1;
                    if absent == 2 && response.is_none() {
                        break None;
                    }
                }
            }
            ensure!(
                Instant::now() < end,
                "caller-drop original UUID remains unresolved; it must not be replayed"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        if let Some(op) = &original {
            if let Some(response) = &response {
                ensure!(
                    op == response,
                    "caller-drop response and original Observe differ"
                );
            }
            self.stable_observe(reconnected, op).await?;
            if op.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed) {
                ensure!(
                    op.pipe_acknowledged && op.message_id == id,
                    "caller-drop completed operation omitted exact driver delivery"
                );
                let record = self.terminal(reconnected, 0, &id).await?;
                if self.sessions[0].revoked {
                    ensure!(
                        matches!(record["state"].as_str(), Some("error" | "unknown"))
                            && record["result"].as_str().is_none_or(str::is_empty),
                        "restarted revoked provider fell back to a successful reply"
                    );
                } else {
                    successful(&record, self.sessions[0].kind)?;
                }
            }
        } else {
            ensure!(
                dropped && response.is_none(),
                "a received mutation outcome lost its durable metadata"
            );
        }
        println!(
            "{}",
            json!({"event":"managed-caller-drop-observed","request_id":id,
            "caller_dropped":dropped,"actual_phase":original.as_ref().map(|o|format!("{:?}",o.phase.as_known())).unwrap_or_else(||"metadata-absent-already-exists".into()),
            "mutation_attempts":1,"forced_lost_ack":false})
        );
        Ok(original)
    }
}

fn validate_original(
    op: &rpc::EnvironmentAgentOperation,
    id: &str,
    scope: &rpc::EnvironmentAgentScope,
) -> anyhow::Result<()> {
    ensure!(
        op.request_id == id
            && op.scope.as_option() == Some(scope)
            && op.fingerprint_sha256.len() == 32
            && op.fingerprint_sha256.iter().any(|b| *b != 0)
            && matches!(
                op.phase.as_known(),
                Some(
                    rpc::EnvironmentAgentPhase::Admitted
                        | rpc::EnvironmentAgentPhase::Issued
                        | rpc::EnvironmentAgentPhase::Completed
                        | rpc::EnvironmentAgentPhase::Rejected
                        | rpc::EnvironmentAgentPhase::Unknown
                )
            ),
        "managed operation changed its original request, scope or durable fingerprint"
    );
    Ok(())
}

fn validate_control(
    op: &rpc::EnvironmentAgentOperation,
    control: &rpc::EnvironmentAgentControl,
) -> anyhow::Result<()> {
    let generation = if control.action.as_known() == Some(rpc::EnvironmentAgentAction::Restart)
        && op.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
    {
        control
            .expected_launch_generation
            .checked_add(1)
            .context("Restart generation overflow")?
    } else {
        control.expected_launch_generation
    };
    let message = if matches!(
        control.action.as_known(),
        Some(
            rpc::EnvironmentAgentAction::Message
                | rpc::EnvironmentAgentAction::Steer
                | rpc::EnvironmentAgentAction::Interrupt
        )
    ) {
        op.request_id.as_str()
    } else {
        ""
    };
    ensure!(
        op.session_id == control.session_id
            && op.driver_id == control.driver_id
            && op.launch_generation == generation
            && op.message_id == message
            && op.cleanup_of_request_id
                == control.cleanup_of_request_id.as_deref().unwrap_or_default(),
        "managed control changed its original session, driver, generation or request lineage"
    );
    Ok(())
}

fn validate_continuity(
    session: &Conversation,
    held: &Continuity,
    current: &Value,
    record: &Value,
) -> anyhow::Result<()> {
    ensure!(
        current["session"]["session_id"] == session.session
            && current["session"]["launch_generation"] == session.generation
            && current["session"]["state"] == "running"
            && current["session"]["cleanup_unknown"] == false
            && current["peer"] == session.peer
            && current["driver"]["driver_id"] == session.driver
            && current["driver"]["native_thread_id"] == session.thread
            && current["driver"]["phase"] == "busy"
            && current["driver"]["active_message_id"] == held.message
            && current["driver"]["current_turn_id"] == held.turn
            && record["id"] == held.message
            && record["driver_id"] == session.driver
            && record["target_session_id"] == session.session
            && record["platform_launch_generation"] == session.generation
            && record["state"] == "running"
            && record["turn_id"] == held.turn
            && record["native_acknowledged"] == true
            && record["error"].is_null()
            && !record["result"]
                .as_str()
                .is_some_and(|s| s.contains("CW_UPDATE_HOLD_EXPIRED")),
        "the original active native turn changed or ended across CW selection"
    );
    Ok(())
}

fn validate_targeted_record(record: &Value, message: &str, turn: &str) -> anyhow::Result<()> {
    ensure!(
        record["expected_active_message_id"] == message
            && record["expected_turn_id"] == turn
            && (record["turn_id"].is_null() || record["turn_id"] == turn),
        "native control record no longer targets the original active turn"
    );
    Ok(())
}

fn validate_restart_peer(
    session: &Conversation,
    original: &Value,
    current: &Value,
) -> anyhow::Result<()> {
    let peer = &current["peer"];
    ensure!(
        current["session"]["session_id"] == session.session
            && current["session"]["launch_generation"] == session.generation
            && current["session"]["state"] == "running"
            && current["session"]["cleanup_unknown"] == false
            && current["driver"]["driver_id"] == session.driver
            && current["driver"]["native_thread_id"] == session.thread
            && peer["identity"]["environment_id"] == original["identity"]["environment_id"]
            && peer["identity"]["session_id"] == session.session
            && peer["identity"]["driver_id"] == session.driver
            && peer["identity"]["boot_id"] == original["identity"]["boot_id"]
            && peer["identity"]["instance_id"].as_str().is_some_and(
                |s| Uuid::parse_str(s).is_ok_and(|u| !u.is_nil() && u.to_string() == s)
            )
            && peer["identity"]["instance_id"] != original["identity"]["instance_id"]
            && peer["identity"]["driver_pid"]
                .as_u64()
                .is_some_and(|p| p > 0)
            && peer["identity"]["driver_start_ticks"]
                .as_u64()
                .is_some_and(|p| p > 0)
            && (peer["identity"]["driver_pid"] != original["identity"]["driver_pid"]
                || peer["identity"]["driver_start_ticks"]
                    != original["identity"]["driver_start_ticks"])
            && peer["guardian_pid"].as_u64().is_some_and(|p| p > 0)
            && peer["guardian_start_ticks"].as_u64().is_some_and(|p| p > 0)
            && (peer["guardian_pid"] != original["guardian_pid"]
                || peer["guardian_start_ticks"] != original["guardian_start_ticks"])
            && peer["provider_pid"].as_u64().is_some_and(|p| p > 0)
            && peer["finished_at"].is_null()
            && peer["error"].is_null(),
        "explicit Restart did not retain the conversation with a new peer birth"
    );
    Ok(())
}

fn known_stop(op: &rpc::EnvironmentAgentOperation) -> bool {
    op.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed)
        && !op.cleanup_unknown
        && match op.lifecycle.as_known() {
            Some(codewire_client::EnvironmentSessionState::Stopped) => op.exit_code.is_none(),
            Some(codewire_client::EnvironmentSessionState::Exited) => op.exit_code == Some(0),
            _ => false,
        }
}

fn successful(record: &Value, kind: rpc::EnvironmentAgentKind) -> anyhow::Result<()> {
    let marker = if kind == rpc::EnvironmentAgentKind::Codex {
        "CWOPENAI"
    } else {
        "CWCLAUDE21238"
    };
    let text = record["result"]
        .as_str()
        .context("native reply omitted its result")?;
    ensure!(
        record["state"] == "completed"
            && record["native_acknowledged"] == true
            && record["error"].is_null()
            && text.contains(marker)
            && text.contains("[REDACTED]")
            && !text.contains(OPENAI_KEY)
            && !text.contains(ANTHROPIC_KEY),
        "stock native turn did not complete through the synthetic typed proxy with redaction"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use codewire_client::{ClientConfig, StaticTokenProvider};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DRIVER: &str = "066b7607-2f23-47ec-ae34-6d78148472a0";
    const MESSAGE: &str = "dff2f8e1-1788-454e-94a9-f4dc6d4b057e";
    const MUTATE: &str = "/codewire.v1.EnvironmentAgentService/MutateEnvironmentAgent";
    const OBSERVE: &str = "/codewire.v1.EnvironmentAgentService/ObserveEnvironmentAgent";

    fn journey() -> Journey {
        let peer = json!({"identity":{"environment_id":"env", "session_id":format!("session-{DRIVER}"),
            "driver_id":DRIVER,"instance_id":MESSAGE,"boot_id":"original-boot", "driver_pid":11,"driver_start_ticks":101},
            "guardian_pid":12,"guardian_start_ticks":102,"provider_pid":13,"finished_at":null,"error":null});
        let record = json!({"id":MESSAGE,"driver_id":DRIVER,"target_session_id":format!("session-{DRIVER}"),
            "platform_launch_generation":1,"state":"completed","native_acknowledged":true,
            "error":null,"result":"CWOPENAI broker [REDACTED]"});
        Journey {
            org: "org".into(),
            environment: "env".into(),
            scope: rpc::EnvironmentAgentScope {
                incarnation: Some(
                    codewire_client::cw_runtime::EnvironmentCwRuntimeIncarnation {
                        org_id: "org".into(),
                        environment_id: "env".into(),
                        pod_uid: "original-pod".into(),
                        binding_generation: 7,
                        ..Default::default()
                    },
                )
                .into(),
                support_image_sha256: vec![7; 32],
                support_image_size: 123,
                ..Default::default()
            },
            sessions: vec![Conversation {
                session: format!("session-{DRIVER}"),
                driver: DRIVER.into(),
                generation: 2,
                kind: rpc::EnvironmentAgentKind::Codex,
                provider_sha256: "ab".repeat(32),
                provider_size: 123,
                peer,
                thread: "original-thread".into(),
                original_message: MESSAGE.into(),
                original_record: record,
                stopped: false,
                revoked: true,
            }],
            requests: vec![],
            saved: vec![],
            continuity: None,
            caller_drop_receipt: None,
        }
    }

    fn operation(
        j: &Journey,
        request: &str,
        phase: rpc::EnvironmentAgentPhase,
    ) -> rpc::EnvironmentAgentOperation {
        rpc::EnvironmentAgentOperation {
            request_id: request.into(),
            scope: Some(j.scope.clone()).into(),
            fingerprint_sha256: vec![9; 32],
            session_id: j.sessions[0].session.clone(),
            driver_id: DRIVER.into(),
            message_id: request.into(),
            launch_generation: 2,
            phase: phase.into(),
            lifecycle: codewire_client::EnvironmentSessionState::Running.into(),
            cleanup_unknown: phase == rpc::EnvironmentAgentPhase::Unknown,
            ..Default::default()
        }
    }

    fn running(j: &Journey) -> (Continuity, Value, Value) {
        let s = &j.sessions[0];
        let held = Continuity {
            message: MESSAGE.into(),
            turn: "original-turn".into(),
            nonce: "1234abcd".into(),
        };
        let current = json!({"session":{"session_id":s.session,"launch_generation":s.generation,"state":"running","cleanup_unknown":false},
            "peer":s.peer,"driver":{"driver_id":s.driver,"native_thread_id":s.thread,"phase":"busy",
                "active_message_id":held.message,"current_turn_id":held.turn}});
        let record = json!({"id":held.message,"driver_id":s.driver,"target_session_id":s.session,
            "platform_launch_generation":s.generation,"state":"running","native_acknowledged":true,
            "turn_id":held.turn,"error":null,"result":null});
        (held, current, record)
    }

    fn response<M: buffa::Message>(value: &M) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/proto")
            .set_body_bytes(value.encode_to_vec())
    }
    fn absent() -> ResponseTemplate {
        ResponseTemplate::new(409)
            .insert_header("content-type", "application/json")
            .set_body_json(json!({"code":"already_exists","message":"metadata absent"}))
    }
    fn client(server: &MockServer) -> CodewireClient {
        CodewireClient::with_http(
            ClientConfig::new(server.uri()).unwrap(),
            StaticTokenProvider::new("synthetic-fixture-token").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap()
    }

    #[test]
    fn active_native_turn_rejects_message_turn_generation_ack_and_expiry_drift() {
        let j = journey();
        let (held, current, record) = running(&j);
        validate_continuity(&j.sessions[0], &held, &current, &record).unwrap();
        for field in 0..8 {
            let (mut current, mut record) = (current.clone(), record.clone());
            match field {
                0 => current["driver"]["active_message_id"] = json!("replacement-message"),
                1 => current["driver"]["current_turn_id"] = json!("replacement-turn"),
                2 => current["driver"]["native_thread_id"] = json!("replacement-thread"),
                3 => record["platform_launch_generation"] = json!(1),
                4 => record["native_acknowledged"] = json!(false),
                5 => record["state"] = json!("completed"),
                6 => record["result"] = json!("CW_UPDATE_HOLD_EXPIRED 1234abcd"),
                _ => current["peer"]["identity"]["instance_id"] = json!("replacement-peer"),
            }
            assert!(
                validate_continuity(&j.sessions[0], &held, &current, &record).is_err(),
                "drift {field}"
            );
        }
    }

    #[test]
    fn restart_control_requires_checked_next_generation_and_original_request_lineage() {
        let j = journey();
        let mut op = operation(&j, MESSAGE, rpc::EnvironmentAgentPhase::Completed);
        let mut control = j.control(0, rpc::EnvironmentAgentAction::Restart, "");
        control.expected_launch_generation = 1;
        op.message_id.clear();
        validate_control(&op, &control).unwrap();
        op.launch_generation = 1;
        assert!(validate_control(&op, &control).is_err());
        op.launch_generation = 2;
        op.driver_id = Uuid::new_v4().to_string();
        assert!(validate_control(&op, &control).is_err());
        op.driver_id = DRIVER.into();
        control.expected_launch_generation = u64::MAX;
        assert!(validate_control(&op, &control).is_err());
        control = j.control(0, rpc::EnvironmentAgentAction::Message, "reply");
        op.message_id = MESSAGE.into();
        validate_control(&op, &control).unwrap();
        op.message_id = Uuid::new_v4().to_string();
        assert!(validate_control(&op, &control).is_err());
    }

    #[test]
    fn known_stop_accepts_only_stopped_without_exit_or_clean_exited_zero() {
        let j = journey();
        let mut op = operation(&j, MESSAGE, rpc::EnvironmentAgentPhase::Completed);
        op.lifecycle = codewire_client::EnvironmentSessionState::Stopped.into();
        assert!(known_stop(&op));
        op.exit_code = Some(0);
        assert!(!known_stop(&op));
        op.lifecycle = codewire_client::EnvironmentSessionState::Exited.into();
        assert!(known_stop(&op));
        op.exit_code = Some(1);
        assert!(!known_stop(&op));
        op.exit_code = Some(0);
        op.cleanup_unknown = true;
        assert!(!known_stop(&op));
        op.cleanup_unknown = false;
        op.lifecycle = codewire_client::EnvironmentSessionState::Failed.into();
        assert!(!known_stop(&op));
    }

    #[test]
    fn restart_peer_keeps_original_conversation_and_requires_new_driver_guardian_births() {
        let j = journey();
        let (_, mut current, _) = running(&j);
        let old = j.sessions[0].peer.clone();
        current["peer"]["identity"]["instance_id"] = json!(Uuid::new_v4().to_string());
        current["peer"]["identity"]["driver_start_ticks"] = json!(201);
        current["peer"]["guardian_start_ticks"] = json!(202);
        validate_restart_peer(&j.sessions[0], &old, &current).unwrap();
        for field in 0..4 {
            let mut bad = current.clone();
            match field {
                0 => bad["peer"]["identity"]["driver_start_ticks"] = json!(101),
                1 => bad["peer"]["guardian_start_ticks"] = json!(102),
                2 => bad["peer"]["identity"]["boot_id"] = json!("replacement-boot"),
                _ => bad["session"]["launch_generation"] = json!(1),
            }
            assert!(validate_restart_peer(&j.sessions[0], &old, &bad).is_err());
        }
    }

    #[tokio::test]
    async fn historical_message_uses_original_generation_through_real_public_reader() {
        let server = MockServer::start().await;
        let j = journey();
        let data = serde_json::to_vec(&json!({"record":j.sessions[0].original_record})).unwrap();
        let reply = rpc::ReadEnvironmentAgentResponse {
            scope: Some(j.scope.clone()).into(),
            session_id: j.sessions[0].session.clone(),
            driver_id: DRIVER.into(),
            launch_generation: 1,
            kind: rpc::EnvironmentAgentRecordKind::Message.into(),
            message_id: MESSAGE.into(),
            record_sha256: Sha256::digest(&data).to_vec(),
            record_json: data,
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.EnvironmentAgentService/ReadEnvironmentAgent",
            ))
            .respond_with(response(&reply))
            .expect(2)
            .mount(&server)
            .await;
        assert_eq!(
            j.record_at(&client(&server), 0, MESSAGE, 1).await.unwrap(),
            j.sessions[0].original_record
        );
        assert!(j.record(&client(&server), 0, MESSAGE).await.is_err());
        let requests = server.received_requests().await.unwrap();
        let first = rpc::ReadEnvironmentAgentRequest::decode_from_slice(&requests[0].body).unwrap();
        let second =
            rpc::ReadEnvironmentAgentRequest::decode_from_slice(&requests[1].body).unwrap();
        assert_eq!(first.expected_launch_generation, 1);
        assert_eq!(second.expected_launch_generation, 2);
        assert_eq!(first.expected_scope.as_option(), Some(&j.scope));
        assert_eq!(first.message_id, MESSAGE);
    }

    #[tokio::test]
    async fn observe_absence_has_no_mutation_and_transport_or_auth_errors_remain_errors() {
        for (status, code, accepted) in [
            (409, "already_exists", true),
            (503, "unavailable", false),
            (403, "permission_denied", false),
            (404, "not_found", false),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(OBSERVE))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("content-type", "application/json")
                        .set_body_json(json!({"code":code,"message":"fixed fixture error"})),
                )
                .expect(1)
                .mount(&server)
                .await;
            let result = journey().observe(&client(&server), MESSAGE).await;
            if accepted {
                assert!(result.unwrap().is_none());
            } else {
                assert!(result.is_err());
            }
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.url.path() == OBSERVE)
            );
        }
    }

    #[tokio::test]
    async fn caller_drop_observes_one_original_unknown_request_without_mutation_replay() {
        let server = MockServer::start().await;
        let mut j = journey();
        let scope = j.scope.clone();
        let session = j.sessions[0].session.clone();
        let scope2 = scope.clone();
        let session2 = session.clone();
        let (receipt_tx, receipt_rx) = tokio::sync::oneshot::channel();
        let receipt =
            std::sync::Arc::new(std::sync::Mutex::new((None::<String>, Some(receipt_tx))));
        let mutate_receipt = receipt.clone();
        j.caller_drop_receipt = Some(receipt_rx);
        Mock::given(method("POST"))
            .and(path(MUTATE))
            .respond_with(move |request: &wiremock::Request| {
                let request =
                    rpc::MutateEnvironmentAgentRequest::decode_from_slice(&request.body).unwrap();
                assert_eq!(request.expected_scope.as_option(), Some(&scope));
                let mut receipt = mutate_receipt.lock().unwrap();
                assert!(receipt.0.is_none(), "one actual original mutation only");
                receipt.0 = Some(request.request_id.clone());
                receipt
                    .1
                    .take()
                    .unwrap()
                    .send(request.request_id.clone())
                    .unwrap();
                let op = rpc::EnvironmentAgentOperation {
                    request_id: request.request_id.clone(),
                    scope: Some(scope.clone()).into(),
                    fingerprint_sha256: vec![9; 32],
                    session_id: session.clone(),
                    driver_id: DRIVER.into(),
                    message_id: request.request_id,
                    launch_generation: 2,
                    phase: rpc::EnvironmentAgentPhase::Completed.into(),
                    pipe_acknowledged: true,
                    lifecycle: codewire_client::EnvironmentSessionState::Running.into(),
                    ..Default::default()
                };
                response(&rpc::MutateEnvironmentAgentResponse {
                    operation: Some(op).into(),
                    ..Default::default()
                })
                .set_delay(Duration::from_millis(300))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(OBSERVE))
            .respond_with(move |request: &wiremock::Request| {
                let request =
                    rpc::ObserveEnvironmentAgentRequest::decode_from_slice(&request.body).unwrap();
                assert_eq!(
                    receipt.lock().unwrap().0.as_ref(),
                    Some(&request.request_id),
                    "Observe must read the original actually received mutation UUID"
                );
                let op = rpc::EnvironmentAgentOperation {
                    request_id: request.request_id.clone(),
                    scope: Some(scope2.clone()).into(),
                    fingerprint_sha256: vec![9; 32],
                    session_id: session2.clone(),
                    driver_id: DRIVER.into(),
                    message_id: request.request_id,
                    launch_generation: 2,
                    phase: rpc::EnvironmentAgentPhase::Unknown.into(),
                    cleanup_unknown: true,
                    reason_code: "platform-agent-dispatch-unknown".into(),
                    lifecycle: codewire_client::EnvironmentSessionState::Running.into(),
                    ..Default::default()
                };
                response(&rpc::ObserveEnvironmentAgentResponse {
                    operation: Some(op).into(),
                    ..Default::default()
                })
            })
            .expect(3)
            .mount(&server)
            .await;
        let original = j
            .caller_cancellation(&client(&server), &client(&server))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            original.phase.as_known(),
            Some(rpc::EnvironmentAgentPhase::Unknown)
        );
        assert_eq!(j.requests.len(), 1);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.iter().filter(|r| r.url.path() == MUTATE).count(),
            1
        );
        for request in requests.iter().filter(|r| r.url.path() == OBSERVE) {
            assert_eq!(
                rpc::ObserveEnvironmentAgentRequest::decode_from_slice(&request.body)
                    .unwrap()
                    .request_id,
                j.requests[0]
            );
        }
    }

    #[tokio::test]
    async fn fresh_client_observe_preserves_original_row_and_refuses_changed_saved_outcome() {
        for changed in [false, true] {
            let server = MockServer::start().await;
            let j = journey();
            let original = operation(&j, MESSAGE, rpc::EnvironmentAgentPhase::Unknown);
            let mut returned = original.clone();
            if changed {
                returned.launch_generation = 1;
            }
            Mock::given(method("POST"))
                .and(path(OBSERVE))
                .respond_with(response(&rpc::ObserveEnvironmentAgentResponse {
                    operation: Some(returned).into(),
                    ..Default::default()
                }))
                .expect(if changed { 1 } else { 2 })
                .mount(&server)
                .await;
            let result = j.stable_observe(&client(&server), &original).await;
            assert_eq!(result.is_err(), changed);
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.url.path() == OBSERVE)
            );
        }
    }

    #[tokio::test]
    async fn unissued_uuid_absence_is_only_observed_and_never_sent_to_mutate() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(OBSERVE))
            .respond_with(absent())
            .expect(2)
            .mount(&server)
            .await;
        let j = journey();
        let first = client(&server);
        let fresh = client(&server);
        assert!(j.observe(&first, MESSAGE).await.unwrap().is_none());
        assert!(j.observe(&fresh, MESSAGE).await.unwrap().is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}
