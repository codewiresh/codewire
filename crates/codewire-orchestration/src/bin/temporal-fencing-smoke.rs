//! Observable Kind proof for the #916 final Temporal fencing protocol.
//!
//! This binary exists only for `--features kind-e2e`. In driver mode it
//! creates disposable environments and worker subprocesses against the real
//! Kind Postgres, Temporal, Kubernetes API, and agent-sandbox controller. In
//! worker mode it serves a scenario-specific task queue with the production
//! workflow/activity code plus the feature-gated evidence hooks.

#[cfg(not(feature = "kind-e2e"))]
fn main() {
    panic!("temporal-fencing-smoke requires --features kind-e2e");
}

#[cfg(feature = "kind-e2e")]
mod enabled {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context as _;
    use codewire_orchestration::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE;
    use codewire_orchestration::sandbox::client::SandboxClient;
    use codewire_orchestration::sandbox::template::gateway_host_key_secret_name;
    use codewire_orchestration::temporal::{
        EnvironmentCommand, EnvironmentWorkflow, EnvironmentWorkflowRun,
        OrganizationDeletionWorkflow, TemporalTrigger, environment_workflow_id,
        organization_deletion_workflow_id,
    };
    use codewire_orchestration::worker;
    use codewire_orchestration::worker::create::{
        SandboxWorkerCfg, environment_per_env_template_name,
    };
    use codewire_orchestration::worker::env_data::{load_backend_row, load_environment};
    use codewire_orchestration::worker::organization_deletion::OrganizationDeletionWorkflowInput;
    use codewire_proto::codewire::v1::{
        DeleteOrganizationRequest, DeleteOrganizationResponse, GetOrganizationRequest,
        Organization, OrganizationDeletionState, OrganizationServiceClient,
    };
    use codewire_server_core::auth::{SESSION_COOKIE_NAME, hash_session_token};
    use codewire_server_core::org_deletion::{
        OrganizationMutationClass, acquire_organization_mutation_lease,
        mark_organization_deletion_started, organization_deletion_operation,
        record_organization_deletion_start_attempt, release_organization_mutation_lease,
    };
    use connectrpc::ErrorCode;
    use connectrpc::client::{ClientConfig, HttpClient};
    use k8s_openapi::api::core::v1::Secret;
    use kube::Api;
    use reqwest::header::COOKIE;
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use temporalio_client::{
        Client, ClientOptions, Connection, ConnectionOptions, WorkflowFetchHistoryOptions,
        WorkflowGetResultOptions, WorkflowSignalOptions, WorkflowStartOptions,
        WorkflowTerminateOptions,
    };
    use temporalio_common::protos::temporal::api::history::v1::history_event::Attributes;
    use tokio::process::{Child, Command};

    const TEMPORAL_NAMESPACE: &str = "default";
    const SANDBOX_NAMESPACE: &str = "dev-sandboxes";
    const SETUP_WAIT_QUIET_LIMIT: Duration = Duration::from_secs(240);
    const SETUP_WAIT_ABSOLUTE_LIMIT: Duration = Duration::from_secs(600);
    const WORKER_DEATH_MARKER: &str = "/workspace/.wi-f-worker-death";
    const WORKER_DEATH_MARKER_WAIT: Duration = Duration::from_secs(30);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CompletionState {
        Pending,
        Complete,
        Terminal,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CompletionDecision {
        Continue,
        Complete,
        Terminal,
        QuietExpired,
        AbsoluteExpired,
    }

    struct ProgressTracker<T> {
        quiet_limit: Duration,
        absolute_limit: Duration,
        last_progress_at: Duration,
        last_observation: Option<T>,
    }

    impl<T: Clone + PartialEq> ProgressTracker<T> {
        fn new(quiet_limit: Duration, absolute_limit: Duration) -> Self {
            Self {
                quiet_limit,
                absolute_limit,
                last_progress_at: Duration::ZERO,
                last_observation: None,
            }
        }

        fn observe(
            &mut self,
            elapsed: Duration,
            state: CompletionState,
            observation: &T,
        ) -> CompletionDecision {
            if elapsed >= self.absolute_limit {
                return CompletionDecision::AbsoluteExpired;
            }
            match state {
                CompletionState::Complete => return CompletionDecision::Complete,
                CompletionState::Terminal => return CompletionDecision::Terminal,
                CompletionState::Pending => {}
            }
            if self.last_observation.as_ref() != Some(observation) {
                self.last_observation = Some(observation.clone());
                self.last_progress_at = elapsed;
            }
            if elapsed.saturating_sub(self.last_progress_at) >= self.quiet_limit {
                CompletionDecision::QuietExpired
            } else {
                CompletionDecision::Continue
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SetupBackendSnapshot {
        setup_complete: bool,
        setup_error: Option<String>,
        owner_generation: Option<i64>,
        owner_activity_id: Option<String>,
        owner_attempt: Option<i32>,
        owner_phase: Option<i32>,
        owner_status: Option<String>,
        owner_pod_uid: Option<String>,
    }

    type SetupBackendRow = (
        bool,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<i32>,
        Option<i32>,
        Option<String>,
        Option<String>,
    );

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SetupHistorySnapshot {
        attempt: i32,
        terminal: Option<String>,
        error: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SetupWaitSnapshot {
        environment: Option<(String, String, Option<String>, i64)>,
        backend: Option<SetupBackendSnapshot>,
        pod: Result<Option<(String, String)>, String>,
        exec_wait_failure: Option<String>,
        evidence: Result<String, String>,
        history: SetupHistorySnapshot,
    }

    impl SetupWaitSnapshot {
        fn completion_state(&self) -> CompletionState {
            if self
                .backend
                .as_ref()
                .is_some_and(|backend| backend.setup_complete)
            {
                CompletionState::Complete
            } else if self
                .backend
                .as_ref()
                .and_then(|backend| backend.setup_error.as_deref())
                .is_some_and(|error| !error.trim().is_empty())
                || self.history.terminal.is_some()
            {
                CompletionState::Terminal
            } else {
                CompletionState::Pending
            }
        }
    }

    struct WorkerProcess {
        child: Child,
    }

    impl WorkerProcess {
        async fn stop(mut self) -> anyhow::Result<()> {
            let pid = self.child.id();
            self.child
                .start_kill()
                .map_err(|error| anyhow::anyhow!("kill fencing worker {pid:?}: {error}"))?;
            tokio::time::timeout(Duration::from_secs(10), self.child.wait())
                .await
                .map_err(|_| anyhow::anyhow!("fencing worker {pid:?} did not exit after kill"))?
                .map_err(|error| anyhow::anyhow!("reap fencing worker {pid:?}: {error}"))?;
            Ok(())
        }
    }

    impl Drop for WorkerProcess {
        fn drop(&mut self) {
            let _ = self.child.start_kill();
        }
    }

    struct Driver {
        database_url: String,
        temporal_address: String,
        orchestration_url: String,
        pool: PgPool,
        temporal: Client,
        sandbox: SandboxClient,
        run_dir: PathBuf,
    }

    impl Driver {
        async fn connect() -> anyhow::Result<Self> {
            let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://codewire:codewire@127.0.0.1:25432/codewire".to_string()
            });
            let temporal_address = std::env::var("TEMPORAL_ADDRESS")
                .unwrap_or_else(|_| "http://127.0.0.1:7233".to_string());
            let orchestration_url = std::env::var("SMOKE_ORCHESTRATION_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8084".to_string());
            let pool = PgPool::connect(&database_url).await?;
            let connection = Connection::connect(
                ConnectionOptions::new(url::Url::parse(&temporal_address)?).build(),
            )
            .await?;
            let temporal = Client::new(
                connection,
                ClientOptions::new(TEMPORAL_NAMESPACE.to_string()).build(),
            )
            .map_err(|error| anyhow::anyhow!("Temporal client: {error}"))?;
            let kube = kube::Client::try_default().await?;
            let run_dir = std::env::temp_dir().join(format!(
                "codewire-temporal-fencing-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&run_dir)?;
            Ok(Self {
                database_url,
                temporal_address,
                orchestration_url,
                pool,
                temporal,
                sandbox: SandboxClient::new(kube, SANDBOX_NAMESPACE),
                run_dir,
            })
        }

        fn scenario_path(&self, scenario: &str, suffix: &str) -> PathBuf {
            self.run_dir.join(format!("{scenario}-{suffix}"))
        }

        fn organization_client(
            &self,
            session_token: &str,
        ) -> anyhow::Result<OrganizationServiceClient<HttpClient>> {
            let config = ClientConfig::new(
                self.orchestration_url
                    .parse()
                    .context("parse orchestration Connect URL")?,
            )
            .with_default_header(COOKIE, format!("{SESSION_COOKIE_NAME}={session_token}"));
            Ok(OrganizationServiceClient::new(
                HttpClient::plaintext(),
                config,
            ))
        }

        async fn delete_organization_via_connect(
            &self,
            organization_id: &str,
            session_token: &str,
        ) -> anyhow::Result<DeleteOrganizationResponse> {
            self.organization_client(session_token)?
                .delete_organization(DeleteOrganizationRequest {
                    org_id: organization_id.into(),
                    ..Default::default()
                })
                .await
                .context("OrganizationService DeleteOrganization")
                .map(|response| response.into_owned())
        }

        async fn get_organization_via_connect(
            &self,
            organization_id: &str,
            session_token: &str,
        ) -> anyhow::Result<Option<Organization>> {
            match self
                .organization_client(session_token)?
                .get_organization(GetOrganizationRequest {
                    org_id: organization_id.into(),
                    ..Default::default()
                })
                .await
            {
                Ok(response) => response
                    .into_owned()
                    .organization
                    .into_option()
                    .map(Some)
                    .ok_or_else(|| anyhow::anyhow!("GetOrganization returned no organization")),
                Err(error) if error.code == ErrorCode::NotFound => Ok(None),
                Err(error) => Err(anyhow::anyhow!(
                    "OrganizationService GetOrganization: {error}"
                )),
            }
        }

        fn spawn_worker(
            &self,
            queue: &str,
            evidence: &Path,
            claim_release: Option<&Path>,
            fail_once: Option<&Path>,
        ) -> anyhow::Result<WorkerProcess> {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .arg("worker")
                .env("DATABASE_URL", &self.database_url)
                .env("TEMPORAL_ADDRESS", &self.temporal_address)
                .env("TEMPORAL_TASK_QUEUE", queue)
                .env("CODEWIRE_KIND_FENCING_EVIDENCE_FILE", evidence)
                .env("INFISICAL_TENANT_ENABLED", "false")
                .env("ENVIRONMENT", "local")
                .env("SESSION_SECRET", "kind-e2e-not-a-real-secret")
                .env("SANDBOX_NAMESPACE", SANDBOX_NAMESPACE)
                .env("SANDBOX_GATEWAY_IMAGE", "codewire-gateway:e2e")
                .env("SANDBOX_RUNTIME_PROFILE", "runc")
                .env("SANDBOX_RUNTIME_CLASS", "runc")
                .env("SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME", "true")
                .env("SANDBOX_WORKSPACE_STORAGE_CLASS", "example-volumes")
                .env("SANDBOX_NETWORK_POLICY_MANAGEMENT", "Managed")
                .env("SANDBOX_DIND_ENABLED", "false")
                .env("SIDECAR_READY_TIMEOUT_SECS", "120")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .kill_on_drop(true);
            if let Some(path) = claim_release {
                command.env("CODEWIRE_KIND_FENCING_CLAIM_RELEASE_FILE", path);
            }
            if let Some(path) = fail_once {
                command.env("CODEWIRE_KIND_FENCING_FAIL_ONCE_FILE", path);
            }
            Ok(WorkerProcess {
                child: command.spawn()?,
            })
        }

        async fn seed_environment(
            &self,
            env_id: &str,
            setup_config: Option<Value>,
        ) -> anyhow::Result<()> {
            self.seed_environment_for(env_id, "org_contract_1", "usr_contract_admin", setup_config)
                .await
        }

        async fn seed_environment_for(
            &self,
            env_id: &str,
            organization_id: &str,
            created_by: &str,
            setup_config: Option<Value>,
        ) -> anyhow::Result<()> {
            let preset_id = format!("preset-{env_id}");
            sqlx::query(
                "INSERT INTO environment_presets (id, org_id, name, slug)
                 VALUES ($1, $2, $3, $1)",
            )
            .bind(&preset_id)
            .bind(organization_id)
            .bind(format!("WI-F {env_id}"))
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "INSERT INTO sandbox_template_config
                        (preset_id, image_ref, sandbox_template_name, warm_pool_size, persistent_storage)
                 VALUES ($1, 'ghcr.io/codewiresh/workspace:latest', 'wi-f-kind', 0, true)",
            )
            .bind(&preset_id)
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "INSERT INTO environments
                        (id, org_id, created_by, type, name, state, desired_state,
                         cpu_millicores, memory_mb, disk_gb, preset_id, setup_config)
                 VALUES ($1, $2, $3, 'sandbox', $1,
                         'pending', 'started', 100, 256, 1, $4, $5)",
            )
            .bind(env_id)
            .bind(organization_id)
            .bind(created_by)
            .bind(&preset_id)
            .bind(setup_config)
            .execute(&self.pool)
            .await?;
            Ok(())
        }

        async fn start_create(
            &self,
            env_id: &str,
            queue: &str,
        ) -> anyhow::Result<temporalio_client::WorkflowHandle<Client, EnvironmentWorkflowRun>>
        {
            self.temporal
                .start_workflow(
                    EnvironmentWorkflow::run,
                    EnvironmentCommand {
                        action: "create".into(),
                        environment_id: env_id.into(),
                        requested_by: "temporal-fencing-smoke".into(),
                    },
                    WorkflowStartOptions::new(queue, environment_workflow_id(env_id)).build(),
                )
                .await
                .map_err(|error| anyhow::anyhow!("start create workflow: {error}"))
        }

        async fn destroy_and_wait(
            &self,
            env_id: &str,
            handle: &temporalio_client::WorkflowHandle<Client, EnvironmentWorkflowRun>,
        ) -> anyhow::Result<()> {
            sqlx::query("UPDATE environments SET desired_state = 'destroyed' WHERE id = $1")
                .bind(env_id)
                .execute(&self.pool)
                .await?;
            handle
                .signal(
                    EnvironmentWorkflow::command,
                    EnvironmentCommand {
                        action: "destroy".into(),
                        environment_id: env_id.into(),
                        requested_by: "temporal-fencing-smoke".into(),
                    },
                    WorkflowSignalOptions::default(),
                )
                .await?;
            tokio::time::timeout(
                Duration::from_secs(180),
                handle.get_result(WorkflowGetResultOptions::default()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("destroy workflow timed out for {env_id}"))??;
            self.wait_environment_state(env_id, "destroyed", Duration::from_secs(30))
                .await
        }

        async fn wait_environment_state(
            &self,
            env_id: &str,
            expected: &str,
            timeout: Duration,
        ) -> anyhow::Result<()> {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let state: Option<String> =
                    sqlx::query_scalar("SELECT state FROM environments WHERE id = $1")
                        .bind(env_id)
                        .fetch_optional(&self.pool)
                        .await?;
                if state.as_deref() == Some(expected) {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "environment {env_id} state was {:?}, expected {expected}",
                        state
                    );
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }

        async fn setup_history_snapshot<W>(
            handle: &temporalio_client::WorkflowHandle<Client, W>,
        ) -> SetupHistorySnapshot
        where
            W: temporalio_common::HasWorkflowDefinition,
        {
            let history = match handle
                .fetch_history(WorkflowFetchHistoryOptions::default())
                .await
            {
                Ok(history) => history,
                Err(error) => {
                    return SetupHistorySnapshot {
                        attempt: 0,
                        terminal: None,
                        error: Some(error.to_string()),
                    };
                }
            };
            let scheduled = history.events().iter().find_map(|event| {
                let Some(Attributes::ActivityTaskScheduledEventAttributes(attributes)) =
                    event.attributes.as_ref()
                else {
                    return None;
                };
                (attributes
                    .activity_type
                    .as_ref()
                    .is_some_and(|kind| kind.name == "EnvironmentSetupActivity"))
                .then_some(event.event_id)
            });
            let attempt = scheduled
                .map(|scheduled| {
                    history
                        .events()
                        .iter()
                        .filter_map(|event| {
                            let Some(Attributes::ActivityTaskStartedEventAttributes(started)) =
                                event.attributes.as_ref()
                            else {
                                return None;
                            };
                            (started.scheduled_event_id == scheduled).then_some(started.attempt)
                        })
                        .max()
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            let terminal = history
                .events()
                .iter()
                .rev()
                .find(|event| event.is_final_wf_execution_event())
                .map(|event| format!("{:?}", event.event_type()));
            SetupHistorySnapshot {
                attempt,
                terminal,
                error: None,
            }
        }

        async fn setup_wait_snapshot<W>(
            &self,
            env_id: &str,
            handle: &temporalio_client::WorkflowHandle<Client, W>,
            evidence_path: &Path,
        ) -> anyhow::Result<SetupWaitSnapshot>
        where
            W: temporalio_common::HasWorkflowDefinition,
        {
            let environment = sqlx::query_as(
                "SELECT state, desired_state, error_reason, environment_operation_generation
                   FROM environments WHERE id = $1",
            )
            .bind(env_id)
            .fetch_optional(&self.pool)
            .await?;
            let backend_row: Option<SetupBackendRow> = sqlx::query_as(
                "SELECT setup_complete, setup_error, setup_owner_generation,
                        setup_owner_activity_id, setup_owner_attempt, setup_owner_phase,
                        setup_owner_status, setup_owner_pod_uid
                   FROM sandbox_environment_backend WHERE environment_id = $1",
            )
            .bind(env_id)
            .fetch_optional(&self.pool)
            .await?;
            let backend = backend_row.map(|row| SetupBackendSnapshot {
                setup_complete: row.0,
                setup_error: row.1,
                owner_generation: row.2,
                owner_activity_id: row.3,
                owner_attempt: row.4,
                owner_phase: row.5,
                owner_status: row.6,
                owner_pod_uid: row.7,
            });
            let pod = self
                .sandbox
                .get_workspace_pod_identity(env_id)
                .await
                .map(|pod| pod.map(|pod| (pod.name, pod.uid)))
                .map_err(|error| error.to_string());
            let evidence = std::fs::read_to_string(evidence_path)
                .map_err(|error| format!("read {}: {error}", evidence_path.display()));
            let exec_wait_failure = evidence
                .as_deref()
                .ok()
                .and_then(|contents| last_exec_wait_failure(contents, env_id));
            let history = Self::setup_history_snapshot(handle).await;
            Ok(SetupWaitSnapshot {
                environment,
                backend,
                pod,
                exec_wait_failure,
                evidence,
                history,
            })
        }

        async fn wait_setup_complete<W>(
            &self,
            env_id: &str,
            handle: &temporalio_client::WorkflowHandle<Client, W>,
            evidence_path: &Path,
        ) -> anyhow::Result<()>
        where
            W: temporalio_common::HasWorkflowDefinition,
        {
            let started = tokio::time::Instant::now();
            let mut progress =
                ProgressTracker::new(SETUP_WAIT_QUIET_LIMIT, SETUP_WAIT_ABSOLUTE_LIMIT);
            loop {
                let snapshot = self
                    .setup_wait_snapshot(env_id, handle, evidence_path)
                    .await?;
                let elapsed = started.elapsed();
                match progress.observe(elapsed, snapshot.completion_state(), &snapshot) {
                    CompletionDecision::Continue => {}
                    CompletionDecision::Complete => return Ok(()),
                    CompletionDecision::Terminal => anyhow::bail!(
                        "setup became terminal before completion for {env_id}: {snapshot:#?}"
                    ),
                    CompletionDecision::QuietExpired => anyhow::bail!(
                        "setup made no observable progress within the quiet bound for {env_id}: {snapshot:#?}"
                    ),
                    CompletionDecision::AbsoluteExpired => anyhow::bail!(
                        "setup exceeded the absolute completion bound for {env_id}: {snapshot:#?}"
                    ),
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        async fn wait_setup_error<W>(
            &self,
            env_id: &str,
            handle: &temporalio_client::WorkflowHandle<Client, W>,
            evidence_path: &Path,
        ) -> anyhow::Result<String>
        where
            W: temporalio_common::HasWorkflowDefinition,
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
            loop {
                let snapshot = self
                    .setup_wait_snapshot(env_id, handle, evidence_path)
                    .await?;
                if let Some(error) = snapshot
                    .backend
                    .as_ref()
                    .and_then(|backend| backend.setup_error.clone())
                    .filter(|error| !error.trim().is_empty())
                {
                    return Ok(error);
                }
                if snapshot.history.terminal.is_some() {
                    anyhow::bail!(
                        "workflow became terminal before setup recorded an error for {env_id}: {snapshot:#?}"
                    );
                }
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("setup did not record an error for {env_id}: {snapshot:#?}");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        async fn cross_run_serialization(&self) -> anyhow::Result<()> {
            let scenario = "cross-run";
            let env_id = format!(
                "env-wif-cross-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let queue = format!(
                "wif-cross-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let evidence = self.scenario_path(scenario, "evidence.jsonl");
            let release = self.scenario_path(scenario, "release");
            self.seed_environment(&env_id, None).await?;
            let worker = self.spawn_worker(&queue, &evidence, Some(&release), None)?;
            let old = self.start_create(&env_id, &queue).await?;
            let old_run = old.run_id().unwrap_or_default().to_string();
            let expected_claim_name = codewire_orchestration::sandbox::claim_name(&env_id);
            wait_evidence(&evidence, &env_id, "claim_row_lock_held", |event| {
                event["claim_name"].as_str() == Some(expected_claim_name.as_str())
                    && event["claim_uid"]
                        .as_str()
                        .is_some_and(|uid| !uid.is_empty())
            })
            .await?;

            let update_pool = self.pool.clone();
            let update_env = env_id.clone();
            let desired_update = tokio::spawn(async move {
                sqlx::query(
                    "UPDATE environments SET desired_state = 'destroyed'
                       WHERE id = $1 /* codewire_wif_intent_wait */",
                )
                .bind(update_env)
                .execute(&update_pool)
                .await
            });
            wait_lock_waiters(&self.pool, 1).await?;

            old.terminate(
                WorkflowTerminateOptions::builder()
                    .reason("cross-run fencing replacement")
                    .build(),
            )
            .await?;

            let replacement = self
                .temporal
                .start_workflow(
                    EnvironmentWorkflow::run,
                    EnvironmentCommand {
                        action: "destroy".into(),
                        environment_id: env_id.clone(),
                        requested_by: "temporal-fencing-smoke".into(),
                    },
                    WorkflowStartOptions::new(&queue, environment_workflow_id(&env_id)).build(),
                )
                .await?;
            let replacement_run = replacement.run_id().unwrap_or_default().to_string();
            anyhow::ensure!(
                replacement_run != old_run,
                "replacement reused the old run ID"
            );
            wait_evidence(&evidence, &env_id, "claim_attempt_started", |event| {
                event["workflow_run_id"].as_str() == Some(&replacement_run)
            })
            .await?;
            wait_lock_waiters(&self.pool, 2).await?;
            let generation_before_release: i64 = sqlx::query_scalar(
                "SELECT environment_operation_generation FROM environments WHERE id = $1",
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(generation_before_release == 1);
            anyhow::ensure!(
                claim_activity_pending(&replacement).await?,
                "replacement claim was not visibly pending behind the row lock"
            );

            std::fs::write(&release, b"release")?;
            desired_update.await??;
            tokio::time::timeout(
                Duration::from_secs(180),
                replacement.get_result(WorkflowGetResultOptions::default()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("replacement destroy timed out"))??;
            self.wait_environment_state(&env_id, "destroyed", Duration::from_secs(30))
                .await?;
            anyhow::ensure!(
                self.sandbox.get_sandbox_claim(&env_id).await?.is_none(),
                "replacement did not delete the old activity's live SandboxClaim"
            );
            let generation: i64 = sqlx::query_scalar(
                "SELECT environment_operation_generation FROM environments WHERE id = $1",
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(generation == 2, "replacement did not claim generation two");
            let before = mutation_snapshot(&self.pool, &env_id).await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let after = mutation_snapshot(&self.pool, &env_id).await?;
            anyhow::ensure!(
                before == after,
                "stale generation wrote after replacement: {before:?} -> {after:?}"
            );
            worker.stop().await?;
            println!("temporal-fencing-smoke: cross-run serialization PASS");
            Ok(())
        }

        async fn worker_death_recovery(&self) -> anyhow::Result<()> {
            let scenario = "worker-death";
            let env_id = format!(
                "env-wif-death-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let queue = format!(
                "wif-death-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let evidence = self.scenario_path(scenario, "evidence.jsonl");
            self.seed_environment(
                &env_id,
                Some(json!({
                    "install_command": format!(
                        "if [ -f {WORKER_DEATH_MARKER} ]; then exit 0; fi; \
                         touch {WORKER_DEATH_MARKER}; sleep 600"
                    ),
                    "include_org_secrets": false,
                    "include_user_secrets": false
                })),
            )
            .await?;
            let worker = self.spawn_worker(&queue, &evidence, None, None)?;
            let handle = self.start_create(&env_id, &queue).await?;
            let attached = wait_evidence(&evidence, &env_id, "exec_attached", |event| {
                event["phase"].as_i64() == Some(2)
            })
            .await?;
            let old_uid = attached["pod_uid"].as_str().unwrap_or_default().to_string();
            anyhow::ensure!(!old_uid.is_empty());
            // Kubernetes returning an exec attachment does not prove that the
            // remote shell has run. Observe the fixture's durable precondition
            // on the exact Pod before injecting worker death.
            self.wait_worker_death_marker(&env_id, &old_uid).await?;
            worker.stop().await?;
            let lease: (String, String) = sqlx::query_as(
                "SELECT setup_owner_status, setup_owner_pod_uid
                   FROM sandbox_environment_backend WHERE environment_id = $1",
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(lease == ("running".into(), old_uid.clone()));

            let replacement_worker = self.spawn_worker(&queue, &evidence, None, None)?;
            let replacement = wait_evidence(&evidence, &env_id, "replacement_ready", |event| {
                event["old_pod_uid"].as_str() == Some(&old_uid)
            })
            .await?;
            let new_uid = replacement["new_pod_uid"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            anyhow::ensure!(!new_uid.is_empty() && new_uid != old_uid);
            wait_evidence(&evidence, &env_id, "quiescence_complete", |event| {
                event["pod_uid"].as_str() == Some(&old_uid)
                    && event["wait_ms"].as_u64().is_some_and(|wait| wait >= 6_000)
            })
            .await?;
            self.wait_setup_complete(&env_id, &handle, &evidence)
                .await?;
            anyhow::ensure!(
                self.sandbox
                    .get_workspace_pod_identity(&env_id)
                    .await?
                    .is_some_and(|pod| !pod.uid.is_empty() && pod.uid != old_uid)
            );
            self.destroy_and_wait(&env_id, &handle).await?;
            replacement_worker.stop().await?;
            println!("temporal-fencing-smoke: worker-death recovery PASS");
            Ok(())
        }

        async fn wait_worker_death_marker(
            &self,
            env_id: &str,
            expected_uid: &str,
        ) -> anyhow::Result<()> {
            let deadline = tokio::time::Instant::now() + WORKER_DEATH_MARKER_WAIT;
            let command = vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("test -f {WORKER_DEATH_MARKER}"),
            ];
            let env = BTreeMap::new();
            let mut last_observation = "marker probe has not run".to_string();

            loop {
                let pod = self.sandbox.get_workspace_pod_identity(env_id).await?;
                let Some(pod) = pod else {
                    anyhow::bail!(
                        "workspace Pod disappeared before worker-death marker for {env_id}; \
                         expected_uid={expected_uid}; last={last_observation}"
                    );
                };
                anyhow::ensure!(
                    pod.uid == expected_uid,
                    "workspace Pod changed before worker-death marker for {env_id}; \
                     expected_uid={expected_uid}; observed={pod:?}; last={last_observation}"
                );

                match self
                    .sandbox
                    .exec_workspace_result_on_pod(&pod.name, &command, "/workspace", &env)
                    .await
                {
                    Ok(result) if result.exit_code == 0 => {
                        let after = self.sandbox.get_workspace_pod_identity(env_id).await?;
                        anyhow::ensure!(
                            after.as_ref().is_some_and(|current| {
                                current.name == pod.name && current.uid == expected_uid
                            }),
                            "workspace Pod changed after worker-death marker for {env_id}; \
                             expected={pod:?}; observed={after:?}"
                        );
                        return Ok(());
                    }
                    Ok(result) => {
                        last_observation = format!(
                            "pod={pod:?}; exit={}; stdout={:?}; stderr={:?}",
                            result.exit_code,
                            String::from_utf8_lossy(&result.stdout),
                            String::from_utf8_lossy(&result.stderr)
                        );
                    }
                    Err(error) => {
                        last_observation = format!("pod={pod:?}; exec_error={error:#}");
                    }
                }

                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "worker-death marker was not observable within the bound for {env_id}; \
                         expected_uid={expected_uid}; last={last_observation}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        async fn same_generation_retry(&self) -> anyhow::Result<()> {
            let scenario = "fail-once";
            let env_id = format!(
                "env-wif-retry-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let queue = format!(
                "wif-retry-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let evidence = self.scenario_path(scenario, "evidence.jsonl");
            let marker = self.scenario_path(scenario, "injected");
            self.seed_environment(
                &env_id,
                Some(json!({
                    "env_vars": {"WI_F_RETRY": "1"},
                    "include_org_secrets": false,
                    "include_user_secrets": false
                })),
            )
            .await?;
            let worker = self.spawn_worker(&queue, &evidence, None, Some(&marker))?;
            let handle = self.start_create(&env_id, &queue).await?;
            wait_evidence(&evidence, &env_id, "fail_once_injected", |_| true).await?;
            wait_evidence(&evidence, &env_id, "recovery_complete", |_| true).await?;
            self.wait_setup_complete(&env_id, &handle, &evidence)
                .await?;
            let claim: (i64, i64) = sqlx::query_as(
                "SELECT e.environment_operation_generation, COUNT(c.*)::bigint
                   FROM environments e
                   JOIN environment_operation_generation_claims c ON c.environment_id = e.id
                  WHERE e.id = $1
                  GROUP BY e.environment_operation_generation",
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(
                claim == (1, 1),
                "retry claimed a second generation: {claim:?}"
            );
            anyhow::ensure!(
                setup_activity_attempted_at_least(&handle, 2).await?,
                "fail-once setup did not retry at attempt two"
            );
            self.destroy_and_wait(&env_id, &handle).await?;
            worker.stop().await?;
            println!("temporal-fencing-smoke: same-generation retry PASS");
            Ok(())
        }

        async fn parallel_clone_cleanup(&self) -> anyhow::Result<()> {
            let scenario = "parallel-clone";
            let env_id = format!(
                "env-wif-clone-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let queue = format!(
                "wif-clone-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let evidence = self.scenario_path(scenario, "evidence.jsonl");
            self.seed_environment(
                &env_id,
                Some(json!({
                    "repos": [
                        {"url": "kind-e2e://clone-fail"},
                        {"url": "kind-e2e://clone-sibling"}
                    ],
                    "include_org_secrets": false,
                    "include_user_secrets": false
                })),
            )
            .await?;
            let worker = self.spawn_worker(&queue, &evidence, None, None)?;
            let handle = self.start_create(&env_id, &queue).await?;
            let joined = wait_evidence(&evidence, &env_id, "clone_group_joined", |_| true).await?;
            anyhow::ensure!(joined["launched"] == 2 && joined["observed"] == 2);
            let replacement =
                wait_evidence(&evidence, &env_id, "replacement_ready", |_| true).await?;
            let old_uid = replacement["old_pod_uid"].as_str().unwrap_or_default();
            let new_uid = replacement["new_pod_uid"].as_str().unwrap_or_default();
            anyhow::ensure!(!old_uid.is_empty() && !new_uid.is_empty() && old_uid != new_uid);
            let error = self.wait_setup_error(&env_id, &handle, &evidence).await?;
            anyhow::ensure!(
                error.contains("injected-clone-failure"),
                "unexpected clone error: {error}"
            );
            let pods = self.sandbox.list_workspace_pod_identities(&env_id).await?;
            anyhow::ensure!(pods.iter().all(|pod| pod.uid != old_uid));
            self.destroy_and_wait(&env_id, &handle).await?;
            worker.stop().await?;
            println!("temporal-fencing-smoke: parallel-clone sibling cleanup PASS");
            Ok(())
        }

        async fn external_cleanup_retry(&self) -> anyhow::Result<()> {
            let scenario = "external-cleanup";
            let env_id = format!(
                "env-wi2-cleanup-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let queue = format!(
                "wi2-cleanup-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let evidence = self.scenario_path(scenario, "evidence.jsonl");
            self.seed_environment(
                &env_id,
                Some(json!({
                    "env_vars": {"WI_2_EXTERNAL_CLEANUP": "1"},
                    "include_org_secrets": false,
                    "include_user_secrets": false
                })),
            )
            .await?;
            let worker = self.spawn_worker(&queue, &evidence, None, None)?;
            let handle = self.start_create(&env_id, &queue).await?;
            self.wait_setup_complete(&env_id, &handle, &evidence)
                .await?;

            let environment = load_environment(&self.pool, &env_id).await?;
            let backend = load_backend_row(&self.pool, &env_id).await?;
            let template_name = environment_per_env_template_name(
                &SandboxWorkerCfg::default(),
                CANONICAL_WORKSPACE_RUNTIME_IMAGE,
                "wi-f-kind",
                &environment,
                &env_id,
            )
            .ok_or_else(|| {
                anyhow::anyhow!("WI-2 fixture unexpectedly selected a shared template")
            })?;
            let workspace = self
                .sandbox
                .get_workspace_pod_identity(&env_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("WI-2 fixture has no workspace Pod"))?;
            let residue = self
                .sandbox
                .environment_residue(&env_id, &backend.pod_name, Some(&template_name))
                .await?;
            for kind in [
                "SandboxClaim/",
                "Sandbox/",
                "Pod/",
                "PersistentVolumeClaim/",
                "Deployment/",
                "Service/",
                "NetworkPolicy/",
                "SandboxTemplate/",
                "SandboxWarmPool/",
            ] {
                anyhow::ensure!(
                    residue
                        .resources
                        .iter()
                        .any(|resource| resource.starts_with(kind)),
                    "WI-2 fixture did not create {kind} residue: {:?}",
                    residue.resources
                );
            }
            let secrets: Api<Secret> =
                Api::namespaced(kube::Client::try_default().await?, SANDBOX_NAMESPACE);
            let host_key_name = gateway_host_key_secret_name(&env_id);
            anyhow::ensure!(
                secrets.get_opt(&host_key_name).await?.is_some(),
                "WI-2 fixture did not create gateway host-key Secret"
            );

            let session_id = format!("session-{env_id}");
            sqlx::query(
                r#"INSERT INTO sandbox_running_sessions
                       (id, environment_id, organization_id, runtime_uid, runtime_name,
                        runtime_namespace, cpu_millicores, memory_mib, disk_gib,
                        started_at, last_observed_at)
                   VALUES ($1, $2, 'org_contract_1', $3, $4, $5, 100, 256, 1, NOW(), NOW())"#,
            )
            .bind(&session_id)
            .bind(&env_id)
            .bind(&workspace.uid)
            .bind(&workspace.name)
            .bind(&backend.namespace)
            .execute(&self.pool)
            .await?;
            let blocking_lease = acquire_organization_mutation_lease(
                &self.pool,
                "org_contract_1",
                OrganizationMutationClass::EnvironmentRuntimeDispatch,
            )
            .await?;

            sqlx::query("UPDATE environments SET desired_state = 'destroyed' WHERE id = $1")
                .bind(&env_id)
                .execute(&self.pool)
                .await?;
            handle
                .signal(
                    EnvironmentWorkflow::command,
                    EnvironmentCommand {
                        action: "destroy".into(),
                        environment_id: env_id.clone(),
                        requested_by: "temporal-fencing-smoke".into(),
                    },
                    WorkflowSignalOptions::default(),
                )
                .await?;

            let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
            loop {
                let residue = self
                    .sandbox
                    .environment_residue(&env_id, &backend.pod_name, Some(&template_name))
                    .await?;
                let marker: Option<chrono::NaiveDateTime> = sqlx::query_scalar(
                    "SELECT external_cleanup_completed_at FROM environments WHERE id = $1",
                )
                .bind(&env_id)
                .fetch_one(&self.pool)
                .await?;
                anyhow::ensure!(
                    marker.is_none(),
                    "external cleanup marker bypassed an unresolved runtime admission"
                );
                if residue.is_empty() {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "external cleanup did not reach the injected marker barrier: {:?}",
                        residue.resources
                    );
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            anyhow::ensure!(
                secrets.get_opt(&host_key_name).await?.is_none(),
                "gateway host-key Secret survived external cleanup"
            );
            let backend_retained: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM sandbox_environment_backend WHERE environment_id = $1)",
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            let session_before_retry: (Option<chrono::DateTime<chrono::Utc>>, Option<String>) =
                sqlx::query_as(
                    "SELECT ended_at, end_reason FROM sandbox_running_sessions WHERE id = $1",
                )
                .bind(&session_id)
                .fetch_one(&self.pool)
                .await?;
            anyhow::ensure!(
                backend_retained
                    && runtime_session_state_is_admissible_before_retry(
                        session_before_retry.0.is_some(),
                        session_before_retry.1.as_deref(),
                    ),
                "external cleanup marker barrier did not retain the backend or preserve an \
                 accepted runtime-session state: backend_retained={backend_retained}, \
                 session={session_before_retry:?}"
            );

            let retry_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let marker: Option<chrono::NaiveDateTime> = sqlx::query_scalar(
                    "SELECT external_cleanup_completed_at FROM environments WHERE id = $1",
                )
                .bind(&env_id)
                .fetch_one(&self.pool)
                .await?;
                anyhow::ensure!(
                    marker.is_none(),
                    "external cleanup marker bypassed the retained runtime admission"
                );
                let barrier_failure_recorded: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS(
                           SELECT 1
                           FROM environment_logs
                           WHERE environment_id = $1
                             AND phase = 'lifecycle_error'
                             AND status = 'failed'
                             AND message LIKE '%external cleanup preconditions are not satisfied%'
                       )"#,
                )
                .bind(&env_id)
                .fetch_one(&self.pool)
                .await?;
                if barrier_failure_recorded {
                    break;
                }
                if tokio::time::Instant::now() >= retry_deadline {
                    anyhow::bail!("marker-barrier fault was not durably recorded");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            release_organization_mutation_lease(&self.pool, &blocking_lease.id).await?;
            tokio::time::timeout(
                Duration::from_secs(180),
                handle.get_result(WorkflowGetResultOptions::default()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("external-cleanup retry workflow timed out"))??;

            let final_state: (String, Option<chrono::NaiveDateTime>) = sqlx::query_as(
                "SELECT state, external_cleanup_completed_at FROM environments WHERE id = $1",
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(
                final_state.0 == "destroyed" && final_state.1.is_some(),
                "cleanup retry did not commit its durable marker: {final_state:?}"
            );
            anyhow::ensure!(
                activity_attempted_at_least(&handle, "EnvironmentDestroyActivity", 2).await?,
                "marker-barrier fault did not produce a Temporal destroy retry"
            );
            let final_residue = self
                .sandbox
                .environment_residue(&env_id, &backend.pod_name, Some(&template_name))
                .await?;
            anyhow::ensure!(
                final_residue.is_empty(),
                "external cleanup marker committed with residue: {:?}",
                final_residue.resources
            );
            let final_db: (bool, Option<chrono::DateTime<chrono::Utc>>, Option<String>) =
                sqlx::query_as(
                    "SELECT EXISTS(SELECT 1 FROM sandbox_environment_backend WHERE environment_id = $1),
                            ended_at, end_reason
                       FROM sandbox_running_sessions WHERE id = $2",
                )
                .bind(&env_id)
                .bind(&session_id)
                .fetch_one(&self.pool)
                .await?;
            anyhow::ensure!(
                !final_db.0
                    && final_db.1.is_some()
                    && matches!(
                        final_db.2.as_deref(),
                        Some("environment_destroyed") | Some("controller_lost_track")
                    ),
                "marker did not finalize runtime state with a recognized reason: {final_db:?}"
            );
            worker.stop().await?;
            println!("temporal-fencing-smoke: external-cleanup retry/no-residue PASS");
            Ok(())
        }

        async fn organization_deletion_retry(&self) -> anyhow::Result<()> {
            let scenario = "organization-deletion";
            let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
            let user_id = format!("usr-org-delete-{suffix}");
            let org_id = format!("org-delete-{suffix}");
            let env_id = format!("env-org-delete-{suffix}");
            let queue = format!("org-delete-{suffix}");
            let session_token = format!("org-delete-session-{suffix}");
            let evidence = self.scenario_path(scenario, "evidence.jsonl");

            sqlx::query(
                r#"INSERT INTO users (id, email, name, email_verified, is_admin)
                   VALUES ($1, $2, 'Organization deletion Kind owner', true, false)"#,
            )
            .bind(&user_id)
            .bind(format!("{suffix}@example.test"))
            .execute(&self.pool)
            .await?;
            sqlx::query(
                r#"INSERT INTO organizations (id, name, slug, created_by)
                   VALUES ($1, 'Organization deletion Kind fixture', $2, $3)"#,
            )
            .bind(&org_id)
            .bind(format!("org-delete-{suffix}"))
            .bind(&user_id)
            .execute(&self.pool)
            .await?;
            sqlx::query(
                r#"INSERT INTO org_members (id, org_id, user_id, role)
                   VALUES ($1, $2, $3, 'owner')"#,
            )
            .bind(format!("member-org-delete-{suffix}"))
            .bind(&org_id)
            .bind(&user_id)
            .execute(&self.pool)
            .await?;
            sqlx::query(
                r#"INSERT INTO sessions
                       (id, user_id, token_hash, expires_at, ip_address, user_agent)
                   VALUES ($1, $2, $3, NOW() + INTERVAL '4 hours', '127.0.0.1',
                           'temporal-fencing-smoke')"#,
            )
            .bind(format!("ses-org-delete-{suffix}"))
            .bind(&user_id)
            .bind(hash_session_token(&session_token))
            .execute(&self.pool)
            .await?;
            self.seed_environment_for(
                &env_id,
                &org_id,
                &user_id,
                Some(json!({
                    "env_vars": {"WI_5_ORGANIZATION_DELETION": "1"},
                    "include_org_secrets": false,
                    "include_user_secrets": false
                })),
            )
            .await?;
            sqlx::query(
                "INSERT INTO local_secrets (path, key, value) VALUES ($1, 'CANARY', 'never-log')",
            )
            .bind(format!("/org-secrets/{org_id}"))
            .execute(&self.pool)
            .await?;

            let worker = self.spawn_worker(&queue, &evidence, None, None)?;
            let environment = self.start_create(&env_id, &queue).await?;
            self.wait_setup_complete(&env_id, &environment, &evidence)
                .await?;
            let backend = load_backend_row(&self.pool, &env_id).await?;
            let environment_row = load_environment(&self.pool, &env_id).await?;
            let template_name = environment_per_env_template_name(
                &SandboxWorkerCfg::default(),
                CANONICAL_WORKSPACE_RUNTIME_IMAGE,
                "wi-f-kind",
                &environment_row,
                &env_id,
            )
            .ok_or_else(|| anyhow::anyhow!("WI-5 fixture selected a shared template"))?;

            // Fail the first generation in the tenant-secret phase after the
            // real runtime and billing phases have completed. No secret value
            // is included in the injected database error.
            sqlx::query(
                "DROP TRIGGER IF EXISTS codewire_kind_org_delete_secret_failure ON local_secrets",
            )
            .execute(&self.pool)
            .await?;
            sqlx::query("DROP FUNCTION IF EXISTS codewire_kind_org_delete_secret_failure()")
                .execute(&self.pool)
                .await?;
            sqlx::query(
                r#"CREATE FUNCTION codewire_kind_org_delete_secret_failure()
                   RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN
                     RAISE EXCEPTION 'injected organization secret deletion failure';
                   END
                   $$"#,
            )
            .execute(&self.pool)
            .await?;
            sqlx::query(
                r#"CREATE TRIGGER codewire_kind_org_delete_secret_failure
                   BEFORE DELETE ON local_secrets FOR EACH ROW
                   EXECUTE FUNCTION codewire_kind_org_delete_secret_failure()"#,
            )
            .execute(&self.pool)
            .await?;

            let first_response = self
                .delete_organization_via_connect(&org_id, &session_token)
                .await?;
            anyhow::ensure!(
                first_response.state.as_known() == Some(OrganizationDeletionState::Deleting)
                    && !first_response.operation_id.is_empty(),
                "organization DELETE did not return a durable deleting operation: {first_response:?}"
            );
            let first_get = self
                .get_organization_via_connect(&org_id, &session_token)
                .await?;
            let first_get = first_get
                .ok_or_else(|| anyhow::anyhow!("organization vanished before deletion ran"))?;
            anyhow::ensure!(
                first_get
                    .deletion_state
                    .as_ref()
                    .and_then(|state| state.as_known())
                    == Some(OrganizationDeletionState::Deleting)
                    && first_get.deletion_operation_id.as_deref()
                        == Some(first_response.operation_id.as_str())
                    && first_get.deletion_failure_code.is_none(),
                "organization GET did not expose the retained deleting state: {first_get:?}"
            );
            let duplicate = self
                .delete_organization_via_connect(&org_id, &session_token)
                .await?;
            anyhow::ensure!(
                duplicate == first_response,
                "duplicate organization DELETE changed the accepted operation: {duplicate:?}"
            );
            let first =
                organization_deletion_operation(&self.pool, &first_response.operation_id).await?;
            let trigger =
                TemporalTrigger::connect(&self.temporal_address, TEMPORAL_NAMESPACE, &queue)
                    .await?;
            record_organization_deletion_start_attempt(&self.pool, &first.id, first.generation)
                .await?;
            let first_input = OrganizationDeletionWorkflowInput {
                operation_id: first.id.clone(),
                organization_id: org_id.clone(),
                generation: first.generation,
            };
            trigger
                .trigger_organization_deletion(first_input.clone())
                .await?;
            // Simulate a crash before the database acknowledgement. The
            // outbox retry must attach to the same running workflow.
            trigger.trigger_organization_deletion(first_input).await?;
            mark_organization_deletion_started(&self.pool, &first.id, first.generation).await?;

            self.wait_deletion_state(&first.id, "failed", Duration::from_secs(120))
                .await?;
            let retained: (String, String, Option<String>) = sqlx::query_as(
                r#"SELECT deletion_state, deletion_phase, deletion_failure_code
                   FROM organizations WHERE id = $1"#,
            )
            .bind(&org_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(
                retained.0 == "delete_failed"
                    && retained.1 == "billing_finalized"
                    && retained.2.as_deref() == Some("tenant_secret_cleanup_failed"),
                "injected secret failure did not retain safe forward state: {retained:?}"
            );
            let failed_get = self
                .get_organization_via_connect(&org_id, &session_token)
                .await?;
            let failed_get = failed_get.ok_or_else(|| {
                anyhow::anyhow!("failed deletion did not retain the organization")
            })?;
            anyhow::ensure!(
                failed_get
                    .deletion_state
                    .as_ref()
                    .and_then(|state| state.as_known())
                    == Some(OrganizationDeletionState::DeleteFailed)
                    && failed_get.deletion_operation_id.as_deref() == Some(first.id.as_str())
                    && failed_get.deletion_failure_code.as_deref()
                        == Some("tenant_secret_cleanup_failed"),
                "organization GET did not expose safe retained failure state: {failed_get:?}"
            );
            let runtime_state: (String, String, bool) = sqlx::query_as(
                r#"SELECT state, desired_state,
                          external_cleanup_completed_at IS NOT NULL
                   FROM environments WHERE id = $1"#,
            )
            .bind(&env_id)
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(runtime_state == ("destroyed".into(), "destroyed".into(), true));
            anyhow::ensure!(
                self.sandbox
                    .environment_residue(&env_id, &backend.pod_name, Some(&template_name))
                    .await?
                    .is_empty(),
                "failed organization deletion retained runtime residue"
            );
            anyhow::ensure!(
                acquire_organization_mutation_lease(
                    &self.pool,
                    &org_id,
                    OrganizationMutationClass::ControlPlaneDatabase,
                )
                .await
                .is_err(),
                "failed organization deletion reopened its write fence"
            );

            sqlx::query("DROP TRIGGER codewire_kind_org_delete_secret_failure ON local_secrets")
                .execute(&self.pool)
                .await?;
            sqlx::query("DROP FUNCTION codewire_kind_org_delete_secret_failure()")
                .execute(&self.pool)
                .await?;

            let retry_response = self
                .delete_organization_via_connect(&org_id, &session_token)
                .await?;
            anyhow::ensure!(
                retry_response.state.as_known() == Some(OrganizationDeletionState::Deleting)
                    && retry_response.operation_id != first.id,
                "failed organization retry did not return a new deleting operation: {retry_response:?}"
            );
            let retry =
                organization_deletion_operation(&self.pool, &retry_response.operation_id).await?;
            anyhow::ensure!(retry.generation == first.generation + 1);
            record_organization_deletion_start_attempt(&self.pool, &retry.id, retry.generation)
                .await?;
            trigger
                .trigger_organization_deletion(OrganizationDeletionWorkflowInput {
                    operation_id: retry.id.clone(),
                    organization_id: org_id.clone(),
                    generation: retry.generation,
                })
                .await?;
            mark_organization_deletion_started(&self.pool, &retry.id, retry.generation).await?;
            self.wait_deletion_state(&retry.id, "completed", Duration::from_secs(120))
                .await?;

            let workflow = self
                .temporal
                .get_workflow_handle::<OrganizationDeletionWorkflow>(
                    organization_deletion_workflow_id(&org_id, first.generation),
                );
            let history = workflow
                .fetch_history(WorkflowFetchHistoryOptions::default())
                .await?;
            let starts = history
                .events()
                .iter()
                .filter(|event| {
                    matches!(
                        event.attributes.as_ref(),
                        Some(Attributes::WorkflowExecutionStartedEventAttributes(_))
                    )
                })
                .count();
            anyhow::ensure!(
                starts == 1,
                "duplicate outbox start created {starts} workflows"
            );

            let org_exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)")
                    .bind(&org_id)
                    .fetch_one(&self.pool)
                    .await?;
            let secret_count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM local_secrets
                   WHERE path = $1 OR left(path, char_length($2) + 1) = $2 || '/'"#,
            )
            .bind(format!("/org-secrets/{org_id}"))
            .bind(format!("/projects/{org_id}"))
            .fetch_one(&self.pool)
            .await?;
            anyhow::ensure!(!org_exists && secret_count == 0);
            let deleted_get = self
                .get_organization_via_connect(&org_id, &session_token)
                .await?;
            anyhow::ensure!(
                deleted_get.is_none(),
                "completed organization deletion remained visible through Connect"
            );
            worker.stop().await?;
            println!("temporal-fencing-smoke: organization deletion failure/retry/no-residue PASS");
            Ok(())
        }

        async fn wait_deletion_state(
            &self,
            operation_id: &str,
            expected: &str,
            timeout: Duration,
        ) -> anyhow::Result<()> {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let state: Option<String> = sqlx::query_scalar(
                    "SELECT state FROM organization_deletion_operations WHERE id = $1",
                )
                .bind(operation_id)
                .fetch_optional(&self.pool)
                .await?;
                if state.as_deref() == Some(expected) {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "organization deletion {operation_id} state was {state:?}, expected {expected}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    async fn worker_main() -> anyhow::Result<()> {
        tracing_subscriber::fmt::init();
        let database_url = std::env::var("DATABASE_URL")?;
        let temporal_address = std::env::var("TEMPORAL_ADDRESS")?;
        let queue = std::env::var("TEMPORAL_TASK_QUEUE")?;
        let pool = codewire_server_core::db::connect(&database_url).await?;
        let trigger = Arc::new(
            codewire_orchestration::temporal::TemporalTrigger::connect(
                &temporal_address,
                TEMPORAL_NAMESPACE,
                &queue,
            )
            .await?,
        );
        let context = Arc::new(worker::WorkerContext {
            pool: pool.clone(),
            cloudflare: None,
            preview_base_domain: String::new(),
            kube: Some(kube::Client::try_default().await?),
            secrets: worker::secrets::SecretStore::from_env(pool),
            github_cfg: worker::github::GitHubAppConfig::from_env(),
            sandbox_cfg: worker::create::SandboxWorkerCfg::from_env(),
            temporal_trigger: trigger,
        });
        codewire_orchestration::temporal::run_temporal_worker(
            context,
            &temporal_address,
            TEMPORAL_NAMESPACE,
            &queue,
        )
        .await
    }

    async fn wait_evidence<F>(
        path: &Path,
        environment_id: &str,
        event_name: &str,
        predicate: F,
    ) -> anyhow::Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
        loop {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            for line in contents.lines() {
                let Ok(event) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                if event["event"] == event_name
                    && event["environment_id"] == environment_id
                    && predicate(&event)
                {
                    return Ok(event);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "evidence {event_name} was not observed for {environment_id}; file={contents}"
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn last_exec_wait_failure(contents: &str, environment_id: &str) -> Option<String> {
        contents.lines().rev().find_map(|line| {
            let event = serde_json::from_str::<Value>(line).ok()?;
            if event["event"] != "exec_wait_failed" || event["environment_id"] != environment_id {
                return None;
            }
            Some(format!(
                "phase={} pod_uid={} error={}",
                event["phase"].as_i64()?,
                event["pod_uid"].as_str()?,
                event["error"].as_str()?
            ))
        })
    }

    async fn wait_lock_waiters(pool: &PgPool, expected: i64) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint
                   FROM pg_stat_activity
                  WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(pool)
            .await?;
            if count >= expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("observed {count} Postgres lock waiters, expected {expected}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn claim_activity_pending<W>(
        handle: &temporalio_client::WorkflowHandle<Client, W>,
    ) -> anyhow::Result<bool>
    where
        W: temporalio_common::HasWorkflowDefinition,
    {
        let history = handle
            .fetch_history(WorkflowFetchHistoryOptions::default())
            .await?;
        let scheduled = history.events().iter().find_map(|event| {
            let Some(Attributes::ActivityTaskScheduledEventAttributes(attributes)) =
                event.attributes.as_ref()
            else {
                return None;
            };
            (attributes
                .activity_type
                .as_ref()
                .is_some_and(|kind| kind.name == "EnvironmentClaimAuthorityActivity"))
            .then_some(event.event_id)
        });
        let Some(scheduled) = scheduled else {
            return Ok(false);
        };
        Ok(!history.events().iter().any(|event| {
            matches!(
                event.attributes.as_ref(),
                Some(Attributes::ActivityTaskCompletedEventAttributes(done))
                    if done.scheduled_event_id == scheduled
            )
        }))
    }

    async fn setup_activity_attempted_at_least<W>(
        handle: &temporalio_client::WorkflowHandle<Client, W>,
        expected_attempt: i32,
    ) -> anyhow::Result<bool>
    where
        W: temporalio_common::HasWorkflowDefinition,
    {
        activity_attempted_at_least(handle, "EnvironmentSetupActivity", expected_attempt).await
    }

    async fn activity_attempted_at_least<W>(
        handle: &temporalio_client::WorkflowHandle<Client, W>,
        activity_name: &str,
        expected_attempt: i32,
    ) -> anyhow::Result<bool>
    where
        W: temporalio_common::HasWorkflowDefinition,
    {
        let history = handle
            .fetch_history(WorkflowFetchHistoryOptions::default())
            .await?;
        let scheduled = history.events().iter().find_map(|event| {
            let Some(Attributes::ActivityTaskScheduledEventAttributes(attributes)) =
                event.attributes.as_ref()
            else {
                return None;
            };
            (attributes
                .activity_type
                .as_ref()
                .is_some_and(|kind| kind.name == activity_name))
            .then_some(event.event_id)
        });
        let Some(scheduled) = scheduled else {
            return Ok(false);
        };
        Ok(history.events().iter().any(|event| {
            matches!(
                event.attributes.as_ref(),
                Some(Attributes::ActivityTaskStartedEventAttributes(started))
                    if started.scheduled_event_id == scheduled && started.attempt >= expected_attempt
            )
        }))
    }

    #[derive(Debug, PartialEq, Eq)]
    struct MutationSnapshot {
        state: String,
        desired_state: String,
        error_reason: Option<String>,
        generation: i64,
        backend: Option<(i32, bool, Option<String>, Option<i64>)>,
        logs: i64,
        journal: i64,
        ports: i64,
    }

    async fn mutation_snapshot(pool: &PgPool, env_id: &str) -> anyhow::Result<MutationSnapshot> {
        let environment: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT state, desired_state, error_reason, environment_operation_generation
               FROM environments WHERE id = $1",
        )
        .bind(env_id)
        .fetch_one(pool)
        .await?;
        let backend = sqlx::query_as(
            "SELECT setup_phase, setup_complete, setup_owner_status, setup_owner_generation
               FROM sandbox_environment_backend WHERE environment_id = $1",
        )
        .bind(env_id)
        .fetch_optional(pool)
        .await?;
        let logs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM environment_logs WHERE environment_id = $1",
        )
        .bind(env_id)
        .fetch_one(pool)
        .await?;
        let journal: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM environment_lifecycle_journal WHERE environment_id = $1",
        )
        .bind(env_id)
        .fetch_one(pool)
        .await?;
        let ports: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM environment_ports WHERE environment_id = $1",
        )
        .bind(env_id)
        .fetch_one(pool)
        .await?;
        Ok(MutationSnapshot {
            state: environment.0,
            desired_state: environment.1,
            error_reason: environment.2,
            generation: environment.3,
            backend,
            logs,
            journal,
            ports,
        })
    }

    fn runtime_session_state_is_admissible_before_retry(
        has_ended: bool,
        end_reason: Option<&str>,
    ) -> bool {
        matches!(
            (has_ended, end_reason),
            (false, None)
                | (true, Some("environment_destroyed"))
                | (true, Some("controller_lost_track"))
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn tracker() -> ProgressTracker<u8> {
            ProgressTracker::new(SETUP_WAIT_QUIET_LIMIT, SETUP_WAIT_ABSOLUTE_LIMIT)
        }

        #[test]
        fn runtime_session_state_accepts_only_the_two_close_winners_or_still_open() {
            assert!(runtime_session_state_is_admissible_before_retry(
                false, None
            ));
            assert!(runtime_session_state_is_admissible_before_retry(
                true,
                Some("environment_destroyed")
            ));
            assert!(runtime_session_state_is_admissible_before_retry(
                true,
                Some("controller_lost_track")
            ));

            assert!(!runtime_session_state_is_admissible_before_retry(
                true, None
            ));
            assert!(!runtime_session_state_is_admissible_before_retry(
                true,
                Some("unknown")
            ));
            assert!(!runtime_session_state_is_admissible_before_retry(
                false,
                Some("environment_destroyed")
            ));
        }

        fn snapshot(
            setup_complete: bool,
            setup_error: Option<&str>,
            terminal: Option<&str>,
        ) -> SetupWaitSnapshot {
            SetupWaitSnapshot {
                environment: None,
                backend: Some(SetupBackendSnapshot {
                    setup_complete,
                    setup_error: setup_error.map(str::to_string),
                    owner_generation: None,
                    owner_activity_id: None,
                    owner_attempt: None,
                    owner_phase: None,
                    owner_status: None,
                    owner_pod_uid: None,
                }),
                pod: Ok(None),
                exec_wait_failure: None,
                evidence: Ok(String::new()),
                history: SetupHistorySnapshot {
                    attempt: 0,
                    terminal: terminal.map(str::to_string),
                    error: None,
                },
            }
        }

        #[test]
        fn durable_and_workflow_state_classify_completion() {
            assert_eq!(
                snapshot(false, None, None).completion_state(),
                CompletionState::Pending
            );
            assert_eq!(
                snapshot(true, None, None).completion_state(),
                CompletionState::Complete
            );
            assert_eq!(
                snapshot(false, Some("setup failed"), None).completion_state(),
                CompletionState::Terminal
            );
            assert_eq!(
                snapshot(false, None, Some("WorkflowExecutionFailed")).completion_state(),
                CompletionState::Terminal
            );
        }

        #[test]
        fn exec_wait_failure_diagnostic_is_exact_and_environment_scoped() {
            let evidence = r#"
{"event":"exec_wait_failed","environment_id":"other","phase":2,"pod_uid":"pod-other","error":"other"}
{"event":"recovery_started","environment_id":"env-1","phase":2,"pod_uid":"pod-1"}
{"event":"exec_wait_failed","environment_id":"env-1","phase":2,"pod_uid":"pod-1","error":"workspace exec completion status unavailable"}
"#;
            assert_eq!(
                last_exec_wait_failure(evidence, "env-1").as_deref(),
                Some("phase=2 pod_uid=pod-1 error=workspace exec completion status unavailable")
            );
            assert_eq!(last_exec_wait_failure(evidence, "missing"), None);
        }

        #[test]
        fn unchanged_observation_expires_at_quiet_bound() {
            let mut tracker = tracker();
            assert_eq!(
                tracker.observe(Duration::ZERO, CompletionState::Pending, &1),
                CompletionDecision::Continue
            );
            assert_eq!(
                tracker.observe(Duration::from_secs(239), CompletionState::Pending, &1),
                CompletionDecision::Continue
            );
            assert_eq!(
                tracker.observe(Duration::from_secs(240), CompletionState::Pending, &1),
                CompletionDecision::QuietExpired
            );
        }

        #[test]
        fn real_progress_extends_only_the_quiet_bound() {
            let mut tracker = tracker();
            assert_eq!(
                tracker.observe(Duration::ZERO, CompletionState::Pending, &1),
                CompletionDecision::Continue
            );
            assert_eq!(
                tracker.observe(Duration::from_secs(239), CompletionState::Pending, &2),
                CompletionDecision::Continue
            );
            assert_eq!(
                tracker.observe(Duration::from_secs(478), CompletionState::Pending, &2),
                CompletionDecision::Continue
            );
            assert_eq!(
                tracker.observe(Duration::from_secs(479), CompletionState::Pending, &2),
                CompletionDecision::QuietExpired
            );
        }

        #[test]
        fn absolute_bound_expires_despite_continuing_progress() {
            let mut tracker = tracker();
            for (elapsed, observation) in [(0, 1), (200, 2), (400, 3), (599, 4)] {
                assert_eq!(
                    tracker.observe(
                        Duration::from_secs(elapsed),
                        CompletionState::Pending,
                        &observation
                    ),
                    CompletionDecision::Continue
                );
            }
            assert_eq!(
                tracker.observe(Duration::from_secs(600), CompletionState::Pending, &5),
                CompletionDecision::AbsoluteExpired
            );
        }

        #[test]
        fn terminal_state_fails_before_a_deadline() {
            let mut tracker = tracker();
            assert_eq!(
                tracker.observe(Duration::from_secs(1), CompletionState::Terminal, &1),
                CompletionDecision::Terminal
            );
        }

        #[test]
        fn completed_state_succeeds_before_a_deadline() {
            let mut tracker = tracker();
            assert_eq!(
                tracker.observe(Duration::from_secs(1), CompletionState::Complete, &1),
                CompletionDecision::Complete
            );
        }
    }

    pub async fn main() -> anyhow::Result<()> {
        if std::env::args().nth(1).as_deref() == Some("worker") {
            return worker_main().await;
        }
        tracing_subscriber::fmt::init();
        let driver = Driver::connect().await?;
        driver.cross_run_serialization().await?;
        driver.worker_death_recovery().await?;
        driver.same_generation_retry().await?;
        driver.parallel_clone_cleanup().await?;
        driver.external_cleanup_retry().await?;
        driver.organization_deletion_retry().await?;
        let _ = std::fs::remove_dir_all(&driver.run_dir);
        println!("temporal-fencing-smoke: PASS");
        Ok(())
    }
}

#[cfg(feature = "kind-e2e")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    enabled::main().await
}
