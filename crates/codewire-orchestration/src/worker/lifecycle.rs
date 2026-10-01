//! Environment lifecycle jobs — port of `HandleEnvironmentStop`,
//! `HandleEnvironmentStart`, `HandleEnvironmentDestroy`, and
//! `HandleEnvironmentReconcile` (handler_environment.go). Reconcile's
//! `Create` action runs create + setup inline (D3: the env-setup NATS
//! publish is retired, so the recovery path chains setup itself).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use temporalio_sdk::activities::ActivityContext;

use super::activity_authority::{ActivityAuthority, AuthorityLost, is_authority_lost};
use super::create::{
    SandboxWorkerCfg, authorize_confidential_runtime_for_environment,
    environment_per_env_template_name, environment_template_opts, load_environment_template_opts,
    ready_timeout_for_isolation, reconcile_or_refresh_runtime_identity,
    reconcile_runtime_identity_for_pod, refresh_workspace_bootstrap,
    requires_running_runtime_identity, run_template_mutation,
};
use super::env_data::{load_backend_row, load_environment};
use super::env_log::emit_authoritative_environment_log_for_states;
use super::gatewayauth::issue_environment_tokens;
use super::port_dns;
use super::setup::{
    handle_post_start_configuration, is_setup_activity_cancelled, is_setup_recovery_failed,
    jittered_duration, wait_for_sidecar,
};
use super::{JobPayload, WorkerContext};
use crate::lifecycle::{Action, PgLifecycleStore, RuntimeAbsenceProof, Service, Snapshot};
use crate::sandbox::client::{
    ProbeResult, SandboxClient, WorkspacePodIdentity, WorkspaceSandboxIdentity,
};

const DELETED_TIMEOUT: Duration = Duration::from_secs(120);
const POD_IP_POLL_TIMEOUT: Duration = Duration::from_secs(300); // start: 5-minute pod IP poll
const RUNNING_RUNTIME_RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);
const RUNNING_RUNTIME_RECOVERY_POLL: Duration = Duration::from_millis(500);
const START_MUTATION_STATES: &[&str] = &["starting"];
const RUNNING_MUTATION_STATES: &[&str] = &["running"];
const STOP_MUTATION_STATES: &[&str] = &["stopping"];
const SOURCE_RESTART_POD_POLL: Duration = Duration::from_millis(250);
const DESTROY_MUTATION_STATES: &[&str] = &["destroying"];
const DESTROY_CLEANUP_MUTATION_STATES: &[&str] = &["destroying", "destroyed"];

fn is_lifecycle_control_loss(error: &anyhow::Error) -> bool {
    is_authority_lost(error)
        || is_setup_activity_cancelled(error)
        || is_setup_recovery_failed(error)
}

fn needs_running_confidential_authorization(
    state: &str,
    desired_state: &str,
    isolation_tier: &str,
) -> bool {
    state == "running" && desired_state == "started" && isolation_tier == "confidential"
}

async fn await_reconcile_or_cancel<T, F>(
    activity_ctx: &ActivityContext,
    future: F,
) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    tokio::select! {
        result = future => result,
        _ = activity_ctx.cancelled() => Err(super::setup::SetupActivityCancelled.into()),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileOutcome {
    #[default]
    Continue,
    Destroyed,
}

/// Mirrors `recordEnvironmentError` (log-only on failure).
async fn record_environment_error(
    svc: &Service<PgLifecycleStore>,
    authority: &ActivityAuthority,
    env_id: &str,
    reason: &str,
) -> anyhow::Result<()> {
    authority.ensure().await?;
    let states = match authority.desired_state() {
        "started" => START_MUTATION_STATES,
        "stopped" => STOP_MUTATION_STATES,
        "destroyed" => DESTROY_MUTATION_STATES,
        _ => &[],
    };
    if let Err(e) = svc.mark_error_for_states(env_id, reason, states).await {
        authority.ensure().await?;
        tracing::error!(
            environment_id = env_id,
            reason,
            error = %e,
            "environment lifecycle: failed to mark error"
        );
    }
    Ok(())
}

fn snapshot(id: &str, state: &str, desired: &str, external_cleanup_complete: bool) -> Snapshot {
    Snapshot {
        id: id.to_string(),
        state: state.to_string(),
        desired_state: desired.to_string(),
        external_cleanup_complete,
    }
}

pub(super) fn start_runtime_is_ready(probe: &ProbeResult) -> bool {
    probe.claim_exists
        && probe.claim_ready
        && probe.pod_exists
        && probe.pod_phase == "Running"
        && !probe.pod_name.is_empty()
        && !probe.pod_uid.is_empty()
        && !probe.pod_ip.is_empty()
}

async fn reconcile_running_runtime_identity(
    ctx: &WorkerContext,
    environment: &super::env_data::EnvironmentRow,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let backend = load_backend_row(&ctx.pool, &environment.id)
        .await
        .map_err(|_| anyhow::anyhow!("environment runtime backend is unavailable"))?;
    if backend.namespace.is_empty() {
        anyhow::bail!("environment runtime backend is unavailable");
    }
    let sandbox = SandboxClient::new(
        ctx.kube
            .clone()
            .ok_or_else(|| anyhow::anyhow!("environment runtime is unavailable"))?,
        &backend.namespace,
    );
    let deadline = tokio::time::Instant::now() + RUNNING_RUNTIME_RECOVERY_TIMEOUT;
    let probe = authority
        .run_while_authoritative_for_states(RUNNING_MUTATION_STATES, async {
            loop {
                match sandbox.probe_environment(&environment.id).await {
                    Ok(probe) if start_runtime_is_ready(&probe) => break Ok(probe),
                    Ok(_) => {
                        tracing::debug!(
                            environment_id = environment.id,
                            "waiting for current running workspace runtime"
                        );
                    }
                    Err(error) => {
                        tracing::debug!(
                            environment_id = environment.id,
                            error = %error,
                            "retrying workspace runtime probe"
                        );
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("environment runtime Pod recovery timed out");
                }
                tokio::time::sleep(RUNNING_RUNTIME_RECOVERY_POLL).await;
            }
        })
        .await?;
    reconcile_or_refresh_runtime_identity(
        ctx,
        environment,
        &backend,
        authority,
        RUNNING_MUTATION_STATES,
        &probe,
        true,
    )
    .await
    .map(|_| ())
}

fn sandbox_client(ctx: &WorkerContext, namespace: &str) -> anyhow::Result<SandboxClient> {
    let Some(kube) = &ctx.kube else {
        anyhow::bail!("sandbox backend is not configured");
    };
    Ok(SandboxClient::new(kube.clone(), namespace))
}

async fn ensure_gateway_stack_for_env(
    ctx: &WorkerContext,
    cfg: &SandboxWorkerCfg,
    env_id: &str,
    namespace: &str,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let env = load_environment(&ctx.pool, env_id).await?;
    let preset_id = env.preset_id.clone().unwrap_or_default();
    let (image_ref, template_base) = load_sandbox_template_config(&ctx.pool, &preset_id).await?;
    let auth_tokens = issue_environment_tokens(&cfg.session_secret, env_id)?;
    let opts = environment_template_opts(
        cfg,
        &image_ref,
        &template_base,
        &env,
        authority.operation_generation(),
        &auth_tokens.coordinate,
        &auth_tokens.daemon,
    )?;
    let client = sandbox_client(ctx, namespace)?;
    run_template_mutation(
        authority,
        &opts,
        START_MUTATION_STATES,
        client.ensure_gateway_stack(&opts),
    )
    .await?;
    authority
        .run_while_authoritative_for_states(
            START_MUTATION_STATES,
            client.wait_for_credential_gateway_ready(
                &opts,
                super::create::ready_timeout_for_isolation(&env.isolation_tier),
            ),
        )
        .await
}

/// Mirrors `loadSandboxTemplateConfig`.
async fn load_sandbox_template_config(
    pool: &PgPool,
    preset_id: &str,
) -> anyhow::Result<(String, String)> {
    let row: (String, String) = sqlx::query_as(
        "SELECT image_ref, sandbox_template_name FROM sandbox_template_config WHERE preset_id = $1",
    )
    .bind(preset_id)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("load sandbox_template_config for {preset_id}: {e}"))?;
    Ok(row)
}

/// Creation may fail before a preset or its runtime configuration exists.
/// Keep any available deterministic name as a hint, but deletion must still
/// discover environment-owned resources when that hint is unavailable.
async fn destroy_template_hint(
    pool: &PgPool,
    preset_id: Option<&str>,
    env_id: &str,
) -> anyhow::Result<Option<String>> {
    let Some(preset_id) = preset_id else {
        return Ok(None);
    };
    let config: Option<(String, String)> = sqlx::query_as(
        "SELECT image_ref, sandbox_template_name FROM sandbox_template_config WHERE preset_id = $1",
    )
    .bind(preset_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| anyhow::anyhow!("load destroy template hint: {error}"))?;
    Ok(config.map(|(image, base)| environment_per_env_template_name(&image, &base, env_id)))
}

/// Mirrors `HandleEnvironmentStop`.
pub async fn handle_environment_stop(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "environment.stop received");
    let svc = Service::for_activity(ctx.pool.clone(), authority.clone());

    authority.ensure().await?;

    let env = load_environment(&ctx.pool, env_id).await?;

    if env.state != "running" && env.state != "stopping" {
        tracing::info!(
            environment_id = env_id,
            state = env.state,
            "environment.stop: evaluating lifecycle state"
        );
    }

    let proceed = svc
        .prepare_stop(&snapshot(
            &env.id,
            &env.state,
            &env.desired_state,
            env.external_cleanup_completed_at.is_some(),
        ))
        .await?;
    if !proceed {
        if requires_running_runtime_identity(&env.state, &env.desired_state) {
            reconcile_running_runtime_identity(ctx, &env, authority).await?;
        }
        tracing::info!(
            environment_id = env_id,
            state = env.state,
            "environment.stop: not in running/stopping state, skipping"
        );
        return Ok(());
    }

    let backend = match load_backend_row(&ctx.pool, env_id).await {
        Ok(b) => b,
        Err(e) => {
            record_environment_error(&svc, authority, env_id, &format!("load backend: {e:#}"))
                .await?;
            return Err(e);
        }
    };

    // Scale the sandbox down to 0 replicas (keeps the claim/sandbox, deletes pod).
    let client = sandbox_client(ctx, &backend.namespace)?;
    let claim_opts = workspace_claim_opts(&env);
    let previous = authority
        .run_while_authoritative_for_states(
            STOP_MUTATION_STATES,
            source_restart_pods(&client, env_id, &backend.pod_name),
        )
        .await?;
    if let Err(e) = authority
        .run_external_mutation(
            STOP_MUTATION_STATES,
            client.suspend_workspace(&claim_opts, &backend.claim_name, &backend.claim_uid),
        )
        .await
    {
        record_environment_error(&svc, authority, env_id, &format!("{e:#}")).await?;
        return Err(anyhow::anyhow!("set replicas 0: {e:#}"));
    }
    authority
        .run_while_authoritative_for_states(
            STOP_MUTATION_STATES,
            wait_for_workspace_suspension(&client, &env, &backend, &previous, DELETED_TIMEOUT),
        )
        .await?;
    if let Err(e) = authority
        .run_external_mutation(STOP_MUTATION_STATES, client.delete_gateway_stack(env_id))
        .await
    {
        tracing::warn!(
            environment_id = env_id,
            error = %e,
            "environment.stop: failed to delete gateway stack, continuing"
        );
    }

    if let Err(e) = svc.complete_stop(env_id).await {
        record_environment_error(&svc, authority, env_id, &format!("{e:#}")).await?;
        return Err(e);
    }

    if let Err(e) = svc.mark_stopped(env_id).await {
        authority.ensure().await?;
        tracing::warn!(environment_id = env_id, error = %e, "environment.stop: mark stopped failed");
    }
    let _ = authority
        .execute_for_states(
            &["stopped"],
            sqlx::query(
                "UPDATE sandbox_environment_backend SET pod_ip = NULL WHERE environment_id = $1",
            )
            .bind(env_id),
        )
        .await;

    // Clean up DNS records for ports (pods are gone, previews unreachable).
    if ctx.cloudflare.is_some()
        && let Err(e) = port_dns::delete_port_dns_records_authoritative(
            ctx,
            env_id,
            authority,
            &["stopped"],
            false,
        )
        .await
    {
        tracing::warn!(error = %e, "environment.stop: failed to clean up port DNS");
    }

    tracing::info!(environment_id = env_id, "environment.stop completed");
    Ok(())
}

/// Resume the durable source-change intent, never an implicit public Stop/Start
/// request. Temporal serializes this with the environment's existing command
/// queue/generation. The stopping -> stopped CAS selects the one activity that
/// may proceed to start; replayed signals cannot suspend a replacement runtime.
pub async fn handle_environment_restart_sources(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: super::setup_lease::SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<()> {
    if activity_ctx.is_cancelled() {
        return Err(super::setup::SetupActivityCancelled.into());
    }
    authority.ensure().await?;
    let env = load_environment(&ctx.pool, &payload.environment_id).await?;
    if !source_restart_pending(&env.state, &env.desired_state) {
        return Ok(());
    }
    authority.ensure_for_states(STOP_MUTATION_STATES).await?;
    let backend = load_backend_row(&ctx.pool, &env.id).await?;
    let client = sandbox_client(ctx, &backend.namespace)?;
    let claim_opts = workspace_claim_opts(&env);
    let previous = await_reconcile_or_cancel(
        &activity_ctx,
        authority.run_while_authoritative_for_states(
            STOP_MUTATION_STATES,
            source_restart_pods(&client, &env.id, &backend.pod_name),
        ),
    )
    .await?;
    await_reconcile_or_cancel(
        &activity_ctx,
        authority.run_external_mutation(
            STOP_MUTATION_STATES,
            client.suspend_workspace(&claim_opts, &backend.claim_name, &backend.claim_uid),
        ),
    )
    .await?;
    // An acknowledged suspend/delete is not evidence of Pod termination. Keep
    // state=stopping (and grants revoked) until the exact old UIDs are gone and
    // the environment has no replacement Pod. A timeout/error retains durable
    // restart intent for the normal reconciler; it must not reset setup history.
    await_reconcile_or_cancel(
        &activity_ctx,
        authority.run_while_authoritative_for_states(
            STOP_MUTATION_STATES,
            wait_for_workspace_suspension(&client, &env, &backend, &previous, DELETED_TIMEOUT),
        ),
    )
    .await?;
    await_reconcile_or_cancel(
        &activity_ctx,
        authority.run_external_mutation(STOP_MUTATION_STATES, client.delete_gateway_stack(&env.id)),
    )
    .await?;
    let svc = Service::for_activity(ctx.pool.clone(), authority.clone());
    if activity_ctx.is_cancelled() {
        return Err(super::setup::SetupActivityCancelled.into());
    }
    authority.ensure_for_states(STOP_MUTATION_STATES).await?;
    if let Err(error) = svc.complete_stop(&env.id).await {
        // Another attempt or a newer lifecycle intention won the state CAS.
        // Never let this activity continue into a second start in that case.
        if error
            .to_string()
            .contains(crate::lifecycle::STATE_NOT_TRANSITIONED)
        {
            return Err(AuthorityLost.into());
        }
        return Err(error);
    }
    svc.mark_stopped(&env.id).await?;
    authority
        .execute_for_states(
            &["stopped"],
            sqlx::query(
                "UPDATE sandbox_environment_backend SET pod_ip=NULL WHERE environment_id=$1",
            )
            .bind(&env.id),
        )
        .await?;
    authority.ensure_for_states(&["stopped"]).await?;
    handle_environment_start(ctx, payload, authority, setup_identity, activity_ctx).await
}

fn source_restart_pending(state: &str, desired: &str) -> bool {
    state == "stopping" && desired == "started"
}

async fn source_restart_pods(
    client: &SandboxClient,
    environment: &str,
    known_name: &str,
) -> anyhow::Result<Vec<WorkspacePodIdentity>> {
    let mut pods = client.list_workspace_pod_identities(environment).await?;
    if !known_name.is_empty()
        && let Some(pod) = client
            .get_workspace_pod_identity_by_name(known_name)
            .await?
        && !pods
            .iter()
            .any(|current| current.name == pod.name && current.uid == pod.uid)
    {
        pods.push(pod);
    }
    anyhow::ensure!(
        pods.iter()
            .all(|pod| !pod.name.is_empty() && !pod.uid.is_empty()),
        "workspace Pod identity is incomplete before source restart"
    );
    Ok(pods)
}

async fn source_restart_pods_absent(
    client: &SandboxClient,
    environment: &str,
    known_name: &str,
    previous: &[WorkspacePodIdentity],
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        previous
            .iter()
            .all(|pod| !pod.name.is_empty() && !pod.uid.is_empty()),
        "previous workspace Pod identity is incomplete"
    );
    if !source_restart_pods(client, environment, known_name)
        .await?
        .is_empty()
    {
        return Ok(false);
    }
    for previous in previous {
        if client
            .get_workspace_pod_identity_by_name(&previous.name)
            .await?
            .is_some()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn wait_for_source_restart_pods_absent(
    client: &SandboxClient,
    environment: &str,
    known_name: &str,
    previous: &[WorkspacePodIdentity],
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    within_workspace_deadline(deadline, async {
        loop {
            if source_restart_pods_absent(client, environment, known_name, previous).await? {
                return Ok(());
            }
            tokio::time::sleep(SOURCE_RESTART_POD_POLL).await;
        }
    })
    .await
}

pub(super) async fn within_workspace_deadline<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    anyhow::ensure!(
        tokio::time::Instant::now() < deadline,
        "workspace lifecycle observation timed out"
    );
    let result = tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| anyhow::anyhow!("workspace lifecycle observation timed out"))??;
    // A future that becomes ready after monopolizing its poll cannot turn a
    // late observation into timely completion.
    anyhow::ensure!(
        tokio::time::Instant::now() < deadline,
        "workspace lifecycle observation timed out"
    );
    Ok(result)
}

fn workspace_claim_opts(env: &super::env_data::EnvironmentRow) -> crate::sandbox::ClaimOpts {
    crate::sandbox::ClaimOpts {
        environment_id: env.id.clone(),
        org_id: env.org_id.clone(),
        operation_generation: env.operation_generation,
        ..Default::default()
    }
}

async fn wait_for_workspace_suspension(
    client: &SandboxClient,
    env: &super::env_data::EnvironmentRow,
    backend: &super::env_data::BackendRow,
    previous: &[WorkspacePodIdentity],
    timeout: Duration,
) -> anyhow::Result<WorkspaceSandboxIdentity> {
    let opts = workspace_claim_opts(env);
    let deadline = tokio::time::Instant::now() + timeout;
    within_workspace_deadline(deadline, async {
        let suspended = loop {
            if let Some(identity) = client
                .workspace_suspension_observed(&opts, &backend.claim_name, &backend.claim_uid)
                .await?
            {
                break identity;
            }
            tokio::time::sleep(SOURCE_RESTART_POD_POLL).await;
        };
        wait_for_source_restart_pods_absent(
            client,
            &env.id,
            &backend.pod_name,
            previous,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?;
        Ok(suspended)
    })
    .await
}

/// One cold-bootstrap path for an explicit start and a stale-generation retry.
/// Neither setup completion/history nor workspace storage is reset. Retain the
/// exact suspended Sandbox across recipe publication and conditional resume.
pub(super) async fn restart_workspace_bootstrap(
    ctx: &WorkerContext,
    env: &super::env_data::EnvironmentRow,
    backend: &super::env_data::BackendRow,
    opts: &crate::sandbox::template::TemplateOpts,
    authority: &ActivityAuthority,
    states: &[&str],
) -> anyhow::Result<()> {
    let client = sandbox_client(ctx, &backend.namespace)?;
    let claim_opts = workspace_claim_opts(env);
    super::create::authorize_confidential_runtime(ctx, opts, authority, states).await?;
    let deadline = tokio::time::Instant::now() + DELETED_TIMEOUT;
    let suspended = within_workspace_deadline(deadline, async {
        let previous = authority
            .run_while_authoritative_for_states(
                states,
                source_restart_pods(&client, &env.id, &backend.pod_name),
            )
            .await?;
        authority
            .run_external_mutation(
                states,
                client.suspend_workspace(&claim_opts, &backend.claim_name, &backend.claim_uid),
            )
            .await?;
        authority
            .run_while_authoritative_for_states(
                states,
                wait_for_workspace_suspension(
                    &client,
                    env,
                    backend,
                    &previous,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                ),
            )
            .await
    })
    .await?;
    refresh_workspace_bootstrap(ctx, env, backend, opts, &suspended, authority, states).await?;
    run_template_mutation(
        authority,
        opts,
        states,
        client.set_replicas_for_identity(
            &claim_opts,
            &backend.claim_name,
            &backend.claim_uid,
            &suspended,
            1,
        ),
    )
    .await
}

/// Mirrors `HandleEnvironmentStart`.
pub async fn handle_environment_start(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: super::setup_lease::SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "environment.start received");
    let svc = Service::for_activity(ctx.pool.clone(), authority.clone());

    authority.ensure().await?;

    let env = load_environment(&ctx.pool, env_id).await?;

    if env.state != "stopped" && env.state != "error" {
        tracing::info!(
            environment_id = env_id,
            state = env.state,
            "environment.start: evaluating lifecycle state"
        );
    }

    let proceed = svc
        .prepare_start(&snapshot(
            &env.id,
            &env.state,
            &env.desired_state,
            env.external_cleanup_completed_at.is_some(),
        ))
        .await?;
    if !proceed {
        tracing::info!(
            environment_id = env_id,
            state = env.state,
            "environment.start: not in stopped/error state, skipping"
        );
        return Ok(());
    }

    let backend = match load_backend_row(&ctx.pool, env_id).await {
        Ok(b) => b,
        Err(e) => {
            record_environment_error(&svc, authority, env_id, &format!("load backend: {e:#}"))
                .await?;
            return Err(e);
        }
    };
    let ns = backend.namespace.clone();
    let client = sandbox_client(ctx, &ns)?;

    let confidential_storage_manifest_uri = if env.isolation_tier == "confidential" {
        let Some(storage) = ctx.confidential_storage.as_ref() else {
            let error = anyhow::anyhow!("confidential storage providers are not configured");
            record_environment_error(&svc, authority, env_id, &format!("{error:#}")).await?;
            return Err(error);
        };
        match await_reconcile_or_cancel(
            &activity_ctx,
            authority.run_external_mutation(
                START_MUTATION_STATES,
                storage.ensure_ready(env_id, env.disk_gb),
            ),
        )
        .await
        {
            Ok(manifest_uri) => Some(manifest_uri),
            Err(error) => {
                if is_lifecycle_control_loss(&error) {
                    return Err(error);
                }
                record_environment_error(
                    &svc,
                    authority,
                    env_id,
                    &format!("key reconciliation: {error:#}"),
                )
                .await?;
                return Err(error);
            }
        }
    } else {
        None
    };

    let ready_timeout = ready_timeout_for_isolation(&env.isolation_tier);
    let mut runtime_opts =
        load_environment_template_opts(ctx, &env, authority.operation_generation()).await?;
    runtime_opts.confidential_storage_manifest_uri =
        confidential_storage_manifest_uri.unwrap_or_default();
    if let Err(error) = await_reconcile_or_cancel(
        &activity_ctx,
        restart_workspace_bootstrap(
            ctx,
            &env,
            &backend,
            &runtime_opts,
            authority,
            START_MUTATION_STATES,
        ),
    )
    .await
    {
        if is_lifecycle_control_loss(&error) {
            return Err(error);
        }
        record_environment_error(
            &svc,
            authority,
            env_id,
            "workspace bootstrap reconciliation failed",
        )
        .await?;
        return Err(error);
    }

    // Wait for the sandbox to become ready again.
    if let Err(e) = await_reconcile_or_cancel(
        &activity_ctx,
        authority.run_while_authoritative_for_states(
            START_MUTATION_STATES,
            client.wait_for_ready(env_id, ready_timeout),
        ),
    )
    .await
    {
        if is_lifecycle_control_loss(&e) {
            return Err(e);
        }
        record_environment_error(&svc, authority, env_id, &format!("{e:#}")).await?;
        return Err(anyhow::anyhow!("wait for sandbox ready: {e:#}"));
    }

    // Poll for pod IP — after scaling 0→1 the claim may still show
    // "Ready" (stale status) before the new pod exists.
    let deadline = tokio::time::Instant::now() + POD_IP_POLL_TIMEOUT;
    let (pod_ip, pod) = await_reconcile_or_cancel(
        &activity_ctx,
        authority.run_while_authoritative_for_states(START_MUTATION_STATES, async {
            loop {
                match client.probe_environment(env_id).await {
                    Ok(probe) if start_runtime_is_ready(&probe) => {
                        break Ok((
                            probe.pod_ip,
                            WorkspacePodIdentity {
                                name: probe.pod_name,
                                uid: probe.pod_uid,
                            },
                        ));
                    }
                    result => {
                        if tokio::time::Instant::now() >= deadline {
                            let detail = result
                                .err()
                                .map(|error| format!("{error:#}"))
                                .unwrap_or_else(|| "workspace Pod identity is incomplete".into());
                            record_environment_error(&svc, authority, env_id, &detail).await?;
                            return Err(anyhow::anyhow!(
                                "get current running workspace Pod identity: {detail}"
                            ));
                        }
                        tracing::debug!(
                            env = env_id,
                            "waiting for current running Pod after scale-up"
                        );
                        tokio::time::sleep(jittered_duration(Duration::from_secs(2))).await;
                    }
                }
            }
        }),
    )
    .await?;

    reconcile_runtime_identity_for_pod(
        ctx,
        &env,
        &backend,
        authority,
        START_MUTATION_STATES,
        Some(&pod),
    )
    .await?;

    if let Err(e) = authority
        .execute_for_states(
            START_MUTATION_STATES,
            sqlx::query(
                "UPDATE sandbox_environment_backend SET pod_ip = $1, pod_name = $2 WHERE environment_id = $3",
            )
            .bind(&pod_ip)
            .bind(&pod.name)
            .bind(env_id),
        )
        .await
    {
        record_environment_error(&svc, authority, env_id, &format!("{e:#}")).await?;
        return Err(anyhow::anyhow!("update pod_ip/pod_name: {e:#}"));
    }

    if let Err(e) =
        ensure_gateway_stack_for_env(ctx, &ctx.sandbox_cfg, env_id, &ns, authority).await
    {
        record_environment_error(&svc, authority, env_id, &format!("gateway stack: {e:#}")).await?;
        return Err(e);
    }

    // Persist the current Pod name/IP only after observing a ready claim and
    // a running Pod with a nonempty UID. The backend schema does not persist
    // that UID, so this is a current-runtime check, not an exact UID binding.
    if let Err(e) = svc.complete_start(env_id).await {
        record_environment_error(&svc, authority, env_id, &format!("{e:#}")).await?;
        return Err(e);
    }

    if let Err(e) = svc.mark_started(env_id).await {
        authority.ensure().await?;
        tracing::warn!(environment_id = env_id, error = %e, "environment.start: mark started failed");
    }

    if let Some(ttl) = env.ttl_seconds
        && let Err(e) = svc.schedule_shutdown_after_ttl(env_id, ttl).await
    {
        authority.ensure().await?;
        tracing::warn!(environment_id = env_id, error = %e, "environment.start: schedule shutdown failed");
    }

    // Gateway readiness + post-start configuration are best-effort,
    // post-running steps (the create path runs the equivalent work in the
    // Setup activity, which records errors on the backend row but never
    // flips the env to `error`). The env is already `running`; a transient
    // gateway hiccup here is a warning, not a lifecycle failure.
    let sidecar_started = std::time::Instant::now();
    match await_reconcile_or_cancel(
        &activity_ctx,
        authority
            .run_while_authoritative_for_states(&["running"], wait_for_sidecar(ctx, &ns, env_id)),
    )
    .await
    {
        Ok(()) => {
            emit_authoritative_environment_log_for_states(
                authority,
                &["running"],
                "gateway_ready",
                "completed",
                "",
                Some(serde_json::json!({
                    "duration_ms": sidecar_started.elapsed().as_millis() as i64,
                    "pod_ip": pod_ip,
                    "namespace": ns,
                })),
            )
            .await?;
            tracing::info!(
                environment_id = env_id,
                pod_ip,
                duration_ms = sidecar_started.elapsed().as_millis() as i64,
                "environment sidecar ready"
            );

            handle_post_start_configuration(
                ctx,
                payload,
                authority,
                setup_identity,
                activity_ctx.clone(),
            )
            .await?;
        }
        Err(e) => {
            if is_lifecycle_control_loss(&e) {
                return Err(e);
            }
            emit_authoritative_environment_log_for_states(
                authority,
                &["running"],
                "gateway_ready",
                "failed",
                &format!("{e:#}"),
                Some(serde_json::json!({
                    "duration_ms": sidecar_started.elapsed().as_millis() as i64,
                    "pod_ip": pod_ip,
                    "namespace": ns,
                })),
            )
            .await?;
            tracing::warn!(
                environment_id = env_id,
                error = %e,
                "environment.start: gateway not ready yet; env is running, skipping post-start configuration"
            );
        }
    }

    tracing::info!(environment_id = env_id, "environment.start completed");
    Ok(())
}

/// Mirrors `HandleEnvironmentDestroy`.
pub async fn handle_environment_destroy(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "environment.destroy received");
    let svc = Service::for_activity(ctx.pool.clone(), authority.clone());

    authority.ensure().await?;

    let env = load_environment(&ctx.pool, env_id).await?;

    let proceed = svc
        .prepare_destroy(&snapshot(
            &env.id,
            &env.state,
            &env.desired_state,
            env.external_cleanup_completed_at.is_some(),
        ))
        .await?;
    if !proceed {
        tracing::info!(
            environment_id = env_id,
            state = env.state,
            "environment.destroy: external cleanup already complete, skipping"
        );
        return Ok(());
    }

    // Every cleanup step below belongs to this attempt's runtime absence
    // proof; the marker resolves only ambiguity that settled before it began.
    let absence_proof = RuntimeAbsenceProof::begin(&ctx.pool).await?;

    port_dns::delete_port_dns_records_authoritative(
        ctx,
        env_id,
        authority,
        DESTROY_CLEANUP_MUTATION_STATES,
        true,
    )
    .await
    .map_err(|error| anyhow::anyhow!("delete port DNS records: {error:#}"))?;

    let backend = match load_backend_row(&ctx.pool, env_id).await {
        Ok(backend) => Some(backend),
        Err(error)
            if matches!(
                error.downcast_ref::<sqlx::Error>(),
                Some(sqlx::Error::RowNotFound)
            ) =>
        {
            None
        }
        Err(error) => {
            return Err(anyhow::anyhow!(
                "load environment backend discovery anchor: {error:#}"
            ));
        }
    };
    let known_sandbox_name = backend
        .as_ref()
        .map(|row| row.pod_name.as_str())
        .unwrap_or_default();
    let mut namespaces = BTreeSet::from([ctx.sandbox_cfg.sandbox_namespace.clone()]);
    if let Some(backend) = &backend
        && !backend.namespace.trim().is_empty()
    {
        namespaces.insert(backend.namespace.clone());
    }
    let retained_session_namespaces: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT runtime_namespace
           FROM sandbox_running_sessions
           WHERE environment_id = $1 AND btrim(runtime_namespace) <> ''"#,
    )
    .bind(env_id)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|error| anyhow::anyhow!("load retained runtime namespaces: {error}"))?;
    namespaces.extend(retained_session_namespaces);

    let per_environment_template =
        destroy_template_hint(&ctx.pool, env.preset_id.as_deref(), env_id).await?;

    for namespace in namespaces {
        if namespace.trim().is_empty() {
            continue;
        }
        let client = sandbox_client(ctx, &namespace)?;
        if let Err(error) = authority
            .run_external_mutation(
                DESTROY_CLEANUP_MUTATION_STATES,
                client.delete_environment_resources(
                    env_id,
                    known_sandbox_name,
                    per_environment_template.as_deref(),
                    env.isolation_tier == "confidential",
                    DELETED_TIMEOUT,
                ),
            )
            .await
        {
            record_environment_error(&svc, authority, env_id, &format!("{error:#}")).await?;
            return Err(anyhow::anyhow!(
                "delete environment resources in {namespace}: {error:#}"
            ));
        }
    }

    if env.isolation_tier == "confidential" {
        let Some(storage) = ctx.confidential_storage.as_ref() else {
            let error = anyhow::anyhow!("confidential storage providers are not configured");
            record_environment_error(&svc, authority, env_id, &format!("{error:#}")).await?;
            return Err(error);
        };
        if let Err(error) = authority
            .run_external_mutation(
                DESTROY_CLEANUP_MUTATION_STATES,
                storage.delete_after_storage_absent(env_id),
            )
            .await
        {
            record_environment_error(&svc, authority, env_id, &format!("key deletion: {error:#}"))
                .await?;
            return Err(error);
        }
    }

    if let Err(e) = svc
        .complete_external_cleanup(env_id, env.state == "destroyed", absence_proof)
        .await
    {
        record_environment_error(&svc, authority, env_id, &format!("{e:#}")).await?;
        return Err(e);
    }

    tracing::info!(
        environment_id = env_id,
        "environment.destroy external cleanup completed"
    );
    Ok(())
}

/// Mirrors `HandleEnvironmentReconcile`.
pub async fn handle_environment_reconcile(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: super::setup_lease::SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<ReconcileOutcome> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "environment.reconcile received");

    if activity_ctx.is_cancelled() {
        return Err(super::setup::SetupActivityCancelled.into());
    }

    authority.ensure().await?;
    let env = load_environment(&ctx.pool, env_id).await?;
    let svc = Service::for_activity(ctx.pool.clone(), authority.clone());
    let action = if resume_completed_workspace(&env.state, &env.desired_state) {
        let backend = load_backend_row(&ctx.pool, env_id).await?;
        if backend.setup_complete {
            // A source restart interrupted during Start must not re-enter
            // full Create/reset_for_retry and erase installation completion.
            Action::Start
        } else {
            svc.reconcile(&snapshot(
                &env.id,
                &env.state,
                &env.desired_state,
                env.external_cleanup_completed_at.is_some(),
            ))
            .await?
        }
    } else {
        svc.reconcile(&snapshot(
            &env.id,
            &env.state,
            &env.desired_state,
            env.external_cleanup_completed_at.is_some(),
        ))
        .await?
    };

    match action {
        Action::Noop if env.state == "destroyed" && env.desired_state == "destroyed" => {
            Ok(ReconcileOutcome::Destroyed)
        }
        Action::Noop => {
            if needs_running_confidential_authorization(
                &env.state,
                &env.desired_state,
                &env.isolation_tier,
            ) {
                let storage = ctx.confidential_storage.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("confidential storage providers are not configured")
                })?;
                let manifest_uri = await_reconcile_or_cancel(
                    &activity_ctx,
                    authority.run_external_mutation(
                        RUNNING_MUTATION_STATES,
                        storage.ensure_ready(env_id, env.disk_gb),
                    ),
                )
                .await?;
                await_reconcile_or_cancel(
                    &activity_ctx,
                    authorize_confidential_runtime_for_environment(
                        ctx,
                        &env,
                        &manifest_uri,
                        authority,
                        RUNNING_MUTATION_STATES,
                    ),
                )
                .await?;
            }

            if requires_running_runtime_identity(&env.state, &env.desired_state)
                && let Err(error) = reconcile_running_runtime_identity(ctx, &env, authority).await
            {
                if is_lifecycle_control_loss(&error) {
                    return Err(error);
                }
                svc.mark_error_for_states(
                    env_id,
                    &format!("environment runtime reconciliation failed: {error:#}"),
                    RUNNING_MUTATION_STATES,
                )
                .await?;
            }
            Ok(ReconcileOutcome::Continue)
        }
        Action::Create => {
            // D3 (Temporal-only): create chains setup inline rather than
            // publishing an env-setup NATS job. The primary create path
            // chains these as two workflow activities; the reconcile
            // recovery path is a single activity, so it runs both here.
            await_reconcile_or_cancel(
                &activity_ctx,
                Box::pin(
                    super::create::handle_environment_create_without_setup_publish(
                        ctx, payload, authority,
                    ),
                ),
            )
            .await?;
            Box::pin(super::setup::handle_environment_setup(
                ctx,
                payload,
                authority,
                setup_identity,
                activity_ctx.clone(),
            ))
            .await?;
            Ok(ReconcileOutcome::Continue)
        }
        Action::Start => {
            await_reconcile_or_cancel(
                &activity_ctx,
                Box::pin(handle_environment_start(
                    ctx,
                    payload,
                    authority,
                    setup_identity,
                    activity_ctx.clone(),
                )),
            )
            .await?;
            Ok(ReconcileOutcome::Continue)
        }
        Action::Stop => {
            await_reconcile_or_cancel(
                &activity_ctx,
                Box::pin(handle_environment_stop(ctx, payload, authority)),
            )
            .await?;
            Ok(ReconcileOutcome::Continue)
        }
        Action::RestartSources => {
            Box::pin(handle_environment_restart_sources(
                ctx,
                payload,
                authority,
                setup_identity,
                activity_ctx,
            ))
            .await?;
            Ok(ReconcileOutcome::Continue)
        }
        Action::Destroy => {
            await_reconcile_or_cancel(
                &activity_ctx,
                Box::pin(handle_environment_destroy(ctx, payload, authority)),
            )
            .await?;
            Ok(ReconcileOutcome::Destroyed)
        }
        Action::Unhandled => {
            tracing::warn!(
                environment_id = env_id,
                state = env.state,
                desired_state = env.desired_state,
                "environment.reconcile: unhandled case"
            );
            Ok(ReconcileOutcome::Continue)
        }
    }
}

fn resume_completed_workspace(state: &str, desired: &str) -> bool {
    desired == "started" && matches!(state, "starting" | "error")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_restart_client(
        responses: Vec<(axum::http::StatusCode, serde_json::Value)>,
    ) -> SandboxClient {
        source_restart_delayed_client(responses, Some(Duration::ZERO))
    }

    fn source_restart_delayed_client(
        responses: Vec<(axum::http::StatusCode, serde_json::Value)>,
        delay: Option<Duration>,
    ) -> SandboxClient {
        use axum::{
            Router,
            body::Body,
            http::{Request, Response, header},
        };
        use std::{
            collections::VecDeque,
            sync::{Arc, Mutex},
        };
        let queued = Arc::new(Mutex::new(VecDeque::from(responses)));
        let service = Router::new().fallback(move |request: Request<Body>| {
            let queued = queued.clone();
            async move {
                match delay {
                    Some(duration) => tokio::time::sleep(duration).await,
                    None => std::future::pending::<()>().await,
                }
                assert_eq!(
                    request.method(),
                    axum::http::Method::GET,
                    "termination observation must be read-only"
                );
                let (status, body) = queued
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes request");
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        SandboxClient::new(kube::Client::new(service, "default"), "dev-sandboxes")
    }

    fn old_pod() -> WorkspacePodIdentity {
        WorkspacePodIdentity {
            name: "workspace-old".into(),
            uid: "uid-old".into(),
        }
    }

    fn pod_list(items: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items})
    }

    fn pod(uid: &str) -> serde_json::Value {
        serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"workspace-old","uid":uid},"status":{"phase":"Running"}})
    }

    fn missing_pod() -> (axum::http::StatusCode, serde_json::Value) {
        (
            axum::http::StatusCode::NOT_FOUND,
            serde_json::json!({"apiVersion":"v1","kind":"Status","status":"Failure","message":"not found","reason":"NotFound","code":404}),
        )
    }

    #[test]
    fn restart_and_completed_workspace_recovery_require_exact_durable_intent() {
        assert!(source_restart_pending("stopping", "started"));
        for state in [
            "pending",
            "creating",
            "starting",
            "running",
            "stopped",
            "error",
            "destroying",
            "destroyed",
        ] {
            assert!(!source_restart_pending(state, "started"));
        }
        for desired in ["stopped", "destroyed", "resized"] {
            assert!(!source_restart_pending("stopping", desired));
            assert!(!resume_completed_workspace("starting", desired));
        }
        assert!(resume_completed_workspace("starting", "started"));
        assert!(resume_completed_workspace("error", "started"));
        assert!(!resume_completed_workspace("pending", "started"));
    }

    #[tokio::test]
    async fn source_restart_requires_old_uid_and_every_workspace_pod_to_be_absent() {
        use axum::http::StatusCode;
        let mut terminating = pod("uid-old");
        terminating["metadata"]["deletionTimestamp"] = serde_json::json!("2026-09-07T12:00:00Z");
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![terminating]))]);
        assert!(
            !source_restart_pods_absent(&client, "environment", "", &[old_pod()])
                .await
                .unwrap()
        );
        // Losing an environment label cannot turn a still-present old Pod into
        // a successful termination observation. A new UID at the old stable
        // name also blocks scale-up until the suspended controller removes it.
        for uid in ["uid-old", "uid-replacement"] {
            let client = source_restart_client(vec![
                (StatusCode::OK, pod_list(vec![])),
                (StatusCode::OK, pod(uid)),
            ]);
            assert!(
                !source_restart_pods_absent(&client, "environment", "", &[old_pod()])
                    .await
                    .unwrap()
            );
        }
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![])), missing_pod()]);
        assert!(
            source_restart_pods_absent(&client, "environment", "", &[old_pod()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn source_restart_rechecks_known_backend_name_and_fails_closed_on_unknown_uid() {
        use axum::http::StatusCode;
        let client = source_restart_client(vec![
            (StatusCode::OK, pod_list(vec![])),
            (StatusCode::OK, pod("uid-old")),
        ]);
        let identities = source_restart_pods(&client, "environment", "workspace-old")
            .await
            .unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].uid, "uid-old");
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![pod("")]))]);
        assert!(
            source_restart_pods(&client, "environment", "")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn source_restart_deadline_bounds_stalled_gets_and_late_success() {
        use axum::http::StatusCode;
        for delay in [None, Some(Duration::from_millis(200))] {
            let client = source_restart_delayed_client(
                vec![(StatusCode::OK, pod_list(vec![])), missing_pod()],
                delay,
            );
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                wait_for_source_restart_pods_absent(
                    &client,
                    "environment",
                    "",
                    &[old_pod()],
                    Duration::from_millis(20),
                ),
            )
            .await
            .expect("original deadline must interrupt the GET");
            assert!(result.unwrap_err().to_string().contains("timed out"));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let result = within_workspace_deadline(deadline, async {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        })
        .await;
        assert!(result.is_err(), "late-ready futures cannot bypass deadline");
    }

    #[tokio::test]
    async fn source_restart_does_not_treat_timeout_as_pod_deletion() {
        use axum::http::StatusCode;
        let client = source_restart_client(vec![(StatusCode::OK, pod_list(vec![pod("uid-old")]))]);
        assert!(
            wait_for_source_restart_pods_absent(
                &client,
                "environment",
                "",
                &[old_pod()],
                Duration::ZERO
            )
            .await
            .is_err()
        );
        let client = source_restart_client(vec![
            (StatusCode::OK, pod_list(vec![pod("uid-old")])),
            (StatusCode::OK, pod_list(vec![])),
            missing_pod(),
        ]);
        wait_for_source_restart_pods_absent(
            &client,
            "environment",
            "",
            &[old_pod()],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn destroy_template_hint_allows_missing_creation_config_but_not_database_failure()
    -> anyhow::Result<()> {
        let pool = PgPool::connect(&std::env::var("TEST_DATABASE_URL")?).await?;
        let preset = format!("destroy-hint-{}", uuid::Uuid::new_v4());
        assert_eq!(destroy_template_hint(&pool, None, "env-test").await?, None);
        assert_eq!(
            destroy_template_hint(&pool, Some(&preset), "env-test").await?,
            None
        );
        sqlx::query(
            r#"INSERT INTO environment_presets (id, name, official, project_spec)
               VALUES ($1, $1, true, '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&preset).execute(&pool).await?;
        sqlx::query("INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name) VALUES ($1, 'example.test/workspace:test', 'workspace-test')")
            .bind(&preset).execute(&pool).await?;
        assert_eq!(
            destroy_template_hint(&pool, Some(&preset), "env-test").await?,
            Some(environment_per_env_template_name(
                "example.test/workspace:test",
                "workspace-test",
                "env-test"
            ))
        );
        sqlx::query("DELETE FROM sandbox_template_config WHERE preset_id = $1")
            .bind(&preset)
            .execute(&pool)
            .await?;
        assert_eq!(
            destroy_template_hint(&pool, Some(&preset), "env-test").await?,
            None
        );
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset)
            .execute(&pool)
            .await?;
        pool.close().await;
        assert!(
            destroy_template_hint(&pool, Some(&preset), "env-test")
                .await
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn authorization_backfill_selects_only_stable_running_confidential_environments() {
        assert!(needs_running_confidential_authorization(
            "running",
            "started",
            "confidential"
        ));
        for candidate in [
            ("running", "stopped", "confidential"),
            ("starting", "started", "confidential"),
            ("stopped", "stopped", "confidential"),
            ("running", "started", "standard"),
        ] {
            assert!(!needs_running_confidential_authorization(
                candidate.0,
                candidate.1,
                candidate.2,
            ));
        }
    }

    fn ready_start_runtime() -> ProbeResult {
        ProbeResult {
            claim_exists: true,
            claim_ready: true,
            pod_exists: true,
            pod_phase: "Running".into(),
            pod_name: "workspace-current".into(),
            pod_uid: "workspace-uid-current".into(),
            pod_ip: "10.0.0.9".into(),
            ..Default::default()
        }
    }

    #[test]
    fn start_requires_ready_claim_and_complete_running_pod_identity() {
        let ready = ready_start_runtime();
        assert!(start_runtime_is_ready(&ready));

        let mut probe = ready.clone();
        probe.claim_ready = false;
        assert!(!start_runtime_is_ready(&probe));

        let mut probe = ready.clone();
        probe.pod_phase = "Pending".into();
        assert!(!start_runtime_is_ready(&probe));

        let mut probe = ready.clone();
        probe.pod_uid.clear();
        assert!(!start_runtime_is_ready(&probe));

        let mut probe = ready;
        probe.pod_ip.clear();
        assert!(!start_runtime_is_ready(&probe));
    }
}
