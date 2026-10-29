//! Rust-owned all-up proof for HTTP/Connect-to-Temporal orchestration wiring.
//!
//! The aggregate diagnostic starts the real orchestration binary and Temporal
//! worker. This smoke creates an environment through its generated Connect
//! client, proves that exact request drove the canonical workflow and activity
//! trail, and exercises the short-lived Port-DNS workflow without Cloudflare.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context as _;
use codewire_orchestration::temporal::{
    DEFAULT_TASK_QUEUE, EnvironmentWorkflow, PortDnsCommand, PortDnsWorkflow,
    environment_workflow_id,
};
use codewire_proto::codewire::v1::{CreateEnvironmentRequest, EnvironmentServiceClient};
use connectrpc::client::{ClientConfig, HttpClient};
use reqwest::header::COOKIE;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use temporalio_client::{
    Client, ClientOptions, Connection, ConnectionOptions, WorkflowFetchHistoryOptions,
    WorkflowGetResultOptions, WorkflowStartOptions, WorkflowTerminateOptions,
};
use temporalio_common::protos::temporal::api::history::v1::history_event::Attributes;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("ORCHESTRATION_RUNTIME_BASE_URL")?;
    let database_url = required_env("DATABASE_URL")?;
    let temporal_address = required_env("TEMPORAL_ADDRESS")?;
    let session_token = required_env("ORCHESTRATION_RUNTIME_SESSION_TOKEN")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
        .context("connect orchestration runtime database")?;
    let temporal = temporal_client(&temporal_address).await?;

    assert_port_dns_workflow(&temporal).await?;
    assert_connect_create_drives_workflow(&temporal, &pool, &base_url, &session_token).await?;

    println!(
        "deploy-shape-smoke: Connect create-to-Temporal activity trail and Port-DNS workflow green"
    );
    Ok(())
}

async fn temporal_client(address: &str) -> anyhow::Result<Client> {
    let url = url::Url::parse(address).context("parse Temporal address")?;
    let connection = Connection::connect(ConnectionOptions::new(url).build())
        .await
        .context("connect Temporal")?;
    Client::new(
        connection,
        ClientOptions::new("default".to_string()).build(),
    )
    .map_err(|error| anyhow::anyhow!("create Temporal client: {error}"))
}

async fn assert_port_dns_workflow(temporal: &Client) -> anyhow::Result<()> {
    let environment_id = format!("env-port-dns-runtime-{}", &Uuid::new_v4().to_string()[..8]);
    let workflow_id = format!("port-dns/create/{environment_id}");
    let handle = temporal
        .start_workflow(
            PortDnsWorkflow::run,
            PortDnsCommand {
                action: "create".into(),
                environment_id,
                ..Default::default()
            },
            WorkflowStartOptions::new(DEFAULT_TASK_QUEUE, &workflow_id).build(),
        )
        .await
        .context("start PortDnsWorkflow")?;
    tokio::time::timeout(
        Duration::from_secs(45),
        handle.get_result(WorkflowGetResultOptions::default()),
    )
    .await
    .context("PortDnsWorkflow timed out")?
    .context("PortDnsWorkflow failed")?;
    Ok(())
}

async fn assert_connect_create_drives_workflow(
    temporal: &Client,
    pool: &PgPool,
    base_url: &str,
    session_token: &str,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM rate_limit WHERE key LIKE 'env_create:%'")
        .execute(pool)
        .await
        .context("clear environment-create rate limit")?;
    let config = ClientConfig::new(base_url.parse().context("parse orchestration base URL")?)
        .with_default_timeout(Duration::from_secs(30))
        .with_default_header(COOKIE, format!("codewire.session_token={session_token}"));
    let client = EnvironmentServiceClient::new(HttpClient::plaintext(), config);
    let created = client
        .create_environment(CreateEnvironmentRequest {
            org_id: "org_contract_1".into(),
            preset_id: Some("preset_contract_1".into()),
            name: Some(format!(
                "rust-deploy-shape-{}",
                &Uuid::new_v4().to_string()[..8]
            )),
            ttl_seconds: Some(120),
            ..Default::default()
        })
        .await
        .context("CreateEnvironment through real Connect listener")?
        .into_owned();
    let environment_id = created
        .environment
        .as_option()
        .context("CreateEnvironment omitted environment")?
        .id
        .clone();
    anyhow::ensure!(
        !environment_id.is_empty(),
        "CreateEnvironment returned empty id"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(75);
    loop {
        let state = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT state, error_reason FROM environments WHERE id = $1",
        )
        .bind(&environment_id)
        .fetch_optional(pool)
        .await?;
        if matches!(state, Some((ref state, Some(ref reason))) if state == "error" && reason.starts_with("template config:"))
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Connect-created environment did not reach template-config error: {state:?}"
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let namespace: String = sqlx::query_scalar(
        "SELECT namespace FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(&environment_id)
    .fetch_one(pool)
    .await
    .context("read Connect-created backend namespace")?;
    anyhow::ensure!(
        !namespace.is_empty(),
        "create activity omitted backend namespace"
    );
    let transitions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM environment_lifecycle_journal
          WHERE environment_id = $1 AND kind = 'transition'
            AND from_state = 'pending' AND to_state = 'creating'",
    )
    .bind(&environment_id)
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(
        transitions > 0,
        "create activity omitted pending-to-creating transition"
    );

    let workflow_id = environment_workflow_id(&environment_id);
    let handle = temporal.get_workflow_handle::<EnvironmentWorkflow>(&workflow_id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let verification = async {
        let history = loop {
            let history = handle
                .fetch_history(WorkflowFetchHistoryOptions::default())
                .await
                .context("fetch Connect-created workflow history")?;
            let completed: HashSet<i64> = history
                .events()
                .iter()
                .filter_map(|event| match event.attributes {
                    Some(Attributes::ActivityTaskCompletedEventAttributes(ref done)) => {
                        Some(done.scheduled_event_id)
                    }
                    _ => None,
                })
                .collect();
            let scheduled: Vec<(i64, String)> = history
                .events()
                .iter()
                .filter_map(|event| match event.attributes {
                    Some(Attributes::ActivityTaskScheduledEventAttributes(ref scheduled)) => {
                        Some((
                            event.event_id,
                            scheduled.activity_type.as_ref()?.name.clone(),
                        ))
                    }
                    _ => None,
                })
                .collect();
            // A first create claims inside its own activity (#3630).
            let expected = [
                "EnvironmentClaimAndCreateActivity",
                "EnvironmentSetupActivity",
            ];
            if scheduled
                .iter()
                .map(|(_, name)| name.as_str())
                .eq(expected)
                && scheduled
                    .iter()
                    .all(|(event_id, _)| completed.contains(event_id))
            {
                break history;
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "Connect-created workflow did not complete its current activity protocol: scheduled={scheduled:?} completed={completed:?}"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let starts = history
            .events()
            .iter()
            .filter(|event| {
                matches!(
                    event.attributes,
                    Some(Attributes::WorkflowExecutionStartedEventAttributes(_))
                )
            })
            .count();
        anyhow::ensure!(
            starts == 1,
            "Connect create produced {starts} workflow starts"
        );
        let run_id = history
            .events()
            .iter()
            .find_map(|event| match event.attributes {
                Some(Attributes::WorkflowExecutionStartedEventAttributes(ref started)) => {
                    Some(started.original_execution_run_id.clone())
                }
                _ => None,
            })
            .filter(|run_id| !run_id.is_empty())
            .context("Connect-created workflow history omitted original run id")?;
        let closed = history.events().iter().any(|event| {
            matches!(
                event.attributes,
                Some(Attributes::WorkflowExecutionCompletedEventAttributes(_))
                    | Some(Attributes::WorkflowExecutionFailedEventAttributes(_))
                    | Some(Attributes::WorkflowExecutionCanceledEventAttributes(_))
                    | Some(Attributes::WorkflowExecutionTerminatedEventAttributes(_))
                    | Some(Attributes::WorkflowExecutionTimedOutEventAttributes(_))
            )
        });
        anyhow::ensure!(
            !closed,
            "Connect-created signal workflow closed instead of awaiting its next command"
        );
        let ledger = sqlx::query_as::<_, (String, i64)>(
            "SELECT workflow_run_id, generation
           FROM environment_operation_generation_claims
          WHERE environment_id = $1
          ORDER BY generation DESC
          LIMIT 1",
        )
        .bind(&environment_id)
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            matches!(ledger, Some((ref ledger_run_id, generation)) if ledger_run_id == &run_id && generation > 0),
            "Connect-created workflow authority ledger mismatch: run={run_id} ledger={ledger:?}"
        );
        let failures: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_logs
          WHERE environment_id = $1 AND phase = 'create_claim' AND status = 'failed'",
        )
        .bind(&environment_id)
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            failures > 0,
            "create activity omitted its deterministic template-config failure trail"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let termination = handle
        .terminate(
            WorkflowTerminateOptions::builder()
                .reason("deploy-shape smoke complete")
                .build(),
        )
        .await;
    verification?;
    termination.context("terminate Connect-created smoke workflow")?;
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
