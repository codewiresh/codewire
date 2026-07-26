//! Live integration smoke for the final Rust-owned Temporal environment
//! protocol (#916).
//!
//! The environment workflow is signal-driven and intentionally remains open
//! after a non-terminal command. This smoke therefore proves the durable
//! generation claim, generation-bearing activity inputs, retry/heartbeat
//! options, and expected database result, then terminates its disposable
//! workflow explicitly.
//!
//! Env: TEMPORAL_ADDRESS (default http://127.0.0.1:7233), DATABASE_URL and
//! SMOKE_ENV_ID (required).

use std::collections::HashSet;
use std::time::Duration;

use sqlx::PgPool;
use temporalio_client::{
    Client, ClientOptions, Connection, ConnectionOptions, WorkflowFetchHistoryOptions,
    WorkflowSignalOptions, WorkflowStartOptions, WorkflowTerminateOptions,
};
use temporalio_common::HasWorkflowDefinition;
use temporalio_common::data_converters::{DataConverter, SerializationContextData};
use temporalio_common::protos::temporal::api::history::v1::history_event::Attributes;

use codewire_orchestration::temporal::{
    DEFAULT_TASK_QUEUE, EnvironmentActivityCommand, EnvironmentClaimInput, EnvironmentCommand,
    EnvironmentWorkflow, environment_workflow_id,
};

fn activity_name(attributes: &Attributes) -> Option<&str> {
    let Attributes::ActivityTaskScheduledEventAttributes(scheduled) = attributes else {
        return None;
    };
    scheduled
        .activity_type
        .as_ref()
        .map(|activity_type| activity_type.name.as_str())
}

async fn verify_activity_input(
    name: &str,
    attributes: &Attributes,
    env_id: &str,
    generation: i64,
) -> anyhow::Result<()> {
    let Attributes::ActivityTaskScheduledEventAttributes(scheduled) = attributes else {
        anyhow::bail!("{name} is not an activity-scheduled event");
    };
    let payloads = scheduled
        .input
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{name} has no input"))?
        .payloads;
    let converter = DataConverter::default();

    if name == "EnvironmentClaimAuthorityActivity" {
        let input: EnvironmentClaimInput = converter
            .from_payloads(&SerializationContextData::Activity, payloads)
            .await?;
        if input.environment_id != env_id {
            anyhow::bail!("claim input environment mismatch: {input:?}");
        }
    } else {
        let input: EnvironmentActivityCommand = converter
            .from_payloads(&SerializationContextData::Activity, payloads)
            .await?;
        if input.environment_id != env_id
            || input.operation_generation != generation
            || input.requested_by != "temporal-smoke"
        {
            anyhow::bail!("{name} input does not carry the claimed authority: {input:?}");
        }
    }

    let heartbeat = scheduled
        .heartbeat_timeout
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("{name} has no heartbeat timeout"))?;
    if heartbeat.seconds != 15 || heartbeat.nanos != 0 {
        anyhow::bail!("{name} heartbeat timeout is not 15s: {heartbeat:?}");
    }
    if scheduled
        .retry_policy
        .as_ref()
        .map(|policy| policy.maximum_attempts)
        != Some(3)
    {
        anyhow::bail!("{name} does not carry the three-attempt retry policy");
    }
    Ok(())
}

async fn verify_final_protocol<W: HasWorkflowDefinition>(
    handle: &temporalio_client::WorkflowHandle<Client, W>,
    pool: &PgPool,
    env_id: &str,
) -> anyhow::Result<()> {
    let run_id = handle
        .run_id()
        .ok_or_else(|| anyhow::anyhow!("started workflow handle has no run ID"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);

    loop {
        let row = sqlx::query_as::<_, (String, Option<String>, i64)>(
            "SELECT state, error_reason, environment_operation_generation
               FROM environments
              WHERE id = $1",
        )
        .bind(env_id)
        .fetch_optional(pool)
        .await?;
        let ledger = sqlx::query_as::<_, (String, i64)>(
            "SELECT workflow_run_id, generation
               FROM environment_operation_generation_claims
              WHERE environment_id = $1
              ORDER BY generation DESC
              LIMIT 1",
        )
        .bind(env_id)
        .fetch_optional(pool)
        .await?;
        let history = handle
            .fetch_history(WorkflowFetchHistoryOptions::default())
            .await?;
        let completed: HashSet<i64> = history
            .events()
            .iter()
            .filter_map(|event| match event.attributes.as_ref() {
                Some(Attributes::ActivityTaskCompletedEventAttributes(done)) => {
                    Some(done.scheduled_event_id)
                }
                _ => None,
            })
            .collect();
        let scheduled: Vec<_> = history
            .events()
            .iter()
            .filter_map(|event| {
                let attributes = event.attributes.as_ref()?;
                activity_name(attributes).map(|name| (event.event_id, name, attributes))
            })
            .collect();

        let expected_names = [
            "EnvironmentClaimAuthorityActivity",
            "EnvironmentCreateActivity",
            "EnvironmentSetupActivity",
        ];
        let names_match = scheduled.len() == expected_names.len()
            && scheduled
                .iter()
                .map(|(_, name, _)| *name)
                .eq(expected_names);
        let all_completed = scheduled
            .iter()
            .all(|(event_id, _, _)| completed.contains(event_id));

        if let (Some((state, Some(reason), generation)), Some((ledger_run_id, ledger_generation))) =
            (row, ledger)
            && state == "error"
            && reason.starts_with("template config:")
            && generation > 0
            && ledger_run_id == run_id
            && ledger_generation == generation
            && names_match
            && all_completed
        {
            for (_, name, attributes) in scheduled {
                verify_activity_input(name, attributes, env_id, generation).await?;
            }
            println!(
                "temporal-smoke: final protocol observed run={run_id} generation={generation} state={state}"
            );
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            let names: Vec<_> = scheduled.iter().map(|(_, name, _)| *name).collect();
            anyhow::bail!(
                "final protocol was not observed before deadline (activities={names:?}, completed={completed:?})"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let address =
        std::env::var("TEMPORAL_ADDRESS").unwrap_or_else(|_| "http://127.0.0.1:7233".to_string());
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
    let env_id =
        std::env::var("SMOKE_ENV_ID").map_err(|_| anyhow::anyhow!("SMOKE_ENV_ID is required"))?;

    let url = url::Url::parse(&address)?;
    let mut attempt = 0;
    let connection = loop {
        attempt += 1;
        match Connection::connect(ConnectionOptions::new(url.clone()).build()).await {
            Ok(connection) => break connection,
            Err(error) if attempt < 15 => {
                eprintln!("temporal-smoke: connect attempt {attempt} failed ({error}); retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "connect temporal after {attempt} attempts: {error}"
                ));
            }
        }
    };
    let client = Client::new(
        connection,
        ClientOptions::new("default".to_string()).build(),
    )
    .map_err(|error| anyhow::anyhow!("temporal client: {error}"))?;
    let pool = PgPool::connect(&database_url).await?;
    let workflow_id = environment_workflow_id(&env_id);

    let handle = client
        .start_workflow(
            EnvironmentWorkflow::run,
            EnvironmentCommand::default(),
            WorkflowStartOptions::new(DEFAULT_TASK_QUEUE, workflow_id.as_str()).build(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("start workflow: {error}"))?;
    println!(
        "temporal-smoke: started {workflow_id} (run {:?})",
        handle.run_id()
    );

    handle
        .signal(
            EnvironmentWorkflow::command,
            EnvironmentCommand {
                action: "create".into(),
                environment_id: env_id.clone(),
                requested_by: "temporal-smoke".into(),
            },
            WorkflowSignalOptions::default(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("signal workflow: {error}"))?;
    println!("temporal-smoke: signaled environment.command create");

    let verification = verify_final_protocol(&handle, &pool, &env_id).await;
    let termination = handle
        .terminate(
            WorkflowTerminateOptions::builder()
                .reason("final-protocol integration smoke complete")
                .build(),
        )
        .await;
    verification?;
    termination.map_err(|error| anyhow::anyhow!("terminate smoke workflow: {error}"))?;

    println!("temporal-smoke: PASS");
    Ok(())
}
