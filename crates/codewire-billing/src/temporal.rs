//! Temporal worker (#38) — the billing service's `OrgTeardownWorkflow`.
//!
//! `DELETE /organizations/{id}` (ported on the orchestration side) must
//! cancel the org's Stripe subscription. Stripe lives only here, so the
//! orchestration handler starts this workflow BY NAME (untyped) on the
//! `codewire-billing` task queue and this worker runs the single
//! subscription-cancel activity.
//!
//! - workflow type `OrgTeardownWorkflow`, ID `org-teardown/{org_id}`
//! - activity name `CancelOrgSubscriptionsActivity`, StartToClose 30m,
//!   retry 2s ×2 → 30s cap, 3 attempts
//! - task queue `codewire-billing` (BILLING_TASK_QUEUE)
//!
//! The activity body mirrors `billing.CancelOrgSubscriptions`
//! (webhook.go): look up the org's active subscription and cancel it;
//! a missing/null subscription is a no-op. A Stripe error surfaces as
//! an `ActivityError` so Temporal retries it.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use temporalio_client::{Client, ClientOptions, Connection, ConnectionOptions};
use temporalio_common::protos::temporal::api::common::v1::RetryPolicy;
use temporalio_macros::{activities, workflow, workflow_methods};
use temporalio_sdk::activities::{ActivityContext, ActivityError};
use temporalio_sdk::{ActivityOptions, Worker, WorkerOptions, WorkflowContext, WorkflowResult};
use temporalio_sdk_core::{CoreRuntime, RuntimeOptions};

use codewire_server_core::account_deletion::{
    self, AccountDeletionPhase, AccountDeletionWorkflowInput,
};

use crate::billing_teardown::{
    OrganizationBillingTeardownInput, OrganizationBillingTeardownResult,
    delete_account_stripe_customers, finalize_organization_billing,
};
use crate::email::EmailClient;
use crate::stripe_client::StripeHandle;

pub const BILLING_TASK_QUEUE: &str = "codewire-billing";

/// Mirrors the orchestration trigger's workflow-ID convention.
pub fn org_teardown_workflow_id(org_id: &str) -> String {
    format!("org-teardown/{org_id}")
}

/// Input for `OrgTeardownWorkflow`. Both sides are Rust, so the field is
/// plain snake_case (no Go-field-name rename).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgTeardownInput {
    pub org_id: String,
}

/// Mirrors `billing.CancelOrgSubscriptions`'s dependencies: the pool for
/// the subscription lookup, the Stripe handle for the cancel call.
pub struct OrgTeardownActivities {
    pub pool: PgPool,
    pub stripe: StripeHandle,
}

#[activities]
impl OrgTeardownActivities {
    /// Dark WI-3 activity consumed by the durable organization workflow in
    /// WI-5. Its input is generation-bound and its database evidence survives
    /// removal of the organization and local subscription rows.
    #[activity(name = "FinalizeOrganizationBillingActivity")]
    pub async fn finalize_billing(
        self: Arc<Self>,
        _ctx: ActivityContext,
        input: OrganizationBillingTeardownInput,
    ) -> Result<OrganizationBillingTeardownResult, ActivityError> {
        finalize_organization_billing(&self.pool, &self.stripe, &input)
            .await
            .map_err(|error| {
                ActivityError::from(anyhow::anyhow!(
                    "organization billing teardown failed: {error}"
                ))
            })
    }

    /// Mirrors `billing.CancelOrgSubscriptions` (webhook.go:706): select
    /// the org's active subscription; if none/null, no-op; else cancel
    /// it via Stripe (errors propagate so Temporal retries).
    #[activity(name = "CancelOrgSubscriptionsActivity")]
    pub async fn cancel(
        self: Arc<Self>,
        _ctx: ActivityContext,
        input: OrgTeardownInput,
    ) -> Result<(), ActivityError> {
        let sub_id: Option<Option<String>> = sqlx::query_scalar(
            r#"SELECT stripe_subscription_id FROM org_subscriptions
               WHERE org_id = $1 AND stripe_subscription_id IS NOT NULL
                 AND status IN ('active', 'trialing', 'past_due')"#,
        )
        .bind(&input.org_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ActivityError::from(anyhow::anyhow!("query org subscription: {e}")))?;

        let Some(Some(sub_id)) = sub_id else {
            // No active subscription — nothing to cancel.
            return Ok(());
        };

        self.stripe
            .cancel_subscription(&sub_id, &format!("cw-legacy-org-teardown-{sub_id}"))
            .await
            .map_err(|e| ActivityError::from(anyhow::anyhow!("cancel subscription: {e}")))?;
        Ok(())
    }
}

/// The billing phases of the account deletion workflow (#3679), scheduled
/// onto this queue by orchestration's `AccountDeletionWorkflow`. Each one
/// resumes from the phase the operation records.
pub struct AccountDeletionBillingActivities {
    pub pool: PgPool,
    pub stripe: StripeHandle,
    pub email: EmailClient,
}

fn account_deletion_error(error: impl std::fmt::Display) -> ActivityError {
    ActivityError::from(anyhow::anyhow!(
        "account deletion billing activity failed: {error}"
    ))
}

#[activities]
impl AccountDeletionBillingActivities {
    /// Delete the personal organizations' Stripe customers, once their own
    /// deletions have completed.
    #[activity(name = "DeleteAccountStripeCustomersActivity")]
    pub async fn delete_stripe_customers(
        self: Arc<Self>,
        _ctx: ActivityContext,
        input: AccountDeletionWorkflowInput,
    ) -> Result<(), ActivityError> {
        delete_account_stripe_customers(&self.pool, &self.stripe, &input.operation_id)
            .await
            .map_err(account_deletion_error)
    }

    /// Send the confirmation mail and complete the operation, which clears
    /// the address. Without mail delivery the account is still deleted: the
    /// operation completes and the missing mail is logged.
    #[activity(name = "SendAccountDeletedMailActivity")]
    pub async fn send_deleted_mail(
        self: Arc<Self>,
        _ctx: ActivityContext,
        input: AccountDeletionWorkflowInput,
    ) -> Result<(), ActivityError> {
        let operation =
            account_deletion::account_deletion_operation(&self.pool, &input.operation_id)
                .await
                .map_err(account_deletion_error)?;
        match operation.phase().map_err(account_deletion_error)? {
            AccountDeletionPhase::UserDeleted => {}
            AccountDeletionPhase::Completed => return Ok(()),
            _ => return Err(account_deletion_error("the user is not deleted yet")),
        }
        match operation.email.as_deref() {
            Some(address) if self.email.is_configured() => self
                .email
                .send_account_deleted(address)
                .await
                .map_err(account_deletion_error)?,
            Some(_) => tracing::warn!(
                operation_id = operation.id,
                "account deleted without a confirmation mail: delivery is not configured"
            ),
            None => {}
        }
        account_deletion::complete_account_deletion(&self.pool, &input.operation_id)
            .await
            .map_err(account_deletion_error)
    }
}

/// Mirrors the orchestration worker's activity options: StartToClose
/// 30m, retry 2s initial, ×2 backoff, 30s max interval, 3 attempts.
fn activity_opts() -> ActivityOptions {
    let mut opts = ActivityOptions::start_to_close_timeout(Duration::from_secs(30 * 60));
    opts.retry_policy = Some(RetryPolicy {
        initial_interval: Duration::from_secs(2).try_into().ok(),
        backoff_coefficient: 2.0,
        maximum_interval: Duration::from_secs(30).try_into().ok(),
        maximum_attempts: 3,
        ..Default::default()
    });
    opts
}

/// Single-shot workflow: cancel the org's subscription, then complete.
#[workflow(name = "OrgTeardownWorkflow")]
#[derive(Default)]
pub struct OrgTeardownWorkflow {}

#[workflow_methods]
impl OrgTeardownWorkflow {
    #[run]
    pub async fn run(
        ctx: &mut WorkflowContext<Self>,
        input: OrgTeardownInput,
    ) -> WorkflowResult<()> {
        ctx.start_activity(
            OrgTeardownActivities::cancel,
            input.clone(),
            activity_opts(),
        )
        .await?;
        Ok(())
    }
}

/// Spawns the billing Temporal worker on a dedicated thread with its own
/// runtime — `Worker::run`'s future is !Send. Retries with backoff
/// forever (server restarts, network partitions), same as the
/// orchestration worker.
pub fn spawn_org_teardown_worker(
    pool: PgPool,
    stripe: StripeHandle,
    email: EmailClient,
    host_port: String,
    namespace: String,
) {
    std::thread::Builder::new()
        .name("temporal-billing-worker".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("temporal billing worker runtime");
            rt.block_on(async move {
                let mut backoff = Duration::from_secs(2);
                loop {
                    match run_org_teardown_worker(
                        pool.clone(),
                        stripe.clone(),
                        email.clone(),
                        &host_port,
                        &namespace,
                    )
                    .await
                    {
                        Ok(()) => break,
                        Err(e) => {
                            tracing::error!(error = %e, backoff = ?backoff, "temporal billing worker failed; retrying");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(60));
                        }
                    }
                }
            });
        })
        .expect("spawn temporal billing worker thread");
}

/// Connects and runs the billing Temporal worker until failure. The
/// caller owns retry/backoff.
pub async fn run_org_teardown_worker(
    pool: PgPool,
    stripe: StripeHandle,
    email: EmailClient,
    host_port: &str,
    namespace: &str,
) -> anyhow::Result<()> {
    let runtime_opts = RuntimeOptions::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("temporal runtime options: {e}"))?;
    let runtime = CoreRuntime::new_assume_tokio(runtime_opts)?;

    let target = if host_port.contains("://") {
        host_port.to_string()
    } else {
        format!("http://{host_port}")
    };
    let conn_opts = ConnectionOptions::new(url::Url::parse(&target)?).build();
    let connection = Connection::connect(conn_opts).await?;
    let client = Client::new(
        connection,
        ClientOptions::new(namespace.to_string()).build(),
    )
    .map_err(|e| anyhow::anyhow!("temporal client: {e}"))?;

    let worker_options = WorkerOptions::new(BILLING_TASK_QUEUE.to_string())
        .register_workflow::<OrgTeardownWorkflow>()?
        .register_activities(OrgTeardownActivities {
            pool: pool.clone(),
            stripe: stripe.clone(),
        })
        .register_activities(AccountDeletionBillingActivities {
            pool,
            stripe,
            email,
        })
        .build();

    let mut worker = Worker::new(&runtime, client, worker_options)
        .map_err(|e| anyhow::anyhow!("temporal billing worker init: {e}"))?;
    tracing::info!(
        task_queue = BILLING_TASK_QUEUE,
        namespace,
        "temporal billing worker started"
    );
    worker
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("temporal billing worker run: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_id_format() {
        assert_eq!(org_teardown_workflow_id("org_x"), "org-teardown/org_x");
    }

    #[test]
    fn input_round_trips() {
        let json = r#"{"org_id":"org_x"}"#;
        let input: OrgTeardownInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.org_id, "org_x");
        assert_eq!(serde_json::to_string(&input).unwrap(), json);
    }
}
