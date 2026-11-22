//! The activity options every workflow in this module schedules with.

use std::time::Duration;

use temporalio_common::protos::temporal::api::common::v1::RetryPolicy;
use temporalio_sdk::{ActivityCancellationType, ActivityOptions};

use super::BILLING_TASK_QUEUE;

pub(super) fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        initial_interval: Duration::from_secs(2).try_into().ok(),
        backoff_coefficient: 2.0,
        maximum_interval: Duration::from_secs(30).try_into().ok(),
        maximum_attempts: 3,
        ..Default::default()
    }
}

pub(super) fn environment_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .heartbeat_timeout(Duration::from_secs(15))
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(retry_policy())
        .build()
}

pub(super) fn short_activity_opts() -> ActivityOptions {
    let mut opts = ActivityOptions::start_to_close_timeout(Duration::from_secs(30 * 60));
    opts.retry_policy = Some(retry_policy().into());
    opts
}

pub(super) fn organization_deletion_activity_opts() -> ActivityOptions {
    environment_activity_opts()
}

pub(super) fn organization_deletion_failure_opts() -> ActivityOptions {
    let mut retry = retry_policy();
    // The destructive phase has already stopped. Keep retrying only the
    // idempotent terminal-state write so a database outage cannot strand a
    // started operation behind a completed Temporal workflow.
    retry.maximum_attempts = 0;
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .heartbeat_timeout(Duration::from_secs(15))
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(retry)
        .build()
}

pub(super) fn organization_billing_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(30 * 60))
        .task_queue(BILLING_TASK_QUEUE)
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(retry_policy())
        .build()
}

/// Every account deletion phase retries until it succeeds: the account is
/// already disabled, and stopping part way would leave it neither usable nor
/// deleted. The backoff tops out at five minutes.
pub(super) fn account_deletion_retry_policy() -> RetryPolicy {
    RetryPolicy {
        initial_interval: Duration::from_secs(10).try_into().ok(),
        backoff_coefficient: 2.0,
        maximum_interval: Duration::from_secs(5 * 60).try_into().ok(),
        maximum_attempts: 0,
        ..Default::default()
    }
}

pub(super) fn account_deletion_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(10 * 60))
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(account_deletion_retry_policy())
        .build()
}

pub(super) fn account_deletion_billing_activity_opts() -> ActivityOptions {
    ActivityOptions::with_start_to_close_timeout(Duration::from_secs(10 * 60))
        .task_queue(BILLING_TASK_QUEUE)
        .cancellation_type(ActivityCancellationType::WaitCancellationCompleted)
        .retry_policy(account_deletion_retry_policy())
        .build()
}
