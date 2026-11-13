//! The Temporal worker: its own thread and runtime, and one connected run.

use std::sync::Arc;
use std::time::Duration;

use temporalio_client::{Client, ClientOptions, Connection, ConnectionOptions};
use temporalio_sdk::runtime::{Runtime, RuntimeOptions};
use temporalio_sdk::{Worker, WorkerOptions};
use tokio_util::sync::CancellationToken;

use super::{
    AccountDeletionActivities, AccountDeletionWorkflow, EnvironmentActivities, EnvironmentWorkflow,
    OrganizationDeletionActivities, OrganizationDeletionWorkflow, PortDnsActivities,
    PortDnsWorkflow, SnapshotActivities, SnapshotCaptureWorkflow, SnapshotDeleteWorkflow,
};
use crate::worker::WorkerContext;

/// The Temporal worker thread's stack. Every activity is polled on this one
/// thread, nested inside the SDK's own futures. In an unoptimised build the
/// create activity's poll frames alone take about 1.75 MiB (the create loop's
/// frame is 1.1 MiB), and its first Kubernetes call overflowed a spawned
/// thread's 2 MiB default (main run 22671); it ran in 3 MiB. A stack is
/// address space, committed only as it is touched.
const TEMPORAL_WORKER_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Spawns the Temporal worker on a dedicated thread with its own
/// runtime — `Worker::run`'s future is !Send, so it cannot ride the
/// main multi-threaded runtime via `tokio::spawn`. Retries with
/// backoff (server restarts, network partitions) until `draining`
/// (#4426), which ends it for good.
pub fn spawn_temporal_worker(
    wctx: Arc<WorkerContext>,
    host_port: String,
    namespace: String,
    task_queue: String,
    draining: CancellationToken,
) {
    std::thread::Builder::new()
        .name("temporal-worker".into())
        .stack_size(TEMPORAL_WORKER_STACK_BYTES)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("temporal worker runtime");
            rt.block_on(async move {
                let mut backoff = Duration::from_secs(2);
                while !draining.is_cancelled() {
                    match run_temporal_worker(
                        wctx.clone(),
                        &host_port,
                        &namespace,
                        &task_queue,
                        draining.cancelled(),
                    )
                    .await
                    {
                        Ok(()) => break,
                        Err(e) if draining.is_cancelled() => {
                            tracing::warn!(error = %e, "temporal worker stopped while draining");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, backoff = ?backoff, "temporal worker failed; retrying");
                            tokio::select! {
                                () = draining.cancelled() => {}
                                () = tokio::time::sleep(backoff) => {}
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(60));
                        }
                    }
                }
            });
        })
        .expect("spawn temporal worker thread");
}

/// Connects and runs the Temporal worker until failure or `shutdown`, which
/// stops it polling and waits for its activity tasks to finish. The caller
/// owns retry/backoff.
pub async fn run_temporal_worker(
    wctx: Arc<WorkerContext>,
    host_port: &str,
    namespace: &str,
    task_queue: &str,
    shutdown: impl Future,
) -> anyhow::Result<()> {
    let runtime_opts = RuntimeOptions::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("temporal runtime options: {e}"))?;
    let runtime = Runtime::from_current_tokio(runtime_opts)?;

    let target = if host_port.contains("://") {
        host_port.to_string()
    } else {
        format!("http://{host_port}")
    };
    let conn_opts = ConnectionOptions::new(url::Url::parse(&target)?)
        // One frontend Service address, connected now. DNS load
        // balancing would open connections lazily inside the first
        // request, whose span the connection then holds (#3581).
        .dns_load_balancing(None)
        .build();
    let connection = Connection::connect(conn_opts).await?;
    let client = Client::new(
        connection,
        ClientOptions::new(namespace.to_string()).build(),
    )
    .map_err(|e| anyhow::anyhow!("temporal client: {e}"))?;

    let worker_options = WorkerOptions::new(task_queue.to_string())
        .register_workflow::<EnvironmentWorkflow>()?
        .register_workflow::<PortDnsWorkflow>()?
        .register_workflow::<OrganizationDeletionWorkflow>()?
        .register_workflow::<AccountDeletionWorkflow>()?
        .register_workflow::<SnapshotCaptureWorkflow>()?
        .register_workflow::<SnapshotDeleteWorkflow>()?
        .register_activities(EnvironmentActivities { wctx: wctx.clone() })
        .register_activities(PortDnsActivities { wctx: wctx.clone() })
        .register_activities(SnapshotActivities { wctx: wctx.clone() })
        .register_activities(OrganizationDeletionActivities { wctx: wctx.clone() })
        .register_activities(AccountDeletionActivities { wctx })
        .build();

    let worker = Worker::new(&runtime, client, worker_options)
        .map_err(|e| anyhow::anyhow!("temporal worker init: {e}"))?;
    tracing::info!(task_queue, namespace, "temporal worker started");
    worker
        .run_until(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!("temporal worker run: {e}"))?;
    tracing::info!(task_queue, namespace, "temporal worker stopped");
    Ok(())
}
