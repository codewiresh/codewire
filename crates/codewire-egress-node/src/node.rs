//! The node service (#4000): admission, the reporter and the supervisor in
//! one process, until a SIGTERM's drain has moved every sandbox.

use std::process::ExitCode;
use std::sync::Arc;

use codewire_confinement::spawn::OwnImage;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::drain::drain_then_shut_down;
use crate::launch::ProcessLaunch;
use crate::orchestration::Orchestration;
use crate::reporter::Reporter;
use crate::settings::NodeSettings;
use crate::supervisor::{Signals, supervisor};

/// The guests' stream port, on the Pod network (`codewire-egress`, 8089/TCP).
pub const STREAM_PORT: u16 = 8089;
/// Admitted streams waiting for the supervisor.
const ADMITTED_QUEUE: usize = 64;

/// Runs the node service; returns when it has drained and shut down.
pub fn run() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let settings = match NodeSettings::from_env() {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(%error, "cw-egress refuses to start");
            return ExitCode::FAILURE;
        }
    };
    // Children start by descriptor from this image, opened before anything
    // could replace it.
    let image = match OwnImage::open() {
        Ok(image) => image,
        Err(error) => {
            tracing::error!(%error, "cw-egress could not open its own image");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "cw-egress could not start its runtime");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(serve(settings, image))
}

async fn serve(settings: NodeSettings, image: OwnImage) -> ExitCode {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(error) => {
            tracing::error!(%error, "cw-egress could not listen for SIGTERM");
            return ExitCode::FAILURE;
        }
    };
    let launch = match ProcessLaunch::new(image, settings.refused) {
        Ok(launch) => launch,
        Err(error) => {
            tracing::error!(%error, "cw-egress could not start the thread that starts its children");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(("0.0.0.0", STREAM_PORT)).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, port = STREAM_PORT, "cw-egress could not listen for guest streams");
            return ExitCode::FAILURE;
        }
    };
    let orchestration = Arc::new(Orchestration {
        url: settings.orchestration_url,
        address: settings.orchestration_address.ip(),
        roots: settings.orchestration_roots,
        token_path: settings.node_token_path,
    });
    // Each front door's credential sessions come from orchestration (#4001).
    let launch = launch.with_front_door_sessions(Arc::clone(&orchestration) as _);
    let (reporter, reporting) = Reporter::start(Arc::clone(&orchestration));
    let signals = Signals::default();
    let (admitted, streams) = mpsc::channel(ADMITTED_QUEUE);
    // The drain stops admission first: the supervisor then returns once its
    // last pair is gone, or at the deadline.
    let admission = tokio::spawn(crate::admission::serve(
        listener,
        Arc::clone(&orchestration),
        reporter.clone(),
        admitted,
        signals.drain.clone(),
    ));
    tokio::spawn(drain_then_shut_down(
        signals.clone(),
        async move {
            terminate.recv().await;
        },
        settings.drain,
    ));
    tracing::info!(port = STREAM_PORT, "cw-egress serves guest streams");
    let drained = supervisor(streams, signals, launch).await;
    tracing::info!(
        moved_idle = drained.moved_idle,
        cut_at_deadline = drained.cut_at_deadline,
        "cw-egress drained"
    );
    admission.abort();
    drop(reporter);
    // The reporter flushes what its Pods left before it ends.
    let _ = reporting.await;
    ExitCode::SUCCESS
}
