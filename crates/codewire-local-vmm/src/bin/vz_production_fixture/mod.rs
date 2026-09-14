use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::future::Future;
use std::io;
#[cfg(any(target_os = "linux", test))]
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use std::{fs::File, io::Seek};

use codewire_daemon::client::SessionClient;
use codewire_local_vmm::network_session::{DenyBroker, NetworkSessionError, run_network_session};
#[cfg(test)]
use codewire_vmm_guest_probe::{GuestBootStage, ProgressFrame, ProgressRequest, SetupBinding};
use codewire_vmm_guest_probe::{NetworkKey, Seed};
#[cfg(any(target_os = "linux", test))]
use codewire_vmm_guest_probe::{SETUP_HEADER_LEN, SetupArchitecture, SetupHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
#[cfg(test)]
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;
use common::*;
mod session;

#[cfg(target_os = "linux")]
mod prepare;
#[cfg(test)]
mod tests;
mod workload;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(210);
const WORKLOAD_DEADLINE: Duration = Duration::from_secs(30);

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

pub(super) fn entry() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or_else(invalid)?;
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        let value = arguments.next().ok_or_else(invalid)?;
        if options.insert(key, value).is_some() {
            return Err(invalid().into());
        }
    }
    match command.as_str() {
        "seed" => make_seed(options),
        "verify" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async { tokio::time::timeout(DEADLINE, verify(options)).await? })
        }
        #[cfg(target_os = "linux")]
        "prepare" => prepare::run(options),
        _ => Err(invalid().into()),
    }
}

fn make_seed(options: BTreeMap<String, String>) -> Result<()> {
    exact_keys(
        &options,
        &["--setup-fd", "--output-fd", "--vm-id", "--generation"],
    )?;
    let setup_fd = descriptor(&options, "--setup-fd")?;
    let output_fd = descriptor(&options, "--output-fd")?;
    if setup_fd == output_fd {
        return Err(invalid().into());
    }
    let mut setup = private_file(setup_fd, false)?;
    let mut output = private_file(output_fd, true)?;
    if output.metadata()?.len() != 0 {
        return Err(invalid().into());
    }
    let seed = seed_from_setup(&mut setup, &options)?;
    let encoded = Zeroizing::new(seed.encode());
    output.write_all(encoded.as_ref())?;
    output.sync_all()?;
    Ok(())
}

enum Finished {
    Network,
    Progress(UnixStream),
    Daemon(SessionClient),
    Workload,
}

async fn verify(options: BTreeMap<String, String>) -> Result<()> {
    let keys = [
        "--network-fd",
        "--progress-fd",
        "--daemon-fd",
        "--control-fd",
        "--seed-fd",
    ];
    exact_keys(&options, &keys)?;
    let numbers = keys
        .iter()
        .map(|key| descriptor(&options, key))
        .collect::<Result<Vec<_>>>()?;
    // Numeric uniqueness prevents taking ownership twice. The Python parent
    // constructs separate socketpairs; Swift independently proves its endpoint
    // identities. This check alone does not claim duplicate-open-file detection.
    if numbers.iter().copied().collect::<BTreeSet<_>>().len() != numbers.len() {
        return Err(invalid().into());
    }
    let seed = Arc::new(fixture_seed(private_file(numbers[4], false)?)?);
    verify_session(
        seed,
        private_stream(numbers[0])?,
        private_stream(numbers[1])?,
        private_stream(numbers[2])?,
        private_stream(numbers[3])?,
    )
    .await
}

async fn verify_session(
    seed: Arc<Seed>,
    network: UnixStream,
    progress: UnixStream,
    daemon: UnixStream,
    control: UnixStream,
) -> Result<()> {
    verify_session_with_workload(
        seed,
        network,
        progress,
        daemon,
        control,
        |client| async move { workload::prove(&client).await },
    )
    .await
}

async fn verify_session_with_workload<W, F>(
    seed: Arc<Seed>,
    network: UnixStream,
    progress: UnixStream,
    daemon: UnixStream,
    mut control: UnixStream,
    workload: W,
) -> Result<()>
where
    W: FnOnce(SessionClient) -> F + Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
{
    let mut network = Some(network);
    let mut progress = Some(progress);
    let mut daemon = Some(daemon);
    let (network_ready_tx, mut network_ready_rx) = oneshot::channel();
    let mut network_ready_tx = Some(network_ready_tx);
    let mut network_ready = false;
    let mut tasks: JoinSet<Result<Finished>> = JoinSet::new();
    let mut retained_progress = None;
    let mut retained_daemon = None;
    let mut workload = Some(workload);
    let mut ready = false;
    let mut workload_complete = false;
    let mut armed = false;
    loop {
        // Completed task failures win over a simultaneous control command.
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => match result.ok_or_else(invalid)??? {
                Finished::Network => {
                    if !armed { return Err(invalid().into()); }
                    // The parent's armed SIGKILL must close the owned network
                    // stream. The parent separately proves actual helper death,
                    // control EOF, process-group absence and private cleanup.
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    drop(retained_daemon);
                    drop(retained_progress);
                    control.write_all(b"C").await?;
                    return Ok(());
                }
                Finished::Progress(stream) => retained_progress = Some(stream),
                Finished::Daemon(client) => retained_daemon = Some(client),
                Finished::Workload => {
                    if !ready || workload_complete {
                        return Err(invalid().into());
                    }
                    workload_complete = true;
                    control.write_all(b"W").await?;
                }
            },
            result = &mut network_ready_rx, if network.is_none() && !network_ready => {
                result?;
                network_ready = true;
            },
            marker = control.read_u8() => match marker? {
                b'N' => {
                    let stream = network.take().ok_or_else(invalid)?;
                    let key = NetworkKey::derive(seed.auth_token(), seed.vm_id(), seed.generation())?;
                    let ready_sender = network_ready_tx.take().ok_or_else(invalid)?;
                    let (vm_id, generation) = (seed.vm_id(), seed.generation());
                    tasks.spawn(async move {
                        let result = run_network_session(stream, key, vm_id, generation, Arc::new(DenyBroker), move || {
                            ready_sender.send(()).map_err(|_| invalid())
                        }).await;
                        // Any termination before the armed ownership check is
                        // rejected, including an otherwise normal peer EOF.
                        match result {
                            Err(NetworkSessionError::FrameIo) => Ok(Finished::Network),
                            _ => Err(invalid().into()),
                        }
                    });
                }
                b'P' => {
                    let stream = progress.take().ok_or_else(invalid)?;
                    let seed = seed.clone();
                    tasks.spawn(async move { prove_progress(stream, &seed).await.map(Finished::Progress) });
                }
                b'D' => {
                    let stream = daemon.take().ok_or_else(invalid)?;
                    let seed = seed.clone();
                    tasks.spawn(async move { prove_daemon(stream, &seed).await.map(Finished::Daemon) });
                }
                b'K' if ready && workload_complete && !armed => {
                    armed = true;
                    control.write_all(b"A").await?;
                }
                _ => return Err(invalid().into()),
            }
        }
        if !ready
            && complete_readiness(
                network_ready,
                retained_progress.is_some(),
                retained_daemon.is_some(),
            )
        {
            ready = true;
            control.write_all(b"R").await?;
            let client = retained_daemon.as_ref().ok_or_else(invalid)?.clone();
            let workload = workload.take().ok_or_else(invalid)?;
            tasks.spawn(async move {
                tokio::time::timeout(WORKLOAD_DEADLINE, workload(client))
                    .await
                    .map_err(|_| invalid())??;
                Ok(Finished::Workload)
            });
        }
    }
}

fn complete_readiness(network: bool, progress: bool, daemon: bool) -> bool {
    network && progress && daemon
}
