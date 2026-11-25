//! The host agent, `cw host run`: it keeps this computer's session with
//! Codewire open, proving the host key, and reconnects when it ends. It runs
//! the lifecycle operations the session sends ([`super::operations`]).

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use futures::StreamExt as _;
use futures::stream::FuturesUnordered;

use codewire_client::hosts::{HostOperation, HostOperationResult};

use super::operations::{self, Outcome};
use super::*;

/// Held while an agent runs, so a computer runs one agent per enrollment.
const AGENT_LOCK_FILE: &str = "host-agent.lock";

/// How long the agent waits before retrying a locked keyring.
const KEY_RETRY: Duration = Duration::from_secs(30);
/// The longest wait between reconnects.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long the agent waits before trying again when Codewire does not
/// recognise the host: long, because it rarely heals, but not forever,
/// because a server-side fault would otherwise strand every host.
const UNRECOGNISED_RETRY: Duration = Duration::from_secs(300);

/// Why one session ended.
enum SessionEnd {
    /// The host was revoked: stop for good.
    Final(String),
    /// Try again after a pause. `attached` says the session had attached,
    /// so the pause starts short again.
    Retry { reason: String, attached: bool },
    /// Codewire does not recognise the host or its key: try again, rarely.
    Unrecognised(String),
    /// Ctrl-C or SIGTERM.
    Stopped,
}

/// Resolves when the agent is asked to stop: Ctrl-C at a terminal, or
/// SIGTERM from a service manager (`systemctl stop`, `launchctl bootout`).
struct StopSignal(tokio::sync::watch::Receiver<bool>);

impl StopSignal {
    fn listen() -> anyhow::Result<Self> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("listen for SIGTERM")?;
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            let _ = stop.send(true);
        });
        Ok(Self(stopped))
    }

    async fn requested(&mut self) {
        let _ = self.0.wait_for(|stop| *stop).await;
    }
}

/// An exclusive kernel lock on a file, held until dropped.
struct AgentLock {
    _file: fs::File,
}

impl AgentLock {
    /// The lock, or `None` while another process holds it.
    fn acquire(path: &Path) -> anyhow::Result<Option<Self>> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
            Err(error) => {
                Err(std::io::Error::from(error)).with_context(|| format!("lock {}", path.display()))
            }
        }
    }
}

pub(super) async fn run(_globals: &Globals) -> anyhow::Result<()> {
    let dir = config_dir()?;
    let enrollment = enrolled(&dir)?;
    // Two agents for one host would each supersede the other's session.
    let _lock = AgentLock::acquire(&dir.join(AGENT_LOCK_FILE))?
        .context("another `cw host run` for this host is already running on this computer")?;
    let platform = this_platform()?;
    let agent = HostAgentClient::new(config::host_client_config(
        &enrollment.server_url,
        &dir,
        enrollment.deployment_ca.as_ref(),
    )?)?;
    eprintln!(
        "Host agent for `{}` ({}) on {}. Ctrl-C stops it.",
        enrollment.name, enrollment.host_id, enrollment.server_url
    );
    let key_store = HostKeyStore::open(&dir, enrollment.key_store)
        .map_err(|error| key_store_error(enrollment.key_store, error))?;
    let mut stop = StopSignal::listen()?;
    let mut backoff = Duration::from_secs(1);
    loop {
        // The key is read for each session, so unlocking the keyring is
        // noticed without a restart.
        let key = match read_key(&key_store, &enrollment.key_entry).await {
            Ok(Some(key)) => Arc::new(key),
            Ok(None) => {
                write_agent_status(&dir, "stopped", "the host key is missing");
                anyhow::bail!(
                    "this computer's host key is missing from {}; run `cw host leave` and `cw host enroll` again",
                    key_store_text(&dir, enrollment.key_store)
                );
            }
            Err(error) => {
                let detail = match (enrollment.key_store, error) {
                    (KeyStore::Keyring, ProtectedStoreError::AccessDenied) => {
                        "waiting for a login to unlock the OS keyring that holds the host key"
                            .to_owned()
                    }
                    (KeyStore::Keyring, other) => format!("the OS keyring is unavailable: {other}"),
                    (KeyStore::File, other) => {
                        format!("the host key file could not be read: {other}")
                    }
                };
                write_agent_status(&dir, "waiting_for_key", &detail);
                eprintln!("{detail}; retrying in {}s", KEY_RETRY.as_secs());
                if wait_or_stop(KEY_RETRY, &mut stop).await {
                    break;
                }
                continue;
            }
        };
        write_agent_status(&dir, "attaching", "");
        match session(&agent, &enrollment, platform, &key, &dir, &mut stop).await {
            SessionEnd::Stopped => break,
            SessionEnd::Final(reason) => {
                write_agent_status(&dir, "revoked", &reason);
                eprintln!("{reason}");
                return Ok(());
            }
            SessionEnd::Unrecognised(reason) => {
                write_agent_status(&dir, "unrecognised", &reason);
                eprintln!(
                    "{reason}; trying again in {}s",
                    UNRECOGNISED_RETRY.as_secs()
                );
                if wait_or_stop(UNRECOGNISED_RETRY, &mut stop).await {
                    break;
                }
            }
            SessionEnd::Retry { reason, attached } => {
                // A session that attached starts the pause short again.
                if attached {
                    backoff = Duration::from_secs(1);
                }
                write_agent_status(&dir, "reconnecting", &reason);
                eprintln!("{reason}; reconnecting in {}s", backoff.as_secs());
                if wait_or_stop(backoff, &mut stop).await {
                    break;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
    write_agent_status(&dir, "stopped", "");
    Ok(())
}

/// Waits, or returns true when asked to stop.
async fn wait_or_stop(duration: Duration, stop: &mut StopSignal) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        () = stop.requested() => true,
    }
}

fn ended(error: ClientError) -> SessionEnd {
    match error.code() {
        ErrorCode::PermissionDenied => SessionEnd::Final(
            "this host is revoked; it cannot attach again (`cw host leave` to clean up)".into(),
        ),
        ErrorCode::Unauthenticated => SessionEnd::Unrecognised(
            "Codewire does not recognise this host or its key; if it was removed, run `cw host leave` and `cw host enroll` again"
                .into(),
        ),
        _ => SessionEnd::Retry {
            reason: format!("the session ended: {}", error.message()),
            attached: false,
        },
    }
}

async fn session(
    agent: &HostAgentClient,
    enrollment: &Enrollment,
    platform: HostPlatform,
    key: &Arc<SigningKey>,
    dir: &Path,
    stop: &mut StopSignal,
) -> SessionEnd {
    let sign = |statement: &[u8]| key.sign(statement).to_bytes().to_vec();
    let placement = operations::Placement::new(&enrollment.host_id);
    // The hello reports what runs here; a host that cannot read its own VMs
    // would report none, so it does not attach until it can.
    let inventory = match operations::inventory(&placement).await {
        Ok(inventory) => inventory,
        Err(error) => {
            return SessionEnd::Retry {
                reason: format!("read this computer's VMs: {error:#}"),
                attached: false,
            };
        }
    };
    let attached = tokio::select! {
        attached = agent.attach(&enrollment.host_id, platform, HOST_CAPABILITY_VERSION, inventory, sign) => attached,
        () = stop.requested() => return SessionEnd::Stopped,
    };
    let mut host = match attached {
        Ok(host) => host,
        Err(error) => return ended(error),
    };
    write_agent_status(dir, "attached", "");
    eprintln!("Attached: this host is online.");
    let ping_every = Duration::from_secs(u64::from(host.attached.ping_interval_seconds.max(1)));
    let mut pings = tokio::time::interval_at(tokio::time::Instant::now() + ping_every, ping_every);
    // Dropped with the session: what they were doing is in the supervisor's
    // journal, and the next session is sent them again.
    let mut running = Running::new(placement.clone());
    // Tunnels end with the session that asked for them, on both sides.
    let mut open_tunnels: FuturesUnordered<Pin<Box<dyn Future<Output = ()>>>> =
        FuturesUnordered::new();
    loop {
        tokio::select! {
            _ = pings.tick() => {
                if let Err(error) = host.ping().await {
                    return attached_end(ended(error));
                }
            }
            Some(()) = open_tunnels.next(), if !open_tunnels.is_empty() => {}
            Some(result) = running.next(), if !running.is_empty() => {
                if let Err(error) = host.send_result(result).await {
                    return attached_end(ended(error));
                }
            }
            event = host.next_event() => match event {
                Ok(HostEvent::Pong) => {}
                Ok(HostEvent::OpenTunnel(request)) => {
                    open_tunnels.push(Box::pin(super::tunnels::serve(
                        agent.clone(),
                        enrollment.host_id.clone(),
                        Arc::clone(key),
                        placement.clone(),
                        *request,
                    )));
                }
                Ok(HostEvent::Operation(operation)) => {
                    if let Some(refused) = running.start(*operation)
                        && let Err(error) = host.send_result(refused).await
                    {
                        return attached_end(ended(error));
                    }
                }
                Ok(HostEvent::Challenge(nonce)) => {
                    if let Err(error) = host.prove(&nonce, sign).await {
                        return attached_end(ended(error));
                    }
                }
                Ok(HostEvent::Revoked) => {
                    return SessionEnd::Final("this host was revoked; the agent stops".into());
                }
                Ok(HostEvent::Superseded) => {
                    return attached_end(SessionEnd::Retry {
                        reason: "another agent for this host attached".into(),
                        attached: false,
                    });
                }
                Ok(HostEvent::Ended) => {
                    return attached_end(SessionEnd::Retry {
                        reason: "the session ended".into(),
                        attached: false,
                    });
                }
                Err(error) => return attached_end(ended(error)),
            },
            () = stop.requested() => return SessionEnd::Stopped,
        }
    }
}

/// Marks a retry after an attached session, so the pause starts short again.
fn attached_end(end: SessionEnd) -> SessionEnd {
    match end {
        SessionEnd::Retry { reason, .. } => SessionEnd::Retry {
            reason,
            attached: true,
        },
        other => other,
    }
}

/// One operation running to its result, with its ID.
type RunningOperation = Pin<Box<dyn Future<Output = (String, HostOperationResult)>>>;

/// The operations one session is running, each to its outcome. They run
/// inside the session's own task, as `cw --local` runs its lifecycle
/// commands, and are dropped with it.
struct Running {
    placement: operations::Placement,
    operations: FuturesUnordered<RunningOperation>,
    ids: HashSet<String>,
}

impl Running {
    fn new(placement: operations::Placement) -> Self {
        Self {
            placement,
            operations: FuturesUnordered::new(),
            ids: HashSet::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Starts `operation`, or answers at once when it is malformed. The same
    /// operation sent again while it runs is not started twice: its one
    /// result answers both.
    fn start(&mut self, operation: HostOperation) -> Option<HostOperationResult> {
        let id = operation.operation_id.clone();
        if self.ids.contains(&id) {
            return None;
        }
        match operations::Operation::parse(operation, &self.placement) {
            Err(failure) => Some(Outcome::Failed(failure).into_result(&id)),
            Ok(parsed) => {
                self.ids.insert(id.clone());
                self.operations.push(Box::pin(async move {
                    let result = operations::run(&parsed).await.into_result(&id);
                    (id, result)
                }));
                None
            }
        }
    }

    /// The next result.
    async fn next(&mut self) -> Option<HostOperationResult> {
        let (id, result) = self.operations.next().await?;
        self.ids.remove(&id);
        Some(result)
    }
}
