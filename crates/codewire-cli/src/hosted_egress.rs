//! A hosted sandbox's egress (#4000 P4, item 2): with the Pod template's
//! egress values present, the bound daemon attaches the TUN, runs the egress
//! loop (`codewire_network_session::guest::hosted`) and serves nothing until
//! the first self-check has passed. Without them, as before hosted egress, it
//! does nothing.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow};
use codewire_daemon_proto::{
    CLUSTER_DNS_IP_ENV, EGRESS_STREAM_ADDR_ENV, EGRESS_TOKEN_PATH, WORKSPACE_BINDING_ADDR_ENV,
};
use codewire_network_session::guest::hosted::{
    EgressEvents, HostedEgressConfig, PodConnector, RoundEnd, run,
};
use codewire_network_session::guest::{InterfaceProbes, PROBE_TIMEOUT, self_check};
use codewire_network_session::hosted::{HOSTED_TUN_NAME, pod_interface, routing};
use codewire_network_session::{EgressTrust, SelfCheck, SelfCheckFailure};
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use uuid::Uuid;

/// What the Pod template gives a broker-mode daemon: the Pod's egress and the
/// address it reaches the binding at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressSettings {
    pub stream_addr: SocketAddrV4,
    pub binding_addr: SocketAddrV4,
    /// The Pod the binding is for, which keys the stream.
    pub pod_uid: Uuid,
    /// The self-check's DNS target. None when missing or unparsable, which
    /// fails the check closed.
    pub cluster_dns: Option<Ipv4Addr>,
}

impl EgressSettings {
    /// None when the template rendered no egress stream: the Pod is not in
    /// broker mode. In broker mode a missing or malformed address, or a Pod
    /// UID that does not parse, refuses to start and names its variable:
    /// nothing falls back to a looked-up name over the TUN.
    pub fn from_lookup(
        pod_uid: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(stream_addr) = lookup(EGRESS_STREAM_ADDR_ENV) else {
            return Ok(None);
        };
        let stream_addr = ipv4_address(EGRESS_STREAM_ADDR_ENV, &stream_addr)?;
        let binding_addr = lookup(WORKSPACE_BINDING_ADDR_ENV).with_context(|| {
            format!("{WORKSPACE_BINDING_ADDR_ENV} is required with {EGRESS_STREAM_ADDR_ENV}")
        })?;
        let binding_addr = ipv4_address(WORKSPACE_BINDING_ADDR_ENV, &binding_addr)?;
        let pod_uid = pod_uid.parse().context("the bound Pod UID is not a UUID")?;
        let cluster_dns = lookup(CLUSTER_DNS_IP_ENV).and_then(|value| value.trim().parse().ok());
        Ok(Some(Self {
            stream_addr,
            binding_addr,
            pod_uid,
            cluster_dns,
        }))
    }

    /// The binding's address and the Pod-interface dial, after proving a
    /// platform connection can be bound to the Pod interface.
    pub(crate) fn binding_route(&self) -> anyhow::Result<(SocketAddr, codewire_tls::PeerDial)> {
        prove_pod_interface()?;
        let dial: codewire_tls::PeerDial = Arc::new(|peer| {
            Box::pin(async move {
                match peer {
                    SocketAddr::V4(peer) => pod_interface::connect_tcp(peer).await,
                    SocketAddr::V6(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "the Pod interface carries IPv4 platform connections only",
                    )),
                }
            })
        });
        Ok((self.binding_addr.into(), dial))
    }
}

fn ipv4_address(name: &str, value: &str) -> anyhow::Result<SocketAddrV4> {
    value
        .trim()
        .parse()
        .with_context(|| format!("{name} is not an IPv4 address and port"))
}

/// A platform connection can be bound to the Pod interface as this uid. A
/// refused bind fails the daemon closed at start, rather than leaving every
/// platform connection to fail later.
fn prove_pod_interface() -> anyhow::Result<()> {
    drop(pod_interface::tcp_socket()?);
    Ok(())
}

/// Attach the TUN, start the egress loop, and return once the first
/// self-check has passed, with that session's egress trust, which the daemon
/// installs before it serves (#4001). The loop runs for as long as the daemon
/// does.
pub(crate) async fn start(settings: EgressSettings) -> anyhow::Result<EgressTrust> {
    let (ready, ready_rx) = oneshot::channel();
    spawn(settings, LoggedEvents::new(Some(ready)))?;
    tracing::info!("hosted daemon waiting for its first egress self-check");
    ready_rx
        .await
        .map_err(|_| anyhow!("the egress loop ended before its first self-check passed"))
}

/// Attach the TUN and run the egress loop in the background, reporting to
/// `events`. [`start`] is the daemon's use; the hosted guest fixture
/// (`codewire-cli-bin`'s `hosted_guest` example) brings its own events.
pub fn spawn<E>(settings: EgressSettings, mut events: E) -> anyhow::Result<()>
where
    E: EgressEvents + Send + 'static,
{
    prove_pod_interface()?;
    let tun = codewire_vmm_guest_probe::tun::open(HOSTED_TUN_NAME)
        .map_err(|error| anyhow!("attach the egress TUN {HOSTED_TUN_NAME}: {error}"))?;
    #[allow(deprecated)]
    // RUSTSEC-2026-0386: an owned `OwnedFd` is outside `AsyncFd::new`'s unsound case, as for the guest's TUN.
    let tun: Arc<AsyncFd<OwnedFd>> =
        Arc::new(AsyncFd::new(tun).context("register the egress TUN")?);
    let config = HostedEgressConfig::HOSTED;
    if settings.cluster_dns.is_none() {
        tracing::error!(
            "{CLUSTER_DNS_IP_ENV} is missing or not an IPv4 address; the egress self-check fails closed"
        );
    }
    let connector = PodConnector::new(
        settings.stream_addr,
        EGRESS_TOKEN_PATH.into(),
        settings.pod_uid,
        config.self_check_bound + PROBE_TIMEOUT,
    );
    let dns = settings.cluster_dns;
    tokio::spawn(async move {
        let routing_log = Mutex::new(RoundLog::default());
        run(
            &config,
            &connector,
            || after_routing(routing::verify, &routing_log, pod_probes(dns)),
            tun,
            &mut events,
        )
        .await
    });
    Ok(())
}

/// The Pod's probes, or a DNS failure when there is no resolver to probe.
async fn pod_probes(cluster_dns: Option<Ipv4Addr>) -> SelfCheck {
    match cluster_dns {
        Some(dns) => self_check(&InterfaceProbes::for_pod(dns)).await,
        None => SelfCheck::Failed(SelfCheckFailure::Dns),
    }
}

/// One self-check: the routing read back first, and `probes` only when it is
/// as the init container made it. A wrong route can let a probe connect,
/// which would report the probe instead of the cause.
///
/// `verify` blocks on netlink under its own 2 s bound, so it runs on a
/// blocking thread, and with the probes' 2 s the check stays inside its 8 s.
/// The routing error's text is logged here, before the reason is sent: the
/// reason on the wire is one fixed value.
async fn after_routing<E>(
    verify: impl FnOnce() -> Result<(), E> + Send + 'static,
    log: &Mutex<RoundLog<String>>,
    probes: impl Future<Output = SelfCheck>,
) -> SelfCheck
where
    E: std::error::Error + Send + Sync + 'static,
{
    let error = match tokio::task::spawn_blocking(verify).await {
        Ok(Ok(())) => return probes.await,
        Ok(Err(error)) => format!("{:#}", anyhow::Error::new(error)),
        // The readback panicked, so nothing says the routing is right.
        Err(error) => format!("{:#}", anyhow::Error::new(error)),
    };
    let admitted = log
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(error.clone(), Instant::now());
    if let Some(repeated) = admitted {
        tracing::error!(
            %error,
            repeated,
            "the Sandbox's routing is not as its init container made it"
        );
    }
    SelfCheck::Failed(SelfCheckFailure::Routing)
}

/// Logs each round, and sends the first passed session's egress trust.
pub struct LoggedEvents {
    ready: Option<oneshot::Sender<EgressTrust>>,
    /// The current session's trust, reported before its self-check.
    trust: Option<EgressTrust>,
    rounds: RoundLog,
}

impl LoggedEvents {
    pub fn new(ready: Option<oneshot::Sender<EgressTrust>>) -> Self {
        Self {
            ready,
            trust: None,
            rounds: RoundLog::default(),
        }
    }
}

impl EgressEvents for LoggedEvents {
    fn egress_trust(&mut self, trust: &EgressTrust) {
        tracing::info!(
            ca = matches!(trust, EgressTrust::Ca(_)),
            "egress stream authenticated"
        );
        self.trust = Some(trust.clone());
    }

    fn ready(&mut self) {
        tracing::info!("egress self-check passed; the daemon serves");
        if let (Some(ready), Some(trust)) = (self.ready.take(), self.trust.take()) {
            // A closed receiver means `start` stopped waiting, as the
            // daemon exits; nobody is left to tell.
            let _ = ready.send(trust);
        }
    }

    fn round_ended(&mut self, end: &RoundEnd) {
        let reason = round_reason(end);
        let Some(repeated) = self.rounds.admit(reason, Instant::now()) else {
            return;
        };
        match end {
            // The reason is in the log before readiness is held back (#4000).
            RoundEnd::SelfCheckFailed(_) => tracing::error!(
                reason,
                repeated,
                "egress self-check failed; the daemon does not serve"
            ),
            RoundEnd::SelfCheckTimedOut => tracing::error!(
                repeated,
                "egress self-check did not finish within its bound"
            ),
            RoundEnd::Connect(error) => {
                tracing::warn!(%error, repeated, "egress stream not opened")
            }
            RoundEnd::SendSelfCheck => {
                tracing::warn!(repeated, "egress self-check result not sent")
            }
            RoundEnd::TrustChanged => tracing::warn!(
                repeated,
                "egress stream dropped: its host's egress trust differs from the one installed"
            ),
            RoundEnd::Bridge(result) => {
                tracing::warn!(?result, repeated, "egress stream ended; redialling")
            }
        }
    }
}

/// A round's end, as one stable word for the log and its rate limit.
fn round_reason(end: &RoundEnd) -> &'static str {
    match end {
        RoundEnd::SelfCheckFailed(SelfCheckFailure::DirectDial) => "direct_dial",
        RoundEnd::SelfCheckFailed(SelfCheckFailure::Dns) => "dns",
        RoundEnd::SelfCheckFailed(SelfCheckFailure::Routing) => "routing",
        RoundEnd::SelfCheckTimedOut => "self_check_timed_out",
        RoundEnd::Connect(_) => "connect",
        RoundEnd::SendSelfCheck => "send_self_check",
        RoundEnd::Bridge(_) => "bridge",
        RoundEnd::TrustChanged => "trust_changed",
    }
}

/// How often a round's end is logged: a sandbox that stays unready retries
/// every few seconds for as long as it lasts.
const ROUND_LOG_EVERY: Duration = Duration::from_secs(60);

/// Logs a round's end when its reason changes, and otherwise once per
/// [`ROUND_LOG_EVERY`], counting the rounds it left out.
struct RoundLog<R = &'static str> {
    last: Option<(R, Instant)>,
    left_out: u64,
}

impl<R> Default for RoundLog<R> {
    fn default() -> Self {
        Self {
            last: None,
            left_out: 0,
        }
    }
}

impl<R: PartialEq> RoundLog<R> {
    /// `Some(rounds left out since the last line)` when this round is logged.
    fn admit(&mut self, reason: R, now: Instant) -> Option<u64> {
        let due = match &self.last {
            Some((last, at)) => *last != reason || now.duration_since(*at) >= ROUND_LOG_EVERY,
            None => true,
        };
        if !due {
            self.left_out += 1;
            return None;
        }
        self.last = Some((reason, now));
        Some(std::mem::take(&mut self.left_out))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const POD: &str = "01234567-89ab-4def-8123-456789abcdef";

    fn settings(pod_uid: &str, values: &[(&str, &str)]) -> anyhow::Result<Option<EgressSettings>> {
        let values: HashMap<String, String> = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        EgressSettings::from_lookup(pod_uid, |key| values.get(key).cloned())
    }

    const STREAM: (&str, &str) = (EGRESS_STREAM_ADDR_ENV, "10.0.0.7:8089");
    const BINDING: (&str, &str) = (WORKSPACE_BINDING_ADDR_ENV, "10.96.0.20:8087");

    #[test]
    fn no_stream_address_is_not_broker_mode() {
        assert_eq!(settings(POD, &[]).unwrap(), None);
        // Without a stream, a binding address alone changes nothing.
        assert_eq!(settings(POD, &[BINDING]).unwrap(), None);
    }

    #[test]
    fn the_template_values_parse_and_a_bad_dns_address_fails_closed() {
        let parsed = settings(POD, &[STREAM, BINDING, (CLUSTER_DNS_IP_ENV, "10.96.0.10")])
            .unwrap()
            .unwrap();
        assert_eq!(parsed.stream_addr, "10.0.0.7:8089".parse().unwrap());
        assert_eq!(parsed.binding_addr, "10.96.0.20:8087".parse().unwrap());
        assert_eq!(parsed.pod_uid, POD.parse::<Uuid>().unwrap());
        assert_eq!(parsed.cluster_dns, Some(Ipv4Addr::new(10, 96, 0, 10)));
        for dns in [None, Some("kube-dns"), Some("10.96.0.10:53")] {
            let mut values = vec![STREAM, BINDING];
            if let Some(dns) = dns {
                values.push((CLUSTER_DNS_IP_ENV, dns));
            }
            assert_eq!(
                settings(POD, &values).unwrap().unwrap().cluster_dns,
                None,
                "{dns:?}"
            );
        }
    }

    #[tokio::test]
    async fn no_resolver_to_probe_is_a_dns_failure() {
        assert_eq!(
            pod_probes(None).await,
            SelfCheck::Failed(SelfCheckFailure::Dns)
        );
    }

    #[derive(Debug, thiserror::Error)]
    #[error("the routing read back without the main default")]
    struct Drifted;

    /// The design's order (#4000): a routing that differs fails the check as
    /// `routing` and no probe runs, so a probe that such a route lets connect
    /// is never reported in the cause's place.
    #[tokio::test]
    async fn a_routing_that_differs_fails_the_check_before_any_probe_runs() {
        let log = Mutex::new(RoundLog::default());
        let probed = std::sync::atomic::AtomicBool::new(false);
        let probes = async {
            probed.store(true, std::sync::atomic::Ordering::SeqCst);
            SelfCheck::Failed(SelfCheckFailure::DirectDial)
        };
        assert_eq!(
            after_routing(|| Err(Drifted), &log, probes).await,
            SelfCheck::Failed(SelfCheckFailure::Routing)
        );
        assert!(!probed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_readback_that_panics_fails_the_check_as_routing() {
        let log = Mutex::new(RoundLog::default());
        let verify = || -> Result<(), Drifted> { panic!("the readback panicked") };
        assert_eq!(
            after_routing(verify, &log, async { SelfCheck::Passed }).await,
            SelfCheck::Failed(SelfCheckFailure::Routing)
        );
    }

    #[tokio::test]
    async fn a_routing_that_reads_back_gives_the_probes_result() {
        let log = Mutex::new(RoundLog::default());
        for result in [
            SelfCheck::Passed,
            SelfCheck::Failed(SelfCheckFailure::Dns),
            SelfCheck::Failed(SelfCheckFailure::DirectDial),
        ] {
            assert_eq!(
                after_routing(|| Ok::<(), Drifted>(()), &log, async { result }).await,
                result
            );
        }
    }

    #[test]
    fn the_first_ready_session_hands_over_its_egress_trust() {
        let (ready, mut ready_rx) = oneshot::channel();
        let mut events = LoggedEvents::new(Some(ready));
        events.egress_trust(&EgressTrust::Ca(vec![0x30; 4]));
        events.round_ended(&RoundEnd::SelfCheckFailed(SelfCheckFailure::Dns));
        assert!(ready_rx.try_recv().is_err(), "a failed round is not ready");
        events.egress_trust(&EgressTrust::None);
        events.ready();
        assert_eq!(ready_rx.try_recv().unwrap(), EgressTrust::None);
        // A later session reports nothing more.
        events.egress_trust(&EgressTrust::Ca(vec![0x30; 4]));
        events.ready();
    }

    #[test]
    fn a_round_is_logged_when_its_reason_changes_and_once_a_minute_otherwise() {
        let mut log = RoundLog::default();
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        assert_eq!(log.admit("connect", at(0)), Some(0));
        assert_eq!(log.admit("connect", at(5)), None);
        assert_eq!(log.admit("connect", at(10)), None);
        // A new reason is logged at once.
        assert_eq!(log.admit("dns", at(15)), Some(2));
        assert_eq!(log.admit("dns", at(20)), None);
        // The same reason again after a minute.
        assert_eq!(log.admit("dns", at(75)), Some(1));
        assert_eq!(log.admit("dns", at(80)), None);
    }

    #[test]
    fn in_broker_mode_a_missing_blank_or_malformed_value_refuses_to_start() {
        let refused = |values: &[(&str, &str)], pod_uid: &str, names: &str| {
            let error = settings(pod_uid, values).unwrap_err();
            assert!(format!("{error:#}").contains(names), "{error:#}");
        };
        // A blank stream address is malformed, not "egress off".
        refused(
            &[(EGRESS_STREAM_ADDR_ENV, " "), BINDING],
            POD,
            EGRESS_STREAM_ADDR_ENV,
        );
        refused(
            &[(EGRESS_STREAM_ADDR_ENV, "codewire-egress:8089"), BINDING],
            POD,
            EGRESS_STREAM_ADDR_ENV,
        );
        // The Pod interface carries IPv4 only.
        refused(
            &[(EGRESS_STREAM_ADDR_ENV, "[fd00::7]:8089"), BINDING],
            POD,
            EGRESS_STREAM_ADDR_ENV,
        );
        // The binding is never looked up by name over the TUN.
        refused(&[STREAM], POD, WORKSPACE_BINDING_ADDR_ENV);
        refused(
            &[STREAM, (WORKSPACE_BINDING_ADDR_ENV, "")],
            POD,
            WORKSPACE_BINDING_ADDR_ENV,
        );
        refused(
            &[
                STREAM,
                (
                    WORKSPACE_BINDING_ADDR_ENV,
                    "codewire-orchestration-workspace-binding:8087",
                ),
            ],
            POD,
            WORKSPACE_BINDING_ADDR_ENV,
        );
        refused(&[STREAM, BINDING], "pod", "Pod UID");
    }
}
