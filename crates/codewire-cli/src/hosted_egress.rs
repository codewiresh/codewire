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
use codewire_daemon_proto::{CLUSTER_DNS_IP_ENV, EGRESS_TOKEN_PATH};
use codewire_network_session::guest::hosted::{
    EgressEvents, HostedEgressConfig, PodConnector, RoundEnd, VersionRefused, run,
};
use codewire_network_session::guest::{
    InterfaceProbes, PROBE_TIMEOUT, ProbeOutcome, SelfCheckProbes, self_check,
};
use codewire_network_session::hosted::{HOSTED_TUN_NAME, pod_interface, routing};
use codewire_network_session::{EgressTrust, SelfCheck, SelfCheckFailure};
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use uuid::Uuid;

mod derp_roots;
pub(crate) use derp_roots::derp_extra_roots;

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
    /// A broker-mode daemon's egress, from the platform addresses parsed at
    /// start (`codewire_daemon::BrokerPlatform`), the one parse of broker
    /// mode.
    pub fn from_broker(
        broker: &codewire_daemon::BrokerPlatform,
        pod_uid: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let pod_uid = pod_uid.parse().context("the bound Pod UID is not a UUID")?;
        let cluster_dns = lookup(CLUSTER_DNS_IP_ENV).and_then(|value| value.trim().parse().ok());
        Ok(Self {
            stream_addr: broker.stream(),
            binding_addr: broker.binding(),
            pod_uid,
            cluster_dns,
        })
    }

    /// For the hosted guest fixture, which has no daemon configuration: the
    /// same one parse of broker mode, over the process environment. None
    /// outside broker mode.
    pub fn from_env(pod_uid: &str) -> anyhow::Result<Option<Self>> {
        codewire_daemon::BrokerPlatform::from_env()?
            .map(|broker| Self::from_broker(&broker, pod_uid, |name| std::env::var(name).ok()))
            .transpose()
    }

    /// The binding's address and the Pod-interface dial.
    pub(crate) fn binding_route(&self) -> (SocketAddr, codewire_tls::PeerDial) {
        (self.binding_addr.into(), pod_dial())
    }
}

/// A broker-mode daemon's tailnet and Mesh platform path (#4000): the
/// coordinator, Mesh and the deployment's DERP relay at their configured
/// addresses, by the same Pod-interface dial as the binding. `refusal` is
/// where the tailnet reports a platform input it refuses, for GetHealth.
pub(crate) fn daemon_platform(
    broker: &codewire_daemon::BrokerPlatform,
    refusal: codewire_daemon::platform_refusal::PlatformRefusal,
    derp_extra_roots: codewire_tailnet::platform_dial::PlatformRoots,
) -> codewire_workspace_access::platform::DaemonPlatform {
    codewire_workspace_access::platform::DaemonPlatform {
        coordinator: broker.coordinator().into(),
        mesh: broker.mesh().map(SocketAddr::from),
        derp_host: broker.derp().host().to_owned(),
        derp: broker.derp().address().into(),
        derp_extra_roots,
        dial: pod_dial(),
        refusal,
    }
}

/// Every platform connection's dial: an IPv4 socket bound to the Pod's
/// interface. The same type as `codewire_tailnet::platform_dial::TcpDial`.
fn pod_dial() -> codewire_tls::PeerDial {
    Arc::new(|peer| {
        Box::pin(async move {
            match peer {
                SocketAddr::V4(peer) => pod_interface::connect_tcp(peer).await,
                SocketAddr::V6(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "the Pod interface carries IPv4 platform connections only",
                )),
            }
        })
    })
}

/// A platform connection can be bound to the Pod interface as this uid.
/// Called once at a broker-mode start, before any platform dial: a refused
/// bind fails the start, rather than leaving every platform connection to
/// fail later.
pub fn prove_pod_interface() -> anyhow::Result<()> {
    drop(pod_interface::tcp_socket()?);
    Ok(())
}

/// The kernel command line this daemon's kernel booted with.
const KERNEL_COMMAND_LINE: &str = "/proc/cmdline";
/// A public resolver the guest-carried self-check queries: it answers UDP
/// from anywhere, so a query that is not blocked is answered.
const PUBLIC_RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);

/// Whether this daemon runs guest-carried, in a standard Pod's guest
/// (#5602): its kernel booted with the parameter only that runtime's VMM
/// sets. It then keeps broker mode's literal platform addresses and runs no
/// egress loop; the guest's network session carries its dials and the host
/// end refuses everything else. A Kata broker Pod's egress path (its egress
/// identity or its egress TUN) alongside the parameter, or the parameter
/// without broker settings, refuses to start: there is no fallback.
pub(crate) fn guest_carried(broker: bool) -> anyhow::Result<bool> {
    let command_line =
        std::fs::read_to_string(KERNEL_COMMAND_LINE).context("read the kernel command line")?;
    guest_carried_from(
        &command_line,
        broker,
        std::path::Path::new(EGRESS_TOKEN_PATH).exists()
            || std::path::Path::new("/sys/class/net")
                .join(HOSTED_TUN_NAME)
                .exists(),
    )
}

fn guest_carried_from(
    command_line: &str,
    broker: bool,
    kata_egress_path: bool,
) -> anyhow::Result<bool> {
    if !codewire_vmm_guest_probe::hosted_control::guest_carried(command_line) {
        return Ok(false);
    }
    anyhow::ensure!(
        broker,
        "a guest-carried daemon needs broker mode's platform addresses; it never dials names"
    );
    anyhow::ensure!(
        !kata_egress_path,
        "a broker Pod's egress path is present in a guest-carried boot; refusing to start without its egress loop"
    );
    Ok(true)
}

/// The guest-carried daemon's start-time self-check (cw-security, #5602),
/// standing in for the broker loop's until the host end joins `cw-egress`:
/// from the workload's network, bound to the Pod interface, a TCP dial to a
/// public address and a DNS query to a public resolver and to the cluster's
/// must all fail. If any is answered the daemon refuses to serve.
pub(crate) async fn guest_carried_self_check(
    cluster_dns: Option<Ipv4Addr>,
) -> anyhow::Result<codewire_proto::codewire::internal::v1::GuestCarriedSelfCheck> {
    let dial_target = codewire_network_session::guest::self_check::DIRECT_DIAL_TARGET;
    let probes = |resolver: SocketAddrV4| InterfaceProbes {
        interface: codewire_network_session::hosted::HOSTED_POD_INTERFACE.to_owned(),
        dial_target: SocketAddr::V4(dial_target),
        resolver: SocketAddr::V4(resolver),
        timeout: PROBE_TIMEOUT,
    };
    // The cluster's resolver is one of the three, so without it the check
    // fails closed, as broker mode's does.
    let Some(dns) = cluster_dns else {
        tracing::error!(
            "{CLUSTER_DNS_IP_ENV} is missing or not an IPv4 address; the guest-carried self-check fails closed"
        );
        anyhow::bail!(
            "the guest-carried self-check has no cluster DNS to probe; refusing to serve"
        );
    };
    let cluster_resolver = SocketAddrV4::new(dns, 53);
    let checks = [
        CarriedProbe::Dial("direct_dial", dial_target, probes(PUBLIC_RESOLVER)),
        CarriedProbe::Dns("public_dns", PUBLIC_RESOLVER, probes(PUBLIC_RESOLVER)),
        CarriedProbe::Dns("cluster_dns", cluster_resolver, probes(cluster_resolver)),
    ];
    check_carried(&checks).await
}

/// One probe of the guest-carried self-check: its name, its target and how
/// it is made.
enum CarriedProbe<P> {
    Dial(&'static str, SocketAddrV4, P),
    Dns(&'static str, SocketAddrV4, P),
}

/// Runs every probe at once, each under its own timeout, and logs each one's
/// name, target and outcome in the order given, whether the check passes or
/// fails. Any probe answered, or one that could not be set up, fails the
/// check; a refusal, no route or a timeout is its pass, as in broker mode's
/// self-check. A pass returns the record the daemon sends with its host key.
async fn check_carried<P: SelfCheckProbes>(
    checks: &[CarriedProbe<P>],
) -> anyhow::Result<codewire_proto::codewire::internal::v1::GuestCarriedSelfCheck> {
    // Together the probes take about one timeout, not one each (#5602).
    let outcomes = futures::future::join_all(checks.iter().map(|check| async move {
        match check {
            CarriedProbe::Dial(name, target, probes) => (name, target, probes.direct_dial().await),
            CarriedProbe::Dns(name, target, probes) => (name, target, probes.dns_query().await),
        }
    }))
    .await;
    let mut report = Vec::with_capacity(checks.len());
    let mut probes = Vec::with_capacity(checks.len());
    let mut answered = false;
    for (name, target, outcome) in outcomes {
        answered |= outcome == ProbeOutcome::Reached;
        probes.push(codewire_proto::codewire::internal::v1::SelfCheckProbe {
            name: (*name).to_owned(),
            target: target.to_string(),
            refused: outcome == ProbeOutcome::Blocked,
            ..Default::default()
        });
        let outcome = match outcome {
            ProbeOutcome::Blocked => "refused",
            ProbeOutcome::Reached => "answered",
        };
        report.push(format!("{name} {target} {outcome}"));
    }
    let report = report.join("; ");
    if answered {
        tracing::error!(probes = %report, "guest-carried egress self-check failed; refusing to serve");
        anyhow::bail!(
            "the guest-carried egress self-check reached the network ({report}); refusing to serve"
        );
    }
    tracing::info!(probes = %report, "guest-carried egress self-check passed");
    Ok(
        codewire_proto::codewire::internal::v1::GuestCarriedSelfCheck {
            probes,
            ..Default::default()
        },
    )
}

/// Attach the TUN, start the egress loop, and return once the first
/// self-check has passed, with that session's egress trust, which the daemon
/// installs before it serves (#4001). The loop runs for as long as the daemon
/// does.
///
/// `refusal` is where the loop reports what redialling cannot heal, for
/// GetHealth: cw-egress refusing this daemon's session version.
pub(crate) async fn start(
    settings: EgressSettings,
    refusal: codewire_daemon::platform_refusal::PlatformRefusal,
) -> anyhow::Result<EgressTrust> {
    let (ready, ready_rx) = oneshot::channel();
    spawn(
        settings,
        LoggedEvents::new(Some(ready)).reporting_to(refusal),
    )?;
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
    /// Where a version refusal is shown in GetHealth; None for the fixture.
    refusal: Option<codewire_daemon::platform_refusal::PlatformRefusal>,
}

/// The health class of cw-egress refusing this daemon's session version.
const EGRESS_VERSION_UNSUPPORTED: &str = "egress_version_unsupported";

impl LoggedEvents {
    pub fn new(ready: Option<oneshot::Sender<EgressTrust>>) -> Self {
        Self {
            ready,
            trust: None,
            rounds: RoundLog::default(),
            refusal: None,
        }
    }

    /// Also show a version refusal in GetHealth, through `refusal`, for as
    /// long as it lasts.
    fn reporting_to(mut self, refusal: codewire_daemon::platform_refusal::PlatformRefusal) -> Self {
        self.refusal = Some(refusal);
        self
    }
}

impl EgressEvents for LoggedEvents {
    fn egress_trust(&mut self, trust: &EgressTrust) {
        tracing::info!(
            ca = matches!(trust, EgressTrust::Ca(_)),
            "egress stream authenticated"
        );
        self.trust = Some(trust.clone());
        // cw-egress admitted this stream, so it accepts the daemon's version.
        if let Some(refusal) = &self.refusal {
            refusal.clear();
        }
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
        if let (RoundEnd::VersionRefused(refused), Some(refusal)) = (end, &self.refusal) {
            refusal.refuse(EGRESS_VERSION_UNSUPPORTED, version_refusal(refused));
        }
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
            RoundEnd::VersionRefused(refused) => tracing::error!(
                class = EGRESS_VERSION_UNSUPPORTED,
                accepted_lowest = refused.lowest,
                accepted_highest = refused.highest,
                spoken = refused.spoken,
                repeated,
                "egress stream not opened: cw-egress does not accept this daemon's session version; only an update heals it"
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
        RoundEnd::VersionRefused(_) => "version_refused",
    }
}

/// A version refusal's words for GetHealth, naming both ranges.
fn version_refusal(refused: &VersionRefused) -> String {
    format!(
        "cw-egress accepts session versions {} to {}, and this daemon speaks {}",
        refused.lowest, refused.highest, refused.spoken
    )
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

    #[tokio::test]
    async fn a_guest_carried_check_without_a_cluster_dns_fails_closed() {
        let error = guest_carried_self_check(None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("no cluster DNS"), "{error}");
    }

    /// Probes that answer as told.
    struct FixedProbes(ProbeOutcome);

    impl SelfCheckProbes for FixedProbes {
        async fn direct_dial(&self) -> ProbeOutcome {
            self.0
        }
        async fn dns_query(&self) -> ProbeOutcome {
            self.0
        }
    }

    #[tokio::test]
    async fn the_guest_carried_check_passes_only_when_every_probe_is_refused() {
        use ProbeOutcome::{Blocked, Reached};
        let target = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 53);
        let all = |outcomes: [ProbeOutcome; 3]| {
            vec![
                CarriedProbe::Dial("direct_dial", target, FixedProbes(outcomes[0])),
                CarriedProbe::Dns("public_dns", target, FixedProbes(outcomes[1])),
                CarriedProbe::Dns("cluster_dns", target, FixedProbes(outcomes[2])),
            ]
        };
        let passed = check_carried(&all([Blocked, Blocked, Blocked]))
            .await
            .unwrap();
        assert_eq!(
            passed
                .probes
                .iter()
                .map(|probe| probe.name.as_str())
                .collect::<Vec<_>>(),
            ["direct_dial", "public_dns", "cluster_dns"]
        );
        assert!(
            passed
                .probes
                .iter()
                .all(|probe| probe.refused && probe.target == "192.0.2.9:53")
        );
        for answered in [
            [Reached, Blocked, Blocked],
            [Blocked, Reached, Blocked],
            [Blocked, Blocked, Reached],
        ] {
            let error = check_carried(&all(answered)).await.unwrap_err().to_string();
            assert!(error.contains("answered"), "{error}");
        }
    }

    /// Probes that each take a second to come back refused.
    struct SlowProbes;

    impl SelfCheckProbes for SlowProbes {
        async fn direct_dial(&self) -> ProbeOutcome {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            ProbeOutcome::Blocked
        }
        async fn dns_query(&self) -> ProbeOutcome {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            ProbeOutcome::Blocked
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_guest_carried_probes_run_together_and_report_in_order() {
        let target = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 53);
        let checks = [
            CarriedProbe::Dial("direct_dial", target, SlowProbes),
            CarriedProbe::Dns("public_dns", target, SlowProbes),
            CarriedProbe::Dns("cluster_dns", target, SlowProbes),
        ];
        let started = tokio::time::Instant::now();
        let passed = check_carried(&checks).await.unwrap();
        // Three one-second probes take one second together, not three.
        assert!(started.elapsed() < std::time::Duration::from_millis(1500));
        assert_eq!(
            passed
                .probes
                .iter()
                .map(|probe| probe.name.as_str())
                .collect::<Vec<_>>(),
            ["direct_dial", "public_dns", "cluster_dns"]
        );
    }

    #[test]
    fn only_the_runtimes_parameter_makes_a_daemon_guest_carried_and_never_a_kata_pod() {
        let carried = "console=ttyS0 rdinit=/init panic=-1 codewire.guest_carried=1";
        assert!(guest_carried_from(carried, true, false).unwrap());
        // No parameter, or one that merely contains its text: broker mode as now.
        for kata in [
            "",
            "console=hvc0 quiet",
            "codewire.guest_carried=10",
            "xcodewire.guest_carried=1",
        ] {
            assert!(!guest_carried_from(kata, true, false).unwrap(), "{kata}");
        }
        // A Kata broker Pod with the parameter forced on still refuses to
        // start without its egress loop, as does the parameter without broker
        // settings.
        assert!(guest_carried_from(carried, true, true).is_err());
        assert!(guest_carried_from(carried, false, false).is_err());
    }
    use std::collections::HashMap;

    use codewire_daemon_proto::{
        API_ADDR_ENV, DERP_ADDR_ENV, EGRESS_STREAM_ADDR_ENV, WORKSPACE_BINDING_ADDR_ENV,
    };

    use super::*;

    const POD: &str = "01234567-89ab-4def-8123-456789abcdef";

    /// A broker Pod's rendering, `values` added.
    fn settings(pod_uid: &str, values: &[(&str, &str)]) -> anyhow::Result<EgressSettings> {
        let values: HashMap<String, String> = [
            (EGRESS_STREAM_ADDR_ENV, "10.0.0.7:8089"),
            (WORKSPACE_BINDING_ADDR_ENV, "10.96.0.20:8087"),
            (API_ADDR_ENV, "10.96.0.30:443"),
            (DERP_ADDR_ENV, "derp.codewire.invalid=10.96.0.40:8443"),
        ]
        .iter()
        .chain(values)
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
        let broker = codewire_daemon::BrokerPlatform::from_lookup(&|key| {
            values.get(key).map(std::ffi::OsString::from)
        })?
        .expect("a rendered stream address is broker mode");
        EgressSettings::from_broker(&broker, pod_uid, |key| values.get(key).cloned())
    }

    #[test]
    fn the_broker_values_parse_and_a_bad_dns_address_fails_closed() {
        let parsed = settings(POD, &[(CLUSTER_DNS_IP_ENV, "10.96.0.10")]).unwrap();
        assert_eq!(parsed.stream_addr, "10.0.0.7:8089".parse().unwrap());
        assert_eq!(parsed.binding_addr, "10.96.0.20:8087".parse().unwrap());
        assert_eq!(parsed.pod_uid, POD.parse::<Uuid>().unwrap());
        assert_eq!(parsed.cluster_dns, Some(Ipv4Addr::new(10, 96, 0, 10)));
        for dns in [None, Some("kube-dns"), Some("10.96.0.10:53")] {
            let values: Vec<(&str, &str)> = dns
                .map(|dns| (CLUSTER_DNS_IP_ENV, dns))
                .into_iter()
                .collect();
            assert_eq!(settings(POD, &values).unwrap().cluster_dns, None, "{dns:?}");
        }
        assert!(
            settings("pod", &[]).is_err(),
            "a Pod UID that is not a UUID"
        );
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

    /// The refusal stays in health across the rounds between, whatever they
    /// end with, and clears only when cw-egress admits a stream.
    #[test]
    fn a_version_refusal_shows_in_health_until_a_stream_is_admitted() {
        let health = codewire_daemon::platform_refusal::PlatformRefusal::default();
        let mut events = LoggedEvents::new(None).reporting_to(health.egress());
        let refused = RoundEnd::VersionRefused(VersionRefused {
            lowest: 3,
            highest: 4,
            spoken: 2,
        });
        events.round_ended(&refused);
        assert_eq!(health.egress().class(), Some(EGRESS_VERSION_UNSUPPORTED));
        assert_eq!(
            version_refusal(&VersionRefused {
                lowest: 3,
                highest: 4,
                spoken: 2,
            }),
            "cw-egress accepts session versions 3 to 4, and this daemon speaks 2"
        );
        // The tailnet's own refusal is another source: neither clears the other.
        assert_eq!(health.class(), None);
        events.round_ended(&RoundEnd::Connect("dialling cw-egress failed".to_owned()));
        events.round_ended(&refused);
        assert_eq!(health.egress().class(), Some(EGRESS_VERSION_UNSUPPORTED));

        events.egress_trust(&EgressTrust::None);
        assert_eq!(health.egress().class(), None);
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
}
