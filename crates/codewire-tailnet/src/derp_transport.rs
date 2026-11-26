//! Reconnecting DERP transport adapter for [`crate::conn::Conn`].
//!
//! This wraps the low-level DERP client in the `Transport` channel shape used
//! by the WireGuard tunnel. Gateway and CLI callers can share the same
//! reconnect/backpressure behavior while deriving their DERP target from their
//! own runtime configuration.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::sync::{mpsc, watch};

use crate::conn::{Transport, WgDatagram};
use crate::derp::{self, BoxedStream, NodePrivate, ReceivedMessage};
use crate::dns::absolute_dns_name;
use crate::platform_dial::{PlatformRoots, TcpDial};
use crate::wg::StaticSecret;

const DERP_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const DERP_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const DERP_PENDING_DATAGRAM_LIMIT: usize = 1024;
const MAX_RESOLVED_DERP_ADDRESSES: usize = 16;

/// Holds a DERP transport's relay connection closed (#5529,
/// `docs/dev/IDLE-STOP.md`, "Suspend"): while held, the transport drops its
/// connection and dials none, and queues what the tunnel sends, up to its
/// pending limit, until released. A suspending daemon holds it, so the
/// relay's traffic can't wake a paused VM.
#[derive(Clone, Debug)]
pub struct DerpHold(Arc<watch::Sender<bool>>);

impl DerpHold {
    pub fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    pub fn hold(&self) {
        self.0.send_replace(true);
    }

    pub fn release(&self) {
        self.0.send_replace(false);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.0.subscribe()
    }
}

impl Default for DerpHold {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpTarget {
    pub host: String,
    pub port: u16,
    pub transport: DerpTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpTransport {
    Plain,
    Tls { skip_verify: bool },
}

/// What each connect and reconnect dials.
#[derive(Clone)]
enum Dial {
    /// `target.host`, looked up on every connect; `absolute` looks it up as
    /// an absolute DNS name.
    Name { absolute: bool },
    /// Exactly these addresses; nothing is looked up.
    Resolved(Arc<[SocketAddr]>),
    /// One platform address through the caller's dial, its certificate
    /// verified against the WebPKI and these roots; nothing is looked up.
    Platform(SocketAddr, TcpDial, Arc<PlatformRoots>),
}

impl Dial {
    /// The `host:port` a named connect looks up. TLS verification and the
    /// HTTP authority use `target.host` whatever this returns.
    fn named_address(target: &DerpTarget, absolute: bool) -> String {
        if absolute {
            format!("{}:{}", absolute_dns_name(&target.host), target.port)
        } else {
            format!("{}:{}", target.host, target.port)
        }
    }
}

pub async fn connect_derp_transport(
    target: &DerpTarget,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    connect_derp_transport_inner(
        target,
        Dial::Name { absolute: false },
        secret,
        &DerpHold::new(),
    )
    .await
}

/// Connect and reconnect like [`connect_derp_transport`], but look up
/// `target.host` as an absolute DNS name every time, so no resolver search
/// domain is ever tried (#2701, see [`crate::dns`]). TLS verification and the
/// HTTP authority keep `target.host`.
pub async fn connect_derp_transport_absolute(
    target: &DerpTarget,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    connect_derp_transport_absolute_held(target, secret, &DerpHold::new()).await
}

/// [`connect_derp_transport_absolute`], held closed while `hold` is.
pub async fn connect_derp_transport_absolute_held(
    target: &DerpTarget,
    secret: &StaticSecret,
    hold: &DerpHold,
) -> Result<Transport, derp::Error> {
    connect_derp_transport_inner(target, Dial::Name { absolute: true }, secret, hold).await
}

/// Connect and reconnect using only an already-resolved address set while
/// retaining [`DerpTarget::host`] for HTTP authority and TLS verification.
/// This prevents a filesystem-confined host transport from silently falling
/// back to libc/Tokio name resolution after startup.
pub async fn connect_derp_transport_resolved(
    target: &DerpTarget,
    addresses: Vec<SocketAddr>,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    let addresses = validate_resolved_addresses(target, addresses)?;
    connect_derp_transport_inner(target, Dial::Resolved(addresses), secret, &DerpHold::new()).await
}

/// Connect and reconnect to one platform address, every connection opened
/// by `dial`, while [`DerpTarget::host`] stays the TLS name and the HTTP
/// authority. The address replaces the map's host and port: a hosted egress
/// daemon reaches the deployment's relay in the cluster, by the Pod
/// interface, and resolves no names. Only a verified TLS target is dialled,
/// against the WebPKI roots and `extra_roots`, whatever the map says, so no
/// caller reaches its relay unverified.
pub async fn connect_derp_transport_platform(
    target: &DerpTarget,
    address: SocketAddr,
    dial: TcpDial,
    extra_roots: PlatformRoots,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    connect_derp_transport_platform_held(
        target,
        address,
        dial,
        extra_roots,
        secret,
        &DerpHold::new(),
    )
    .await
}

/// [`connect_derp_transport_platform`], held closed while `hold` is.
pub async fn connect_derp_transport_platform_held(
    target: &DerpTarget,
    address: SocketAddr,
    dial: TcpDial,
    extra_roots: PlatformRoots,
    secret: &StaticSecret,
    hold: &DerpHold,
) -> Result<Transport, derp::Error> {
    if target.host.trim().is_empty()
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
    {
        return Err(derp::Error::Protocol("invalid platform DERP target"));
    }
    if target.transport != (DerpTransport::Tls { skip_verify: false }) {
        return Err(derp::Error::Protocol(
            "a platform DERP target must verify its certificate",
        ));
    }
    let dial = Dial::Platform(address, dial, Arc::new(extra_roots));
    connect_derp_transport_inner(target, dial, secret, hold).await
}

async fn connect_derp_transport_inner(
    target: &DerpTarget,
    dial: Dial,
    secret: &StaticSecret,
    hold: &DerpHold,
) -> Result<Transport, derp::Error> {
    let secret_bytes = secret.to_bytes();
    let initial = connect_derp_client(target, &dial, secret_bytes).await?;
    let mut hold = hold.subscribe();

    let (to_transport, mut to_transport_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (from_transport_tx, from_transport) = mpsc::unbounded_channel::<WgDatagram>();
    let target = target.clone();

    tokio::spawn(async move {
        let mut pending = VecDeque::new();
        let mut next_client = Some(initial);
        let mut reconnect_delay = DERP_RECONNECT_INITIAL_DELAY;

        loop {
            if *hold.borrow() {
                // A connection made before the hold goes with it.
                next_client = None;
                if !wait_released(&mut hold, &mut to_transport_rx, &mut pending).await {
                    return;
                }
                tracing::info!(derp_host = %target.host, "rust tailnet DERP transport released");
            }
            let mut client = match next_client.take() {
                Some(client) => client,
                None => match reconnect(
                    &mut hold,
                    &mut to_transport_rx,
                    &mut pending,
                    &mut reconnect_delay,
                    &target,
                    || connect_derp_client(&target, &dial, secret_bytes),
                )
                .await
                {
                    Reconnect::Connected(client) => client,
                    // The loop's top waits for the release.
                    Reconnect::Held => continue,
                    Reconnect::Closed => return,
                },
            };

            tracing::info!(
                derp_host = %target.host,
                derp_port = target.port,
                "rust tailnet DERP transport connected"
            );
            reconnect_delay = DERP_RECONNECT_INITIAL_DELAY;

            loop {
                while let Some(dg) = pending.pop_front() {
                    if let Err(err) = client.send(&dg.peer, &dg.data).await {
                        queue_pending_derp_datagram_front(&mut pending, dg);
                        tracing::warn!(
                            error = %err,
                            "rust tailnet DERP transport send failed; reconnecting"
                        );
                        break;
                    }
                }
                if !pending.is_empty() {
                    break;
                }

                tokio::select! {
                    () = wait_held(&mut hold) => {
                        tracing::info!(derp_host = %target.host, "rust tailnet DERP transport held closed");
                        break;
                    }
                    maybe = to_transport_rx.recv() => {
                        let Some(dg) = maybe else { return; };
                        if let Err(err) = client.send(&dg.peer, &dg.data).await {
                            queue_pending_derp_datagram(&mut pending, dg);
                            tracing::warn!(
                                error = %err,
                                "rust tailnet DERP transport send failed; reconnecting"
                            );
                            break;
                        }
                    }
                    msg = client.recv() => {
                        match msg {
                            Ok(ReceivedMessage::Packet { source, data }) => {
                                if from_transport_tx.send(WgDatagram { peer: source, data }).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "rust tailnet DERP transport receive failed; reconnecting"
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(Transport {
        to_transport,
        from_transport,
        peer_updates: None,
        path_probe: None,
        local_endpoint_updates: None,
    })
}

/// How a reconnect ended.
enum Reconnect<C> {
    Connected(C),
    /// The hold was set: nothing more is dialled until it is released.
    Held,
    /// The tunnel is gone.
    Closed,
}

/// Dials until a connection opens, backing off between failures and
/// queueing what the tunnel sends meanwhile. The hold is checked before each
/// dial and raced against the dial and the backoff, so a held transport
/// dials no more, and a connection that opens as the hold is set is dropped
/// before anything is sent on it.
async fn reconnect<C, F, Fut>(
    hold: &mut watch::Receiver<bool>,
    to_transport_rx: &mut mpsc::UnboundedReceiver<WgDatagram>,
    pending: &mut VecDeque<WgDatagram>,
    delay: &mut Duration,
    target: &DerpTarget,
    mut dial: F,
) -> Reconnect<C>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<C, derp::Error>>,
{
    loop {
        if *hold.borrow() {
            return Reconnect::Held;
        }
        let dialed = tokio::select! {
            biased;
            () = wait_held(hold) => return Reconnect::Held,
            dialed = dial() => dialed,
        };
        let err = match dialed {
            Ok(_) if *hold.borrow() => return Reconnect::Held,
            Ok(client) => return Reconnect::Connected(client),
            Err(err) => err,
        };
        tracing::warn!(
            error = %err,
            delay_ms = delay.as_millis(),
            derp_host = %target.host,
            derp_port = target.port,
            "rust tailnet DERP transport reconnect failed"
        );
        let sleep = tokio::time::sleep(*delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                () = wait_held(hold) => return Reconnect::Held,
                maybe = to_transport_rx.recv() => {
                    let Some(dg) = maybe else { return Reconnect::Closed; };
                    queue_pending_derp_datagram(pending, dg);
                }
            }
        }
        *delay = (*delay * 2).min(DERP_RECONNECT_MAX_DELAY);
    }
}

/// Waits for the hold to be set. A hold whose every [`DerpHold`] is gone is
/// never set again, so this never returns.
async fn wait_held(hold: &mut watch::Receiver<bool>) {
    if hold.wait_for(|held| *held).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Waits for the hold to be released, queueing what the tunnel sends
/// meanwhile. Returns false when the tunnel is gone.
async fn wait_released(
    hold: &mut watch::Receiver<bool>,
    to_transport_rx: &mut mpsc::UnboundedReceiver<WgDatagram>,
    pending: &mut VecDeque<WgDatagram>,
) -> bool {
    loop {
        tokio::select! {
            // A hold whose every handle is gone is never set again.
            _ = hold.wait_for(|held| !*held) => return true,
            maybe = to_transport_rx.recv() => {
                let Some(dg) = maybe else { return false; };
                queue_pending_derp_datagram(pending, dg);
            }
        }
    }
}

async fn connect_derp_client(
    target: &DerpTarget,
    dial: &Dial,
    secret_bytes: [u8; 32],
) -> Result<derp::Client<BoxedStream>, derp::Error> {
    let private = NodePrivate::from_raw(secret_bytes);
    let candidates = match dial {
        Dial::Resolved(addresses) => addresses
            .iter()
            .copied()
            .map(ConnectAddress::Resolved)
            .collect::<Vec<_>>(),
        Dial::Name { absolute } => vec![ConnectAddress::Named(Dial::named_address(
            target, *absolute,
        ))],
        Dial::Platform(address, dial, roots) => {
            vec![ConnectAddress::Platform(
                *address,
                Arc::clone(dial),
                Arc::clone(roots),
            )]
        }
    };
    let mut last_error = None;
    for address in candidates {
        let mut rng = OsRng;
        let result = match (target.transport.clone(), address) {
            (DerpTransport::Plain, ConnectAddress::Named(address)) => {
                derp::connect_plain(&address, &target.host, private.clone(), &mut rng)
                    .await
                    .map(|client| client.boxed())
            }
            (DerpTransport::Plain, ConnectAddress::Resolved(address)) => {
                derp::connect_plain_resolved(address, &target.host, private.clone(), &mut rng)
                    .await
                    .map(|client| client.boxed())
            }
            // `connect_derp_transport_platform` admits only verified TLS.
            (DerpTransport::Plain, ConnectAddress::Platform(..)) => Err(derp::Error::Protocol(
                "a platform DERP target must verify its certificate",
            )),
            (DerpTransport::Tls { skip_verify }, address) => {
                let tls_config = if skip_verify {
                    derp::insecure_tls_config_for_tests()
                } else {
                    derp::webpki_tls_config()
                };
                match address {
                    ConnectAddress::Named(address) => derp::connect_tls(
                        &address,
                        &target.host,
                        tls_config,
                        private.clone(),
                        &mut rng,
                    )
                    .await
                    .map(|client| client.boxed()),
                    ConnectAddress::Resolved(address) => derp::connect_tls_resolved(
                        address,
                        &target.host,
                        tls_config,
                        private.clone(),
                        &mut rng,
                    )
                    .await
                    .map(|client| client.boxed()),
                    ConnectAddress::Platform(address, dial, roots) => {
                        match (derp::webpki_tls_config_with_roots(&roots), skip_verify) {
                            (Err(error), _) => Err(error),
                            (Ok(_), true) => Err(derp::Error::Protocol(
                                "a platform DERP target must verify its certificate",
                            )),
                            (Ok(config), false) => match dial(address).await {
                                Ok(tcp) => derp::connect_tls_stream(
                                    tcp,
                                    &target.host,
                                    config,
                                    private.clone(),
                                    &mut rng,
                                )
                                .await
                                .map(|client| client.boxed()),
                                Err(error) => Err(error.into()),
                            },
                        }
                    }
                }
            }
        };
        match result {
            Ok(client) => return Ok(client),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(derp::Error::Protocol("DERP resolved address set is empty")))
}

enum ConnectAddress {
    Named(String),
    Resolved(SocketAddr),
    Platform(SocketAddr, TcpDial, Arc<PlatformRoots>),
}

fn validate_resolved_addresses(
    target: &DerpTarget,
    addresses: Vec<SocketAddr>,
) -> Result<Arc<[SocketAddr]>, derp::Error> {
    if target.host.trim().is_empty()
        || target.port == 0
        || addresses.is_empty()
        || addresses.len() > MAX_RESOLVED_DERP_ADDRESSES
        || addresses.iter().any(|address| {
            address.port() != target.port
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
        })
    {
        return Err(derp::Error::Protocol("invalid resolved DERP target"));
    }
    let mut addresses = addresses;
    addresses.sort_unstable();
    addresses.dedup();
    Ok(Arc::from(addresses))
}

fn queue_pending_derp_datagram(pending: &mut VecDeque<WgDatagram>, dg: WgDatagram) {
    if pending.len() >= DERP_PENDING_DATAGRAM_LIMIT {
        pending.pop_front();
    }
    pending.push_back(dg);
}

fn queue_pending_derp_datagram_front(pending: &mut VecDeque<WgDatagram>, dg: WgDatagram) {
    if pending.len() >= DERP_PENDING_DATAGRAM_LIMIT {
        pending.pop_back();
    }
    pending.push_front(dg);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> DerpTarget {
        DerpTarget {
            host: "relay.example.com".to_owned(),
            port: 443,
            transport: DerpTransport::Tls { skip_verify: false },
        }
    }

    #[test]
    fn resolved_targets_are_exact_port_bound_and_deduplicated() {
        let addresses = validate_resolved_addresses(
            &target(),
            vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.10:443".parse().unwrap(),
                "192.0.2.10:443".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(
            validate_resolved_addresses(&target(), vec!["192.0.2.10:8443".parse().unwrap()])
                .is_err()
        );
        assert!(
            validate_resolved_addresses(&target(), vec!["0.0.0.0:443".parse().unwrap()]).is_err()
        );
        assert!(validate_resolved_addresses(&target(), Vec::new()).is_err());
    }

    fn datagram(byte: u8) -> WgDatagram {
        WgDatagram {
            peer: crate::derp::NodePublic::from_raw([byte; 32]),
            data: vec![byte],
        }
    }

    /// Every await in the hold's tests is bounded by this.
    const BOUND: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_hold_is_seen_by_the_connected_transport_and_released_only_by_release() {
        let hold = DerpHold::new();
        let mut held = hold.subscribe();
        let (to_transport, mut to_transport_rx) = mpsc::unbounded_channel();
        let mut pending = VecDeque::new();

        hold.hold();
        tokio::time::timeout(BOUND, wait_held(&mut held))
            .await
            .expect("a connected transport sees the hold");

        // Held, what the tunnel sends is queued, not dropped.
        to_transport.send(datagram(1)).unwrap();
        to_transport.send(datagram(2)).unwrap();
        {
            let waiting = wait_released(&mut held, &mut to_transport_rx, &mut pending);
            tokio::pin!(waiting);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                    .await
                    .is_err(),
                "the transport stays closed while held"
            );
            hold.release();
            assert!(tokio::time::timeout(BOUND, waiting).await.unwrap());
        }
        let queued: Vec<u8> = pending.iter().map(|dg| dg.data[0]).collect();
        assert_eq!(queued, [1, 2]);
    }

    #[tokio::test]
    async fn a_transport_nobody_can_hold_is_never_held_and_a_gone_tunnel_ends_the_wait() {
        let mut held = DerpHold::new().subscribe();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wait_held(&mut held))
                .await
                .is_err()
        );

        let hold = DerpHold::new();
        hold.hold();
        let mut held = hold.subscribe();
        let (to_transport, mut to_transport_rx) = mpsc::unbounded_channel::<WgDatagram>();
        drop(to_transport);
        let mut pending = VecDeque::new();
        assert!(!tokio::time::timeout(
            BOUND,
            wait_released(&mut held, &mut to_transport_rx, &mut pending)
        )
        .await
        .unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn a_hold_during_a_failing_reconnect_stops_the_dialing() {
        let (_to_transport, mut to_transport_rx) = mpsc::unbounded_channel();
        let mut pending = VecDeque::new();
        let target = target();
        let dials = std::cell::Cell::new(0_u32);
        let failing = || {
            dials.set(dials.get() + 1);
            std::future::ready(Err::<(), _>(derp::Error::Protocol("unreachable")))
        };

        // Unheld, a failing relay is dialled again after each backoff.
        let hold = DerpHold::new();
        let mut held = hold.subscribe();
        let mut delay = DERP_RECONNECT_INITIAL_DELAY;
        let unheld = reconnect(
            &mut held,
            &mut to_transport_rx,
            &mut pending,
            &mut delay,
            &target,
            failing,
        );
        assert!(tokio::time::timeout(Duration::from_millis(3_500), unheld)
            .await
            .is_err());
        assert_eq!(dials.get(), 3, "dialled at 0 s, 1 s and 3 s");

        // Held during the backoff: it ends at once, with no further dial.
        dials.set(0);
        let mut delay = DERP_RECONNECT_INITIAL_DELAY;
        let started = tokio::time::Instant::now();
        let (ended, ()) = tokio::join!(
            reconnect(
                &mut held,
                &mut to_transport_rx,
                &mut pending,
                &mut delay,
                &target,
                failing,
            ),
            async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                hold.hold();
            }
        );
        assert!(matches!(ended, Reconnect::Held));
        assert!(started.elapsed() < DERP_RECONNECT_INITIAL_DELAY);
        assert_eq!(dials.get(), 1);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(dials.get(), 1);

        // Held already: nothing is dialled at all, and a connection that
        // opens as the hold is set is dropped.
        dials.set(0);
        let ended = reconnect(
            &mut held,
            &mut to_transport_rx,
            &mut pending,
            &mut delay,
            &target,
            failing,
        )
        .await;
        assert!(matches!(ended, Reconnect::Held));
        assert_eq!(dials.get(), 0);
        let release_then_open = || {
            hold.hold();
            std::future::ready(Ok::<(), derp::Error>(()))
        };
        hold.release();
        let ended = reconnect(
            &mut held,
            &mut to_transport_rx,
            &mut pending,
            &mut delay,
            &target,
            release_then_open,
        )
        .await;
        assert!(matches!(ended, Reconnect::Held));
    }

    #[test]
    fn an_absolute_dial_looks_up_the_absolute_name_and_keeps_the_target_host() {
        let target = DerpTarget {
            host: "ingress-nginx-controller.ingress-nginx.svc.cluster.local".to_owned(),
            port: 443,
            transport: DerpTransport::Tls { skip_verify: false },
        };
        assert_eq!(
            Dial::named_address(&target, true),
            "ingress-nginx-controller.ingress-nginx.svc.cluster.local.:443"
        );
        assert_eq!(
            Dial::named_address(&target, false),
            "ingress-nginx-controller.ingress-nginx.svc.cluster.local:443"
        );
    }
}
