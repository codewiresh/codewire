//! Dial the Kubernetes API through the deployment's near API servers (#2238).
//!
//! In-cluster, every connection goes to the `kubernetes` Service, which
//! spreads them over all API servers. Where one is far away, each call through
//! it pays that distance. A deployment can name its near API servers in order
//! ([`PREFERRED_ADDRS_ENV`]): each new connection then dials the first one
//! that the `default/kubernetes` EndpointSlice lists as ready and that answered
//! its last connect, and the Service as before when none does. Only where the
//! connection goes changes: the TLS server name is pinned to the Service's
//! host, so the connection verifies against the Service name every API
//! server's certificate carries, exactly as today. A connect that fails at TCP
//! or at TLS skips that server for a while.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use tokio::sync::Notify;
use tokio::time::Instant;
use tower::{BoxError, Service};

/// Ordered `ip:port` list of the near API servers. Unset or empty dials the
/// Service only.
pub const PREFERRED_ADDRS_ENV: &str = "CODEWIRE_KUBE_API_PREFERRED_ADDRS";

/// A powered-off server does not refuse; its dial waits this long.
const DIAL_TIMEOUT: Duration = Duration::from_secs(2);
/// After a failed dial, new connections skip that server this long.
const DOWN_FOR: Duration = Duration::from_secs(10);
/// How often the ready set is re-read, and at once after a failed dial. A get
/// rather than a watch: the grant stays one named get, and the API server
/// itself drops a dead peer from the slice only when its lease lapses, tens of
/// seconds later, so a watch would add little; a failed connect is the faster
/// signal.
const REFRESH_EVERY: Duration = Duration::from_secs(10);
/// The API servers' own address list, which only `default` holds.
const ENDPOINTS_NAMESPACE: &str = "default";
const ENDPOINTS_NAME: &str = "kubernetes";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreferredAddrsError {
    #[error("{PREFERRED_ADDRS_ENV}: {0:?} is not an IP address and port")]
    Invalid(String),
    #[error("{PREFERRED_ADDRS_ENV} names {0} twice")]
    Duplicate(SocketAddr),
}

/// The near API servers, in the order connections prefer them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreferredApiServers(Vec<SocketAddr>);

impl PreferredApiServers {
    pub fn parse(value: &str) -> Result<Self, PreferredAddrsError> {
        let mut addrs = Vec::new();
        for item in value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let addr: SocketAddr = item
                .parse()
                .map_err(|_| PreferredAddrsError::Invalid(item.to_owned()))?;
            if addrs.contains(&addr) {
                return Err(PreferredAddrsError::Duplicate(addr));
            }
            addrs.push(addr);
        }
        Ok(Self(addrs))
    }

    pub fn from_env() -> Result<Self, PreferredAddrsError> {
        Self::parse(&std::env::var(PREFERRED_ADDRS_ENV).unwrap_or_default())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Which preferred servers new connections may dial.
#[derive(Default)]
struct Health {
    /// The EndpointSlice's ready addresses; `None` until the first read, when
    /// every preferred server may be tried.
    ready: Option<HashSet<IpAddr>>,
    down_until: HashMap<SocketAddr, Instant>,
}

struct DialState {
    preferred: Vec<SocketAddr>,
    health: Mutex<Health>,
    refresh: Notify,
    /// [`DIAL_TIMEOUT`], except in tests on a loaded runner.
    connect_timeout: Duration,
}

impl DialState {
    fn candidates(&self, now: Instant) -> Vec<SocketAddr> {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        self.preferred
            .iter()
            .copied()
            .filter(|addr| {
                health
                    .ready
                    .as_ref()
                    .is_none_or(|ready| ready.contains(&addr.ip()))
                    && health
                        .down_until
                        .get(addr)
                        .is_none_or(|until| *until <= now)
            })
            .collect()
    }

    fn mark_down(&self, addr: SocketAddr, now: Instant) {
        self.health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .down_until
            .insert(addr, now + DOWN_FOR);
        self.refresh.notify_one();
    }

    fn set_ready(&self, ready: HashSet<IpAddr>) {
        self.health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ready = Some(ready);
    }
}

/// Which API server each new connection dials, and what it has learned of
/// each: see the module header. [`Self::wrap`] puts it around kube's TLS
/// connector.
#[derive(Clone)]
pub struct PreferredDialer {
    state: Arc<DialState>,
}

impl PreferredDialer {
    pub fn new(preferred: PreferredApiServers) -> Self {
        Self::with_timeout(preferred, DIAL_TIMEOUT)
    }

    /// This dialer with a connect bound other than [`DIAL_TIMEOUT`]: a test's
    /// hang guard, so a slow runner never reads as a down server.
    #[cfg(test)]
    pub(crate) fn with_connect_timeout(preferred: PreferredApiServers, timeout: Duration) -> Self {
        Self::with_timeout(preferred, timeout)
    }

    fn with_timeout(preferred: PreferredApiServers, connect_timeout: Duration) -> Self {
        Self {
            state: Arc::new(DialState {
                preferred: preferred.0,
                health: Mutex::default(),
                refresh: Notify::new(),
                connect_timeout,
            }),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.state.preferred.is_empty()
    }

    /// `connector`, choosing each connection's server. It must verify TLS
    /// against a fixed server name, not the address it is handed: kube's
    /// connector does once `tls_server_name` names the Service.
    pub fn wrap<C>(&self, connector: C) -> PreferredConnector<C> {
        PreferredConnector {
            connector,
            state: self.state.clone(),
        }
    }

    /// Keep the ready set current until every clone of this dialer is gone.
    /// `client` should be one built on this dialer.
    pub fn keep_ready(&self, client: kube::Client) -> impl Future<Output = ()> + Send + 'static {
        keep_ready(Arc::downgrade(&self.state), client)
    }
}

/// A connector that tries the preferred servers in turn, then the Service.
/// A preferred server counts as down after any failure of the whole connect,
/// TCP or TLS, so a server that accepts but cannot complete TLS is skipped
/// too.
#[derive(Clone)]
pub struct PreferredConnector<C> {
    connector: C,
    state: Arc<DialState>,
}

impl<C> Service<Uri> for PreferredConnector<C>
where
    C: Service<Uri> + Clone + Send + 'static,
    C::Response: Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Send + 'static,
{
    type Response = C::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<C::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, service: Uri) -> Self::Future {
        let connector = self.connector.clone();
        let state = self.state.clone();
        Box::pin(dial(connector, state, service))
    }
}

async fn dial<C>(
    mut connector: C,
    state: Arc<DialState>,
    service: Uri,
) -> Result<C::Response, BoxError>
where
    C: Service<Uri>,
    C::Error: Into<BoxError>,
{
    for addr in state.candidates(Instant::now()) {
        let target = at(&service, addr)?;
        let error = match tokio::time::timeout(state.connect_timeout, connector.call(target)).await
        {
            Ok(Ok(stream)) => {
                connected(&addr.to_string());
                return Ok(stream);
            }
            Ok(Err(error)) => error.into().to_string(),
            Err(_) => format!("not connected in {:?}", state.connect_timeout),
        };
        tracing::warn!(%addr, %error, "Kubernetes API server connect failed; trying the next");
        state.mark_down(addr, Instant::now());
    }
    let stream = connector.call(service).await.map_err(Into::into)?;
    connected("service");
    Ok(stream)
}

/// `service` with its authority replaced by `addr`: only where to connect
/// changes.
fn at(service: &Uri, addr: SocketAddr) -> Result<Uri, http::Error> {
    let mut parts = http::uri::Builder::new()
        .authority(addr.to_string())
        .path_and_query("/");
    if let Some(scheme) = service.scheme() {
        parts = parts.scheme(scheme.clone());
    }
    parts.build()
}

fn connected(backend: &str) {
    tracing::debug!(backend, "Kubernetes API connection opened");
    connections_metric().with_label_values(&[backend]).inc();
}

fn connections_metric() -> &'static IntCounterVec {
    static CONNECTIONS: OnceLock<IntCounterVec> = OnceLock::new();
    CONNECTIONS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_kube_api_connections_total",
                "New Kubernetes API connections by the server dialed: a preferred address, or the Service."
            ),
            &["backend"]
        )
        .expect("Kubernetes API connection metric registration must be unique")
    })
}

async fn keep_ready(state: Weak<DialState>, client: kube::Client) {
    let slices: kube::Api<EndpointSlice> = kube::Api::namespaced(client, ENDPOINTS_NAMESPACE);
    loop {
        let Some(state) = state.upgrade() else {
            return;
        };
        match slices.get(ENDPOINTS_NAME).await {
            Ok(slice) => state.set_ready(ready_addresses(&slice)),
            // The last ready set and the dial backoff still apply.
            Err(error) => tracing::warn!(%error, "Kubernetes API server list unavailable"),
        }
        tokio::select! {
            () = state.refresh.notified() => {}
            () = tokio::time::sleep(REFRESH_EVERY) => {}
        }
    }
}

/// Addresses of the endpoints not marked unready; a slice with no endpoints
/// has none.
fn ready_addresses(slice: &EndpointSlice) -> HashSet<IpAddr> {
    slice
        .endpoints
        .iter()
        .flatten()
        .filter(|endpoint| {
            endpoint
                .conditions
                .as_ref()
                .and_then(|conditions| conditions.ready)
                != Some(false)
        })
        .flat_map(|endpoint| &endpoint.addresses)
        .filter_map(|address| address.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests;
