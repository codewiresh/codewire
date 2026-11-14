//! The router's listeners and their accept loops.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use codewire_egress_front_door::{CaError, CertifiedKey, FrontDoor, FrontDoorConfig, LeafSource};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::Routes;
use super::ca::LocalCa;
use super::proxy::Proxy;

/// Live connections across every environment. A browser opens several per
/// host over HTTP/1.1, and a dev server's tabs keep WebSockets open.
const MAX_CONNECTIONS: usize = 256;
/// A dev server's reload socket can stay quiet for a long time.
const WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// How long an accept loop rests after a failed accept, such as running out
/// of file descriptors, before it tries again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Why the router could not listen on its port.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BindError {
    /// This user may not listen on the port: on Linux, a port below
    /// `net.ipv4.ip_unprivileged_port_start`.
    #[error("not permitted to listen on 127.0.0.1:{0}")]
    NotPermitted(u16),
    /// Another program listens on it.
    #[error("another program listens on 127.0.0.1:{0}")]
    InUse(u16),
    #[error("listening on 127.0.0.1:{0}: {1}")]
    Other(u16, io::Error),
}

/// The leaves the router serves: the local CA's, for the names a running
/// environment's labelled port has, and no others.
struct RoutedLeaves<R> {
    ca: Arc<LocalCa>,
    routes: Arc<R>,
}

impl<R: Routes> LeafSource for RoutedLeaves<R> {
    fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), CaError> {
        let host = host.to_ascii_lowercase();
        if self.routes.route(&host).is_none() {
            return Err(CaError::UnboundHost);
        }
        self.ca.leaf(&host)
    }
}

/// A running router. Dropping it closes its listeners and every connection.
pub(crate) struct Router {
    port: u16,
    tasks: Vec<JoinHandle<()>>,
    close: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Router")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Router {
    /// Listen on `127.0.0.1:port`, and on `[::1]:port` where that is free, and
    /// serve every running environment's labelled ports. Port 0 picks one.
    pub(crate) fn start<R: Routes>(
        ca: Arc<LocalCa>,
        routes: Arc<R>,
        port: u16,
    ) -> Result<Self, BindError> {
        let ipv4 = bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            .map_err(|error| bind_error(port, error))?;
        let port = ipv4
            .local_addr()
            .map_err(|error| BindError::Other(port, error))?
            .port();
        let mut listeners = vec![ipv4];
        // Browsers try both loopbacks for a `.localhost` name; [::1] is a
        // convenience, so a host without it, or with it taken, still serves.
        if let Ok(ipv6) = bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)) {
            listeners.push(ipv6);
        }
        let door = Arc::new(FrontDoor::new(
            RoutedLeaves {
                ca,
                routes: routes.clone(),
            },
            Proxy::new(routes, port),
            FrontDoorConfig {
                max_connections: MAX_CONNECTIONS,
                websocket_idle_timeout: WEBSOCKET_IDLE_TIMEOUT,
                port,
            },
        ));
        let tasks = listeners
            .into_iter()
            .map(|listener| tokio::spawn(accept_loop(listener, door.clone())))
            .collect();
        Ok(Self {
            port,
            tasks,
            close: Box::new(move || door.close()),
        })
    }

    /// The port it listens on.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        (self.close)();
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let listener = std::net::TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

fn bind_error(port: u16, error: io::Error) -> BindError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => BindError::NotPermitted(port),
        io::ErrorKind::AddrInUse => BindError::InUse(port),
        _ => BindError::Other(port, error),
    }
}

async fn accept_loop<R: Routes>(
    listener: TcpListener,
    door: Arc<FrontDoor<Proxy<R>, RoutedLeaves<R>>>,
) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
        };
        let door = door.clone();
        // A connection that names no served host is closed; the front door
        // logs why, without the name.
        drop(tokio::spawn(async move {
            let _ = door.accept_named(stream).await;
        }));
    }
}
