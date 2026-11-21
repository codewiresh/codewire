//! Registering with the kubelet, and serving it until it forgets this plugin.

use std::convert::Infallible;
use std::io;
use std::num::NonZeroU16;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::{Endpoint, Server};

use crate::plugin::{Health, KvmPlugin};
use crate::v1beta1::device_plugin_server::DevicePluginServer;
use crate::v1beta1::registration_client::RegistrationClient;
use crate::v1beta1::{DevicePluginOptions, RegisterRequest};
use crate::{KUBELET_SOCKET, PLUGIN_SOCKET, RESOURCE_NAME};

/// The kubelet's device plugin API version this plugin speaks.
const API_VERSION: &str = "v1beta1";

/// A kubelet that starts removes every plugin socket, then serves its own.
/// Retrying the connection for a while keeps the node from going without the
/// resource for this container's restart back-off.
const CONNECT_ATTEMPTS: u32 = 30;

/// What the plugin hands out, and where it meets the kubelet.
pub struct Config {
    /// The kubelet's device plugin directory: its socket and this plugin's.
    pub plugin_dir: PathBuf,
    /// The node's device, given to each container at `/dev/kvm`.
    pub node_device: String,
    /// How many Pods on the node may hold the device at once.
    pub devices: NonZeroU16,
    /// How often the device's health and this plugin's socket are checked,
    /// and how long to wait between connection attempts to the kubelet.
    pub poll: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot remove the stale plugin socket {path}: {source}")]
    RemoveStale { path: PathBuf, source: io::Error },
    #[error("cannot listen on {path}: {source}")]
    Listen { path: PathBuf, source: io::Error },
    #[error("cannot reach the kubelet at {path}: {source}")]
    Connect {
        path: PathBuf,
        source: tonic::transport::Error,
    },
    #[error("the kubelet refused the registration: {0}")]
    Refused(Box<tonic::Status>),
    #[error("the plugin's server stopped: {0}")]
    Serve(tonic::transport::Error),
    #[error("the plugin's server stopped without an error")]
    ServerEnded,
    #[error("the plugin's server task failed: {0}")]
    Task(tokio::task::JoinError),
}

/// Serves the kubelet for as long as the process runs, registering again
/// each time a kubelet restart removes this plugin's socket.
pub async fn run(config: Config) -> Result<Infallible, Error> {
    let (health_tx, health) = watch::channel(Health::of(Path::new(&config.node_device)));
    let _monitor = AbortOnDropHandle::new(tokio::spawn(watch_health(
        config.node_device.clone(),
        config.poll,
        health_tx,
    )));
    loop {
        serve_until_forgotten(&config, health.clone()).await?;
        tracing::info!("this plugin's socket was removed; registering again");
    }
}

async fn watch_health(node_device: String, poll: Duration, health: watch::Sender<Health>) {
    let mut ticks = tokio::time::interval(poll);
    loop {
        ticks.tick().await;
        let now = Health::of(Path::new(&node_device));
        health.send_if_modified(|current| {
            if *current == now {
                return false;
            }
            tracing::warn!(device = %node_device, health = ?now, "the device's health changed");
            *current = now;
            true
        });
    }
}

/// Listens on this plugin's socket, registers it, and returns once the socket
/// at that path is no longer the one it bound.
async fn serve_until_forgotten(
    config: &Config,
    health: watch::Receiver<Health>,
) -> Result<(), Error> {
    let socket = config.plugin_dir.join(PLUGIN_SOCKET);
    match std::fs::remove_file(&socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::RemoveStale {
                path: socket,
                source,
            });
        }
    }
    let listen_error = |source| Error::Listen {
        path: socket.clone(),
        source,
    };
    let listener = UnixListener::bind(&socket).map_err(listen_error)?;
    let bound = identity(&socket).map_err(listen_error)?;

    let plugin = KvmPlugin::new(config.devices.get(), config.node_device.clone(), health);
    let mut server = AbortOnDropHandle::new(tokio::spawn(
        Server::builder()
            .add_service(DevicePluginServer::new(plugin))
            .serve_with_incoming(UnixListenerStream::new(listener)),
    ));
    register(&config.plugin_dir.join(KUBELET_SOCKET), config.poll).await?;
    tracing::info!(
        resource = RESOURCE_NAME,
        devices = config.devices.get(),
        device = %config.node_device,
        "registered with the kubelet"
    );

    let mut ticks = tokio::time::interval(config.poll);
    loop {
        tokio::select! {
            ended = &mut server => {
                return Err(match ended {
                    Ok(Ok(())) => Error::ServerEnded,
                    Ok(Err(error)) => Error::Serve(error),
                    Err(error) => Error::Task(error),
                });
            }
            _ = ticks.tick() => {
                if identity(&socket).ok() != Some(bound) {
                    return Ok(());
                }
            }
        }
    }
}

fn identity(socket: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(socket)?;
    Ok((metadata.dev(), metadata.ino()))
}

async fn register(kubelet_socket: &Path, retry: Duration) -> Result<(), Error> {
    let mut attempt = 1;
    loop {
        match register_once(kubelet_socket).await {
            Ok(()) => return Ok(()),
            Err(error @ Error::Connect { .. }) if attempt < CONNECT_ATTEMPTS => {
                tracing::warn!(%error, attempt, "cannot reach the kubelet yet; retrying");
                attempt += 1;
                tokio::time::sleep(retry).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn register_once(kubelet_socket: &Path) -> Result<(), Error> {
    let path = kubelet_socket.to_owned();
    let connector = tower::service_fn(move |_| {
        let path = path.clone();
        async move { Ok::<_, io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
    });
    let channel = Endpoint::from_static("http://kubelet")
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .connect_with_connector(connector)
        .await
        .map_err(|source| Error::Connect {
            path: kubelet_socket.to_owned(),
            source,
        })?;
    RegistrationClient::new(channel)
        .register(RegisterRequest {
            version: API_VERSION.to_owned(),
            endpoint: PLUGIN_SOCKET.to_owned(),
            resource_name: RESOURCE_NAME.to_owned(),
            options: Some(DevicePluginOptions::default()),
        })
        .await
        .map_err(|status| Error::Refused(Box::new(status)))?;
    Ok(())
}
