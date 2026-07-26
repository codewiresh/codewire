use std::future::Future;
use std::io as std_io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;
use tokio::io;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

pub const DEFAULT_PROXY_MODE: u32 = 0o660;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerProxySettings {
    pub listen_path: PathBuf,
    pub upstream_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerSocketPathKind {
    CodewireProxy,
    GuestDind,
    HostDocker,
    HostContainerd,
    Other,
}

#[derive(Debug, Default)]
pub struct DockerProxyStats {
    accepted_connections: AtomicU64,
    upstream_dial_failures: AtomicU64,
    completed_connections: AtomicU64,
}

impl DockerProxyStats {
    pub fn accepted_connections(&self) -> u64 {
        self.accepted_connections.load(Ordering::Relaxed)
    }

    pub fn upstream_dial_failures(&self) -> u64 {
        self.upstream_dial_failures.load(Ordering::Relaxed)
    }

    pub fn completed_connections(&self) -> u64 {
        self.completed_connections.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Error)]
pub enum DockerProxyError {
    #[error("docker proxy listen path is empty")]
    EmptyListenPath,
    #[error("docker proxy upstream path is empty")]
    EmptyUpstreamPath,
    #[error("docker proxy {name} path must be absolute: {path}")]
    RelativePath { name: &'static str, path: String },
    #[error("docker proxy listen and upstream paths must differ: {0}")]
    SameListenAndUpstream(String),
    #[error("docker proxy {name} path is a forbidden host socket: {path}")]
    ForbiddenHostSocket { name: &'static str, path: String },
    #[error("create docker proxy parent directory {path}: {source}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("refusing to replace non-socket docker proxy path {0}")]
    ExistingNonSocket(PathBuf),
    #[error("remove stale docker proxy socket {path}: {source}")]
    RemoveStaleSocket {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("listen on docker proxy socket {path}: {source}")]
    Listen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("chmod docker proxy socket {path}: {source}")]
    Chmod {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("accept docker proxy connection: {0}")]
    Accept(#[source] std_io::Error),
}

impl DockerProxySettings {
    pub fn new(
        listen_path: impl Into<PathBuf>,
        upstream_path: impl Into<PathBuf>,
    ) -> Result<Self, DockerProxyError> {
        let settings = Self {
            listen_path: listen_path.into(),
            upstream_path: upstream_path.into(),
        };
        validate_settings(&settings)?;
        Ok(settings)
    }
}

pub fn classify_socket_path(path: &Path) -> DockerSocketPathKind {
    match path.to_str().unwrap_or_default() {
        "/codewire/run/docker.sock" => DockerSocketPathKind::CodewireProxy,
        "/var/run/docker/docker.sock" => DockerSocketPathKind::GuestDind,
        "/var/run/docker.sock" | "/run/docker.sock" => DockerSocketPathKind::HostDocker,
        "/run/containerd/containerd.sock" | "/var/run/containerd/containerd.sock" => {
            DockerSocketPathKind::HostContainerd
        }
        _ => DockerSocketPathKind::Other,
    }
}

pub fn validate_settings(settings: &DockerProxySettings) -> Result<(), DockerProxyError> {
    validate_path("listen", &settings.listen_path, false)?;
    validate_path("upstream", &settings.upstream_path, true)?;
    if settings.listen_path == settings.upstream_path {
        return Err(DockerProxyError::SameListenAndUpstream(
            settings.listen_path.display().to_string(),
        ));
    }
    Ok(())
}

pub async fn serve_docker_socket_proxy<F>(
    settings: DockerProxySettings,
    shutdown: F,
) -> Result<Arc<DockerProxyStats>, DockerProxyError>
where
    F: Future<Output = ()>,
{
    validate_settings(&settings)?;
    prepare_listen_path(&settings.listen_path)?;
    let listener =
        UnixListener::bind(&settings.listen_path).map_err(|source| DockerProxyError::Listen {
            path: settings.listen_path.clone(),
            source,
        })?;
    std::fs::set_permissions(
        &settings.listen_path,
        std::fs::Permissions::from_mode(DEFAULT_PROXY_MODE),
    )
    .map_err(|source| DockerProxyError::Chmod {
        path: settings.listen_path.clone(),
        source,
    })?;

    let stats = Arc::new(DockerProxyStats::default());
    info!(
        listen_path = %settings.listen_path.display(),
        upstream_path = %settings.upstream_path.display(),
        listen_kind = ?classify_socket_path(&settings.listen_path),
        upstream_kind = ?classify_socket_path(&settings.upstream_path),
        "docker socket proxy listening"
    );

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                let _ = std::fs::remove_file(&settings.listen_path);
                return Ok(stats);
            }
            accepted = listener.accept() => {
                let (downstream, _) = accepted.map_err(DockerProxyError::Accept)?;
                let accepted_connections =
                    stats.accepted_connections.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(
                    accepted_connections,
                    upstream_path = %settings.upstream_path.display(),
                    "docker proxy connection accepted"
                );
                let stats = Arc::clone(&stats);
                let upstream_path = settings.upstream_path.clone();
                tokio::spawn(async move {
                    proxy_docker_connection(downstream, upstream_path, stats).await;
                });
            }
        }
    }
}

fn validate_path(
    name: &'static str,
    path: &Path,
    forbid_host_socket: bool,
) -> Result<(), DockerProxyError> {
    let path_string = path.display().to_string();
    if path.as_os_str().is_empty() {
        return match name {
            "listen" => Err(DockerProxyError::EmptyListenPath),
            _ => Err(DockerProxyError::EmptyUpstreamPath),
        };
    }
    if !path.is_absolute() {
        return Err(DockerProxyError::RelativePath {
            name,
            path: path_string,
        });
    }
    if forbid_host_socket
        && matches!(
            classify_socket_path(path),
            DockerSocketPathKind::HostDocker | DockerSocketPathKind::HostContainerd
        )
    {
        return Err(DockerProxyError::ForbiddenHostSocket {
            name,
            path: path_string,
        });
    }
    Ok(())
}

fn prepare_listen_path(path: &Path) -> Result<(), DockerProxyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    std::fs::create_dir_all(parent).map_err(|source| DockerProxyError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })?;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|source| DockerProxyError::RemoveStaleSocket {
                path: path.to_path_buf(),
                source,
            })?;
        }
        Ok(_) => return Err(DockerProxyError::ExistingNonSocket(path.to_path_buf())),
        Err(err) if err.kind() == std_io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(DockerProxyError::RemoveStaleSocket {
                path: path.to_path_buf(),
                source: err,
            });
        }
    }
    Ok(())
}

async fn proxy_docker_connection(
    mut downstream: UnixStream,
    upstream_path: PathBuf,
    stats: Arc<DockerProxyStats>,
) {
    let mut upstream = match UnixStream::connect(&upstream_path).await {
        Ok(upstream) => upstream,
        Err(err) => {
            let upstream_dial_failures =
                stats.upstream_dial_failures.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                upstream_path = %upstream_path.display(),
                upstream_dial_failures,
                error = %err,
                "docker proxy upstream dial failed"
            );
            return;
        }
    };

    let result = io::copy_bidirectional(&mut downstream, &mut upstream).await;
    if let Err(err) = result {
        debug!(upstream_path = %upstream_path.display(), error = %err, "docker proxy connection ended with copy error");
    }
    let completed_connections = stats.completed_connections.fetch_add(1, Ordering::Relaxed) + 1;
    debug!(
        upstream_path = %upstream_path.display(),
        completed_connections,
        "docker proxy connection completed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use uuid::Uuid;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("codewire-gateway-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn validates_commodity_proxy_paths() {
        let settings =
            DockerProxySettings::new("/codewire/run/docker.sock", "/var/run/docker/docker.sock")
                .unwrap();
        assert_eq!(
            classify_socket_path(&settings.listen_path),
            DockerSocketPathKind::CodewireProxy
        );
        assert_eq!(
            classify_socket_path(&settings.upstream_path),
            DockerSocketPathKind::GuestDind
        );
    }

    #[test]
    fn rejects_host_docker_and_containerd_upstreams() {
        for path in [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/var/run/containerd/containerd.sock",
        ] {
            let err = DockerProxySettings::new("/codewire/run/docker.sock", path).unwrap_err();
            assert!(matches!(
                err,
                DockerProxyError::ForbiddenHostSocket {
                    name: "upstream",
                    ..
                }
            ));
        }
    }

    #[test]
    fn rejects_relative_and_identical_paths() {
        assert!(matches!(
            DockerProxySettings::new("docker.sock", "/var/run/docker/docker.sock").unwrap_err(),
            DockerProxyError::RelativePath { name: "listen", .. }
        ));
        assert!(matches!(
            DockerProxySettings::new("/codewire/run/docker.sock", "/codewire/run/docker.sock")
                .unwrap_err(),
            DockerProxyError::SameListenAndUpstream(_)
        ));
    }

    #[tokio::test]
    async fn proxies_unix_socket_streams_and_reports_stats() {
        let dir = tmp_path("docker-proxy");
        std::fs::create_dir_all(&dir).unwrap();
        let upstream_path = dir.join("upstream.sock");
        let proxy_path = dir.join("proxy.sock");

        let upstream = UnixListener::bind(&upstream_path).unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut conn, _) = upstream.accept().await.unwrap();
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).await.unwrap();
            conn.write_all(&buf).await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let settings = DockerProxySettings::new(&proxy_path, &upstream_path).unwrap();
        let proxy_task = tokio::spawn(serve_docker_socket_proxy(settings, async move {
            let _ = shutdown_rx.await;
        }));

        wait_for_socket(&proxy_path).await;
        let mut conn = UnixStream::connect(&proxy_path).await.unwrap();
        conn.write_all(b"hello-docker-proxy").await.unwrap();
        conn.shutdown().await.unwrap();

        let mut response = Vec::new();
        conn.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"hello-docker-proxy");
        upstream_task.await.unwrap();

        shutdown_tx.send(()).unwrap();
        let stats = proxy_task.await.unwrap().unwrap();
        assert_eq!(stats.accepted_connections(), 1);
        assert_eq!(stats.upstream_dial_failures(), 0);
        assert_eq!(stats.completed_connections(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    async fn wait_for_socket(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("socket {} was not created", path.display());
    }
}
