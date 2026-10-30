//! SSH readiness and file access against the workspace daemon's SSH server
//! (design §3, L4): connect to the current workspace Pod's SSH port over the
//! Pod network, handshake as user `codewire` with no credentials (none-auth;
//! only orchestration may reach that port), open the `sftp` subsystem, and
//! complete the SFTP INIT/VERSION exchange — the exact connection path the
//! API's file routes use at runtime.

use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::client::SandboxClient;
use super::host_keys::HostKeyStore;

/// The workspace daemon's SSH port, which only orchestration may reach.
pub const WORKSPACE_SSH_PORT: u16 = codewire_daemon_proto::WORKSPACE_SSH_PORT;
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Between access readiness attempts.
const ACCESS_READY_POLL: Duration = Duration::from_millis(100);
/// One direct connect of an access readiness attempt. A freshly bound
/// member's endpoint is regenerated (new identity, its bridge) a few hundred
/// milliseconds after the bind, and a SYN that lands before that is dropped
/// by policy; the kernel would only resend it after its 1 s RTO (#3625). A
/// short connect, tried again at once, sends a fresh SYN instead.
const ACCESS_DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
/// For this long an access readiness attempt connects over the Pod network
/// only; after it, an attempt may fall back to a kube port-forward, as the
/// file routes do.
const ACCESS_DIRECT_ONLY_WINDOW: Duration = Duration::from_secs(5);
/// How long one access readiness attempt may take, connect to key exchange.
const ACCESS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A live raw port-forward stream. Holds the kube port-forwarder so
/// the underlying stream stays open for the caller's lifetime.
pub struct PortForwardedStream {
    stream: Box<dyn AsyncReadWrite>,
    _pf: Option<kube::api::Portforwarder>,
}

impl PortForwardedStream {
    pub fn into_parts(self) -> (Box<dyn AsyncReadWrite>, Option<kube::api::Portforwarder>) {
        (self.stream, self._pf)
    }
}

impl AsyncRead for PortForwardedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_read(context, buffer)
    }
}

impl AsyncWrite for PortForwardedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.stream.as_mut()).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_shutdown(context)
    }
}

async fn direct_stream(pod: &Pod, pod_name: &str, port: u16) -> anyhow::Result<TcpStream> {
    direct_stream_within(pod, pod_name, port, DIRECT_CONNECT_TIMEOUT).await
}

async fn direct_stream_within(
    pod: &Pod,
    pod_name: &str,
    port: u16,
    connect_timeout: Duration,
) -> anyhow::Result<TcpStream> {
    let pod_ip = pod
        .status
        .as_ref()
        .and_then(|status| status.pod_ip.as_deref())
        .filter(|ip| !ip.is_empty())
        .ok_or_else(|| anyhow::anyhow!("pod {pod_name} has no pod IP"))?;
    let ip: IpAddr = pod_ip
        .parse()
        .map_err(|e| anyhow::anyhow!("parse pod IP {pod_ip}: {e}"))?;
    let addr = SocketAddr::new(ip, port);

    tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("connect {addr}: timed out"))?
        .map_err(|e| anyhow::anyhow!("connect {addr}: {e}"))
}

/// How an access readiness attempt reaches the Pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessProbePath {
    /// The Pod network only, with [`ACCESS_DIRECT_CONNECT_TIMEOUT`].
    DirectOnly,
    /// The Pod network, then a kube port-forward ([`SandboxClient::workspace_ssh_stream`]).
    DirectThenForward,
}

/// Why one access probe failed: on the host key (none recorded, or the
/// daemon presented another), or before it reached the daemon at all.
enum ProbeFailure {
    Key(anyhow::Error),
    Transport(anyhow::Error),
}

/// What one access attempt proves after the pinned key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessProof {
    /// The key exchange alone: the bound daemon serves its recorded key.
    KeyExchange,
    /// Also the none-auth login, a session, the SFTP subsystem and
    /// `realpath`: everything setup's health check proves (#3684).
    LoginAndSftp,
}

/// Attempts in the first [`ACCESS_DIRECT_ONLY_WINDOW`] of the wait use the
/// Pod network only: a slow port-forward there would hide a SYN the
/// member's not-yet-regenerated policy dropped. Later attempts may forward.
fn access_probe_path(waited: Duration) -> AccessProbePath {
    if waited < ACCESS_DIRECT_ONLY_WINDOW {
        AccessProbePath::DirectOnly
    } else {
        AccessProbePath::DirectThenForward
    }
}

/// Accepts exactly the host key the environment's currently bound Pod
/// recorded.
struct PinnedHostKey(russh::keys::PublicKey);

impl PinnedHostKey {
    async fn current(env_id: &str, host_keys: &dyn HostKeyStore) -> anyhow::Result<Self> {
        let (_, key) = host_keys
            .current_host_key(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("read the recorded host key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("no host key is recorded for the bound Pod"))?;
        Ok(Self(russh::keys::PublicKey::from_openssh(&key).map_err(
            |_| anyhow::anyhow!("the recorded host key is not an OpenSSH key"),
        )?))
    }
}

impl russh::client::Handler for PinnedHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(
            server_public_key,
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.0.key_data()
        ))
    }
}

fn sidecar_ssh_config() -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config::default())
}

impl SandboxClient {
    /// Opens a raw kube port-forward stream to the environment pod.
    pub async fn port_forward_stream(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let pod_name = self
            .get_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("port-forward: resolve pod name: {e}"))?;
        self.port_forward_pod_stream(&pod_name, port).await
    }

    /// A stream to `port` of the current workspace Pod: the exact Pod the
    /// bound Sandbox controls, over the Pod network, else through a kube
    /// port-forward to that Pod.
    pub async fn workspace_ssh_stream(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let pod = self
            .current_workspace_pod_object(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("workspace SSH: {e}"))?;
        let pod_name = pod
            .metadata
            .name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("workspace SSH: the Pod has no name"))?;
        let direct_error = match direct_stream(&pod, &pod_name, port).await {
            Ok(stream) => {
                return Ok(PortForwardedStream {
                    stream: Box::new(stream),
                    _pf: None,
                });
            }
            Err(err) => err,
        };
        self.forwarded_stream(&pod_name, port, direct_error).await
    }

    async fn port_forward_pod_stream(
        &self,
        pod_name: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let direct_error = match self.direct_pod_stream(pod_name, port).await {
            Ok(stream) => {
                return Ok(PortForwardedStream {
                    stream: Box::new(stream),
                    _pf: None,
                });
            }
            Err(err) => err,
        };
        self.forwarded_stream(pod_name, port, direct_error).await
    }

    async fn forwarded_stream(
        &self,
        pod_name: &str,
        port: u16,
        direct_error: anyhow::Error,
    ) -> anyhow::Result<PortForwardedStream> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let mut pf = pods
            .portforward(pod_name, &[port])
            .await
            .map_err(|e| anyhow::anyhow!("direct pod TCP: {direct_error}; port-forward: {e}"))?;
        let stream = pf
            .take_stream(port)
            .ok_or_else(|| anyhow::anyhow!("port-forward: no stream for port {port}"))?;

        Ok(PortForwardedStream {
            stream: Box::new(stream),
            _pf: Some(pf),
        })
    }

    async fn direct_pod_stream(&self, pod_name: &str, port: u16) -> anyhow::Result<TcpStream> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let pod = pods
            .get(pod_name)
            .await
            .map_err(|e| anyhow::anyhow!("get pod {pod_name}: {e}"))?;
        direct_stream(&pod, pod_name, port).await
    }

    /// The `access_ready` stage (design L4): the environment's currently
    /// bound Pod has recorded a host key, and that Pod's SSH port completes a
    /// key exchange presenting exactly that key. The daemon records its key
    /// only once bound, so this proves the bound daemon serves SSH.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn wait_for_workspace_access_ready(
        &self,
        env_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        self.wait_for_workspace_access_ready_on(
            env_id,
            WORKSPACE_SSH_PORT,
            timeout,
            ACCESS_DIRECT_CONNECT_TIMEOUT,
            host_keys,
            AccessProof::KeyExchange,
        )
        .await
        .map(|_| ())
    }

    /// Create's `access_ready` stage with setup's health check in the same
    /// connection (#3684): the pinned key exchange, then the none-auth login,
    /// a session, the SFTP subsystem and `realpath`, retried as
    /// [`Self::wait_for_workspace_access_ready`] retries. Returns the UID of
    /// the Pod it proved, so setup can tell that its own check would repeat it.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn prove_workspace_access(
        &self,
        env_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<String> {
        self.wait_for_workspace_access_ready_on(
            env_id,
            WORKSPACE_SSH_PORT,
            timeout,
            ACCESS_DIRECT_CONNECT_TIMEOUT,
            host_keys,
            AccessProof::LoginAndSftp,
        )
        .await
    }

    /// `connect_timeout` bounds each direct attempt's connect:
    /// [`ACCESS_DIRECT_CONNECT_TIMEOUT`] in production, and in tests a bound
    /// loopback never misses, since they test the probe, not that bound.
    async fn wait_for_workspace_access_ready_on(
        &self,
        env_id: &str,
        port: u16,
        timeout: Duration,
        connect_timeout: Duration,
        host_keys: &dyn HostKeyStore,
        proof: AccessProof,
    ) -> anyhow::Result<String> {
        // The last host-key failure, and any transport failure since it. A
        // probe that never reached the daemon says nothing about its key, so
        // it never hides the key failure from the timeout's reason.
        let mut key = None;
        let mut transport = None;
        let started = tokio::time::Instant::now();
        let ready = tokio::time::timeout(timeout, async {
            loop {
                let path = access_probe_path(started.elapsed());
                let attempt = tokio::time::timeout(
                    ACCESS_HANDSHAKE_TIMEOUT,
                    self.pinned_key_exchange(env_id, port, connect_timeout, host_keys, path, proof),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(ProbeFailure::Transport(anyhow::anyhow!(
                        "SSH key exchange timed out"
                    )))
                });
                match attempt {
                    Ok(pod_uid) => return pod_uid,
                    Err(ProbeFailure::Key(error)) => {
                        key = Some(error);
                        transport = None;
                    }
                    Err(ProbeFailure::Transport(error)) => transport = Some(error),
                }
                tokio::time::sleep(ACCESS_READY_POLL).await;
            }
        })
        .await;
        ready.map_err(|_| match (transport.take(), key.take()) {
            (Some(transport), Some(key)) => anyhow::anyhow!(
                "workspace SSH access readiness timed out: {transport}, after {key}"
            ),
            (Some(error), None) | (None, Some(error)) => {
                anyhow::anyhow!("workspace SSH access readiness timed out: {error}")
            }
            (None, None) => anyhow::anyhow!("workspace SSH access readiness timed out"),
        })
    }

    async fn pinned_key_exchange(
        &self,
        env_id: &str,
        port: u16,
        connect_timeout: Duration,
        host_keys: &dyn HostKeyStore,
        path: AccessProbePath,
        proof: AccessProof,
    ) -> Result<String, ProbeFailure> {
        let pinned = PinnedHostKey::current(env_id, host_keys)
            .await
            .map_err(ProbeFailure::Key)?;
        // One Pod for the whole attempt, so the UID returned is the Pod proved.
        let pod = self
            .current_workspace_pod_object(env_id)
            .await
            .map_err(|e| ProbeFailure::Transport(anyhow::anyhow!("workspace SSH: {e}")))?;
        let pod_name = pod.metadata.name.clone().ok_or_else(|| {
            ProbeFailure::Transport(anyhow::anyhow!("workspace SSH: the Pod has no name"))
        })?;
        let pod_uid = pod.metadata.uid.clone().unwrap_or_default();
        let (stream, _pf) = match path {
            AccessProbePath::DirectOnly => {
                let stream = direct_stream_within(&pod, &pod_name, port, connect_timeout)
                    .await
                    .map_err(ProbeFailure::Transport)?;
                (Box::new(stream) as Box<dyn AsyncReadWrite>, None)
            }
            AccessProbePath::DirectThenForward => {
                match direct_stream(&pod, &pod_name, port).await {
                    Ok(stream) => (Box::new(stream) as Box<dyn AsyncReadWrite>, None),
                    Err(direct_error) => self
                        .forwarded_stream(&pod_name, port, direct_error)
                        .await
                        .map_err(ProbeFailure::Transport)?
                        .into_parts(),
                }
            }
        };
        let mut handle = russh::client::connect_stream(sidecar_ssh_config(), stream, pinned)
            .await
            .map_err(|e| {
                ProbeFailure::Key(anyhow::anyhow!(
                    "SSH key exchange with the recorded host key: {e}"
                ))
            })?;
        if proof == AccessProof::LoginAndSftp {
            login_and_sftp(&mut handle, "workspace access")
                .await
                .map_err(ProbeFailure::Transport)?;
        }
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(pod_uid)
    }

    /// The workspace daemon's SSH server, presenting the host key recorded
    /// for the current generation, completes a none-auth handshake and an
    /// SFTP exchange: the health check after setup.
    pub async fn check_sidecar_ready(
        &self,
        env_id: &str,
        port: u16,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        let pinned = PinnedHostKey::current(env_id, host_keys)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness host key: {e}"))?;
        let stream = self
            .workspace_ssh_stream(env_id, port)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness connect: {e}"))?;
        let (stream, _pf) = stream.into_parts();

        let mut handle = russh::client::connect_stream(sidecar_ssh_config(), stream, pinned)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness ssh handshake: {e}"))?;
        login_and_sftp(&mut handle, "sidecar readiness").await?;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }
}

/// On a connection whose key exchange presented the recorded key: the
/// none-auth login, a session, the SFTP subsystem and `realpath`. Errors name
/// `context` and the step that failed.
async fn login_and_sftp<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    context: &str,
) -> anyhow::Result<()> {
    let authenticated = handle
        .authenticate_none("codewire")
        .await
        .map(|r| matches!(r, russh::client::AuthResult::Success))
        .unwrap_or(false);
    if !authenticated {
        anyhow::bail!("{context} ssh handshake: none-auth rejected");
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| anyhow::anyhow!("{context} sftp init: open session: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| anyhow::anyhow!("{context} sftp init: subsystem: {e}"))?;
    let session = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| anyhow::anyhow!("{context} sftp init: {e}"))?;
    session
        .canonicalize(".")
        .await
        .map_err(|e| anyhow::anyhow!("{context} sftp realpath: {e}"))?;
    let _ = session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, Response, StatusCode, header};
    use serde_json::json;
    use std::sync::Mutex;

    const NAMESPACE: &str = "synthetic-sandboxes";
    const ENVIRONMENT: &str = "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000001";
    const SANDBOX_UID: &str = "5a4db0c5-e29b-41d4-a716-446655440000";
    /// A loopback connect on a loaded workstation has taken over 300 ms, past
    /// [`ACCESS_DIRECT_CONNECT_TIMEOUT`]; these tests probe a live listener,
    /// so they bound the connect well clear of that.
    const TEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// The Claim, its bound Sandbox and the Pod that Sandbox controls, at
    /// `pod_ip`. Records every path the client reads.
    fn workspace_chain(
        pod_ip: &str,
        controller_uid: &str,
    ) -> (SandboxClient, Arc<Mutex<Vec<String>>>) {
        let claim = crate::sandbox::claim_name(ENVIRONMENT);
        let objects = [
            (
                format!(
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxclaims/{claim}"
                ),
                json!({"apiVersion":"extensions.agents.x-k8s.io/v1beta1","kind":"SandboxClaim",
                    "metadata":{"name":claim,"namespace":NAMESPACE,"uid":"c0ffee00-e29b-41d4-a716-446655440000"},
                    "status":{"sandbox":{"name":"sandbox-a"}}}),
            ),
            (
                format!("/apis/agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxes/sandbox-a"),
                json!({"apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
                    "metadata":{"name":"sandbox-a","namespace":NAMESPACE,"uid":SANDBOX_UID,
                        "annotations":{"agents.x-k8s.io/pod-name":"workspace-a"}}}),
            ),
            (
                format!("/api/v1/namespaces/{NAMESPACE}/pods/workspace-a"),
                json!({"apiVersion":"v1","kind":"Pod",
                    "metadata":{"name":"workspace-a","namespace":NAMESPACE,"uid":"7e7b20f6-0bd2-4f11-8b16-9c239851eb52",
                        "labels":{"codewire.sh/type":"workspace"},
                        "ownerReferences":[{"apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
                            "name":"sandbox-a","uid":controller_uid,"controller":true}]},
                    "status":{"phase":"Running","podIP":pod_ip}}),
            ),
        ];
        let paths = Arc::new(Mutex::new(Vec::new()));
        let recorded = paths.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let recorded = recorded.clone();
            let objects = objects.clone();
            async move {
                let path = request.uri().path().to_owned();
                recorded.lock().unwrap().push(path.clone());
                let (status, body) = objects.iter().find(|(known, _)| *known == path).map_or(
                    (StatusCode::NOT_FOUND, json!({"kind":"Status","code":404})),
                    |(_, object)| (StatusCode::OK, object.clone()),
                );
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        (
            SandboxClient::new(kube::Client::new(service, "default"), NAMESPACE),
            paths,
        )
    }

    #[tokio::test]
    async fn ssh_reaches_the_bound_workspace_pod_over_the_pod_network() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, paths) = workspace_chain("127.0.0.1", SANDBOX_UID);
        let accepted = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = client
            .workspace_ssh_stream(ENVIRONMENT, port)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), accepted)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // A direct Pod-network connection, never a kube port-forward, and
        // never a gateway lookup: only the Claim → Sandbox → Pod chain.
        assert!(stream.into_parts().1.is_none());
        let paths = paths.lock().unwrap().clone();
        assert_eq!(paths.len(), 3, "{paths:?}");
        assert!(paths[2].ends_with("/pods/workspace-a"));
        assert!(paths.iter().all(|path| !path.contains("gateway")));
    }

    /// A store holding one recorded key, or none.
    struct Recorded(Option<String>);

    #[async_trait::async_trait]
    impl HostKeyStore for Recorded {
        async fn current_host_key(
            &self,
            _environment_id: &str,
        ) -> Result<Option<(i64, String)>, sqlx::Error> {
            Ok(self.0.clone().map(|key| (3, key)))
        }
    }

    struct Refusing;

    impl russh::server::Handler for Refusing {
        type Error = russh::Error;
    }

    /// Accepts the none-auth login and serves SFTP's `realpath`, as a bound
    /// daemon does: what create's full access proof needs (#3684).
    #[derive(Default)]
    struct Serving {
        channels: std::collections::HashMap<russh::ChannelId, russh::Channel<russh::server::Msg>>,
    }

    impl russh::server::Handler for Serving {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: russh::ChannelId,
            name: &str,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let Some(open) = self.channels.remove(&channel).filter(|_| name == "sftp") else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            session.channel_success(channel)?;
            tokio::spawn(russh_sftp::server::run(open.into_stream(), Realpath));
            Ok(())
        }
    }

    struct Realpath;

    impl russh_sftp::server::Handler for Realpath {
        type Error = russh_sftp::protocol::StatusCode;

        fn unimplemented(&self) -> Self::Error {
            russh_sftp::protocol::StatusCode::OpUnsupported
        }

        async fn realpath(
            &mut self,
            id: u32,
            _path: String,
        ) -> Result<russh_sftp::protocol::Name, Self::Error> {
            Ok(russh_sftp::protocol::Name {
                id,
                files: vec![russh_sftp::protocol::File::dummy("/workspace")],
            })
        }
    }

    /// An SSH server on `listener` presenting `key` that logs in and serves
    /// SFTP, for every connection.
    fn serving_ssh_server(listener: tokio::net::TcpListener, key: russh::keys::PrivateKey) {
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) =
                        russh::server::run_stream(config, stream, Serving::default()).await
                    {
                        let _ = session.await;
                    }
                });
            }
        });
    }

    fn host_key(seed: u8) -> russh::keys::PrivateKey {
        use russh::keys::ssh_key::private::Ed25519Keypair;
        russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    /// An SSH server on `listener` presenting `key`, for every connection.
    fn ssh_server(listener: tokio::net::TcpListener, key: russh::keys::PrivateKey) {
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, stream, Refusing).await {
                        let _ = session.await;
                    }
                });
            }
        });
    }

    fn openssh(key: &russh::keys::PrivateKey) -> String {
        key.public_key().to_openssh().unwrap()
    }

    #[tokio::test]
    async fn access_is_ready_once_the_pod_presents_the_recorded_host_key() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        ssh_server(listener, host_key(1));
        let (client, _) = workspace_chain("127.0.0.1", SANDBOX_UID);
        client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_secs(10),
                TEST_CONNECT_TIMEOUT,
                &Recorded(Some(openssh(&host_key(1)))),
                AccessProof::KeyExchange,
            )
            .await
            .unwrap();
    }

    /// #3684: create's full proof logs in and opens SFTP on the one
    /// connection, and returns the UID of the Pod it reached.
    #[tokio::test]
    async fn the_full_access_proof_logs_in_opens_sftp_and_names_the_pod() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        serving_ssh_server(listener, host_key(1));
        let (client, _) = workspace_chain("127.0.0.1", SANDBOX_UID);
        let pod_uid = client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_secs(10),
                TEST_CONNECT_TIMEOUT,
                &Recorded(Some(openssh(&host_key(1)))),
                AccessProof::LoginAndSftp,
            )
            .await
            .unwrap();
        assert!(!pod_uid.is_empty(), "the proved Pod's UID");
    }

    /// A daemon that completes the key exchange but refuses the login is not
    /// proven, while the key-exchange-only wait still accepts it.
    #[tokio::test]
    async fn the_full_access_proof_needs_the_login_the_key_exchange_does_not() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        ssh_server(listener, host_key(1));
        let (client, _) = workspace_chain("127.0.0.1", SANDBOX_UID);
        let keys = Recorded(Some(openssh(&host_key(1))));
        let error = client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_millis(1_500),
                TEST_CONNECT_TIMEOUT,
                &keys,
                AccessProof::LoginAndSftp,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("workspace access ssh handshake: none-auth rejected"),
            "{error}"
        );
        client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_secs(10),
                TEST_CONNECT_TIMEOUT,
                &keys,
                AccessProof::KeyExchange,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn access_is_not_ready_without_the_current_recorded_key() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        ssh_server(listener, host_key(1));
        let (client, _) = workspace_chain("127.0.0.1", SANDBOX_UID);
        // Another key, as a previous generation's, or none recorded yet.
        for (store, reason) in [
            (Recorded(Some(openssh(&host_key(2)))), "recorded host key"),
            (Recorded(None), "no host key is recorded"),
        ] {
            let error = client
                .wait_for_workspace_access_ready_on(
                    ENVIRONMENT,
                    port,
                    Duration::from_millis(1_500),
                    TEST_CONNECT_TIMEOUT,
                    &store,
                    AccessProof::KeyExchange,
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
        // A port that is not SSH never becomes ready.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        drop(silent);
        let error = client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_millis(600),
                TEST_CONNECT_TIMEOUT,
                &Recorded(Some(openssh(&host_key(1)))),
                AccessProof::KeyExchange,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
    }

    #[tokio::test]
    async fn a_pod_another_sandbox_controls_is_never_reached() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, _) = workspace_chain("127.0.0.1", "5a4db0c5-9dad-11d1-80b4-00c04fd430c8");
        assert!(
            client
                .workspace_ssh_stream(ENVIRONMENT, port)
                .await
                .is_err()
        );
        // Refused before any connection to the Pod.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        // The workspace SSH port is the daemon's, from the shared contract.
        assert_eq!(
            WORKSPACE_SSH_PORT,
            codewire_daemon_proto::WORKSPACE_SSH_PORT
        );
    }

    #[test]
    fn access_readiness_connects_directly_before_it_may_forward() {
        assert_eq!(
            access_probe_path(Duration::ZERO),
            AccessProbePath::DirectOnly
        );
        assert_eq!(
            access_probe_path(ACCESS_DIRECT_ONLY_WINDOW - Duration::from_millis(1)),
            AccessProbePath::DirectOnly
        );
        assert_eq!(
            access_probe_path(ACCESS_DIRECT_ONLY_WINDOW),
            AccessProbePath::DirectThenForward
        );
        // A dropped SYN costs one short connect, never the kernel's 1 s RTO.
        assert!(ACCESS_DIRECT_CONNECT_TIMEOUT + ACCESS_READY_POLL < Duration::from_secs(1));
    }

    #[tokio::test]
    /// The only orchestration SSH client trusts exactly the recorded key:
    /// never another public key, and never a host certificate, even one
    /// over the recorded key (codewire#3626 condition 7).
    async fn the_pinned_key_accepts_only_the_recorded_public_key() {
        use russh::keys::ssh_key::{
            PrivateKey,
            certificate::{Builder, CertType},
            private::Ed25519Keypair,
        };

        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let mut pinned = PinnedHostKey(key.public_key().clone());
        let public_key = key.public_key().clone().into();
        assert!(
            russh::client::Handler::check_server_key(&mut pinned, &public_key)
                .await
                .unwrap()
        );
        let other = PrivateKey::from(Ed25519Keypair::from_seed(&[8; 32]))
            .public_key()
            .clone()
            .into();
        assert!(
            !russh::client::Handler::check_server_key(&mut pinned, &other)
                .await
                .unwrap()
        );

        let mut builder = Builder::new(
            vec![0; 32],
            key.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal("sidecar.test").unwrap();
        let certificate = builder.sign(&key).unwrap().into();
        assert!(
            !russh::client::Handler::check_server_key(&mut pinned, &certificate)
                .await
                .unwrap()
        );
    }
}
