//! Isolated public mutation and private TLS broker process ownership.
//!
//! Neither orchestration nor the gateway constructs these protected handles.
//! Configuration never falls back to shared service credentials or kubeconfig;
//! schema migrations and authority provisioning belong to their existing owners.

mod config;
#[cfg(test)]
mod kind;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_access::{CredentialAuthKind, builtin_provider_catalog};
use codewire_credential_broker::codex_enrollment::{CodexEnrollmentConfig, CodexEnrollmentOwner};
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticator, PlatformCredentialBridgeService,
};
use codewire_credential_broker::{BrokerUpstreamTransport, OpenAiHttpsTransport};
use codewire_platform_credentials::{PlatformAccessProfileStore, PlatformCredentialStore};
use codewire_protected_store::openbao_workload_identity::KubernetesOpenBaoWorkloadIdentity;
use codewire_protected_store::secret_envelope::{KekProvider, OpenBaoTransitProvider};
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect::ConnectAuthLayer;
use codewire_server_core::http::AppBuilder;
use codewire_tls::{ServerTlsFiles, TlsIncoming};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::KubernetesPlatformBridgeAuthenticator;
use crate::mutation::CredentialMutationOwner;
pub use config::CredentialServiceConfig;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSPORT_GRACE: Duration = Duration::from_secs(5);

/// Closed failure classes; provider, SQL, filesystem, Kubernetes and transport
/// errors are never retained as a source or formatted into logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeError {
    #[error("invalid isolated credential configuration: {0}")]
    Configuration(&'static str),
    #[error("isolated credential database unavailable")]
    Database,
    #[error("isolated credential Kubernetes identity unavailable")]
    Kubernetes,
    #[error("isolated credential OpenBao authority unavailable")]
    OpenBao,
    #[error("isolated Codex enrollment unavailable")]
    Enrollment,
    #[error("credential provider transport unavailable")]
    Provider,
    #[error("credential broker TLS identity unavailable")]
    Tls,
    #[error("credential listener unavailable")]
    Listener,
    #[error("credential HTTP service stopped unexpectedly")]
    Http,
    #[error("credential private service stopped unexpectedly")]
    Private,
    #[error("credential owner cleanup failed")]
    Cleanup,
    #[error("credential shutdown signal unavailable")]
    Signal,
}

/// Run the production service using only explicit restricted dependencies.
/// The caller retains the runtime until this returns: dropping this future
/// cannot prove provider or database cleanup after an issued mutation.
pub async fn run(
    config: CredentialServiceConfig,
    shutdown: impl Future<Output = Result<(), RuntimeError>> + Send,
) -> Result<(), RuntimeError> {
    // Config rejects every SQLx/libpq default and requires an explicit nonempty
    // password, so this parser cannot consult pgpass or ambient key files.
    let options = config
        .database_url
        .parse::<PgConnectOptions>()
        .map_err(|_| RuntimeError::Configuration("CREDENTIAL_DATABASE_URL"))?
        .application_name("codewire-credential-service")
        .disable_statement_logging();
    let pool = tokio::time::timeout(
        DATABASE_TIMEOUT,
        PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options),
    )
    .await
    .map_err(|_| RuntimeError::Database)?
    .map_err(|_| RuntimeError::Database)?;
    let result = run_connected(config, pool.clone(), shutdown).await;
    // Every owner has drained before its underlying connection pool closes.
    pool.close().await;
    result
}

async fn run_connected(
    config: CredentialServiceConfig,
    pool: PgPool,
    shutdown: impl Future<Output = Result<(), RuntimeError>> + Send,
) -> Result<(), RuntimeError> {
    // Explicit in-cluster configuration never searches the user's kubeconfig.
    let kube_config = kube::Config::incluster().map_err(|_| RuntimeError::Kubernetes)?;
    let client = kube::Client::try_from(kube_config).map_err(|_| RuntimeError::Kubernetes)?;
    let identity =
        KubernetesOpenBaoWorkloadIdentity::from_env(client.clone(), "CREDENTIAL_BAO_AUDIENCE")
            .map_err(|_| RuntimeError::Kubernetes)?;
    let provider = Arc::new(
        OpenBaoTransitProvider::new(config.openbao, Arc::new(identity))
            .map_err(|_| RuntimeError::OpenBao)?,
    );
    provider
        .authority_id()
        .await
        .map_err(|_| RuntimeError::OpenBao)?;
    let upstream = OpenAiHttpsTransport::resolve(CredentialAuthKind::OAuth)
        .await
        .map_err(|_| RuntimeError::Provider)?;
    let enrollment = enrollment_config(config.codex_executable, config.runtime_directory)?;
    let store = Arc::new(PlatformCredentialStore::new(
        pool.clone(),
        provider,
        builtin_provider_catalog(),
    ));
    let bridge = PlatformCredentialBridgeService::new(
        Arc::new(KubernetesPlatformBridgeAuthenticator::new(
            client,
            pool.clone(),
        )),
        store.clone(),
        PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog()),
        upstream,
    );
    let mutation = Arc::new(CredentialMutationOwner::new(
        pool.clone(),
        store,
        CodexEnrollmentOwner::new(enrollment),
    ));
    serve_owned(
        Listeners {
            public: config.public_listen,
            private: config.private_listen,
            tls: config.private_tls,
        },
        pool,
        mutation,
        bridge,
        shutdown,
    )
    .await
}

fn enrollment_config(
    executable: std::path::PathBuf,
    runtime_directory: std::path::PathBuf,
) -> Result<CodexEnrollmentConfig, RuntimeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let private = runtime_directory.join("codex-enrollment");
        // The memory-volume mount itself may be root/group-owned. Create only
        // our private child, never chmod an existing object or create parents.
        match std::fs::DirBuilder::new().mode(0o700).create(&private) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RuntimeError::Enrollment),
        }
        CodexEnrollmentConfig::new(executable, private, "/usr/bin:/bin".into())
            .map_err(|_| RuntimeError::Enrollment)
    }
    #[cfg(not(unix))]
    {
        let _ = (executable, runtime_directory);
        Err(RuntimeError::Enrollment)
    }
}

struct Listeners {
    public: std::net::SocketAddr,
    private: std::net::SocketAddr,
    tls: ServerTlsFiles,
}

// Generic dependency composition stays private. Synthetic tests can exercise
// these exact listeners/owners without adding production fixture switches.
async fn serve_owned<A, U>(
    listeners: Listeners,
    pool: PgPool,
    mutation: Arc<CredentialMutationOwner>,
    bridge: PlatformCredentialBridgeService<A, U>,
    shutdown: impl Future<Output = Result<(), RuntimeError>> + Send,
) -> Result<(), RuntimeError>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    let ready = Arc::new(AtomicBool::new(false));
    let stop = CancellationToken::new();
    let mut servers = JoinSet::new();
    let result = async {
        listeners
            .tls
            .validate()
            .await
            .map_err(|_| RuntimeError::Tls)?;
        let public = TcpListener::bind(listeners.public)
            .await
            .map_err(|_| RuntimeError::Listener)?;
        let private = TcpListener::bind(listeners.private)
            .await
            .map_err(|_| RuntimeError::Listener)?;
        let incoming =
            TlsIncoming::new(private, listeners.tls.clone()).map_err(|_| RuntimeError::Tls)?;
        let app = AppBuilder::new("codewire-credential-service")
            .with_health_and_db_probe(pool.clone(), {
                let ready = ready.clone();
                let tls = listeners.tls.clone();
                move || {
                    let ready = ready.clone();
                    let tls = tls.clone();
                    async move {
                        ready.load(Ordering::Acquire)
                            && matches!(
                                tokio::time::timeout(Duration::from_secs(1), tls.validate()).await,
                                Ok(Ok(()))
                            )
                            && ready.load(Ordering::Acquire)
                    }
                }
            })
            .with_connect_routes_auth(
                mutation.router(),
                ConnectAuthLayer::oauth_bearer_only(AuthState { pool }),
            )
            .into_router();
        let grpc = bridge.clone().into_server();
        let private_stop = stop.clone();
        servers.spawn(async move {
            tonic::transport::Server::builder()
                .add_service(grpc)
                .serve_with_incoming_shutdown(incoming, private_stop.cancelled_owned())
                .await
                .map_err(|_| RuntimeError::Private)
        });
        let public_stop = stop.clone();
        servers.spawn(async move {
            axum::serve(public, app)
                .with_graceful_shutdown(public_stop.cancelled_owned())
                .await
                .map_err(|_| RuntimeError::Http)
        });
        ready.store(true, Ordering::Release);
        tracing::info!("isolated credential listeners ready");
        tokio::select! {
            biased;
            result = shutdown => result,
            result = servers.join_next() => match result {
                Some(Ok(Err(error))) => Err(error),
                _ => Err(RuntimeError::Listener),
            },
        }
    }
    .await;
    ready.store(false, Ordering::Release);
    // Close BOTH admission owners synchronously before allowing transport
    // grace. Then join every owner, including active blocking refresh tasks.
    mutation.start_shutdown();
    bridge.start_shutdown();
    stop.cancel();
    let (mutation_result, (), ()) = tokio::join!(mutation.shutdown(), bridge.shutdown(), async {
        if tokio::time::timeout(TRANSPORT_GRACE, async {
            while servers.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            servers.shutdown().await;
        }
    });
    result.and(mutation_result.map_err(|_| RuntimeError::Cleanup))
}
