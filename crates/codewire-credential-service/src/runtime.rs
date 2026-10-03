//! Isolated public mutation and private TLS broker process ownership.
//!
//! Neither orchestration nor the gateway constructs these protected handles.
//! Configuration never falls back to shared service credentials or kubeconfig;
//! schema migrations and authority provisioning belong to their existing owners.

mod config;
mod hardening;
#[cfg(test)]
mod kind;
mod ssh;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_access::{HttpProvider, builtin_provider_catalog};
use codewire_credential_broker::GitHubAppAuthorizationOwner;
use codewire_credential_broker::codex_enrollment::{CodexEnrollmentConfig, CodexEnrollmentOwner};
use codewire_credential_broker::github_enrollment::{
    GitHubEnrollmentConfig, GitHubEnrollmentOwner,
};
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticator, PlatformCredentialBridgeService,
};
use codewire_credential_broker::platform::keepalive::OAuthKeepAlive;
use codewire_credential_broker::{BrokerUpstreamTransport, ProviderHttpsTransport};
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_protected_store::openbao_workload_identity::{
    KubernetesOpenBaoWorkloadIdentity, OpenBaoWorkloadIdentity,
};
use codewire_protected_store::secret_envelope::{KekProvider, OpenBaoTransitProvider};
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect::ConnectAuthLayer;
use codewire_server_core::http::AppBuilder;
use codewire_tls::{ServerTlsFiles, TlsIncoming};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Connection as _, PgPool};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use crate::KubernetesPlatformBridgeAuthenticator;
use crate::mutation::CredentialMutationOwner;
use crate::repositories::GithubRepositoryOwner;
pub use config::CredentialServiceConfig;
pub use hardening::harden_process;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(10);
/// A pooled database connection idle this long is pinged before reuse.
const DATABASE_REPROVE_AFTER_IDLE: Duration = Duration::from_secs(1);
const TRANSPORT_GRACE: Duration = Duration::from_secs(5);

/// Diagnostics when `RUST_LOG` is unset: closed runtime events plus the
/// broker's secret-free per-phase timing lines on their dedicated target.
pub const DEFAULT_LOG_FILTER: &str = "info,codewire_credential_broker::timing=info";

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
    #[error("credential process hardening unavailable")]
    Hardening,
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
        database_pool_options().connect_with(options),
    )
    .await
    .map_err(|_| RuntimeError::Database)?
    .map_err(|_| RuntimeError::Database)?;
    let result = run_connected(config, pool.clone(), shutdown).await;
    // Every owner has drained before its underlying connection pool closes.
    pool.close().await;
    result
}

/// The credential database pool of the service and of its Kind fixture.
fn database_pool_options() -> PgPoolOptions {
    database_pool_options_reproving_after(DATABASE_REPROVE_AFTER_IDLE)
}

/// sqlx would ping every connection on every acquire, and one lease acquires
/// many times. sqlx already pings each connection when it is released and
/// closes it if that fails, so a connection idle for less than
/// `reprove_after_idle` was proven live that recently and is used as is. A
/// longer-idle one is pinged first; if the ping fails it is closed and
/// replaced, and the caller never sees the failure.
///
/// A connection that dies within that window (a Postgres restart or failover
/// during active use, which fails in-flight statements anyway) fails the one
/// statement that next uses it and is then discarded on release. That lease
/// fails as Unavailable, which ends that Sandbox's bridge epoch; its next
/// request opens a new one.
fn database_pool_options_reproving_after(reprove_after_idle: Duration) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(5))
        .test_before_acquire(false)
        .before_acquire(move |connection, metadata| {
            Box::pin(async move {
                // A rejected connection is closed without logging the error.
                Ok(metadata.idle_for < reprove_after_idle || connection.ping().await.is_ok())
            })
        })
}

async fn run_connected(
    config: CredentialServiceConfig,
    pool: PgPool,
    shutdown: impl Future<Output = Result<(), RuntimeError>> + Send,
) -> Result<(), RuntimeError> {
    // Explicit in-cluster configuration never searches the user's kubeconfig.
    let kube_config = kube::Config::incluster().map_err(|_| RuntimeError::Kubernetes)?;
    let client = kube::Client::try_from(kube_config).map_err(|_| RuntimeError::Kubernetes)?;
    let authorities = match config.keks {
        config::KekAuthorityConfig::OpenBao {
            credential,
            application,
        } => {
            let identity: Arc<dyn OpenBaoWorkloadIdentity> = Arc::new(
                KubernetesOpenBaoWorkloadIdentity::from_env(
                    client.clone(),
                    "CREDENTIAL_BAO_AUDIENCE",
                )
                .map_err(|_| RuntimeError::Kubernetes)?,
            );
            let credential_openbao = Arc::new(
                OpenBaoTransitProvider::new(*credential, identity.clone())
                    .map_err(|_| RuntimeError::OpenBao)?,
            );
            let application_openbao = Arc::new(
                OpenBaoTransitProvider::new(*application, identity)
                    .map_err(|_| RuntimeError::OpenBao)?,
            );
            credential_openbao
                .authority_id()
                .await
                .map_err(|_| RuntimeError::OpenBao)?;
            application_openbao
                .authority_id()
                .await
                .map_err(|_| RuntimeError::OpenBao)?;
            crate::authority::RuntimeKekAuthorities::new(credential_openbao, application_openbao)
        }
        #[cfg(feature = "kind-e2e")]
        config::KekAuthorityConfig::KindTest => {
            tracing::warn!("using the Kind-only credential KEK test provider");
            let test = Arc::new(codewire_protected_store::secret_envelope::TestKekProvider);
            crate::authority::RuntimeKekAuthorities::new(test.clone(), test)
        }
    };
    // The platform process serves many environments. Resolve the finite product
    // destination families; each operation still requires its exact profile lease.
    // This long-lived process is the only broker that keeps provider
    // connections alive between requests; per-environment brokers do not.
    let upstream = ProviderHttpsTransport::resolve_pooled(&std::collections::BTreeSet::from([
        HttpProvider::OpenAiApiKey,
        HttpProvider::CodexOAuth,
        HttpProvider::AnthropicApiKey,
        HttpProvider::GitHubOAuth,
    ]))
    .await
    .map_err(|_| RuntimeError::Provider)?;
    // Browser App authorization has a separate fixed transport family. Its
    // owner is composed privately into the credential broker solely for
    // durable refresh; guest requests still cannot reach its OAuth exchange
    // or account-discovery endpoints.
    let github_app_authorization = match config.github_app_authorization {
        Some(config) => Some(Arc::new(GitHubAppAuthorizationOwner::new(
            config,
            Arc::new(
                ProviderHttpsTransport::resolve(&std::collections::BTreeSet::from([
                    HttpProvider::GitHubAppAuthorization,
                ]))
                .await
                .map_err(|_| RuntimeError::Provider)?,
            ),
        ))),
        None => None,
    };
    let enrollment = enrollment_config(config.codex_executable, config.runtime_directory.clone())?;
    let github = github_enrollment_config(config.github_executable, &config.runtime_directory)?;
    let store = authorities.credential_store(pool.clone());
    // Idle rotating OAuth credentials are refreshed by this same process,
    // through the same journal, transport and App owner as on-demand refresh.
    let keepalive = config.oauth_keepalive.map(|keepalive| {
        Arc::new(OAuthKeepAlive::new(
            store.clone(),
            Arc::new(upstream.clone()),
            github_app_authorization.clone(),
            keepalive,
        ))
    });
    let repositories = Arc::new(GithubRepositoryOwner::new(
        pool.clone(),
        store.clone(),
        Arc::new(upstream.clone()),
        github_app_authorization.clone(),
    ));
    let bridge = PlatformCredentialBridgeService::new(
        Arc::new(authorities.kubernetes_authenticator(client, pool.clone())),
        store.clone(),
        PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog()),
        upstream,
    );
    let bridge = match &github_app_authorization {
        Some(owner) => bridge
            .with_github_app_authorization_owner(owner.clone())
            .map_err(|_| RuntimeError::Configuration("GitHub App authorization owner"))?,
        None => bridge,
    };
    let bridge = ssh::configure(bridge, &config.runtime_directory)?;
    let mutation = Arc::new(CredentialMutationOwner::new(
        pool.clone(),
        store,
        CodexEnrollmentOwner::new(enrollment),
        GitHubEnrollmentOwner::new(github),
        github_app_authorization,
    ));
    serve_owned(
        Listeners {
            public: config.public_listen,
            public_origin: config.public_origin,
            private: config.private_listen,
            tls: config.private_tls,
        },
        pool,
        authorities.delegation_provider(),
        mutation,
        repositories,
        bridge,
        keepalive,
        shutdown,
    )
    .await
}

fn github_enrollment_config(
    executable: std::path::PathBuf,
    runtime_directory: &std::path::Path,
) -> Result<GitHubEnrollmentConfig, RuntimeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let private = runtime_directory.join("github-enrollment");
        match std::fs::DirBuilder::new().mode(0o700).create(&private) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RuntimeError::Enrollment),
        }
        GitHubEnrollmentConfig::new(executable, private, "/usr/bin:/bin".into())
            .map_err(|_| RuntimeError::Enrollment)
    }
    #[cfg(not(unix))]
    {
        let _ = (executable, runtime_directory);
        Err(RuntimeError::Enrollment)
    }
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
    public_origin: http::HeaderValue,
    private: std::net::SocketAddr,
    tls: ServerTlsFiles,
}

// Generic dependency composition stays private. Synthetic tests can exercise
// these exact listeners/owners without adding production fixture switches.
// Every owner is an explicit argument so one place shows its start and drain.
#[allow(clippy::too_many_arguments)]
async fn serve_owned<A, U>(
    listeners: Listeners,
    pool: PgPool,
    provider: Arc<dyn KekProvider>,
    mutation: Arc<CredentialMutationOwner>,
    repositories: Arc<GithubRepositoryOwner>,
    bridge: PlatformCredentialBridgeService<A, U>,
    keepalive: Option<Arc<OAuthKeepAlive>>,
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
        let delegation = crate::delegation::router(pool.clone(), provider, bridge.clone());
        let app = AppBuilder::new("codewire-credential-service")
            .with_routes(delegation)
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
                ConnectAuthLayer::credential_mutation(
                    AuthState { pool: pool.clone() },
                    listeners.public_origin.clone(),
                ),
            )
            .with_connect_routes_auth(
                repositories.router(),
                ConnectAuthLayer::github_repository(AuthState { pool }, listeners.public_origin),
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
        if let Some(keepalive) = &keepalive {
            keepalive.start();
        }
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
    // Close all admission owners synchronously before allowing transport
    // grace. Then join every owner, including active blocking refresh tasks.
    mutation.start_shutdown();
    repositories.start_shutdown();
    bridge.start_shutdown();
    if let Some(keepalive) = &keepalive {
        keepalive.start_shutdown();
    }
    stop.cancel();
    let (mutation_result, (), bridge_result, (), ()) = tokio::join!(
        mutation.shutdown(),
        repositories.shutdown(),
        bridge.shutdown(),
        async {
            // A keep-alive refresh past `begin` reaches its terminal outcome.
            if let Some(keepalive) = &keepalive {
                keepalive.shutdown().await;
            }
        },
        async {
            if tokio::time::timeout(TRANSPORT_GRACE, async {
                while servers.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                servers.shutdown().await;
            }
        }
    );
    result
        .and(mutation_result.map_err(|_| RuntimeError::Cleanup))
        .and(bridge_result.map_err(|_| RuntimeError::Cleanup))
}
