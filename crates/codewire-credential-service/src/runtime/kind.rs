//! Non-promotable Kind libtest entrypoint, never a production runtime switch.
//!
//! The checked-in Kind harness supplies the real Deployment, restricted login,
//! Kubernetes authority, TLS and workspace/gateway topology. Only device login,
//! provider HTTP and the KEK are synthetic. This does not prove live OpenBao or
//! Dev acceptance, and provider counters do not prove native auth-cache rereads
//! or Kubernetes projected-token rotation.

mod config;
mod enrollment;
mod provider;

use super::*;
use codewire_protected_store::secret_envelope::TestKekProvider;

const TARGET: &str = "codewire_kind_credential_fixture";

/// Long-lived services-ci-only listener. The image harness must select this
/// exact ignored test with --nocapture; ordinary crate tests never start it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the managed codewire-e2e Kind fixture Deployment and synthetic restricted DB"]
async fn serve_kind_credential_fixture() -> Result<(), RuntimeError> {
    let config = config::Config::from_env()?;
    // No inherited RUST_LOG can expose SQL, requests, provider material or
    // projected tokens. These two targets emit only closed runtime events.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "off,codewire_kind_credential_fixture=info,codewire_credential_service::runtime=info",
        ))
        .with_current_span(false)
        .try_init()
        .map_err(|_| RuntimeError::Configuration("Kind fixture diagnostics"))?;
    let kube_config = kube::Config::incluster().map_err(|_| RuntimeError::Kubernetes)?;
    if kube_config.default_namespace != config::NAMESPACE {
        return Err(RuntimeError::Configuration("managed Kind namespace"));
    }
    let client = kube::Client::try_from(kube_config).map_err(|_| RuntimeError::Kubernetes)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| RuntimeError::Signal)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| RuntimeError::Signal)?;
    let options = config
        .database_url
        .parse::<PgConnectOptions>()
        .map_err(|_| RuntimeError::Configuration("CREDENTIAL_DATABASE_URL"))?
        .application_name("codewire-kind-credential-fixture")
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
    let result = async {
        config::assert_restricted_login(&pool).await?;
        let provider = provider::SyntheticProvider::new();
        // Keep the private tmpfs fixture alive through both owner drains.
        let (fixture, enrollment) = enrollment::Fixture::create(&config.runtime_directory)?;
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            Arc::new(TestKekProvider),
            builtin_provider_catalog(),
        ));
        let bridge = PlatformCredentialBridgeService::new(
            Arc::new(KubernetesPlatformBridgeAuthenticator::new(
                client,
                pool.clone(),
            )),
            store.clone(),
            PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog()),
            provider.clone(),
        );
        let mutation = Arc::new(CredentialMutationOwner::new(
            pool.clone(),
            store,
            CodexEnrollmentOwner::new(enrollment),
        ));
        tracing::info!(target: TARGET, event = "fixture_starting", "fixture_starting");
        let result = serve_owned(config.listeners, pool.clone(), mutation, bridge, async {
            let signal = tokio::select! {
                value = terminate.recv() => value,
                value = interrupt.recv() => value,
            };
            signal.ok_or(RuntimeError::Signal)
        })
        .await;
        provider.log_totals();
        match result {
            Ok(()) => fixture.close(),
            Err(error) => {
                // A listener/signal error can mask a simultaneous owner
                // cleanup error. Preserve the outer root on every failure,
                // including any homes the enrollment owner retained.
                fixture.retain();
                Err(error)
            }
        }
    }
    .await;
    pool.close().await;
    tracing::info!(target: TARGET, event = "fixture_stopped", success = result.is_ok(), "fixture_stopped");
    result
}
