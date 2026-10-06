//! Credential runtime startup and readiness, with synthetic broker trust.
use super::*;
use crate::config::*;
use crate::credentials::tls_test_support::Identity;
use std::collections::BTreeMap;

const BOUND: Duration = Duration::from_secs(10);

async fn bounded<F: Future>(future: F) -> F::Output {
    timeout(BOUND, future)
        .await
        .expect("bounded credential runtime fixture")
}

async fn configured(
    broker: &Identity,
    daemon: String,
) -> (GatewayConfig, TcpListener, TcpListener, tempfile::TempDir) {
    let ssh = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ready = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = tempfile::tempdir().unwrap();
    let token = host.path().join("gateway-token");
    std::fs::write(&token, "synthetic.gateway.runtime").unwrap();
    let vars = BTreeMap::from([
        (DAEMON_AUTH_TOKEN_ENV, "synthetic-runtime-daemon".into()),
        (SHIM_ADDR_ENV, daemon),
        (
            SSH_HOST_KEY_PATH_ENV,
            host.path().join("host_ed25519").display().to_string(),
        ),
        (ENVIRONMENT_ID_ENV, uuid::Uuid::new_v4().to_string()),
        (ENVIRONMENT_OPERATION_GENERATION_ENV, "7".into()),
        (
            CREDENTIAL_GATEWAY_TOKEN_FILE_ENV,
            token.display().to_string(),
        ),
        // An unavailable destination: nothing here dials the broker.
        (
            CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
            "https://localhost:1".into(),
        ),
        (
            CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV,
            broker.roots.display().to_string(),
        ),
    ]);
    let config = GatewayConfig::from_getenv(|name| vars.get(name).cloned()).unwrap();
    assert!(config.credentials.is_some());
    (config, ssh, ready, host)
}

async fn ready_status(address: &str) -> reqwest::StatusCode {
    bounded(
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/readyz"))
            .send(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn credential_runtime_readiness_follows_current_broker_trust() {
    let broker = Identity::new("localhost");
    let daemon = spawn_minimal_daemon().await;
    let (config, ssh, ready, _host) = configured(&broker, daemon).await;
    let ready_address = ready.local_addr().unwrap().to_string();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(run_gateway_with_listeners(config, ssh, ready, async move {
        let _ = stopped.await;
    }));
    wait_for_readyz_ok(&ready_address).await;
    let original = std::fs::read(&broker.roots).unwrap();
    std::fs::write(&broker.roots, "synthetic-invalid-readiness-projection").unwrap();
    assert_eq!(
        ready_status(&ready_address).await,
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::write(&broker.roots, original).unwrap();
    assert_eq!(ready_status(&ready_address).await, reqwest::StatusCode::OK);
    stop.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn runtime_rejects_invalid_broker_trust_before_readiness_and_drops_shutdown_future() {
    let broker = Identity::new("localhost");
    let (config, ssh, ready, _host) = configured(&broker, "http://[".into()).await;
    let ready_address = ready.local_addr().unwrap();
    std::fs::write(&broker.roots, "synthetic-invalid-broker-roots-canary").unwrap();
    let (sender, receiver) = oneshot::channel::<()>();
    let result = bounded(run_gateway_with_listeners(config, ssh, ready, async move {
        let _ = receiver.await;
    }))
    .await;
    let error = result.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("synthetic-invalid-broker-roots-canary"));
    assert!(
        error
            .to_string()
            .contains("credential broker trust unavailable")
    );
    assert!(
        sender.is_closed(),
        "shutdown future outlived failed runtime"
    );
    assert!(TcpStream::connect(ready_address).await.is_err());
}
