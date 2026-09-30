//! Actual HTTPS runtime and private TLS stream ownership, with synthetic PKI.
use super::*;
use crate::config::*;
use crate::credentials::tests::Harness as Broker;
use crate::credentials::tls_test_support::Identity;
use std::collections::BTreeMap;

const BOUND: Duration = Duration::from_secs(10);

async fn bounded<F: Future>(future: F) -> F::Output {
    timeout(BOUND, future)
        .await
        .expect("bounded credential runtime fixture")
}

async fn configured(
    broker: &Broker,
    identity: &Identity,
    daemon: String,
) -> (
    GatewayConfig,
    TcpListener,
    TcpListener,
    String,
    tempfile::TempDir,
) {
    let ssh = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ready = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let credential_address = reserve_local_addr().await;
    let authority = format!(
        "localhost:{}",
        credential_address.rsplit_once(':').unwrap().1
    );
    let (environment, token, origin, roots) = broker.runtime_coordinates();
    let host = tempfile::tempdir().unwrap();
    let vars = BTreeMap::from([
        (DAEMON_AUTH_TOKEN_ENV, "synthetic-runtime-daemon".into()),
        (SHIM_ADDR_ENV, daemon),
        (
            SSH_HOST_KEY_PATH_ENV,
            host.path().join("host_ed25519").display().to_string(),
        ),
        (ENVIRONMENT_ID_ENV, environment.to_string()),
        (ENVIRONMENT_OPERATION_GENERATION_ENV, "7".into()),
        (CREDENTIAL_HTTPS_AUTHORITY_ENV, authority.clone()),
        (CREDENTIAL_HTTPS_LISTEN_ADDR_ENV, "127.0.0.1:8443".into()),
        (
            CREDENTIAL_GATEWAY_TOKEN_FILE_ENV,
            token.display().to_string(),
        ),
        (
            CREDENTIAL_TLS_CERT_FILE_ENV,
            identity.certificate.display().to_string(),
        ),
        (
            CREDENTIAL_TLS_KEY_FILE_ENV,
            identity.key.display().to_string(),
        ),
        (CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV, origin),
        (
            CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV,
            roots.display().to_string(),
        ),
    ]);
    let mut config = GatewayConfig::from_getenv(|name| vars.get(name).cloned()).unwrap();
    // Production parsing still requires port8443. Only this in-process fixture
    // moves its private config to an ephemeral listener to avoid host collisions.
    config.credentials.as_mut().unwrap().listen_addr = credential_address.parse().unwrap();
    (
        config,
        ssh,
        ready,
        format!("https://{authority}/v1/responses"),
        host,
    )
}

async fn request_after_listen(client: reqwest::Client, url: String) -> reqwest::Response {
    let parsed = url::Url::parse(&url).unwrap();
    wait_for_tcp(&format!("127.0.0.1:{}", parsed.port().unwrap())).await;
    bounded(
        client
            .post(url)
            .bearer_auth("workspace.projected.runtime")
            .json(&serde_json::json!({}))
            .send(),
    )
    .await
    .unwrap()
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
async fn https_runtime_keeps_ssh_ready_and_drains_an_unconsumed_stream_before_exit() {
    let mut broker = Broker::with_tls(false, true).await;
    let identity = Identity::new("localhost");
    let daemon = spawn_minimal_daemon().await;
    let (config, ssh, ready, url, _host) = configured(&broker, &identity, daemon).await;
    let ready_address = ready.local_addr().unwrap().to_string();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(run_gateway_with_listeners(config, ssh, ready, async move {
        let _ = stopped.await;
    }));
    let response = tokio::spawn(request_after_listen(identity.client(), url));
    let mut call = broker.call().await;
    call.accept();
    let request = call.request().await;
    assert_eq!(request.path, "/responses");
    call.start(&request.request_id).await;
    let response = bounded(response).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    wait_for_readyz_ok(&ready_address).await;
    // Retain the unconsumed HTTP body and private response writer. Graceful
    // HTTP waiting before ingress cancellation would hang this shutdown.
    stop.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
    call.closed().await;
    drop(response);
    broker.stop().await;
}

#[tokio::test]
async fn runtime_startup_failure_drains_live_credential_transport() {
    let mut broker = Broker::with_tls(false, true).await;
    let identity = Identity::new("localhost");
    let daemon = reserve_local_addr().await;
    let (mut config, ssh, ready, url, host) = configured(&broker, &identity, daemon.clone()).await;
    // The HTTPS owner starts while the gateway still waits for its daemon.
    // Once the daemon listens, a real host-key failure causes the normal
    // error return, not an injected shutdown hook.
    let not_a_directory = host.path().join("not-a-directory");
    std::fs::write(&not_a_directory, "").unwrap();
    config.host_key_path = not_a_directory.join("host_ed25519").display().to_string();
    let task = tokio::spawn(run_gateway_with_listeners(
        config,
        ssh,
        ready,
        std::future::pending(),
    ));
    let response = tokio::spawn(request_after_listen(identity.client(), url));
    let mut call = broker.call().await;
    call.accept();
    let request = call.request().await;
    call.start(&request.request_id).await;
    let response = bounded(response).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        !task.is_finished(),
        "gateway exited while waiting for its daemon"
    );
    spawn_minimal_daemon_at(&daemon).await;
    let error = bounded(task).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("load host key"), "{error:#}");
    call.closed().await;
    drop(response);
    broker.stop().await;
}

#[tokio::test]
async fn runtime_rejects_invalid_tls_before_readiness_and_drops_shutdown_future() {
    let broker = Broker::with_tls(false, true).await;
    let identity = Identity::new("localhost");
    let (config, ssh, ready, _url, _host) = configured(&broker, &identity, "http://[".into()).await;
    let ready_address = ready.local_addr().unwrap();
    std::fs::write(&identity.key, "synthetic-invalid-private-key-canary").unwrap();
    let (sender, receiver) = oneshot::channel::<()>();
    let result = bounded(run_gateway_with_listeners(config, ssh, ready, async move {
        let _ = receiver.await;
    }))
    .await;
    let error = result.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("synthetic-invalid-private-key-canary"));
    assert!(
        error
            .to_string()
            .contains("credential server TLS unavailable")
    );
    assert!(
        sender.is_closed(),
        "shutdown future outlived failed runtime"
    );
    assert!(TcpStream::connect(ready_address).await.is_err());
    broker.stop().await;
}

#[tokio::test]
async fn https_runtime_rejects_untrusted_clients_and_reloads_its_server_identity() {
    let broker = Broker::with_tls(false, true).await;
    let identity = Identity::new("localhost");
    let daemon = spawn_minimal_daemon().await;
    let (config, ssh, ready, url, _host) = configured(&broker, &identity, daemon).await;
    let ready_address = ready.local_addr().unwrap().to_string();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(run_gateway_with_listeners(config, ssh, ready, async move {
        let _ = stopped.await;
    }));
    let parsed = url::Url::parse(&url).unwrap();
    wait_for_tcp(&format!("127.0.0.1:{}", parsed.port().unwrap())).await;
    wait_for_readyz_ok(&ready_address).await;
    // No authorization means a successfully authenticated TLS connection must
    // reach the closed HTTP admission path without contacting the broker.
    assert_eq!(
        bounded(identity.client().post(&url).send())
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(ready_status(&ready_address).await, reqwest::StatusCode::OK);
    let (_, _, _, broker_roots) = broker.runtime_coordinates();
    for path in [&identity.key, &broker_roots] {
        let original = std::fs::read(path).unwrap();
        std::fs::write(path, "synthetic-invalid-readiness-projection").unwrap();
        assert_eq!(
            ready_status(&ready_address).await,
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        std::fs::write(path, original).unwrap();
        assert_eq!(ready_status(&ready_address).await, reqwest::StatusCode::OK);
    }
    let rotated = Identity::new("localhost");
    assert!(bounded(rotated.client().post(&url).send()).await.is_err());
    std::fs::copy(&rotated.certificate, &identity.certificate).unwrap();
    std::fs::copy(&rotated.key, &identity.key).unwrap();
    assert!(bounded(identity.client().post(&url).send()).await.is_err());
    assert_eq!(
        bounded(rotated.client().post(&url).send())
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    stop.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
    broker.stop().await;
}
