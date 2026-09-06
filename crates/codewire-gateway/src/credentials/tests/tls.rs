//! Real TLS private-RPC tests using only per-test synthetic service identities.
use super::*;
use crate::credentials::tls_test_support::Identity;

#[tokio::test]
async fn tls_admissions_reload_roots_and_never_reuse_a_previous_private_channel() {
    let mut h = Harness::with_tls(false, true).await;
    let pending = h.submit(request(WORKSPACE_ONE));
    let mut original = h.call().await;
    original.accept();
    let forwarded = original.request().await;
    assert_eq!(forwarded.path, "/responses");
    assert_eq!(original.workspace, WORKSPACE_ONE.as_bytes());
    original.start(&forwarded.request_id).await;
    let response = bounded(pending).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A malformed current root must deny a new call even while the original
    // channel is healthy. Neither native roots nor cached trust may rescue it.
    let roots = h.directory.path().join("broker-roots.pem");
    std::fs::write(&roots, "synthetic-invalid-root-canary").unwrap();
    let denied = bounded(h.ingress.respond(request(WORKSPACE_TWO))).await;
    assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        bounded(to_bytes(denied.into_body(), 1024))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.calls.try_recv().is_err());

    // A changed server identity under another root independently rejects new
    // calls. Keeping the old connection would incorrectly admit this request.
    let identity = h.tls.as_ref().unwrap();
    std::fs::write(&roots, &identity.root_pem).unwrap();
    let rotated = Identity::new("localhost");
    std::fs::copy(&rotated.certificate, &identity.certificate).unwrap();
    std::fs::copy(&rotated.key, &identity.key).unwrap();
    let denied = bounded(h.ingress.respond(request(WORKSPACE_TWO))).await;
    assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(h.calls.try_recv().is_err());

    std::fs::write(&roots, &rotated.root_pem).unwrap();
    std::fs::write(h.directory.path().join("token"), GATEWAY_TWO).unwrap();
    let pending = h.submit(request(WORKSPACE_TWO));
    let mut current = h.call().await;
    assert_eq!(current.gateway, format!("Bearer {GATEWAY_TWO}"));
    assert_eq!(current.workspace, WORKSPACE_TWO.as_bytes());
    current.accept();
    let forwarded = current.request().await;
    current.start(&forwarded.request_id).await;
    let current_response = bounded(pending).await.unwrap();
    assert_eq!(current_response.status(), StatusCode::OK);

    // Shutdown owns both outgoing transports even with HTTP response owners
    // and both private response senders deliberately retained by the fixture.
    bounded(h.ingress.shutdown()).await;
    original.closed().await;
    current.closed().await;
    drop((response, current_response));
    h.stop().await;
}

#[tokio::test]
async fn tls_name_mismatch_and_plaintext_peer_cannot_admit_projected_identity() {
    let mut h = Harness::with_tls(false, true).await;
    let wrong = Identity::new("other-broker.internal");
    let identity = h.tls.as_ref().unwrap();
    std::fs::copy(&wrong.certificate, &identity.certificate).unwrap();
    std::fs::copy(&wrong.key, &identity.key).unwrap();
    std::fs::write(h.directory.path().join("broker-roots.pem"), &wrong.root_pem).unwrap();
    assert_eq!(
        bounded(h.ingress.respond(request(WORKSPACE_ONE)))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(h.calls.try_recv().is_err());
    h.stop().await;

    let mut plain = Harness::new(false).await;
    // Use the same plaintext test peer only as a negative TLS destination;
    // production still receives an HTTPS endpoint, never a raw Channel.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let identity = Identity::new("localhost");
    let ingress = CredentialIngress::new(
        CredentialIngressConfig::new(
            Uuid::new_v4(),
            7,
            AUTHORITY,
            plain.directory.path().join("token"),
            ClientTlsEndpoint::new(
                format!("https://localhost:{}", address.port()),
                identity.roots.clone(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        bounded(ingress.respond(request(WORKSPACE_ONE)))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(plain.calls.try_recv().is_err());
    bounded(ingress.shutdown()).await;
    bounded(peer).await.unwrap();
    plain.stop().await;
}
