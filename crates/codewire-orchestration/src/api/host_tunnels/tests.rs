use super::*;

const HOST: &str = "5d0c1f3e-2a4b-4c6d-8e9f-0a1b2c3d4e5f";

/// The next tunnel request a session is sent, or a failure after 5 s, so a
/// regression fails the test instead of hanging it.
async fn asked(session: &mut Registration) -> HostOpenTunnel {
    tokio::time::timeout(Duration::from_secs(5), session.requests.recv())
        .await
        .expect("a tunnel request within 5 s")
        .expect("the session's request channel is open")
}

fn target() -> TunnelTarget {
    TunnelTarget {
        host_id: HOST.into(),
        environment_id: "3fa85f64-5717-4562-b3fc-2c963f66afa6".into(),
        local_environment_id: "9b2e7c1a-0d4f-4e8b-a6c3-5f1d2e3a4b5c".into(),
        generation: 4,
    }
}

#[tokio::test]
async fn a_host_with_no_session_here_cannot_be_reached() {
    let tunnels = HostTunnels::new();
    assert!(matches!(
        tunnels.open(&target()).await,
        Err(TunnelError::HostNotHere)
    ));
}

/// The session is asked for the tunnel with a fresh nonce; the host's
/// stream claims it once, and the caller gets what the stream hands over.
#[tokio::test]
async fn a_tunnel_is_asked_of_the_session_and_claimed_once() {
    let tunnels = HostTunnels::new();
    let mut session = tunnels.register(HOST, 1);
    let opening = tokio::spawn({
        let tunnels = Arc::clone(&tunnels);
        async move { tunnels.open(&target()).await }
    });
    let request = asked(&mut session).await;
    assert_eq!(request.environment_id, target().environment_id);
    assert_eq!(request.local_environment_id, target().local_environment_id);
    assert_eq!(request.generation, 4);
    assert_eq!(
        request.kind.as_known(),
        Some(HostTunnelKind::HOST_TUNNEL_KIND_DAEMON_GRPC)
    );
    assert_eq!(request.nonce.len(), NONCE_BYTES);

    let pending = tunnels.take_pending(&request.tunnel_id).unwrap();
    assert_eq!(pending.host_id, HOST);
    assert_eq!(pending.nonce.as_slice(), request.nonce.as_slice());
    assert!(
        tunnels.take_pending(&request.tunnel_id).is_none(),
        "claimed once"
    );
    let (_ours, theirs) = tokio::io::duplex(8);
    assert!(
        pending
            .opened
            .send(Ok(OpenedTunnel {
                stream: theirs,
                daemon_capability: Zeroizing::new("capability".into()),
            }))
            .is_ok()
    );
    let opened = opening.await.unwrap().unwrap();
    assert_eq!(opened.daemon_capability.as_str(), "capability");
}

#[tokio::test(start_paused = true)]
async fn a_tunnel_not_opened_in_time_times_out_and_cannot_be_claimed_after() {
    let tunnels = HostTunnels::new();
    let mut session = tunnels.register(HOST, 1);
    let opening = tokio::spawn({
        let tunnels = Arc::clone(&tunnels);
        async move { tunnels.open(&target()).await }
    });
    let request = asked(&mut session).await;
    tokio::time::advance(Duration::from_secs(TUNNEL_OPEN_SECS + 1)).await;
    assert!(matches!(opening.await.unwrap(), Err(TunnelError::TimedOut)));
    assert!(tunnels.take_pending(&request.tunnel_id).is_none());
}

/// A tunnel lives no longer than the session that asked for it.
#[tokio::test]
async fn a_session_that_ends_takes_its_tunnels_with_it() {
    let tunnels = HostTunnels::new();
    let mut session = tunnels.register(HOST, 1);
    let opening = tokio::spawn({
        let tunnels = Arc::clone(&tunnels);
        async move { tunnels.open(&target()).await }
    });
    let request = asked(&mut session).await;
    let pending = tunnels.take_pending(&request.tunnel_id).unwrap();
    let ended = pending.session.clone();
    drop(session);
    assert!(ended.is_cancelled(), "the tunnel's session ended");
    drop(pending);
    assert!(matches!(
        opening.await.unwrap(),
        Err(TunnelError::HostNotHere)
    ));
    assert!(matches!(
        tunnels.open(&target()).await,
        Err(TunnelError::HostNotHere)
    ));
}

/// Tunnels go through the host's newest session; an older one ending does
/// not take the newer one's place away.
#[tokio::test]
async fn the_newest_session_carries_the_hosts_tunnels() {
    let tunnels = HostTunnels::new();
    let older = tunnels.register(HOST, 1);
    let mut newer = tunnels.register(HOST, 2);
    // A late registration of an older session changes nothing.
    let stale = tunnels.register(HOST, 1);
    drop(stale);
    drop(older);
    let opening = tokio::spawn({
        let tunnels = Arc::clone(&tunnels);
        async move { tunnels.open(&target()).await }
    });
    let request = asked(&mut newer).await;
    assert!(tunnels.take_pending(&request.tunnel_id).is_some());
    opening.abort();
}

/// A caller that gives up on `open` before the host answers, as a connect
/// timeout does, leaves no pending tunnel behind.
#[tokio::test]
async fn a_dropped_open_leaves_no_pending_tunnel() {
    let tunnels = HostTunnels::new();
    let mut session = tunnels.register(HOST, 1);
    let opening = tokio::spawn({
        let tunnels = Arc::clone(&tunnels);
        async move { tunnels.open(&target()).await }
    });
    let request = asked(&mut session).await;
    assert!(tunnels.pending_proof(&request.tunnel_id).is_some());
    opening.abort();
    assert!(opening.await.is_err_and(|error| error.is_cancelled()));
    assert!(tunnels.pending_proof(&request.tunnel_id).is_none());
    assert!(tunnels.take_pending(&request.tunnel_id).is_none());
}

/// Reading a pending tunnel's proof inputs doesn't take it.
#[tokio::test]
async fn reading_a_pending_proof_leaves_the_tunnel() {
    let tunnels = HostTunnels::new();
    let mut session = tunnels.register(HOST, 1);
    let _opening = tokio::spawn({
        let tunnels = Arc::clone(&tunnels);
        async move { tunnels.open(&target()).await }
    });
    let request = asked(&mut session).await;
    let (host, nonce) = tunnels.pending_proof(&request.tunnel_id).unwrap();
    assert_eq!(host, HOST);
    assert_eq!(nonce.as_slice(), request.nonce.as_slice());
    assert!(tunnels.take_pending(&request.tunnel_id).is_some());
}
