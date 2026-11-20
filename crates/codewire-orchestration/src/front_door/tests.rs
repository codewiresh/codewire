use super::*;

fn key() -> BindingKey {
    BindingKey {
        environment_id: Uuid::from_u128(7),
        pod_uid: "pod-uid".into(),
        generation: 3,
    }
}

fn prefixed(length: u32, message: &[u8]) -> Vec<u8> {
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    frame
}

#[test]
fn a_frame_is_exactly_its_length_and_the_message_that_follows() {
    let message = [1_u8, 2, 3];
    let frame = framed(&message).unwrap();
    assert_eq!(frame, prefixed(3, &message));
    assert_eq!(frame_message(&frame), Some(&message[..]));

    let largest = vec![9_u8; CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES];
    assert_eq!(
        frame_message(&framed(&largest).unwrap()),
        Some(&largest[..])
    );
}

#[test]
fn a_frame_whose_length_is_zero_too_large_or_not_its_bytes_is_refused() {
    let max = u32::try_from(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES).unwrap();
    let over = vec![0_u8; CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 1];
    let whole = prefixed(4, &[1, 2, 3, 4]);
    for (case, frame) in [
        ("empty", Vec::new()),
        ("a partial prefix", vec![0, 0, 1]),
        ("a zero length", prefixed(0, &[])),
        ("the maximum plus one", prefixed(max + 1, &over)),
        ("a frame split across two", whole[..6].to_vec()),
        ("the rest of a split frame", whole[6..].to_vec()),
        ("two frames in one", [whole.clone(), whole.clone()].concat()),
        ("trailing bytes", [whole.clone(), vec![0]].concat()),
    ] {
        assert_eq!(frame_message(&frame), None, "{case}");
    }
    assert_eq!(framed(&[]), None);
    assert_eq!(framed(&over), None);
}

#[tokio::test]
async fn the_newest_epoch_of_a_binding_is_current_until_it_ends() {
    let epochs = Arc::new(FrontDoorEpochs::default());
    assert!(epochs.current(&key()).is_none());
    let (first_joins, _first) = mpsc::channel(1);
    let first = epochs.register(key(), first_joins.clone());
    assert!(epochs.current(&key()).unwrap().1.same_channel(&first_joins));

    let first_id = epochs.current(&key()).unwrap().0;
    // A successor admitted during the renewal replaces it at once.
    let (second_joins, _second) = mpsc::channel(1);
    let second = epochs.register(key(), second_joins.clone());
    assert!(
        epochs
            .current(&key())
            .unwrap()
            .1
            .same_channel(&second_joins)
    );
    assert!(
        epochs.current(&key()).unwrap().0 > first_id,
        "a newer epoch has a greater id"
    );

    // The draining epoch ending leaves its successor current.
    drop(first);
    assert!(
        epochs
            .current(&key())
            .unwrap()
            .1
            .same_channel(&second_joins)
    );
    drop(second);
    assert!(epochs.current(&key()).is_none());
}

#[tokio::test]
async fn another_binding_never_finds_an_epoch() {
    let epochs = Arc::new(FrontDoorEpochs::default());
    let (joins, _receiver) = mpsc::channel(1);
    let _registration = epochs.register(key(), joins);
    for other in [
        BindingKey {
            environment_id: Uuid::from_u128(8),
            ..key()
        },
        BindingKey {
            pod_uid: "other-uid".into(),
            ..key()
        },
        BindingKey {
            generation: 4,
            ..key()
        },
    ] {
        assert!(epochs.current(&other).is_none(), "{other:?}");
    }
}

/// #4001: a Pod has one live session. A newer one stops the older, and
/// takes its place only once the older has let go; the older's end frees
/// nothing of the newer's.
#[tokio::test]
async fn a_newer_session_for_a_pod_stops_the_older_and_waits_for_it() {
    let wait = std::time::Duration::from_secs(30);
    let epochs = Arc::new(FrontDoorEpochs::default());
    let first_stop = CancellationToken::new();
    let first = epochs.take_session("pod-a", first_stop.clone(), wait).await;

    let second_stop = CancellationToken::new();
    let taking = tokio::spawn({
        let epochs = Arc::clone(&epochs);
        let stop = second_stop.clone();
        async move { epochs.take_session("pod-a", stop, wait).await }
    });
    first_stop.cancelled().await;
    tokio::task::yield_now().await;
    assert!(!taking.is_finished(), "it waits while the older holds on");
    drop(first);
    let second = tokio::time::timeout(wait, taking).await.unwrap().unwrap();
    assert!(!second_stop.is_cancelled());

    // The older's place is gone without taking the newer's with it, and a
    // newer one still waits on it.
    let third_stop = CancellationToken::new();
    let taking = tokio::spawn({
        let epochs = Arc::clone(&epochs);
        async move { epochs.take_session("pod-a", third_stop, wait).await }
    });
    second_stop.cancelled().await;
    drop(second);
    let _third = tokio::time::timeout(wait, taking).await.unwrap().unwrap();

    // Another Pod's session is its own.
    let other_stop = CancellationToken::new();
    let _other = epochs.take_session("pod-b", other_stop.clone(), wait).await;
    assert!(!other_stop.is_cancelled());
}

/// A newer session that an older one never lets go of joins anyway once its
/// wait is over.
#[tokio::test(start_paused = true)]
async fn a_newer_session_waits_for_the_older_only_so_long() {
    let epochs = Arc::new(FrontDoorEpochs::default());
    let wait = std::time::Duration::from_secs(5);
    let _held = epochs
        .take_session("pod-a", CancellationToken::new(), wait)
        .await;
    let started = tokio::time::Instant::now();
    let _newer = epochs
        .take_session("pod-a", CancellationToken::new(), wait)
        .await;
    assert!(started.elapsed() >= wait);
}
