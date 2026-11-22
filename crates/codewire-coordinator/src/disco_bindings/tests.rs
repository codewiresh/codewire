use super::*;
use crate::node_bindings::{Claim, MemoryBindings, Refusal, SessionBinding};

fn key(byte: u8) -> String {
    disco_hex(&DiscoPublic::from_raw([byte; 32]))
}

fn daemon(store: &Arc<MemoryBindings>, environment: Uuid, session: Uuid) -> SessionBinding {
    SessionBinding::new(
        store.clone(),
        Principal::Environment(environment),
        environment,
        session,
    )
}

async fn seen_from(store: &MemoryBindings, key: &str, environment: Uuid) -> Seen {
    seen(store, key, environment).await.unwrap()
}

/// #5962: a disco key a daemon announced is its environment's own; to any
/// other environment it is bound elsewhere, and a key nobody announced is
/// unbound. A client of the environment is bound elsewhere too, so a daemon
/// can't pass a client's key off as its own.
#[tokio::test]
async fn a_disco_key_is_seen_as_the_environments_own_only_from_its_daemon() {
    let store = Arc::new(MemoryBindings::default());
    let (env, other) = (Uuid::new_v4(), Uuid::new_v4());
    let mut own = daemon(&store, env, Uuid::new_v4());
    assert_eq!(own.claim(key(1)).await.unwrap(), Claim::Bound);
    let mut client = SessionBinding::new(
        store.clone(),
        Principal::User("someone".into()),
        env,
        Uuid::new_v4(),
    );
    assert_eq!(client.claim(key(2)).await.unwrap(), Claim::Bound);

    assert_eq!(seen_from(&store, &key(1), env).await, Seen::Here);
    assert_eq!(seen_from(&store, &key(1), other).await, Seen::Elsewhere);
    assert_eq!(seen_from(&store, &key(2), env).await, Seen::Elsewhere);
    assert_eq!(seen_from(&store, &key(3), env).await, Seen::Unbound);
}

/// #5962: another environment announcing a held disco key is refused, and
/// the holder keeps it. The same environment's new session takes it over.
#[tokio::test]
async fn a_held_disco_key_is_refused_to_another_environment() {
    let store = Arc::new(MemoryBindings::default());
    let (env, other) = (Uuid::new_v4(), Uuid::new_v4());
    let mut own = daemon(&store, env, Uuid::new_v4());
    assert_eq!(own.claim(key(1)).await.unwrap(), Claim::Bound);

    let mut intruder = daemon(&store, other, Uuid::new_v4());
    assert_eq!(
        intruder.claim(key(1)).await.unwrap(),
        Claim::Refused(Refusal::BoundElsewhere)
    );
    assert_eq!(seen_from(&store, &key(1), env).await, Seen::Here);

    let previous = own.session();
    let mut reconnected = daemon(&store, env, Uuid::new_v4());
    assert_eq!(
        reconnected.claim(key(1)).await.unwrap(),
        Claim::TookOver { previous }
    );
    assert_eq!(seen_from(&store, &key(1), env).await, Seen::Here);
}

/// #5962: a node that restarts its tailscale gets a fresh disco key. The new
/// key binds, and the old one stops counting at once, whether the rotation
/// comes in the same session or in a new one after the old session ended.
#[tokio::test]
async fn a_rotated_disco_key_stops_counting_at_once() {
    let store = Arc::new(MemoryBindings::default());
    let env = Uuid::new_v4();
    let mut session = daemon(&store, env, Uuid::new_v4());
    assert_eq!(session.claim(key(1)).await.unwrap(), Claim::Bound);
    assert_eq!(session.claim(key(2)).await.unwrap(), Claim::Bound);
    assert_eq!(seen_from(&store, &key(1), env).await, Seen::Unbound);
    assert_eq!(seen_from(&store, &key(2), env).await, Seen::Here);

    session.release().await;
    assert_eq!(seen_from(&store, &key(2), env).await, Seen::Unbound);
    let mut restarted = daemon(&store, env, Uuid::new_v4());
    assert_eq!(restarted.claim(key(3)).await.unwrap(), Claim::Bound);
    assert_eq!(seen_from(&store, &key(3), env).await, Seen::Here);
    assert_eq!(seen_from(&store, &key(2), env).await, Seen::Unbound);

    // A released key stays its environment's: another one is still refused.
    let mut intruder = daemon(&store, Uuid::new_v4(), Uuid::new_v4());
    assert_eq!(
        intruder.claim(key(2)).await.unwrap(),
        Claim::Refused(Refusal::BoundElsewhere)
    );
}
