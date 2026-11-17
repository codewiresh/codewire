use super::*;

const KEY: &str = "0f0f";

fn user(id: &str) -> Principal {
    Principal::User(id.to_owned())
}

async fn bound(store: &dyn BindingStore) -> Binding {
    store
        .get(KEY)
        .await
        .unwrap()
        .expect("a live binding")
        .binding
}

/// Another signed-in user announcing the key under a session of its own.
async fn intrude(store: &dyn BindingStore, env: Uuid) -> Claim {
    claim(store, KEY, &user("intruder"), env, Uuid::new_v4())
        .await
        .unwrap()
}

/// Spec: another principal is refused while the key's session is live and
/// for the binding's seven days after it ends; then the key is free.
#[tokio::test(start_paused = true)]
async fn another_principal_is_refused_while_live_and_for_the_ttl_after_the_end() {
    let store = MemoryBindings::default();
    let env = Uuid::new_v4();
    let (owner, holder) = (user("owner"), Uuid::new_v4());
    assert_eq!(
        claim(&store, KEY, &owner, env, holder).await.unwrap(),
        Claim::Bound
    );

    assert_eq!(
        intrude(&store, env).await,
        Claim::Refused(Refusal::BoundElsewhere)
    );

    release(&store, KEY, holder).await.unwrap();
    assert_eq!(bound(&store).await.session, None);
    tokio::time::advance(NODE_BINDING_TTL - Duration::from_secs(60)).await;
    assert_eq!(
        intrude(&store, env).await,
        Claim::Refused(Refusal::BoundElsewhere)
    );

    tokio::time::advance(Duration::from_secs(120)).await;
    assert_eq!(intrude(&store, env).await, Claim::Bound);
}

/// Spec: the same principal announcing the key from another environment is
/// refused; an environment's daemon is a principal of its own.
#[tokio::test]
async fn the_same_principal_from_another_environment_is_refused() {
    let store = MemoryBindings::default();
    let (env, other_env) = (Uuid::new_v4(), Uuid::new_v4());
    claim(&store, KEY, &user("owner"), env, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(
        claim(&store, KEY, &user("owner"), other_env, Uuid::new_v4())
            .await
            .unwrap(),
        Claim::Refused(Refusal::BoundElsewhere)
    );
    assert_eq!(
        claim(
            &store,
            KEY,
            &Principal::Environment(env),
            env,
            Uuid::new_v4()
        )
        .await
        .unwrap(),
        Claim::Refused(Refusal::BoundElsewhere)
    );
}

/// Spec: a session that ended (here, gone silent) leaves the binding to its
/// principal, whose next session in the same environment binds it again.
#[tokio::test]
async fn the_owner_reconnects_after_its_session_ended() {
    let store = MemoryBindings::default();
    let env = Uuid::new_v4();
    let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
    claim(&store, KEY, &user("owner"), env, first)
        .await
        .unwrap();
    release(&store, KEY, first).await.unwrap();

    assert_eq!(
        claim(&store, KEY, &user("owner"), env, second)
            .await
            .unwrap(),
        Claim::Bound
    );
    assert_eq!(bound(&store).await.session, Some(second));
}

/// Spec: a takeover retires the older session, and that session's late end
/// leaves its successor's binding alone.
#[tokio::test]
async fn a_late_release_after_a_takeover_leaves_the_successor_bound() {
    let store = MemoryBindings::default();
    let env = Uuid::new_v4();
    let (old, new) = (Uuid::new_v4(), Uuid::new_v4());
    claim(&store, KEY, &user("owner"), env, old).await.unwrap();
    assert_eq!(
        claim(&store, KEY, &user("owner"), env, new).await.unwrap(),
        Claim::TookOver { previous: old }
    );

    release(&store, KEY, old).await.unwrap();
    assert_eq!(bound(&store).await.session, Some(new));
    // The retired session's own refresh finds it is no longer named.
    assert_eq!(refresh(&store, KEY, old).await.unwrap(), Refresh::Lost);
    assert_eq!(refresh(&store, KEY, new).await.unwrap(), Refresh::Kept);
}

/// Spec: a live session's hourly rewrite keeps its binding past the first
/// TTL, so another principal is still refused; without it, the key frees.
#[tokio::test(start_paused = true)]
async fn the_hourly_refresh_keeps_a_live_binding_past_its_first_ttl() {
    let env = Uuid::new_v4();
    let holder = Uuid::new_v4();
    let refreshed = MemoryBindings::default();
    let unrefreshed = MemoryBindings::default();
    for store in [&refreshed, &unrefreshed] {
        claim(store, KEY, &user("owner"), env, holder)
            .await
            .unwrap();
    }
    let mut elapsed = Duration::ZERO;
    while elapsed <= NODE_BINDING_TTL {
        tokio::time::advance(NODE_BINDING_REFRESH).await;
        elapsed += NODE_BINDING_REFRESH;
        assert_eq!(
            refresh(&refreshed, KEY, holder).await.unwrap(),
            Refresh::Kept
        );
    }

    assert_eq!(
        intrude(&refreshed, env).await,
        Claim::Refused(Refusal::BoundElsewhere)
    );
    assert_eq!(intrude(&unrefreshed, env).await, Claim::Bound);
}

/// A store whose reads both complete before either racer writes.
struct Racing {
    inner: MemoryBindings,
    reads: tokio::sync::Barrier,
}

impl BindingStore for Racing {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Stored>, BindingError>> {
        Box::pin(async move {
            let read = self.inner.get(key).await;
            self.reads.wait().await;
            read
        })
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
    ) -> BoxFuture<'a, Result<Write, BindingError>> {
        self.inner.create(key, binding)
    }

    fn update<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
        revision: u64,
    ) -> BoxFuture<'a, Result<Write, BindingError>> {
        self.inner.update(key, binding, revision)
    }
}

/// Spec: of two sessions racing for one key, exactly one wins and the loser
/// is refused rather than overwriting, for a free key and an ended binding.
#[tokio::test]
async fn racing_claims_leave_exactly_one_winner() {
    let env = Uuid::new_v4();
    for ended_first in [false, true] {
        let store = Racing {
            inner: MemoryBindings::default(),
            reads: tokio::sync::Barrier::new(2),
        };
        if ended_first {
            let earlier = Uuid::new_v4();
            claim(&store.inner, KEY, &user("owner"), env, earlier)
                .await
                .unwrap();
            release(&store.inner, KEY, earlier).await.unwrap();
        }
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let owner = user("owner");
        let (claim_a, claim_b) = tokio::join!(
            claim(&store, KEY, &owner, env, a),
            claim(&store, KEY, &owner, env, b),
        );
        let outcomes = [claim_a.unwrap(), claim_b.unwrap()];
        let winners: Vec<Uuid> = [a, b]
            .into_iter()
            .zip(outcomes)
            .filter(|(_, outcome)| *outcome == Claim::Bound)
            .map(|(session, _)| session)
            .collect();
        assert_eq!(winners.len(), 1, "{outcomes:?}");
        assert!(
            outcomes.contains(&Claim::Refused(Refusal::LostRace)),
            "{outcomes:?}"
        );
        assert_eq!(bound(&store.inner).await.session, Some(winners[0]));
    }
}

/// The KV bucket's compare-and-set paths: create only when absent, update
/// only at the revision read, and the rules over both.
#[tokio::test]
#[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
async fn kv_bindings_compare_and_set_against_jetstream() {
    let nats_url =
        std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
    let replicas = std::env::var("NATS_KV_REPLICAS").map_or(1, |raw| raw.parse().unwrap());
    let client = async_nats::connect(nats_url).await.unwrap();
    let plane = crate::CoordinationPlane::setup(client, replicas)
        .await
        .unwrap();
    let store = &plane.node_bindings;
    let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let env = Uuid::new_v4();
    let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
    let binding = |session| Binding {
        principal: user("owner"),
        environment: env,
        session,
    };

    assert!(store.get(&key).await.unwrap().is_none());
    assert_eq!(
        claim(store, &key, &user("owner"), env, first)
            .await
            .unwrap(),
        Claim::Bound
    );
    assert_eq!(
        store.create(&key, &binding(Some(second))).await.unwrap(),
        Write::Conflict
    );
    let stale = store.get(&key).await.unwrap().unwrap().revision;
    assert_eq!(refresh(store, &key, first).await.unwrap(), Refresh::Kept);
    assert_eq!(
        store
            .update(&key, &binding(Some(second)), stale)
            .await
            .unwrap(),
        Write::Conflict
    );
    assert_eq!(
        claim(store, &key, &user("intruder"), env, Uuid::new_v4())
            .await
            .unwrap(),
        Claim::Refused(Refusal::BoundElsewhere)
    );
    assert_eq!(
        claim(store, &key, &user("owner"), env, second)
            .await
            .unwrap(),
        Claim::TookOver { previous: first }
    );
    release(store, &key, first).await.unwrap();
    assert_eq!(
        store.get(&key).await.unwrap().unwrap().binding,
        binding(Some(second))
    );
    release(store, &key, second).await.unwrap();
    assert_eq!(
        store.get(&key).await.unwrap().unwrap().binding,
        binding(None)
    );

    store.0.purge(&key).await.unwrap();
    assert!(store.get(&key).await.unwrap().is_none());
    assert_eq!(
        claim(store, &key, &user("intruder"), env, Uuid::new_v4())
            .await
            .unwrap(),
        Claim::Bound
    );
    store.0.purge(&key).await.unwrap();
}
