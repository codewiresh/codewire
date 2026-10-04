//! Reuse of decrypted provider material within one platform broker bridge
//! epoch (hosted or owner-local delegation).
//!
//! The platform broker owns one [`EpochMaterialCache`] per bridge epoch and
//! drops it with the epoch. It is never process-wide or persistent. A value
//! is keyed by the whole [`CredentialRecord`] it was read under: owner, id,
//! provider, authentication kind, status, expiry and both generations, which
//! together cover every input to the envelope's associated data. Revocation,
//! replacement, refresh and Reconnect change a generation, so a value filled
//! for an earlier record can never match a later one.
//!
//! The cache authorizes nothing, and reuses a value only for the record its
//! caller admitted for this use. A hosted epoch's lease rereads its
//! credential's record and admits it against the epoch's authority decision,
//! which it evaluates again whenever that record changed and reuses for at
//! most a minute; a lease with full per-request checks (owner-local
//! delegation) still runs every authority, grant and record check before and
//! after the reuse. Either way the admitted record must equal this key. A hit
//! never extends a value's life: every method drops values older than
//! [`MATERIAL_REUSE_TTL`], and while any value remains, one sweeper task per
//! cache drops each at its expiry even if the epoch makes no further call.
//! Dropping the cache drops every value at once and stops its sweeper.

use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use codewire_access::CredentialId;
use codewire_protected_store::ProtectedValue;
use tokio::task::AbortHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::CredentialRecord;

/// Hard lifetime of one retained value, counted from its fill.
pub const MATERIAL_REUSE_TTL: Duration = Duration::from_secs(120);
/// Values one epoch retains at once.
pub const MAX_REUSED_MATERIALS: usize = 8;
/// Larger values are read through on every use and never retained. API keys
/// are at most 1 KiB, a GitHub App bundle holds two tokens of at most 4 KiB,
/// and a Codex ChatGPT bundle is a few KiB of JWTs.
pub const MAX_REUSED_MATERIAL_BYTES: usize = 16 * 1024;

/// One epoch's decrypted values, each copied out per use. Deliberately not
/// `Clone`, `Debug`, `Default` or serializable: only an epoch's admission
/// creates one, and no copy of it, or a description of it, can leave that
/// epoch. Every method is synchronous; no lock is held across an await.
pub struct EpochMaterialCache {
    shared: Arc<Mutex<Entries>>,
}

#[derive(Default)]
struct Entries {
    values: Vec<Entry>,
    /// The one task that drops values at their expiry while any remain. It
    /// holds only a weak reference, so it never keeps a value alive.
    sweeper: Option<AbortHandle>,
}

struct Entry {
    record: CredentialRecord,
    filled_at: Instant,
    value: Zeroizing<Box<[u8]>>,
}

impl Entry {
    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.filled_at) < MATERIAL_REUSE_TTL
    }
}

impl Entries {
    fn prune(&mut self, now: Instant) {
        self.values.retain(|entry| entry.live(now));
    }

    fn next_expiry(&self) -> Option<Instant> {
        self.values
            .iter()
            .map(|entry| entry.filled_at + MATERIAL_REUSE_TTL)
            .min()
    }
}

impl EpochMaterialCache {
    // A cache exists only where an epoch is admitted; there is no default one.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Entries {
                values: Vec::with_capacity(MAX_REUSED_MATERIALS),
                sweeper: None,
            })),
        }
    }

    /// A fresh copy of the value filled for exactly `record`, if one was
    /// filled less than [`MATERIAL_REUSE_TTL`] ago.
    pub fn get(&self, record: &CredentialRecord) -> Option<ProtectedValue> {
        let entries = self.entries();
        let entry = entries
            .values
            .iter()
            .find(|entry| entry.record == *record)?;
        ProtectedValue::from_slice(&entry.value).ok()
    }

    /// Retain a copy of `value` for exactly `record`, replacing any value of
    /// the same credential. Values over [`MAX_REUSED_MATERIAL_BYTES`] are not
    /// retained. When the epoch already holds [`MAX_REUSED_MATERIALS`] live
    /// values, the oldest fill is dropped. Inside a Tokio runtime this starts
    /// the cache's sweeper if none is running.
    pub fn fill(&self, record: &CredentialRecord, value: &ProtectedValue) {
        let bytes = value.expose_secret();
        if bytes.len() > MAX_REUSED_MATERIAL_BYTES {
            return;
        }
        let mut entries = self.entries();
        entries
            .values
            .retain(|entry| entry.record.metadata.id != record.metadata.id);
        if entries.values.len() >= MAX_REUSED_MATERIALS
            && let Some(oldest) = entries
                .values
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.filled_at)
                .map(|(index, _)| index)
        {
            entries.values.swap_remove(oldest);
        }
        entries.values.push(Entry {
            record: record.clone(),
            filled_at: Instant::now(),
            value: Zeroizing::new(Box::from(bytes)),
        });
        if entries.sweeper.is_none()
            && let (Ok(runtime), Some(deadline)) =
                (tokio::runtime::Handle::try_current(), entries.next_expiry())
        {
            let sweeper = runtime.spawn(sweep(Arc::downgrade(&self.shared), deadline));
            entries.sweeper = Some(sweeper.abort_handle());
        }
    }

    /// Drop every value of this credential.
    pub fn evict(&self, credential: &CredentialId) {
        self.entries()
            .values
            .retain(|entry| entry.record.metadata.id != *credential);
    }

    /// Keep only values whose credential `keep` accepts. `keep` runs under
    /// the cache's lock and must not call back into it.
    pub fn retain_credentials(&self, keep: impl Fn(&CredentialId) -> bool) {
        self.entries()
            .values
            .retain(|entry| keep(&entry.record.metadata.id));
    }

    /// Drop every value.
    pub fn clear(&self) {
        self.entries().values.clear();
    }

    /// The number of live values.
    pub fn len(&self) -> usize {
        self.entries().values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The locked entries, with every expired value already dropped.
    fn entries(&self) -> MutexGuard<'_, Entries> {
        let mut entries = lock(&self.shared);
        entries.prune(Instant::now());
        entries
    }

    /// The values held right now, without pruning: only the sweeper and the
    /// methods above may have dropped expired ones.
    #[cfg(test)]
    fn held(&self) -> usize {
        lock(&self.shared).values.len()
    }
}

impl Drop for EpochMaterialCache {
    fn drop(&mut self) {
        let mut entries = lock(&self.shared);
        if let Some(sweeper) = entries.sweeper.take() {
            sweeper.abort();
        }
        entries.values.clear();
    }
}

fn lock(shared: &Mutex<Entries>) -> MutexGuard<'_, Entries> {
    // Only `retain_credentials`' predicate runs under this lock. Should a
    // panic ever poison it, retain nothing: every caller then reads through.
    shared.lock().unwrap_or_else(|poisoned| {
        let mut entries = poisoned.into_inner();
        entries.values.clear();
        entries
    })
}

/// Drop each value at its expiry until none remain, then stop. Holding only a
/// weak reference, the task ends at its next wake once its cache is dropped,
/// and the cache's drop aborts it at once.
async fn sweep(shared: Weak<Mutex<Entries>>, mut deadline: Instant) {
    loop {
        tokio::time::sleep_until(deadline).await;
        match sweep_once(&shared) {
            Some(next) => deadline = next,
            None => return,
        }
    }
}

fn sweep_once(shared: &Weak<Mutex<Entries>>) -> Option<Instant> {
    let shared = shared.upgrade()?;
    let mut entries = lock(&shared);
    entries.prune(Instant::now());
    let next = entries.next_expiry();
    if next.is_none() {
        entries.sweeper = None;
    }
    next
}

/// Compile-time proof that the cache implements neither `Clone` nor `Debug`.
/// Each probe is ambiguous, and so fails to compile, if the trait is ever
/// implemented for the type.
const _: () = {
    trait AmbiguousIfClone<A> {
        fn probe() {}
    }
    impl<T> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}
    trait AmbiguousIfDebug<A> {
        fn probe() {}
    }
    impl<T> AmbiguousIfDebug<()> for T {}
    impl<T: std::fmt::Debug> AmbiguousIfDebug<u8> for T {}
    trait AmbiguousIfDefault<A> {
        fn probe() {}
    }
    impl<T> AmbiguousIfDefault<()> for T {}
    impl<T: Default> AmbiguousIfDefault<u8> for T {}
    let _ = <EpochMaterialCache as AmbiguousIfClone<_>>::probe;
    let _ = <EpochMaterialCache as AmbiguousIfDebug<_>>::probe;
    let _ = <EpochMaterialCache as AmbiguousIfDefault<_>>::probe;
};

#[cfg(test)]
mod tests {
    use codewire_access::{
        CredentialAuthKind, CredentialMetadata, CredentialStatus, Owner, OwnerId, Placement,
        ProviderId,
    };

    use super::*;
    use crate::CredentialVersion;

    fn record(id: &str) -> CredentialRecord {
        CredentialRecord {
            metadata: CredentialMetadata {
                id: CredentialId::parse(id).unwrap(),
                placement: Placement::Platform,
                owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::ApiKey,
                display_name: "Synthetic".into(),
                account_hint: None,
                ssh_public_key: None,
                status: CredentialStatus::Active,
                expires_at_unix: None,
                revocation_generation: 1,
            },
            version: CredentialVersion {
                revocation_generation: 1,
                material_generation: 1,
            },
        }
    }

    fn value(bytes: &[u8]) -> ProtectedValue {
        ProtectedValue::from_slice(bytes).unwrap()
    }

    fn reused(cache: &EpochMaterialCache, record: &CredentialRecord) -> Option<Vec<u8>> {
        cache
            .get(record)
            .map(|value| value.expose_secret().to_vec())
    }

    #[test]
    fn the_key_is_the_whole_record() {
        let cache = EpochMaterialCache::new();
        let filled = record("synthetic-credential");
        cache.fill(&filled, &value(b"synthetic-material-never-public"));
        assert_eq!(
            reused(&cache, &filled).as_deref(),
            Some(b"synthetic-material-never-public".as_slice())
        );
        type Change = fn(&mut CredentialRecord);
        let changes: [(&str, Change); 11] = [
            ("id", |r| {
                r.metadata.id = CredentialId::parse("synthetic-other").unwrap()
            }),
            ("owner", |r| {
                r.metadata.owner = Owner::User(OwnerId::parse("synthetic-other").unwrap())
            }),
            ("organization owner", |r| {
                r.metadata.owner = Owner::Organization(OwnerId::parse("synthetic-owner").unwrap())
            }),
            ("provider", |r| {
                r.metadata.provider = ProviderId::parse("anthropic").unwrap()
            }),
            ("kind", |r| {
                r.metadata.authentication_kind = CredentialAuthKind::OAuth
            }),
            ("status", |r| r.metadata.status = CredentialStatus::Revoked),
            ("expiry", |r| r.metadata.expires_at_unix = Some(1)),
            ("metadata revocation", |r| {
                r.metadata.revocation_generation = 2
            }),
            ("revocation", |r| r.version.revocation_generation = 2),
            ("material", |r| r.version.material_generation = 2),
            ("display name", |r| {
                r.metadata.display_name = "Renamed".into()
            }),
        ];
        for (name, change) in changes {
            let mut other = filled.clone();
            change(&mut other);
            assert!(reused(&cache, &other).is_none(), "{name}");
        }
        assert!(reused(&cache, &filled).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn values_expire_two_minutes_after_their_fill_and_hits_do_not_extend_them() {
        let cache = EpochMaterialCache::new();
        let filled = record("synthetic-credential");
        cache.fill(&filled, &value(b"synthetic-material"));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(reused(&cache, &filled).is_some());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(reused(&cache, &filled).is_some(), "a hit at 119 s");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(reused(&cache, &filled).is_none(), "expired at 120 s");
        assert!(cache.is_empty(), "an expired value is dropped");
        // A new fill starts a new lifetime.
        cache.fill(&filled, &value(b"synthetic-material"));
        tokio::time::advance(MATERIAL_REUSE_TTL - Duration::from_millis(1)).await;
        assert!(reused(&cache, &filled).is_some());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(reused(&cache, &filled).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn an_epoch_retains_at_most_eight_values_and_drops_the_oldest_fill() {
        let cache = EpochMaterialCache::new();
        let records: Vec<_> = (0..=MAX_REUSED_MATERIALS)
            .map(|index| record(&format!("synthetic-credential-{index}")))
            .collect();
        for (index, record) in records.iter().enumerate() {
            cache.fill(record, &value(format!("synthetic-{index}").as_bytes()));
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(cache.len(), MAX_REUSED_MATERIALS);
        assert!(reused(&cache, &records[0]).is_none(), "oldest fill dropped");
        for (index, record) in records.iter().enumerate().skip(1) {
            assert_eq!(
                reused(&cache, record),
                Some(format!("synthetic-{index}").into_bytes())
            );
        }
        // A refill of a credential replaces its value; it never adds a second.
        let mut replaced = records[1].clone();
        replaced.version.material_generation = 2;
        cache.fill(&replaced, &value(b"synthetic-replacement"));
        assert_eq!(cache.len(), MAX_REUSED_MATERIALS);
        assert!(reused(&cache, &records[1]).is_none());
        assert_eq!(
            reused(&cache, &replaced).as_deref(),
            Some(b"synthetic-replacement".as_slice())
        );
    }

    #[test]
    fn values_over_sixteen_kibibytes_are_read_through() {
        assert_eq!(MAX_REUSED_MATERIAL_BYTES, 16 * 1024);
        let cache = EpochMaterialCache::new();
        let filled = record("synthetic-credential");
        cache.fill(&filled, &value(&vec![7; MAX_REUSED_MATERIAL_BYTES + 1]));
        assert!(cache.is_empty());
        assert!(reused(&cache, &filled).is_none());
        // A value of exactly the bound is retained.
        cache.fill(&filled, &value(&vec![7; MAX_REUSED_MATERIAL_BYTES]));
        assert_eq!(
            reused(&cache, &filled).map(|bytes| bytes.len()),
            Some(MAX_REUSED_MATERIAL_BYTES)
        );
    }

    #[test]
    fn eviction_drops_only_that_credential() {
        let cache = EpochMaterialCache::new();
        let first = record("synthetic-first");
        let second = record("synthetic-second");
        cache.fill(&first, &value(b"synthetic-first"));
        cache.fill(&second, &value(b"synthetic-second"));
        cache.evict(&first.metadata.id);
        assert!(reused(&cache, &first).is_none());
        assert!(reused(&cache, &second).is_some());
    }

    #[test]
    fn retention_and_clearing_drop_values_by_credential() {
        let cache = EpochMaterialCache::new();
        let first = record("synthetic-first");
        let second = record("synthetic-second");
        cache.fill(&first, &value(b"synthetic-first"));
        cache.fill(&second, &value(b"synthetic-second"));
        cache.retain_credentials(|id| *id == second.metadata.id);
        assert!(reused(&cache, &first).is_none());
        assert!(reused(&cache, &second).is_some());
        cache.clear();
        assert!(cache.is_empty());
    }

    /// Filled outside a runtime, so no sweeper exists: only the call itself
    /// can drop the expired values.
    #[test]
    fn every_method_drops_expired_values() {
        let unrelated = record("synthetic-unrelated");
        for method in ["len", "get", "evict", "retain", "fill"] {
            let cache = EpochMaterialCache::new();
            cache.fill(&record("synthetic-first"), &value(b"synthetic-first"));
            cache.fill(&record("synthetic-second"), &value(b"synthetic-second"));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            runtime.block_on(async {
                tokio::time::advance(MATERIAL_REUSE_TTL).await;
                assert_eq!(cache.held(), 2, "{method}: nothing swept the values");
                match method {
                    "len" => assert_eq!(cache.len(), 0),
                    "get" => assert!(cache.get(&unrelated).is_none()),
                    "evict" => cache.evict(&unrelated.metadata.id),
                    "retain" => cache.retain_credentials(|_| true),
                    "fill" => cache.fill(&unrelated, &value(b"synthetic-unrelated")),
                    _ => unreachable!(),
                }
                let expected = usize::from(method == "fill");
                assert_eq!(cache.held(), expected, "{method} kept an expired value");
            });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_cache_holds_no_expired_value_without_another_call() {
        let cache = EpochMaterialCache::new();
        cache.fill(&record("synthetic-first"), &value(b"synthetic-first"));
        tokio::time::sleep(Duration::from_secs(60)).await;
        cache.fill(&record("synthetic-second"), &value(b"synthetic-second"));
        assert_eq!(cache.held(), 2);
        // From here on only the sweeper touches the cache.
        tokio::time::sleep(Duration::from_secs(61)).await;
        assert_eq!(cache.held(), 1, "the first value outlived its TTL");
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(cache.held(), 0, "the second value outlived its TTL");
        assert_eq!(alive_tasks(), 0, "the sweeper stops once nothing remains");
        // A later fill starts a new sweeper.
        cache.fill(&record("synthetic-third"), &value(b"synthetic-third"));
        assert_eq!(alive_tasks(), 1);
        tokio::time::sleep(MATERIAL_REUSE_TTL).await;
        tokio::task::yield_now().await;
        assert_eq!(cache.held(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_epoch_has_one_sweeper_and_dropping_the_cache_stops_it() {
        let cache = EpochMaterialCache::new();
        for index in 0..MAX_REUSED_MATERIALS * 2 {
            cache.fill(
                &record(&format!("synthetic-credential-{index}")),
                &value(b"synthetic-material"),
            );
        }
        assert_eq!(alive_tasks(), 1);
        drop(cache);
        for _ in 0..10 {
            if alive_tasks() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(alive_tasks(), 0, "a dropped cache left its sweeper running");
    }

    fn alive_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    #[test]
    fn each_use_receives_its_own_copy() {
        let cache = EpochMaterialCache::new();
        let filled = record("synthetic-credential");
        let original = value(b"synthetic-material");
        cache.fill(&filled, &original);
        drop(original);
        let first = cache.get(&filled).unwrap();
        let second = cache.get(&filled).unwrap();
        assert_ne!(
            first.expose_secret().as_ptr(),
            second.expose_secret().as_ptr()
        );
        assert_eq!(first.expose_secret(), second.expose_secret());
    }
}
