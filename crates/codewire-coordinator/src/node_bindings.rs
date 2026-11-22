//! Node keys bound to the principal and environment that announced them
//! (#5120).
//!
//! The rules are in `docs/dev/DERP-STUN.md`, "Coordinator sessions and node
//! keys": the first session to announce a key binds it, only the same
//! principal in the same environment takes it over, and every change is a
//! compare-and-set on the binding's revision, so a session that loses a race
//! is refused and never overwrites the winner. With NATS the bindings live in
//! a KV bucket every replica shares; without it, in the local registry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_nats::jetstream::kv;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use uuid::Uuid;

use super::peer::BoxFuture;

/// Shared bucket of node key bindings, keyed by lowercase hex.
pub(crate) const NODE_BINDING_BUCKET: &str = "coordinator-node-bindings";
/// A binding ages out this long after its last write, as NATS counts it.
pub(crate) const NODE_BINDING_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How often a live session rewrites its binding, well inside the TTL.
pub(crate) const NODE_BINDING_REFRESH: Duration = Duration::from_secs(60 * 60);

/// Who a node key is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Principal {
    /// The signed-in user of a CLI client, by user id.
    User(String),
    /// An environment's own daemon.
    Environment(Uuid),
}

/// One node key's owner, and the session that holds it while one lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Binding {
    pub(crate) principal: Principal,
    pub(crate) environment: Uuid,
    /// The live session holding the key; `None` once that session ended.
    pub(crate) session: Option<Uuid>,
}

/// A binding as read, with the revision a compare-and-set expects.
#[derive(Debug)]
pub(crate) struct Stored {
    pub(crate) binding: Binding,
    pub(crate) revision: u64,
}

/// The result of a compare-and-set write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Write {
    Written,
    /// The key was not in the state the write expected.
    Conflict,
}

/// Why the binding store could not answer.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BindingError {
    #[error("node binding store unavailable")]
    Store(#[source] async_nats::Error),
    #[error("node binding is not readable")]
    Decode(#[from] serde_json::Error),
}

/// The bucket bindings live in. Writes are compare-and-set only.
pub(crate) trait BindingStore: Send + Sync {
    /// The binding for `key`, if one lives.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Stored>, BindingError>>;
    /// Writes `binding` only while no binding lives for `key`.
    fn create<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
    ) -> BoxFuture<'a, Result<Write, BindingError>>;
    /// Writes `binding` only while `key` is still at `revision`.
    fn update<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
        revision: u64,
    ) -> BoxFuture<'a, Result<Write, BindingError>>;
}

/// The outcome of a session announcing a node key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Claim {
    /// The key is now bound to this session.
    Bound,
    /// The key is now bound to this session; `previous` held it and is retired.
    TookOver {
        previous: Uuid,
    },
    Refused(Refusal),
}

/// Why a session's node key was refused; the session ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Another principal, or the same one in another environment, holds it.
    BoundElsewhere,
    /// Another session changed the binding between this one's read and write.
    LostRace,
    /// The binding store could not be read or written.
    Unavailable,
}

/// The outcome of a live session rewriting its binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refresh {
    Kept,
    /// The binding no longer names this session; it ends as if taken over.
    Lost,
}

/// Binds `key` to `session` when it is free, or bound to the same principal
/// and environment.
pub(crate) async fn claim(
    store: &dyn BindingStore,
    key: &str,
    principal: &Principal,
    environment: Uuid,
    session: Uuid,
) -> Result<Claim, BindingError> {
    let wanted = Binding {
        principal: principal.clone(),
        environment,
        session: Some(session),
    };
    let Some(stored) = store.get(key).await? else {
        return Ok(match store.create(key, &wanted).await? {
            Write::Written => Claim::Bound,
            Write::Conflict => Claim::Refused(Refusal::LostRace),
        });
    };
    let current = stored.binding;
    if current.principal != *principal || current.environment != environment {
        return Ok(Claim::Refused(Refusal::BoundElsewhere));
    }
    let won = match current.session {
        Some(holder) if holder == session => return Ok(Claim::Bound),
        Some(previous) => Claim::TookOver { previous },
        None => Claim::Bound,
    };
    Ok(match store.update(key, &wanted, stored.revision).await? {
        Write::Written => won,
        Write::Conflict => Claim::Refused(Refusal::LostRace),
    })
}

/// Rewrites `session`'s binding unchanged, which restarts its TTL.
pub(crate) async fn refresh(
    store: &dyn BindingStore,
    key: &str,
    session: Uuid,
) -> Result<Refresh, BindingError> {
    let Some(stored) = store.get(key).await? else {
        return Ok(Refresh::Lost);
    };
    if stored.binding.session != Some(session) {
        return Ok(Refresh::Lost);
    }
    Ok(
        match store.update(key, &stored.binding, stored.revision).await? {
            Write::Written => Refresh::Kept,
            Write::Conflict => Refresh::Lost,
        },
    )
}

/// Drops `session` from the binding while the binding still names it, so an
/// end that comes after a takeover leaves the successor's binding alone.
pub(crate) async fn release(
    store: &dyn BindingStore,
    key: &str,
    session: Uuid,
) -> Result<(), BindingError> {
    let Some(stored) = store.get(key).await? else {
        return Ok(());
    };
    if stored.binding.session != Some(session) {
        return Ok(());
    }
    let ended = Binding {
        session: None,
        ..stored.binding
    };
    // A conflict means another session wrote first, and its binding stands.
    store.update(key, &ended, stored.revision).await?;
    Ok(())
}

/// One session's binding of a key it announced, by the key's lowercase hex:
/// its node key, or its disco key in the disco bucket (#5962).
pub(crate) struct SessionBinding {
    store: Arc<dyn BindingStore>,
    principal: Principal,
    environment: Uuid,
    session: Uuid,
    key: Option<String>,
}

impl SessionBinding {
    pub(crate) fn new(
        store: Arc<dyn BindingStore>,
        principal: Principal,
        environment: Uuid,
        session: Uuid,
    ) -> Self {
        Self {
            store,
            principal,
            environment,
            session,
            key: None,
        }
    }

    /// The session's own id in a binding: retiring it names this id.
    pub(crate) fn session(&self) -> Uuid {
        self.session
    }

    /// Claims the key of a node the session sent. A key the session already
    /// holds is not claimed again; a key it replaces is released.
    pub(crate) async fn claim(&mut self, key: String) -> Result<Claim, BindingError> {
        if self.key.as_deref() == Some(key.as_str()) {
            return Ok(Claim::Bound);
        }
        let claimed = claim(
            self.store.as_ref(),
            &key,
            &self.principal,
            self.environment,
            self.session,
        )
        .await?;
        if !matches!(claimed, Claim::Refused(_))
            && let Some(previous) = self.key.replace(key)
            && let Err(error) = release(self.store.as_ref(), &previous, self.session).await
        {
            tracing::warn!(error = ?error, "coordinator node binding release failed");
        }
        Ok(claimed)
    }

    /// Rewrites the binding of the key the session holds, if any.
    pub(crate) async fn refresh(&self) -> Result<Refresh, BindingError> {
        match &self.key {
            Some(key) => refresh(self.store.as_ref(), key, self.session).await,
            None => Ok(Refresh::Kept),
        }
    }

    /// Drops the session from its binding when the session ends.
    pub(crate) async fn release(self) {
        if let Some(key) = self.key
            && let Err(error) = release(self.store.as_ref(), &key, self.session).await
        {
            tracing::warn!(error = ?error, "coordinator node binding release failed");
        }
    }
}

/// The NATS KV bucket every replica shares.
#[derive(Clone)]
pub(crate) struct KvBindings(pub(crate) kv::Store);

impl BindingStore for KvBindings {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Stored>, BindingError>> {
        Box::pin(async move {
            let entry = self
                .0
                .entry(key)
                .await
                .map_err(|error| BindingError::Store(error.into()))?;
            match entry {
                Some(entry) if entry.operation == kv::Operation::Put => Ok(Some(Stored {
                    binding: serde_json::from_slice(&entry.value)?,
                    revision: entry.revision,
                })),
                _ => Ok(None),
            }
        })
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
    ) -> BoxFuture<'a, Result<Write, BindingError>> {
        Box::pin(async move {
            let value = Bytes::from(serde_json::to_vec(binding)?);
            match self.0.create(key, value).await {
                Ok(_) => Ok(Write::Written),
                Err(error) if error.kind() == kv::CreateErrorKind::AlreadyExists => {
                    Ok(Write::Conflict)
                }
                Err(error) => Err(BindingError::Store(error.into())),
            }
        })
    }

    fn update<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
        revision: u64,
    ) -> BoxFuture<'a, Result<Write, BindingError>> {
        Box::pin(async move {
            let value = Bytes::from(serde_json::to_vec(binding)?);
            match self.0.update(key, value, revision).await {
                Ok(_) => Ok(Write::Written),
                Err(error) if error.kind() == kv::UpdateErrorKind::WrongLastRevision => {
                    Ok(Write::Conflict)
                }
                Err(error) => Err(BindingError::Store(error.into())),
            }
        })
    }
}

/// The local registry's bindings when the coordinator runs without NATS,
/// with the bucket's TTL and revisions.
#[derive(Default)]
pub(crate) struct MemoryBindings {
    state: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    /// The last revision written to any key, as a KV stream's sequence.
    revision: u64,
    entries: HashMap<String, MemoryEntry>,
}

struct MemoryEntry {
    binding: Binding,
    revision: u64,
    written: Instant,
}

impl MemoryBindings {
    fn read(&self, key: &str) -> Option<Stored> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .entries
            .get(key)
            .filter(|entry| entry.written.elapsed() < NODE_BINDING_TTL)
            .map(|entry| Stored {
                binding: entry.binding.clone(),
                revision: entry.revision,
            })
    }

    /// Writes while `key`'s live revision is `expected` (`None`: no binding).
    fn write(&self, key: &str, binding: &Binding, expected: Option<u64>) -> Write {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.written) < NODE_BINDING_TTL);
        if state.entries.get(key).map(|entry| entry.revision) != expected {
            return Write::Conflict;
        }
        state.revision += 1;
        let revision = state.revision;
        state.entries.insert(
            key.to_owned(),
            MemoryEntry {
                binding: binding.clone(),
                revision,
                written: now,
            },
        );
        Write::Written
    }
}

impl BindingStore for MemoryBindings {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Stored>, BindingError>> {
        Box::pin(std::future::ready(Ok(self.read(key))))
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
    ) -> BoxFuture<'a, Result<Write, BindingError>> {
        Box::pin(std::future::ready(Ok(self.write(key, binding, None))))
    }

    fn update<'a>(
        &'a self,
        key: &'a str,
        binding: &'a Binding,
        revision: u64,
    ) -> BoxFuture<'a, Result<Write, BindingError>> {
        Box::pin(std::future::ready(Ok(self.write(
            key,
            binding,
            Some(revision),
        ))))
    }
}

#[cfg(test)]
mod tests;
