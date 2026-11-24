//! The mint cache (docs/dev/SANDBOX-IDENTITY.md, "Minting"): a token is
//! returned again until half its lifetime, so a repeat costs a TokenReview
//! but no signature. It is keyed by Sandbox, canonical audience, the
//! Sandbox's groups version and the registration's version, so a change to
//! either misses. An entry is also returned only for the subject it was made
//! for, so a version that repeats (a registration removed and added again)
//! still misses when anything in the token would differ.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use crate::identity::token::TokenSubject;

/// Tokens kept per replica: each is about a kilobyte.
pub const MAX_CACHED_TOKENS: usize = 16 * 1024;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct CacheKey {
    pub(crate) environment_id: String,
    pub(crate) audience: String,
    pub(crate) groups_version: i64,
    pub(crate) audience_version: i64,
}

struct Entry {
    subject: TokenSubject,
    token: Zeroizing<String>,
    expires_at: i64,
    /// Unix seconds from which this token is no longer handed out.
    stale_at: i64,
}

pub(crate) struct CachedToken {
    pub(crate) token: Zeroizing<String>,
    pub(crate) expires_at: i64,
}

pub(crate) struct TokenCache {
    capacity: usize,
    entries: Mutex<HashMap<CacheKey, Entry>>,
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::with_capacity(MAX_CACHED_TOKENS)
    }
}

impl TokenCache {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The token cached for `key` and `subject`, if it is before its half
    /// lifetime at `now` (Unix seconds).
    pub(crate) fn get(
        &self,
        key: &CacheKey,
        subject: &TokenSubject,
        now: i64,
    ) -> Option<CachedToken> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(key)?;
        (entry.subject == *subject && now < entry.stale_at).then(|| CachedToken {
            token: entry.token.clone(),
            expires_at: entry.expires_at,
        })
    }

    /// Keep `token`, issued at `issued_at`, for `key`. A full cache first
    /// drops the stale entries, then the one that goes stale soonest.
    pub(crate) fn insert(
        &self,
        key: CacheKey,
        subject: TokenSubject,
        token: Zeroizing<String>,
        issued_at: i64,
        expires_at: i64,
    ) {
        let stale_at = issued_at.saturating_add(expires_at.saturating_sub(issued_at) / 2);
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !entries.contains_key(&key) && entries.len() >= self.capacity {
            entries.retain(|_, entry| entry.stale_at > issued_at);
            if entries.len() >= self.capacity
                && let Some(soonest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.stale_at)
                    .map(|(key, _)| key.clone())
            {
                entries.remove(&soonest);
            }
        }
        if self.capacity > 0 {
            entries.insert(
                key,
                Entry {
                    subject,
                    token,
                    expires_at,
                    stale_at,
                },
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}
