//! The process-wide budget for `WriteFiles` request bodies, taken before the
//! body is read (SPEC.md, "File transfer"; #5804).
//!
//! The per-organization and per-environment limit in `write_many` is taken
//! once the request is decoded, when its body is already in memory. This
//! admission runs first: it charges each request the most bytes its body may
//! hold, refuses at once one that does not fit, and reads no more of the body
//! than it charged. The charge then follows the decoded files: `write_files`
//! takes it into the worker that holds them, so it is held until the worker
//! finishes, or until the request is dropped if no worker took it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use codewire_proto::codewire::v1 as proto;
use http::{HeaderMap, header};

use super::WRITE_FILES_MAX_MESSAGE_BYTES;

/// The most `WriteFiles` request bytes one server process holds at once.
///
/// It admits two calls of the largest size, [`WRITE_FILES_MAX_MESSAGE_BYTES`]
/// (about 26.6 MB each), with room for small ones beside them. A call holds
/// its raw body and then the decoded copy, so the two largest calls peak at
/// about 2 × 2 × 26.6 MB, roughly 110 MB: about a fifth of the orchestration
/// server's 512 MiB memory limit. The whole budget spent on small calls peaks
/// at about twice 64 MiB, roughly a quarter.
pub const WRITE_FILES_BODY_BUDGET: usize = 64 * 1024 * 1024;

/// The most of [`WRITE_FILES_BODY_BUDGET`] one caller holds at once: two calls
/// of the largest size, about 53 MB, so no one account holds the whole budget.
pub const WRITE_FILES_PRINCIPAL_SHARE: usize = 2 * WRITE_FILES_MAX_MESSAGE_BYTES;

/// The most of [`WRITE_FILES_BODY_BUDGET`] one organization's calls hold at
/// once, across its accounts: two calls of the largest size. The organization
/// is named only in the decoded request, so this share is taken once the
/// caller is admitted to it, before anything is written.
pub const WRITE_FILES_ORGANIZATION_SHARE: usize = 2 * WRITE_FILES_MAX_MESSAGE_BYTES;

// The budget holds two of the largest calls but not three, and neither one
// caller's share nor one organization's is the whole budget.
const _: () = {
    assert!(2 * WRITE_FILES_MAX_MESSAGE_BYTES <= WRITE_FILES_BODY_BUDGET);
    assert!(3 * WRITE_FILES_MAX_MESSAGE_BYTES > WRITE_FILES_BODY_BUDGET);
    assert!(WRITE_FILES_PRINCIPAL_SHARE < WRITE_FILES_BODY_BUDGET);
    assert!(WRITE_FILES_ORGANIZATION_SHARE < WRITE_FILES_BODY_BUDGET);
};

/// Names the caller a request is charged to, from what the mount's
/// authentication put on the request. Requests that name no one share one
/// share between them.
pub type WriteFilesPrincipal = fn(&Request) -> Option<String>;

const BUDGET_FULL: &str = "the server is already holding as many file batches as it can; \
     send this one again shortly";
const SHARE_FULL: &str = "you are already sending as many file batches as one account may; \
     send this one when one finishes";
pub(super) const ORGANIZATION_SHARE_FULL: &str = "this organization is already sending as many \
     file batches as it may; send this one when one finishes";

/// Applies the `WriteFiles` body budget to `router`, one budget per call.
///
/// Apply it inside the mount's authentication, so an unauthenticated request
/// never takes or touches the budget, with a `principal` that reads the caller
/// that authentication established. Every other path passes through.
pub fn write_files_admission(router: axum::Router, principal: WriteFilesPrincipal) -> axum::Router {
    with_budget(router, Arc::new(BodyBudget::new(principal)))
}

pub(super) fn with_budget(router: axum::Router, budget: Arc<BodyBudget>) -> axum::Router {
    router.layer(axum::middleware::from_fn_with_state(budget, admit))
}

async fn admit(State(budget): State<Arc<BodyBudget>>, request: Request, next: Next) -> Response {
    if request.uri().path() != proto::FILE_SERVICE_WRITE_FILES_SPEC.procedure {
        return next.run(request).await;
    }
    let bytes = charge(request.headers());
    let permit = match budget.try_take((budget.principal)(&request), bytes) {
        Ok(permit) => permit,
        Err(refusal) => {
            return connectrpc::ConnectError::resource_exhausted(refusal)
                .into_http_response(request.headers())
                .map(Body::new);
        }
    };
    // The charge bounds what is read: a body longer than it declared fails
    // the call rather than being held. The limit counts the bytes on the
    // wire; the dispatcher's message limit bounds a compressed body's
    // decoded size.
    let limit = read_limit(bytes);
    let mut request = request.map(|body| Body::new(http_body_util::Limited::new(body, limit)));
    // The request is the charge's only owner: held until the worker finishes,
    // or the request is dropped. The dispatcher moves the request's extensions
    // into the handler's context, and `write_files` takes the charge from
    // there into its worker; a request that never reaches the worker, or a
    // caller that leaves before it, releases the charge with the request.
    request.extensions_mut().insert(BodyCharge::new(permit));
    next.run(request).await
}

/// The most bytes a request's body may hold, as its headers tell it: the
/// declared length, or the largest message when the length is unknown or the
/// body is compressed, since a small compressed body can decode to the
/// largest.
fn charge(headers: &HeaderMap) -> usize {
    let compressed = [
        header::CONTENT_ENCODING.as_str(),
        "connect-content-encoding",
    ]
    .into_iter()
    .flat_map(|name| headers.get_all(name))
    .any(|value| {
        !value
            .to_str()
            .is_ok_and(|coding| coding.trim().eq_ignore_ascii_case("identity"))
    });
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let declared = match (lengths.next(), lengths.next()) {
        (Some(length), None) => length
            .to_str()
            .ok()
            .and_then(|length| length.trim().parse::<usize>().ok()),
        _ => None,
    };
    match declared {
        Some(length) if !compressed => length.min(WRITE_FILES_MAX_MESSAGE_BYTES),
        _ => WRITE_FILES_MAX_MESSAGE_BYTES,
    }
}

/// How much of an admitted body is read. A body charged less than the largest
/// message stops at its charge. One charged the largest may run one byte past
/// it, so the dispatcher's own message limit refuses it, as
/// `resource_exhausted`, rather than the read failing as `internal`; one byte
/// more is nothing to hold.
fn read_limit(charge: usize) -> usize {
    if charge >= WRITE_FILES_MAX_MESSAGE_BYTES {
        WRITE_FILES_MAX_MESSAGE_BYTES + 1
    } else {
        charge
    }
}

/// The bytes held for admitted requests, in all and per caller, under one
/// lock so the two always agree.
pub(super) struct BodyBudget {
    principal: WriteFilesPrincipal,
    held: Arc<Mutex<Held>>,
}

#[derive(Default)]
struct Held {
    total: usize,
    /// Only callers holding a request; `None` is every request that named no
    /// one.
    by_principal: HashMap<Option<String>, usize>,
    /// Only organizations holding a charge assigned to them.
    by_organization: HashMap<String, usize>,
}

impl BodyBudget {
    pub(super) fn new(principal: WriteFilesPrincipal) -> Self {
        Self {
            principal,
            held: Arc::default(),
        }
    }

    /// The bytes held in all and per caller.
    #[cfg(test)]
    pub(super) fn held(&self) -> (usize, HashMap<Option<String>, usize>) {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        (held.total, held.by_principal.clone())
    }

    /// The bytes held per organization.
    #[cfg(test)]
    pub(super) fn held_by_organization(&self) -> HashMap<String, usize> {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.by_organization.clone()
    }

    /// Holds `bytes` for `principal`, or says why they do not fit.
    pub(super) fn try_take(
        &self,
        principal: Option<String>,
        bytes: usize,
    ) -> Result<BodyPermit, &'static str> {
        // A panic while holding the lock cannot leave a count half-changed.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let share = held.by_principal.get(&principal).copied().unwrap_or(0);
        if share + bytes > WRITE_FILES_PRINCIPAL_SHARE {
            return Err(SHARE_FULL);
        }
        if held.total + bytes > WRITE_FILES_BODY_BUDGET {
            return Err(BUDGET_FULL);
        }
        held.total += bytes;
        *held.by_principal.entry(principal.clone()).or_default() += bytes;
        Ok(BodyPermit {
            held: Arc::clone(&self.held),
            principal,
            organization: None,
            bytes,
        })
    }
}

/// The charge of an admitted request, in its extensions until a handler takes
/// it. A clone shares the one slot, so the charge is taken once.
#[derive(Clone)]
pub(super) struct BodyCharge(Arc<Mutex<Option<BodyPermit>>>);

impl BodyCharge {
    pub(super) fn new(permit: BodyPermit) -> Self {
        Self(Arc::new(Mutex::new(Some(permit))))
    }

    /// The permit, the first time it is asked for.
    pub(super) fn take(&self) -> Option<BodyPermit> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// Bytes held for one admitted request until it is dropped.
pub(super) struct BodyPermit {
    held: Arc<Mutex<Held>>,
    principal: Option<String>,
    organization: Option<String>,
    bytes: usize,
}

impl BodyPermit {
    /// Counts these bytes in `org_id`'s share as well, once, or says that they
    /// do not fit, when the organization already holds
    /// [`WRITE_FILES_ORGANIZATION_SHARE`].
    pub(super) fn charge_organization(&mut self, org_id: &str) -> Result<(), &'static str> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let share = held.by_organization.get(org_id).copied().unwrap_or(0);
        if share + self.bytes > WRITE_FILES_ORGANIZATION_SHARE {
            return Err(ORGANIZATION_SHARE_FULL);
        }
        *held.by_organization.entry(org_id.to_owned()).or_default() += self.bytes;
        self.organization = Some(org_id.to_owned());
        Ok(())
    }
}

impl Drop for BodyPermit {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.total = held.total.saturating_sub(self.bytes);
        release(&mut held.by_principal, &self.principal, self.bytes);
        if let Some(organization) = &self.organization {
            release(&mut held.by_organization, organization, self.bytes);
        }
    }
}

/// Takes `bytes` from `key`'s share, removing a share that reaches zero so
/// the map holds only what is held.
fn release<K, Q>(shares: &mut HashMap<K, usize>, key: &Q, bytes: usize)
where
    K: std::borrow::Borrow<Q> + std::hash::Hash + Eq,
    Q: std::hash::Hash + Eq + ?Sized,
{
    if let Some(share) = shares.get_mut(key) {
        *share = share.saturating_sub(bytes);
        if *share == 0 {
            shares.remove(key);
        }
    }
}

#[cfg(test)]
mod tests;
