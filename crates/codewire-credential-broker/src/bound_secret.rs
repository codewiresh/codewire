//! What a placement gives the front door's swap for a host-bound application
//! secret (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap"): the
//! epoch's grants, each a first-bind record and the placeholder it derives,
//! a lease's reread of the secret's row, and the lease's failures.

use codewire_access::{FirstBindSecret, HostBinding, SecretPlaceholder};

pub use codewire_credential_bridge::{BOUND_SECRET_ROUTE, BOUND_SECRET_SLOT};

/// One of an epoch's bound-secret grants: what the Pod's first bind recorded
/// of a secret its selected sources hold, and the placeholder that record
/// derives under the environment's application-secret key, which the Pod
/// was projected.
#[derive(Clone, Debug)]
pub struct EpochBoundSecret {
    pub record: FirstBindSecret,
    pub placeholder: SecretPlaceholder,
}

/// A secret's row as a lease read it: its binding now, which matched the
/// record's identity, generation and the request's host, and the version of
/// its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSecretRow {
    pub binding: HostBinding,
    pub value_version: u64,
}

/// Why a bound secret's lease was refused. The first three are the spec's
/// named refusals; the rest answer as every lease failure does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BoundSecretLeaseError {
    /// The binding no longer names the host, or the record never did.
    #[error("the secret is not bound to this host")]
    NotBoundToHost,
    /// Another `binding_id` or generation than the record's, or plain now.
    #[error("the secret's binding changed")]
    BindingChanged,
    #[error("the secret was deleted")]
    Deleted,
    #[error("the bound secret's lease was denied")]
    Denied,
    #[error("the bound secret's authority is unavailable")]
    Unavailable,
}

/// One swap's audit line (docs/dev/SECRETS-AND-CREDENTIALS.md, "Audit and
/// logs"): the key, its scope, the host, the presentation and the outcome.
/// The placement adds the environment and the user it acts for. Never a
/// value, a placeholder, a path or a header value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundSecretSwap<'a> {
    pub key: &'a str,
    /// `project`, `organization` or `user`.
    pub scope: &'static str,
    pub host: &'a str,
    /// `header`, `basic` or `basic-user`, or `unread` for a refusal before
    /// the secret's binding was read.
    pub presentation: &'static str,
    /// `swapped`, or the refusal's code.
    pub outcome: &'static str,
}
