//! Admin → Manage account access: one account's row (#3297, #4541).

pub(crate) struct AccountAccessView {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) name: String,
    pub(crate) email_verified: bool,
    pub(crate) enabled: bool,
    /// Suspended by an administrator: only Unsuspend brings it back.
    pub(crate) suspended: bool,
    /// "Bounced" or "Marked as spam" when SES suppressed the address
    /// (#4548), else empty.
    pub(crate) mail_suppressed: &'static str,
    /// The signed-in administrator's own account, which it can't suspend.
    pub(crate) own: bool,
    pub(crate) reason: String,
    pub(crate) has_reason: bool,
    pub(crate) created_at: String,
    pub(crate) identities: Vec<LinkedIdentityView>,
    pub(crate) deletion: AccountDeletionOffer,
}

/// Whether an account row offers "Delete account" (#4541).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountDeletionOffer {
    Offered,
    /// The signed-in admin's own account, deleted from Settings.
    OwnAccount,
    /// Another admin, demoted before their account is deleted.
    Admin,
}

impl AccountDeletionOffer {
    pub(crate) fn is_offered(self) -> bool {
        self == Self::Offered
    }

    /// Why the row offers no deletion, empty when it does.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Offered => "",
            Self::OwnAccount => "Your account. Delete it in Settings.",
            Self::Admin => "An admin. Demote them first.",
        }
    }
}

/// A GitHub or Google identity that signs in to an account, for admins.
#[derive(Debug)]
pub(crate) struct LinkedIdentityView {
    /// "GitHub" or "Google".
    pub(crate) provider: &'static str,
    /// The provider's stable subject.
    pub(crate) subject: String,
    /// The provider account it was linked as, when known.
    pub(crate) account: String,
    pub(crate) linked_at: String,
}
