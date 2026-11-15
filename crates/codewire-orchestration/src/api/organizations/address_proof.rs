//! What an account's own row proves about its email address. A server with
//! mail proves an address by an email; one without mail proves it by a
//! vouch instead (#4121): setup's admin, an admin enabling the account, or
//! an invitation's own link. Accepting an invitation and sending one read
//! that proof here, so the two cannot disagree on it (#4805). Accepting then
//! narrows a vouch on purpose: it admits only through the invitation's own
//! link, within a day of its issue (`vouched_for_this_link`).

use sqlx::PgConnection;

/// The caller's address, as its users row records it.
pub(super) struct AddressProof {
    /// The address is the invitation's; false when no invitation address
    /// was given.
    pub(super) matches: bool,
    pub(super) verified: bool,
    /// The server vouched for the address (`email_vouched_by`).
    pub(super) vouched: bool,
}

impl AddressProof {
    /// An account may invite others once its address is proven, by an email
    /// or by a vouch.
    pub(super) fn may_invite(&self) -> bool {
        self.verified || self.vouched
    }
}

/// Reads `user_id`'s address, against `invitation_email` when one is given,
/// and holds the row shared until the transaction ends, so neither the
/// address nor its proof can change before what it admits commits. The
/// address is compared with SQL `lower()` on both sides, the rule
/// ListMyInvitations uses, so the two always agree on which invitations are
/// the caller's. `None` when no such account exists. Each caller maps the
/// error to its own answer.
pub(super) async fn read(
    conn: &mut PgConnection,
    user_id: &str,
    invitation_email: Option<&str>,
) -> Result<Option<AddressProof>, sqlx::Error> {
    let row: Option<(bool, bool, bool)> = sqlx::query_as(
        r#"SELECT COALESCE(lower(email) = lower($2), false),
                  COALESCE(email_verified, false),
                  email_vouched_by IS NOT NULL
           FROM users
           WHERE id = $1
           FOR SHARE"#,
    )
    .bind(user_id)
    .bind(invitation_email)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(matches, verified, vouched)| AddressProof {
        matches,
        verified,
        vouched,
    }))
}
