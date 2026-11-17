//! The invitation page's views and form (#3840).

use super::*;

#[derive(Debug)]
pub(crate) struct InvitationView {
    pub(crate) organization_name: String,
    /// Masked by the platform: "j•••@example.com".
    pub(crate) email: String,
    pub(crate) inviter_name: String,
    pub(crate) role: &'static str,
    /// When the invitation expires, as Unix seconds.
    pub(crate) expires_at: i64,
}

/// Which branch of the invitation page a visitor sees (#3840).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvitationState {
    /// Not signed in: sign in, or sign up with the invited address.
    SignedOut,
    /// Signed in with an address that is not the invited one.
    OtherAccount,
    /// Signed in with the invited address, not verified yet.
    Unverified,
    /// Signed in with the invited, verified address: one click accepts.
    Ready,
}

/// The invitation page. The invited address in `invitation.email` is masked,
/// and the token never reaches the page except as the Sign up form's hidden
/// field, which hands it to sign-up in a POST body.
pub(crate) struct InvitationPageView {
    pub(crate) invitation: InvitationView,
    pub(crate) state: InvitationState,
    pub(crate) signed_in_as: String,
    pub(crate) csrf_token: String,
    pub(crate) signup_token: String,
    pub(crate) login_url: String,
    pub(crate) error: String,
}

impl fmt::Debug for InvitationPageView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationPageView")
            .field("invitation", &self.invitation)
            .field("state", &self.state)
            .field("signed_in_as", &self.signed_in_as)
            .field("csrf_token", &redacted(&self.csrf_token))
            .field("signup_token", &redacted(&self.signup_token))
            .field("login_url", &self.login_url)
            .field("error", &self.error)
            .finish()
    }
}

/// The invitation link's token, posted once by the page's script (#3840).
#[derive(Deserialize)]
pub(crate) struct InvitationOpenSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) t: String,
}

impl fmt::Debug for InvitationOpenSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationOpenSubmission")
            .field("csrf", &redacted(&self.csrf))
            .field("t", &redacted(&self.t))
            .finish()
    }
}
