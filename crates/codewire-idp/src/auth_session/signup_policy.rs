//! The configuration-owned sign-up policy: how a server admits an account
//! (`IDP_SIGNUP`), and in review mode which invite codes admit one at once.

use std::fmt;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use sha2::{Digest, Sha256};

const SIGNUP_INVITE_CODE_HASHES_ENV: &str = "IDP_SIGNUP_INVITE_CODE_HASHES";
const SIGNUP_MODE_ENV: &str = "IDP_SIGNUP";
const SIGNUP_REASON_ENV: &str = "IDP_SIGNUP_REASON";
const SHA256_DIGEST_BYTES: usize = 32;
const SHA256_HEX_CHARS: usize = SHA256_DIGEST_BYTES * 2;

/// Configuration-owned signup invite policy.
///
/// Runtime configuration sends signups through access review when the hash
/// list is empty. Trusted tests can opt into the explicit open-signup policy.
/// A configured policy stores only fixed-size SHA-256 digests; plaintext
/// invite codes are never retained.
#[derive(Clone, Default)]
pub struct SignupInvitePolicy {
    accepted_hashes: Arc<[[u8; SHA256_DIGEST_BYTES]]>,
    open_signup: bool,
    mode: SignupMode,
    /// Whether a sign-up that waits for the admin says why
    /// (`IDP_SIGNUP_REASON=required`); review mode always asks.
    reason_required: bool,
}

/// How sign-up admits an account (#4121).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SignupMode {
    /// Human verification, then immediate access for an accepted invite code
    /// and access review without one. The hosted default.
    #[default]
    Review,
    /// Only a person with an organization invitation for their address, or
    /// the first-account link, is admitted; anyone else waits for the admin.
    InviteOnly,
    /// Every sign-up is admitted and verifies its address before it signs
    /// in. Hosted at launch, with review off.
    Open,
}

impl SignupMode {
    /// The mode as `IDP_SIGNUP` names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::InviteOnly => "invite-only",
            Self::Open => "open",
        }
    }

    /// `IDP_SIGNUP`: unset, empty or `review`, `invite-only`, or `open`.
    pub fn from_env_value(value: Option<&str>) -> anyhow::Result<Self> {
        match value.map(str::trim).unwrap_or_default() {
            "" | "review" => Ok(Self::Review),
            "invite-only" => Ok(Self::InviteOnly),
            "open" => Ok(Self::Open),
            other => anyhow::bail!(
                "{SIGNUP_MODE_ENV} must be `review`, `invite-only` or `open`, not `{other}`"
            ),
        }
    }
}

/// Why a sign-in with the right password is refused, if it is.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignInRefusal {
    /// Verify the email first; sign-in offers a new link.
    EmailUnverified,
    /// The account is disabled, or waits for the admin.
    Disabled,
}

/// `GET /api/auth/sign-up/mode` (public): `{"mode": "invite-only",
/// "reason": false}` and the like, so the dashboard's sign-up page asks for
/// what this server checks.
pub fn mode_router(policy: &SignupInvitePolicy) -> Router {
    let published = serde_json::json!({
        "mode": policy.mode.as_str(),
        "reason": policy.reason_required(),
    });
    Router::new().route(
        "/api/auth/sign-up/mode",
        get(move || async move { Json(published) }),
    )
}

impl fmt::Debug for SignupInvitePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignupInvitePolicy")
            .field("configured", &self.is_configured())
            .field("open_signup", &self.open_signup)
            .field("accepted_hash_count", &self.accepted_hashes.len())
            .field("mode", &self.mode)
            .field("reason_required", &self.reason_required)
            .finish()
    }
}

impl SignupInvitePolicy {
    /// Construct the explicit open-signup policy used by trusted tests.
    pub fn open() -> Self {
        Self {
            accepted_hashes: Arc::default(),
            open_signup: true,
            mode: SignupMode::Review,
            reason_required: false,
        }
    }

    /// Parse an optional comma-separated list of lowercase SHA-256 hex
    /// digests. Absent or whitespace-only input selects access review.
    pub fn from_sha256_hashes(value: Option<&str>) -> anyhow::Result<Self> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(Self::default());
        };

        let mut accepted_hashes = Vec::new();
        for encoded in value.split(',').map(str::trim) {
            let digest = decode_sha256_digest(encoded)?;
            if accepted_hashes.contains(&digest) {
                anyhow::bail!("{SIGNUP_INVITE_CODE_HASHES_ENV} contains a duplicate digest");
            }
            accepted_hashes.push(digest);
        }

        Ok(Self {
            accepted_hashes: accepted_hashes.into(),
            open_signup: false,
            mode: SignupMode::Review,
            reason_required: false,
        })
    }

    /// The policy in `mode`.
    pub fn with_mode(mut self, mode: SignupMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn mode(&self) -> SignupMode {
        self.mode
    }

    /// The policy with `IDP_SIGNUP_REASON`: unset or empty, or `required`.
    pub fn with_reason_setting(mut self, value: Option<&str>) -> anyhow::Result<Self> {
        self.reason_required = match value.map(str::trim).unwrap_or_default() {
            "" => false,
            "required" => true,
            other => {
                anyhow::bail!("{SIGNUP_REASON_ENV} must be `required` or unset, not `{other}`")
            }
        };
        Ok(self)
    }

    /// Whether a sign-up that waits for the admin must say why: always in
    /// review mode, and on an invite-only server when the operator asks.
    pub fn reason_required(&self) -> bool {
        match self.mode {
            SignupMode::Review => true,
            SignupMode::InviteOnly => self.reason_required,
            SignupMode::Open => false,
        }
    }

    /// With mail an unverified address is asked to verify its email, whether
    /// or not the account is enabled (#4481), and a verified but disabled one
    /// is told it is disabled. An invite-only server with no mail has nothing
    /// to verify by: a vouched address stands in for a verified one, and
    /// anything else waits for the admin.
    pub(crate) fn sign_in_refusal(
        &self,
        mail: bool,
        enabled: bool,
        verified: bool,
        vouched: bool,
    ) -> Option<SignInRefusal> {
        let mode = match self.mode {
            SignupMode::InviteOnly if mail => SignupMode::Review,
            mode => mode,
        };
        match mode {
            SignupMode::Review | SignupMode::Open if !verified => {
                Some(SignInRefusal::EmailUnverified)
            }
            SignupMode::Review | SignupMode::Open if !enabled => Some(SignInRefusal::Disabled),
            SignupMode::Review | SignupMode::Open => None,
            SignupMode::InviteOnly if enabled && (verified || vouched) => None,
            SignupMode::InviteOnly => Some(SignInRefusal::Disabled),
        }
    }

    /// Whether signup requires one of the configured invite codes.
    pub fn is_configured(&self) -> bool {
        !self.accepted_hashes.is_empty()
    }

    /// Whether a sign-up, by email or a provider, is admitted before anything
    /// is written: everyone in open mode, an accepted invite code in review
    /// mode. An invite-only server admits only by invitation, which email
    /// sign-up reads in its transaction.
    pub(crate) fn admits_at_once(&self, invite_code: &str) -> bool {
        match self.mode {
            SignupMode::Open => true,
            SignupMode::Review => self.accepts(invite_code),
            SignupMode::InviteOnly => false,
        }
    }

    pub(crate) fn accepts(&self, invite_code: &str) -> bool {
        if self.open_signup {
            return true;
        }
        if !self.is_configured() || invite_code.is_empty() {
            return false;
        }

        let candidate: [u8; SHA256_DIGEST_BYTES] = Sha256::digest(invite_code.as_bytes()).into();
        let mut accepted = 0u8;
        for expected in self.accepted_hashes.iter() {
            accepted |= constant_time_digest_eq(&candidate, expected);
        }
        accepted == 1
    }
}

fn decode_sha256_digest(encoded: &str) -> anyhow::Result<[u8; SHA256_DIGEST_BYTES]> {
    sha256_digest_from_hex(encoded).ok_or_else(|| {
        anyhow::anyhow!(
            "{SIGNUP_INVITE_CODE_HASHES_ENV} entries must be {SHA256_HEX_CHARS}-character lowercase SHA-256 hex digests"
        )
    })
}

/// A SHA-256 digest written as 64 lowercase hex characters, or `None`.
pub(super) fn sha256_digest_from_hex(encoded: &str) -> Option<[u8; SHA256_DIGEST_BYTES]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != SHA256_HEX_CHARS
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }

    let mut digest = [0u8; SHA256_DIGEST_BYTES];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Some(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest syntax is validated before decoding"),
    }
}

fn constant_time_digest_eq(
    left: &[u8; SHA256_DIGEST_BYTES],
    right: &[u8; SHA256_DIGEST_BYTES],
) -> u8 {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    u8::from(difference == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite_digest(invite_code: &str) -> String {
        format!("{:x}", Sha256::digest(invite_code.as_bytes()))
    }

    #[test]
    fn signup_invite_policy_requires_review_without_hashes() {
        for value in [None, Some(""), Some("   ")] {
            let policy = SignupInvitePolicy::from_sha256_hashes(value).unwrap();
            assert!(!policy.is_configured());
            assert!(!policy.accepts(""));
            assert!(!policy.accepts("any-value"));
        }

        let open = SignupInvitePolicy::open();
        assert!(open.accepts(""));
        assert!(open.accepts("any-value"));
    }

    #[test]
    fn configured_signup_invite_policy_accepts_only_matching_values() {
        let first = invite_digest("synthetic-invite-one");
        let second = invite_digest("synthetic-invite-two");
        let configured = format!("{first}, {second}");
        let policy = SignupInvitePolicy::from_sha256_hashes(Some(&configured)).unwrap();

        assert!(policy.is_configured());
        assert!(policy.accepts("synthetic-invite-one"));
        assert!(policy.accepts("synthetic-invite-two"));
        assert!(!policy.accepts(""));
        assert!(!policy.accepts("synthetic-invite-three"));

        let debug = format!("{policy:?}");
        assert!(!debug.contains(&first));
        assert!(!debug.contains("synthetic-invite"));
    }

    #[test]
    fn each_mode_admits_at_once_only_what_it_should() {
        let code = "synthetic-invite-one";
        let digest = invite_digest(code);
        let hashes = SignupInvitePolicy::from_sha256_hashes(Some(&digest)).unwrap();
        for (mode, no_code, accepted, wrong) in [
            (SignupMode::Review, false, true, false),
            (SignupMode::Open, true, true, true),
            (SignupMode::InviteOnly, false, false, false),
        ] {
            let policy = hashes.clone().with_mode(mode);
            assert_eq!(policy.admits_at_once(""), no_code, "{mode:?}");
            assert_eq!(policy.admits_at_once(code), accepted, "{mode:?}");
            assert_eq!(
                policy.admits_at_once("synthetic-invite-two"),
                wrong,
                "{mode:?}"
            );
        }
    }

    #[test]
    fn signup_invite_policy_rejects_invalid_hash_configuration() {
        let digest = invite_digest("synthetic-invite");
        for value in [
            "abc".to_owned(),
            "A".repeat(SHA256_HEX_CHARS),
            "g".repeat(SHA256_HEX_CHARS),
            format!("{digest},"),
            format!("{digest},{digest}"),
        ] {
            let error = SignupInvitePolicy::from_sha256_hashes(Some(&value)).unwrap_err();
            assert!(error.to_string().contains(SIGNUP_INVITE_CODE_HASHES_ENV));
            assert!(!error.to_string().contains("synthetic-invite"));
        }
    }

    #[test]
    fn signup_mode_parses_only_the_three_modes() {
        for value in [None, Some(""), Some(" "), Some("review")] {
            assert_eq!(
                SignupMode::from_env_value(value).unwrap(),
                SignupMode::Review
            );
        }
        assert_eq!(
            SignupMode::from_env_value(Some(" invite-only ")).unwrap(),
            SignupMode::InviteOnly
        );
        assert_eq!(
            SignupMode::from_env_value(Some("open")).unwrap(),
            SignupMode::Open
        );
        for value in ["closed", "Invite-Only", "invite_only", "OPEN"] {
            let error = SignupMode::from_env_value(Some(value)).unwrap_err();
            assert!(error.to_string().contains(SIGNUP_MODE_ENV));
        }
        let policy = SignupInvitePolicy::default().with_mode(SignupMode::InviteOnly);
        assert_eq!(policy.mode(), SignupMode::InviteOnly);
        assert!(format!("{policy:?}").contains("InviteOnly"));
    }

    #[tokio::test]
    async fn the_mode_is_published_for_the_sign_up_page() {
        use axum::http::StatusCode;
        use tower::ServiceExt as _;
        for (mode, reason) in [
            (SignupMode::Review, true),
            (SignupMode::InviteOnly, false),
            (SignupMode::Open, false),
        ] {
            let policy = SignupInvitePolicy::default().with_mode(mode);
            let response = mode_router(&policy)
                .oneshot(
                    axum::http::Request::get("/api/auth/sign-up/mode")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let published: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                published,
                serde_json::json!({ "mode": mode.as_str(), "reason": reason })
            );
            assert_eq!(
                SignupMode::from_env_value(published["mode"].as_str()).unwrap(),
                mode
            );
        }
    }

    #[test]
    fn sign_in_needs_a_verified_or_vouched_address_on_an_invite_only_server() {
        use SignInRefusal::{Disabled, EmailUnverified};
        let review = SignupInvitePolicy::default();
        let invite_only = SignupInvitePolicy::default().with_mode(SignupMode::InviteOnly);
        // (enabled, verified, vouched) → review, invite-only
        for (enabled, verified, vouched, in_review, invite_only_refusal) in [
            (true, false, false, Some(EmailUnverified), Some(Disabled)),
            (true, false, true, Some(EmailUnverified), None),
            (true, true, false, None, None),
            (false, false, false, Some(EmailUnverified), Some(Disabled)),
            (false, false, true, Some(EmailUnverified), Some(Disabled)),
            (false, true, false, Some(Disabled), Some(Disabled)),
        ] {
            assert_eq!(
                review.sign_in_refusal(true, enabled, verified, vouched),
                in_review
            );
            assert_eq!(
                invite_only.sign_in_refusal(false, enabled, verified, vouched),
                invite_only_refusal,
                "{enabled} {verified} {vouched}"
            );
        }
        // With mail, an invite-only server verifies like review.
        assert_eq!(
            invite_only.sign_in_refusal(true, true, false, true),
            Some(EmailUnverified)
        );
    }
}
