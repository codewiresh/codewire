//! `POST /api/auth/sign-up` (public): email and password sign-up, one path for
//! every `IDP_SIGNUP` mode, which only decides what admits an account.
//!
//! - `review`, the hosted default: Turnstile; an invite code admits at once,
//!   and anyone else waits for access review with a reason.
//! - `open`: Turnstile; everyone is admitted.
//! - `invite-only`, self-hosted (#4121): an organization invitation for the
//!   address admits; anyone else waits for the admin, saying why when
//!   `IDP_SIGNUP_REASON=required`. Nothing is taken before setup has made the
//!   admin. Turnstile only when its keys are set. Without mail the admin
//!   vouches for the address (`email_vouched_by`) and an admitted account
//!   signs in at once.
//!
//! On every server an invitation link admits a sign-up at exactly its
//! address, with no code, review or reason, and skips Turnstile (#4121: "the
//! private invite is enough").
//!
//! With mail every address is verified by email before it signs in, and
//! sign-up issues no session (#4481).

use super::sign_up_invitation::{
    address_taken, invitation_for_sign_up, invitation_is_live, invite_only_refusal,
};
use super::*;

/// Whether a sign-up from an invitation link also passes Turnstile. Decided
/// no, on every server (#4121, cw-pm for the owner): a per-address link
/// skips the challenge; every other sign-up passes it.
const TURNSTILE_FOR_INVITED: bool = false;

/// What admitted a sign-up, or that nothing did.
enum Admission {
    /// Decided before anything is written: an invite code in review mode, or
    /// everyone in open mode.
    AtOnce,
    /// An organization invitation, by id.
    Invitation(String),
    /// Nothing: the account waits for review or for the admin.
    Waiting,
}

impl Admission {
    fn enabled(&self) -> bool {
        !matches!(self, Self::Waiting)
    }

    /// Who vouched for the address on a server with no mail.
    fn vouched_by(&self, mail: bool) -> Option<&'static str> {
        match self {
            _ if mail => None,
            Self::Invitation(_) => Some("invitation"),
            _ => None,
        }
    }

    fn reason_is_missing(&self, policy: &SignupInvitePolicy, reason: &str) -> bool {
        !self.enabled()
            && policy.reason_required()
            && (reason.is_empty() || reason.chars().count() > MAX_ACCESS_REASON_CHARS)
    }
}

fn reason_missing() -> AppError {
    AppError::BadRequest("Tell us why you want to use Codewire".into())
}

/// The checks a sign-up passes before it writes anything: the email and
/// password, Turnstile, the reason, and mail to verify with. Review and open
/// decide admission here; an invitation, and any sign-up on an invite-only
/// server, is read in the sign-up's transaction, so its admission is `None`
/// until then. A refusal counts in `codewire_idp_sign_up_refusals_total`
/// (#3297).
async fn admit(
    state: &SessionAuthState,
    req: &SignUpRequest,
) -> Result<Option<Admission>, AppError> {
    let outcome = admit_checks(state, req).await;
    if let Err(error) = &outcome {
        crate::abuse_metrics::sign_up_refused(error.status());
    }
    outcome
}

async fn admit_checks(
    state: &SessionAuthState,
    req: &SignUpRequest,
) -> Result<Option<Admission>, AppError> {
    // email-required → 400 "Email is required".
    if req.email.is_empty() {
        return Err(AppError::BadRequest("Email is required".into()));
    }
    // ValidatePassword → 400 with its message.
    if let Err(msg) = validate_password(&req.password) {
        return Err(AppError::BadRequest(msg.into()));
    }
    let policy = &state.signup_invite_policy;
    let mode = policy.mode();
    let mail = state.email.is_configured();
    let turnstile_configured = !matches!(state.human_verification, HumanVerification::Unavailable);
    // An invite-only server without Turnstile's keys asks no one. Otherwise
    // only a token that names a live invitation for this address skips the
    // challenge; a missing or wrong one gets it, so the parameter is never a
    // way around it.
    let human_verification = (mode != SignupMode::InviteOnly || turnstile_configured)
        && (TURNSTILE_FOR_INVITED
            || !invitation_is_live(&state.pool, &req.invitation_token, &req.email, mail).await?);
    if human_verification {
        validate_turnstile(state, &req.email, &req.turnstile_token).await?;
    }

    let decided = match mode {
        _ if !req.invitation_token.is_empty() => None,
        SignupMode::InviteOnly => None,
        _ if policy.admits_at_once(&req.invite_code) => Some(Admission::AtOnce),
        _ => Some(Admission::Waiting),
    };
    if decided
        .as_ref()
        .is_some_and(|admission| admission.reason_is_missing(policy, req.reason.trim()))
    {
        return Err(reason_missing());
    }
    // Every email sign-up verifies its address before it signs in; an invite
    // code only enables the account (#4481). Only an invite-only server goes
    // without mail, where the admin vouches instead.
    if mode != SignupMode::InviteOnly && !mail {
        return Err(AppError::ServiceUnavailable(
            "Email verification is temporarily unavailable".into(),
        ));
    }
    Ok(decided)
}

/// Whether this sign-up counts against the sign-up limits (#3297). On an
/// invite-only server an invitation bounds its own sign-up, so an invited
/// sign-up doesn't count, and nothing uninvited can use up the allowance and
/// lock invitees out. A token that names no live invitation is refused here,
/// before anything is counted; the transaction still checks the invitation
/// again before admitting. Every other sign-up counts, an uninvited one on an
/// invite-only server included, since it creates an account that waits.
async fn counts_against_signup_limit(
    state: &SessionAuthState,
    req: &SignUpRequest,
) -> Result<bool, AppError> {
    if state.signup_invite_policy.mode() != SignupMode::InviteOnly
        || req.invitation_token.is_empty()
    {
        return Ok(true);
    }
    let mail = state.email.is_configured();
    if invitation_is_live(&state.pool, &req.invitation_token, &req.email, mail).await? {
        Ok(false)
    } else {
        Err(invite_only_refusal())
    }
}

pub(super) async fn sign_up(
    State(state): State<SessionAuthState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<SignUpRequest>,
) -> Result<Response, AppError> {
    let decided = admit(&state, &req).await?;
    if counts_against_signup_limit(&state, &req).await?
        && let Err(refused) = crate::signup_limit::take(&state, &headers).await
    {
        return Ok(refused.into_response());
    }

    // A repeated request for an unverified pending account only reissues its
    // verification email. This makes the post-commit delivery failure
    // recoverable without changing a password or allowing a disabled account
    // to sign in. An invite-only server checks the address in its transaction.
    if state.signup_invite_policy.mode() != SignupMode::InviteOnly {
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&state.pool)
            .await?;
        if exists.is_some() {
            if let Some(response) = retry_pending_signup(&state, &headers, &req.email).await? {
                return Ok(response);
            }
            return Err(AppError::Conflict(
                "An account with this email already exists".into(),
            ));
        }
    }

    let CreatedAccount {
        user,
        admission,
        verification_token,
    } = create_account(&state, &req, decided).await?;
    let mail = state.email.is_configured();
    let enabled = admission.enabled();
    let (ip, ua) = request_info(&headers);
    let invitation_id = match &admission {
        Admission::Invitation(id) => Some(id.as_str()),
        _ => None,
    };
    log_audit(
        &state.pool,
        if enabled {
            "user.signup"
        } else {
            "user.signup.access_requested"
        },
        &user.id,
        &ip,
        &ua,
        json!({
            "email": req.email,
            "enabled": enabled,
            "vouched_by": admission.vouched_by(mail),
            "invitation_id": invitation_id,
        }),
        "info",
    )
    .await;

    // No session: the password proves only who chose it, so the account signs
    // in once the address's owner has verified it (#4481).
    if let Some(token) = verification_token {
        return deliver_signup_verification(&state, user, token, !enabled).await;
    }
    // No mail: an admitted account was vouched for and signs in now; anyone
    // else waits for the admin.
    if !enabled {
        let body = SignUpResponseBody {
            user,
            session: None,
            access_pending: true,
            verification_pending: false,
        };
        return Ok((StatusCode::ACCEPTED, Json(body)).into_response());
    }
    let created = create_session(&state.pool, &user.id, &ip, &ua)
        .await
        .map_err(|_| AppError::InternalMsg("Account created but session failed".into()))?;
    Ok(with_cookie(
        session_cookie_string(&created.token, state.secure),
        Json(SignUpResponseBody {
            user,
            session: Some(created.response),
            access_pending: false,
            verification_pending: false,
        }),
    ))
}

/// An email sign-up's stored account.
struct CreatedAccount {
    user: UserResponse,
    admission: Admission,
    /// The emailed verification link's token, with mail.
    verification_token: Option<String>,
}

/// Stores the user and its password account in one transaction, after an
/// invite-only server's admission, with a verification link when there is
/// mail.
async fn create_account(
    state: &SessionAuthState,
    req: &SignUpRequest,
    decided: Option<Admission>,
) -> Result<CreatedAccount, AppError> {
    let hash = hash_password(&req.password)?;
    let user_id = hex_id();
    let account_id = hex_id();
    let name: Option<&str> = if req.name.is_empty() {
        None
    } else {
        Some(&req.name)
    };
    let mail = state.email.is_configured();

    // users + accounts in one transaction (`provider_id='credential'`,
    // `account_id=email`, `password=hash`). `created_at`/`updated_at`
    // are set to the same NOW() the session/response will format.
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin tx");
        AppError::InternalMsg("Failed to create account".into())
    })?;
    let admission = match decided {
        Some(admission) => admission,
        None => invitation_admission(state, &mut tx, req).await?,
    };
    let reason = req.reason.trim();
    if admission.reason_is_missing(&state.signup_invite_policy, reason) {
        return Err(reason_missing());
    }
    let enabled = admission.enabled();
    let stored_access_reason = (!enabled && !reason.is_empty()).then_some(reason);

    let created_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO users
            (id, email, email_verified, name, enabled, access_reason, email_vouched_by,
             created_at, updated_at)
        VALUES ($1, $2, false, $3, $4, $5, $6, NOW(), NOW())
        RETURNING created_at
        "#,
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(name)
    .bind(enabled)
    .bind(stored_access_reason)
    .bind(admission.vouched_by(mail))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create user");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    sqlx::query(
        r#"
        INSERT INTO accounts
            (id, user_id, provider_id, account_id, password, created_at, updated_at)
        VALUES ($1, $2, 'credential', $3, $4, NOW(), NOW())
        "#,
    )
    .bind(&account_id)
    .bind(&user_id)
    .bind(&req.email)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create account");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    let verification_token = if mail {
        Some(
            create_verification_in_transaction(
                &mut tx,
                &req.email,
                VerificationPurpose::EmailVerification,
                Duration::hours(24),
            )
            .await?,
        )
    } else {
        None
    };

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit tx");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    Ok(CreatedAccount {
        user: UserResponse {
            id: user_id,
            email: req.email.clone(),
            email_verified: false,
            name: name.map(str::to_owned),
            image: None,
            is_admin: false,
            two_factor_enabled: false,
            cli_signed_in: false,
            onboarding_completed: false,
            created_at: format_time(created_at),
        },
        admission,
        verification_token,
    })
}

/// Admission by invitation, and any admission on an invite-only server, in
/// the sign-up's transaction: on an invite-only server nothing before setup
/// has made the admin; one sign-up per address at a time, whatever its case;
/// then an organization invitation, or on an invite-only server nothing; and
/// never an address that already has an account.
async fn invitation_admission(
    state: &SessionAuthState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    req: &SignUpRequest,
) -> Result<Admission, AppError> {
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to admit a sign-up by invitation");
        AppError::InternalMsg("Failed to create account".into())
    };
    let invite_only = state.signup_invite_policy.mode() == SignupMode::InviteOnly;
    if invite_only
        && !crate::admin_bootstrap::admin_exists(&mut **tx)
            .await
            .map_err(failed)?
    {
        return Err(AppError::ServiceUnavailable(
            "This server is still being set up; its admin comes first".into(),
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('signup:' || lower($1), 0))")
        .bind(&req.email)
        .execute(&mut **tx)
        .await
        .map_err(failed)?;
    let admission = if req.invitation_token.is_empty() {
        Admission::Waiting
    } else {
        let mail = state.email.is_configured();
        let invitation =
            invitation_for_sign_up(tx, &req.invitation_token, &req.email, mail, invite_only)
                .await?;
        Admission::Invitation(invitation.id)
    };
    if address_taken(tx, &req.email).await? {
        return Err(AppError::Conflict(
            "An account with this email already exists; sign in instead".into(),
        ));
    }
    Ok(admission)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An account saved whose verification email couldn't be sent is the one
    /// sign-up 503 with a code, so the page can say it was saved (#4723).
    #[tokio::test]
    async fn an_unsent_verification_email_answers_with_its_code() {
        let state = SessionAuthState {
            // Never connected: no mail is configured, so no mail is counted.
            pool: PgPool::connect_lazy("postgres://localhost/none").unwrap(),
            secure: false,
            signup_invite_policy: SignupInvitePolicy::open(),
            frontend_url: String::new(),
            email: EmailClient::disabled(),
            human_verification: HumanVerification::TrustedTest,
            turnstile_bypass_email: String::new(),
            client_address_key: "synthetic-client-address-key".into(),
            http: reqwest::Client::new(),
            operator_email: None,
        };
        let user = UserResponse {
            id: "synthetic-user".into(),
            email: "synthetic@example.invalid".into(),
            email_verified: false,
            name: None,
            image: None,
            is_admin: false,
            two_factor_enabled: false,
            cli_signed_in: false,
            onboarding_completed: false,
            created_at: String::new(),
        };

        let answered =
            deliver_signup_verification(&state, user, "synthetic-token".into(), false).await;

        assert!(
            matches!(
                answered,
                Err(AppError::Coded {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    code: "verification_email_unsent",
                    ..
                })
            ),
            "{:?}",
            answered.err()
        );
    }
}
