//! `POST /api/auth/sign-up` (public): email and password sign-up, one path for
//! every `IDP_SIGNUP` mode, which only decides what admits an account.
//!
//! - `review`, the hosted default: Turnstile; an invite code admits at once,
//!   and anyone else waits for access review with a reason.
//! - `open`: Turnstile; everyone is admitted.
//! - `invite-only`, self-hosted (#4121): an organization invitation for the
//!   address admits; anyone else waits for the admin, saying why when
//!   `IDP_SIGNUP_REASON=required`. Nothing is taken before setup has made the
//!   admin. Turnstile only when its keys are set, and never for an invite
//!   link. Without mail the admin vouches for the address (`email_vouched_by`)
//!   and an admitted account signs in at once.
//!
//! With mail every address is verified by email before it signs in, and
//! sign-up issues no session (#4481).

use super::sign_up_invitation::{address_taken, invitation_for_sign_up, invitation_is_live};
use super::*;

/// Whether a sign-up from an invite link also passes Turnstile when an
/// invite-only server has its keys. Decided no (#4121, cw-pm for the owner):
/// a per-address, one-time link skips the challenge; every other sign-up
/// passes it.
const TURNSTILE_FOR_INVITED: bool = false;

/// What admitted a sign-up, or that nothing did.
enum Admission {
    /// Decided before anything is written: an invite code in review mode, or
    /// everyone in open mode.
    AtOnce,
    /// An organization invitation, by id (invite-only).
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
/// decide admission here; an invite-only server reads its invitation in the
/// sign-up's transaction, so its admission is `None` until then.
async fn admit(
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
    let human_verification = match mode {
        SignupMode::Review | SignupMode::Open => true,
        SignupMode::InviteOnly if !turnstile_configured => false,
        SignupMode::InviteOnly if TURNSTILE_FOR_INVITED => true,
        // Only a token that names a live invitation for this address skips
        // the challenge; a missing or wrong one gets it, so the parameter is
        // never a way around it.
        SignupMode::InviteOnly => {
            !invitation_is_live(&state.pool, &req.invitation_token, &req.email, mail).await?
        }
    };
    if human_verification {
        validate_turnstile(state, &req.email, &req.turnstile_token).await?;
    }

    let decided = match mode {
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

pub(super) async fn sign_up(
    State(state): State<SessionAuthState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<SignUpRequest>,
) -> Result<Response, AppError> {
    let decided = admit(&state, &req).await?;

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
        None => invite_only_admission(state, &mut tx, req).await?,
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
            created_at: format_time(created_at),
        },
        admission,
        verification_token,
    })
}

/// Admission on an invite-only server, in the sign-up's transaction: nothing
/// before setup has made the admin; one sign-up per address at a time,
/// whatever its case; then an organization invitation, or nothing; and never
/// an address that already has an account.
async fn invite_only_admission(
    state: &SessionAuthState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    req: &SignUpRequest,
) -> Result<Admission, AppError> {
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to admit an invite-only sign-up");
        AppError::InternalMsg("Failed to create account".into())
    };
    if !crate::admin_bootstrap::admin_exists(&mut **tx)
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
            invitation_for_sign_up(tx, &req.invitation_token, &req.email, mail).await?;
        Admission::Invitation(invitation.id)
    };
    if address_taken(tx, &req.email).await? {
        return Err(AppError::Conflict(
            "An account with this email already exists; sign in instead".into(),
        ));
    }
    Ok(admission)
}
