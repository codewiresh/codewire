//! First-run 5-step onboarding overlay (#6659):
//! 1. Name organization (`/onboarding/workspace`) — pre-2FA admitted
//! 2. Choose a plan (`/{slug}/onboarding/plan`) — pre-2FA admitted
//! 3. Secure account / 2FA (`/{slug}/onboarding/2fa`) — auto-skips if 2FA already enabled
//! 4. Connect your code (`/{slug}/onboarding/code`)
//! 5. Bring your AI subscription (`/{slug}/onboarding/ai`) -> marks `onboarding_completed_at`

use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use codewire_proto::codewire::v1::{Credential, CredentialAuthenticationKind, CredentialStatus};
use connectrpc::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    billing_connect,
    connect::{create_organization as create_organization_rpc, organizations},
    credentials_connect,
    error::WebError,
    raw_auth::{post_json, post_json_with_origin},
    response::{
        error_page, login_redirect, redirect, render_billing_page, render_page, render_template,
        two_factor_redirect,
    },
    routes::{ONBOARDING_WORKSPACE_PATH, authentication::totp_qr_svg},
    security::{
        canonical_cookie, csrf_cookie, page_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::{
        OnboardingAiTemplate, OnboardingChrome, OnboardingCodeTemplate, OnboardingPlanTemplate,
        OnboardingTwoFactorTemplate, OnboardingWorkspaceTemplate,
    },
    view::{
        OrganizationFormSubmission, OrganizationFormView, OrganizationRow,
        apply_organization_error, valid_organization_slug, validate_organization_form,
    },
};

#[derive(Debug, Default, Deserialize)]
pub(super) struct PlanQuery {
    #[serde(default)]
    canceled: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct PlanReturnQuery {
    #[serde(default)]
    session_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChoosePlanSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    plan: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PaygCardBeginSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    top_up: Option<String>,
    #[serde(default)]
    top_up_amount: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PaygCardFinishSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    setup_intent: String,
}

#[derive(Debug, Default, Serialize)]
struct CardSetupAnswer {
    #[serde(skip_serializing_if = "String::is_empty")]
    client_secret: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Serialize)]
struct EmptyRequest {}

#[derive(Deserialize)]
struct TwoFactorEnableResponse {
    #[serde(rename = "totpUri")]
    totp_uri: String,
    secret: String,
}

#[derive(Deserialize)]
struct CompleteOnboardingResponse {
    #[allow(dead_code)]
    #[serde(default)]
    completed: bool,
}

fn valid_form(state: &AppState, headers: &HeaderMap, csrf: &str) -> bool {
    request_has_same_origin(headers, &state.public_origin) && valid_csrf_token(headers, csrf)
}

fn private_card_json(status: StatusCode, answer: CardSetupAnswer) -> Response {
    let mut response = (status, Json(answer)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

fn private_card_error(status: StatusCode, message: &str) -> Response {
    private_card_json(
        status,
        CardSetupAnswer {
            error: message.to_owned(),
            ..Default::default()
        },
    )
}

#[allow(clippy::result_large_err)]
async fn resolve_org_json(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
) -> Result<(IdentityUser, OrganizationRow, axum::http::HeaderValue), Response> {
    let cookie = canonical_cookie(headers).map_err(|()| {
        private_card_error(
            StatusCode::UNAUTHORIZED,
            "Sign in again to continue card verification.",
        )
    })?;
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => private_card_error(
                StatusCode::UNAUTHORIZED,
                "Sign in again to continue card verification.",
            ),
            _ => private_card_error(
                StatusCode::BAD_GATEWAY,
                "Could not verify your session right now.",
            ),
        })?;
    let orgs = organizations(state, cookie.clone())
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => private_card_error(
                StatusCode::UNAUTHORIZED,
                "Sign in again to continue card verification.",
            ),
            _ => private_card_error(
                StatusCode::BAD_GATEWAY,
                "Could not load your organization right now.",
            ),
        })?;
    let Some(org) = orgs.into_iter().find(|org| org.slug == slug) else {
        return Err(private_card_error(
            StatusCode::NOT_FOUND,
            "Organization not found.",
        ));
    };
    Ok((identity, org, cookie))
}

fn chrome(
    step: u8,
    identity: &IdentityUser,
    org_slug: &str,
    csrf_token: String,
) -> OnboardingChrome {
    OnboardingChrome {
        step,
        email: identity.email().to_owned(),
        org_slug: org_slug.to_owned(),
        csrf_token,
    }
}

/// Resolves an authenticated user + organization by slug. Steps 1 and 2 admit
/// pre-2FA sessions (`require_2fa = false`); steps 4 and 5 enforce 2FA.
#[allow(clippy::result_large_err)]
async fn resolve_org(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    continuation: &str,
    require_2fa: bool,
) -> Result<(IdentityUser, OrganizationRow, axum::http::HeaderValue), Response> {
    let cookie = canonical_cookie(headers).map_err(|()| login_redirect(continuation, headers))?;
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => login_redirect(continuation, headers),
            other => error_page(other),
        })?;
    if require_2fa && let Err(WebError::TwoFactorRequired) = enforce_two_factor(&identity) {
        return Err(two_factor_redirect(continuation, headers));
    }
    let orgs = organizations(state, cookie.clone())
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => login_redirect(continuation, headers),
            other => error_page(other),
        })?;
    let Some(org) = orgs.into_iter().find(|org| org.slug == slug) else {
        return Err(redirect(ONBOARDING_WORKSPACE_PATH.to_owned(), headers));
    };
    Ok((identity, org, cookie))
}

/// Formats a raw Base32 TOTP secret in 4-character groups (`JBSW Y3DP EHPK 3PXP`)
/// and a masked preview (`JBSW •••• •••• 3PXP`) for Step 3 (#6659).
fn format_totp_secret(secret: &str) -> (String, String) {
    let clean: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let chars: Vec<char> = clean.chars().collect();
    let grouped = chars
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ");
    let masked = if chars.len() <= 8 {
        grouped.clone()
    } else {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{prefix} •••• •••• {suffix}")
    };
    (grouped, masked)
}

/// Step 1: Name organization (`GET /onboarding/workspace`). Admits pre-2FA sessions.
pub(super) async fn workspace_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return login_redirect(ONBOARDING_WORKSPACE_PATH, &headers),
        Err(error) => return error_page(error),
    };
    let csrf = page_csrf_token(&headers);
    let form = OrganizationFormView::default();
    let chrome = chrome(1, &identity, "", csrf.clone());
    with_csrf_cookie(
        render_page(OnboardingWorkspaceTemplate {
            chrome: &chrome,
            form: &form,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

/// Step 1 submit (`POST /onboarding/workspace/_actions/create`).
pub(super) async fn create_workspace_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<OrganizationFormSubmission>,
) -> Response {
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return login_redirect(ONBOARDING_WORKSPACE_PATH, &headers),
        Err(error) => return error_page(error),
    };
    if !valid_form(&state, &headers, &submission.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let mut form = OrganizationFormView {
        name: submission.name.trim().to_owned(),
        slug: submission.slug.trim().to_owned(),
        ..Default::default()
    };
    validate_organization_form(&mut form);
    let csrf = page_csrf_token(&headers);
    let chrome = chrome(1, &identity, "", csrf.clone());
    if form.has_errors() {
        return with_csrf_cookie(
            render_template(
                StatusCode::UNPROCESSABLE_ENTITY,
                OnboardingWorkspaceTemplate {
                    chrome: &chrome,
                    form: &form,
                },
            ),
            csrf_cookie(&state.public_origin, &csrf),
        );
    }
    let Ok(cookie) = canonical_cookie(&headers) else {
        return login_redirect(ONBOARDING_WORKSPACE_PATH, &headers);
    };
    match create_organization_rpc(&state, cookie, &form).await {
        Ok(()) => redirect(format!("/{}/onboarding/plan", form.slug), &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(ONBOARDING_WORKSPACE_PATH, &headers)
        }
        Err(error) => {
            apply_organization_error(&mut form, &error);
            with_csrf_cookie(
                render_template(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    OnboardingWorkspaceTemplate {
                        chrome: &chrome,
                        form: &form,
                    },
                ),
                csrf_cookie(&state.public_origin, &csrf),
            )
        }
    }
}

/// Step 2: Choose a plan (`GET /{slug}/onboarding/plan`). Admits pre-2FA sessions.
pub(super) async fn plan_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<PlanQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/plan");
    let (identity, org, cookie) =
        match resolve_org(&state, &headers, &slug, &continuation, false).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
    let facts = match billing_connect::onboarding_billing_facts(&state, cookie, &org.id).await {
        Ok(facts) => facts,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(error) => return error_page(error),
    };
    if !facts.billing_enabled {
        return redirect(format!("/{}/onboarding/2fa", org.slug), &headers);
    }
    let csrf = page_csrf_token(&headers);
    let chrome = chrome(2, &identity, &org.slug, csrf.clone());
    let error = if !query.canceled.is_empty() {
        "Checkout was canceled. Choose a plan when you are ready."
    } else if query.error == "checkout-failed" {
        "Unable to start checkout right now. Please try again."
    } else if query.error == "payg-card-required" {
        "Add a card to activate Pay as you go."
    } else if query.error == "reconcile-failed" {
        "We could not verify your subscription yet. Refresh or choose a plan again."
    } else {
        ""
    };
    crate::response::with_billing_referrer_policy(with_csrf_cookie(
        render_billing_page(OnboardingPlanTemplate {
            chrome: &chrome,
            billing_enabled: facts.billing_enabled,
            has_payment_method: facts.has_payment_method,
            stripe_publishable_key: &facts.stripe_publishable_key,
            error,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    ))
}

/// Step 2 action (`POST /{slug}/onboarding/plan/_actions/choose`).
pub(super) async fn choose_plan_action(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ChoosePlanSubmission>,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/plan");
    let (_, org, cookie) = match resolve_org(&state, &headers, &slug, &continuation, false).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if !valid_form(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    let facts =
        match billing_connect::onboarding_billing_facts(&state, cookie.clone(), &org.id).await {
            Ok(facts) => facts,
            Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
            Err(error) => return error_page(error),
        };
    if !facts.billing_enabled {
        return redirect(format!("/{}/onboarding/2fa", org.slug), &headers);
    }
    let plan = form.plan.trim().to_ascii_lowercase();
    match plan.as_str() {
        "payg" => match billing_connect::activate_payg_plan(&state, cookie, org.id).await {
            Ok(()) => redirect(format!("/{}/onboarding/2fa", org.slug), &headers),
            Err(error) if error.code == ErrorCode::FailedPrecondition => redirect(
                format!("/{}/onboarding/plan?error=payg-card-required", org.slug),
                &headers,
            ),
            Err(_) => redirect(
                format!("/{}/onboarding/plan?error=checkout-failed", org.slug),
                &headers,
            ),
        },
        "pro" | "max" => {
            let origin = state.public_origin.as_str().trim_end_matches('/');
            let success_url = format!(
                "{origin}/{}/onboarding/plan/return?session_id={{CHECKOUT_SESSION_ID}}",
                org.slug
            );
            let cancel_url = format!("{origin}/{}/onboarding/plan?canceled=1", org.slug);
            match billing_connect::create_plan_checkout(
                &state,
                cookie,
                org.id,
                plan,
                success_url,
                cancel_url,
            )
            .await
            {
                Ok(url) => {
                    let safe = billing_connect::safe_stripe_url(url);
                    if safe.is_empty() {
                        redirect(
                            format!("/{}/onboarding/plan?error=checkout-failed", org.slug),
                            &headers,
                        )
                    } else {
                        redirect(safe, &headers)
                    }
                }
                Err(_) => redirect(
                    format!("/{}/onboarding/plan?error=checkout-failed", org.slug),
                    &headers,
                ),
            }
        }
        _ => redirect(format!("/{}/onboarding/plan", org.slug), &headers),
    }
}

/// Step 2 PAYG SetupIntent start (`POST /{slug}/onboarding/plan/_actions/payg-card-begin`).
pub(super) async fn payg_card_begin_action(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<PaygCardBeginSubmission>,
) -> Response {
    if !valid_organization_slug(&slug) {
        return private_card_error(StatusCode::NOT_FOUND, "Organization not found.");
    }
    if !valid_form(&state, &headers, &form.csrf) {
        return private_card_error(
            StatusCode::FORBIDDEN,
            "Session expired. Reload the page and try again.",
        );
    }
    let (_, org, cookie) = match resolve_org_json(&state, &headers, &slug).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let top_up_cents = billing_connect::top_up_cents(&form.top_up_amount).unwrap_or(2000);
    let choice = billing_connect::CardSetupChoice {
        auto_top_up_enabled: form.top_up.as_deref() == Some("true"),
        auto_top_up_cents: top_up_cents,
        credit_cents: None,
    };
    let client_hop = codewire_server_core::client_address::forwarded_client_hop(&headers);
    match billing_connect::begin_card_setup(&state, cookie, client_hop, org.id, choice).await {
        Ok(client_secret) => private_card_json(
            StatusCode::OK,
            CardSetupAnswer {
                client_secret,
                ..Default::default()
            },
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => private_card_error(
            StatusCode::UNAUTHORIZED,
            "Sign in again to continue card verification.",
        ),
        Err(_) => private_card_error(
            StatusCode::BAD_GATEWAY,
            "Could not start card verification right now.",
        ),
    }
}

/// Step 2 PAYG SetupIntent finish (`POST /{slug}/onboarding/plan/_actions/payg-card-finish`).
pub(super) async fn payg_card_finish_action(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<PaygCardFinishSubmission>,
) -> Response {
    if !valid_organization_slug(&slug) {
        return private_card_error(StatusCode::NOT_FOUND, "Organization not found.");
    }
    if !valid_form(&state, &headers, &form.csrf) {
        return private_card_error(
            StatusCode::FORBIDDEN,
            "Session expired. Reload the page and try again.",
        );
    }
    let (_, org, cookie) = match resolve_org_json(&state, &headers, &slug).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if let Err(error) = billing_connect::finish_card_setup(
        &state,
        cookie.clone(),
        org.id.clone(),
        form.setup_intent,
    )
    .await
    {
        if error.code == ErrorCode::Unauthenticated {
            return private_card_error(
                StatusCode::UNAUTHORIZED,
                "Sign in again to continue card verification.",
            );
        }
        return private_card_error(
            StatusCode::BAD_GATEWAY,
            "Could not save your card right now.",
        );
    }
    if let Err(error) = billing_connect::activate_payg_plan(&state, cookie, org.id).await {
        if error.code == ErrorCode::Unauthenticated {
            return private_card_error(
                StatusCode::UNAUTHORIZED,
                "Sign in again to continue card verification.",
            );
        }
        return private_card_error(
            StatusCode::BAD_GATEWAY,
            "Card saved, but activating Pay as you go failed. Please try again.",
        );
    }
    private_card_json(
        StatusCode::OK,
        CardSetupAnswer {
            location: format!("/{}/onboarding/2fa", org.slug),
            ..Default::default()
        },
    )
}

/// Step 2 Stripe Checkout return (`GET /{slug}/onboarding/plan/return?session_id=...`).
pub(super) async fn plan_return(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<PlanReturnQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/plan");
    let (_, org, cookie) = match resolve_org(&state, &headers, &slug, &continuation, false).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if query.session_id.trim().is_empty() {
        return redirect(format!("/{}/onboarding/plan", org.slug), &headers);
    }
    match billing_connect::reconcile_plan_checkout(&state, cookie, org.id, query.session_id).await {
        Ok(()) => redirect(format!("/{}/onboarding/2fa", org.slug), &headers),
        Err(_) => redirect(
            format!("/{}/onboarding/plan?error=reconcile-failed", org.slug),
            &headers,
        ),
    }
}

/// Step 3: Secure account / 2FA (`GET /{slug}/onboarding/2fa`). Auto-skips if
/// 2FA is already enabled on the account.
pub(super) async fn two_factor_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/2fa");
    let (identity, org, cookie) =
        match resolve_org(&state, &headers, &slug, &continuation, false).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
    if identity.two_factor_enabled() {
        return redirect(format!("/{}/onboarding/code", org.slug), &headers);
    }
    let setup = match post_json::<_, TwoFactorEnableResponse>(
        &state,
        "/api/auth/two-factor/enable",
        Some(cookie),
        &EmptyRequest {},
    )
    .await
    {
        Ok(response) if response.status.is_success() => match response.body {
            Some(body) => body,
            None => return error_page(WebError::IdentityUnavailable),
        },
        Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
            return login_redirect(&continuation, &headers);
        }
        _ => return error_page(WebError::IdentityUnavailable),
    };
    let Some(qr_svg) = totp_qr_svg(&setup.totp_uri) else {
        return error_page(WebError::IdentityUnavailable);
    };
    let (grouped_secret, masked_secret) = format_totp_secret(&setup.secret);
    let csrf = page_csrf_token(&headers);
    let chrome = chrome(3, &identity, &org.slug, csrf.clone());
    with_csrf_cookie(
        render_page(OnboardingTwoFactorTemplate {
            chrome: &chrome,
            qr_svg: &qr_svg,
            secret: &setup.secret,
            grouped_secret: &grouped_secret,
            masked_secret: &masked_secret,
            error: "",
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

fn is_active_credential(credential: &Credential) -> bool {
    credential.status == CredentialStatus::Active
}

/// Step 4: Connect your code (`GET /{slug}/onboarding/code`).
pub(super) async fn code_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/code");
    let (identity, org, cookie) =
        match resolve_org(&state, &headers, &slug, &continuation, true).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
    let credentials = credentials_connect::list_credentials(&state, cookie)
        .await
        .unwrap_or_default();
    let github_connected = credentials
        .iter()
        .any(|c| is_active_credential(c) && c.provider.eq_ignore_ascii_case("github"));
    let ssh_connected = credentials.iter().any(|c| {
        is_active_credential(c) && c.authentication_kind == CredentialAuthenticationKind::SshKey
    });
    let csrf = page_csrf_token(&headers);
    let chrome = chrome(4, &identity, &org.slug, csrf.clone());
    with_csrf_cookie(
        render_page(OnboardingCodeTemplate {
            chrome: &chrome,
            github_connected,
            ssh_connected,
            error: "",
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

/// Step 5: Bring your AI subscription (`GET /{slug}/onboarding/ai`).
pub(super) async fn ai_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/ai");
    let (identity, org, cookie) =
        match resolve_org(&state, &headers, &slug, &continuation, true).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
    let credentials = credentials_connect::list_credentials(&state, cookie)
        .await
        .unwrap_or_default();
    let claude_connected = credentials.iter().any(|c| {
        is_active_credential(c)
            && (c.authentication_kind == CredentialAuthenticationKind::ClaudeSignIn
                || (c.authentication_kind == CredentialAuthenticationKind::Oauth
                    && (c.provider.eq_ignore_ascii_case("claude")
                        || c.provider.eq_ignore_ascii_case("anthropic"))))
    });
    let codex_connected = credentials.iter().any(|c| {
        is_active_credential(c)
            && c.authentication_kind == CredentialAuthenticationKind::Oauth
            && (c.provider.eq_ignore_ascii_case("codex")
                || c.provider.eq_ignore_ascii_case("openai"))
    });
    let antigravity_connected = credentials.iter().any(|c| {
        is_active_credential(c)
            && c.authentication_kind == CredentialAuthenticationKind::Oauth
            && (c.provider.eq_ignore_ascii_case("antigravity")
                || c.provider.eq_ignore_ascii_case("google"))
    });
    let api_key_connected = credentials.iter().any(|c| {
        is_active_credential(c) && c.authentication_kind == CredentialAuthenticationKind::ApiKey
    });
    let csrf = page_csrf_token(&headers);
    let chrome = chrome(5, &identity, &org.slug, csrf.clone());
    with_csrf_cookie(
        render_page(OnboardingAiTemplate {
            chrome: &chrome,
            claude_connected,
            codex_connected,
            antigravity_connected,
            api_key_connected,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

/// Finishes onboarding (`POST /{slug}/onboarding/_actions/complete`), marking
/// `users.onboarding_completed_at` and landing on `/{slug}/sandboxes/`.
pub(super) async fn complete_action(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<crate::view::CsrfSubmission>,
) -> Response {
    if !valid_organization_slug(&slug) {
        return error_page(WebError::NotFound);
    }
    let continuation = format!("/{slug}/onboarding/ai");
    let (_, org, cookie) = match resolve_org(&state, &headers, &slug, &continuation, true).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if !valid_form(&state, &headers, &form.csrf) {
        return error_page(WebError::CsrfRejected);
    }
    match post_json_with_origin::<_, CompleteOnboardingResponse>(
        &state,
        "/api/auth/complete-onboarding",
        cookie,
        &EmptyRequest {},
    )
    .await
    {
        Ok(response) if response.status.is_success() => {
            redirect(format!("/{}/sandboxes/", org.slug), &headers)
        }
        Ok(response) if response.status == StatusCode::UNAUTHORIZED => {
            login_redirect(&continuation, &headers)
        }
        _ => error_page(WebError::IdentityUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_secret_formats_grouped_and_masked() {
        let (grouped, masked) = format_totp_secret("jbswy3dpehpk3pxp");
        assert_eq!(grouped, "JBSW Y3DP EHPK 3PXP");
        assert_eq!(masked, "JBSW •••• •••• 3PXP");
    }

    #[test]
    fn private_card_json_sets_no_store_and_vary_cookie() {
        let response = private_card_json(
            StatusCode::OK,
            CardSetupAnswer {
                client_secret: "seti_secret_test".into(),
                ..Default::default()
            },
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::VARY).unwrap(), "Cookie");
    }
}
