//! Stripe session creation for the BillingService Connect methods.
//!
//! Authorization and input validation are applied by the Connect adapter
//! before these shared operations reach Stripe.

use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use codewire_server_core::{AppError, AppResult};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use url::{Origin, Url};

use crate::routes::BillingState;

#[derive(Debug)]
pub struct CheckoutRequest {
    pub plan: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug)]
pub struct PortalRequest {
    pub return_url: String,
}

#[derive(Debug)]
pub struct SetupRequest {
    pub success_url: String,
    pub cancel_url: String,
}

/// Configured frontend origin used to constrain Stripe navigation targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendOrigin(Origin);

impl FrontendOrigin {
    pub fn parse(configured_url: &str) -> anyhow::Result<Self> {
        let url = Url::parse(configured_url)
            .map_err(|error| anyhow::anyhow!("invalid FRONTEND_URL: {error}"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.origin(), Origin::Tuple(..))
        {
            anyhow::bail!("FRONTEND_URL must be an absolute HTTP(S) origin");
        }
        Ok(Self(url.origin()))
    }

    /// Billing's public Stripe webhook URL on this origin: the ingress routes
    /// `/api/webhooks/stripe` on the frontend host to billing.
    pub fn webhook_url(&self) -> String {
        format!("{}/api/webhooks/stripe", self.0.ascii_serialization())
    }

    fn validate_redirect(&self, field: &str, value: &str) -> Result<(), AppError> {
        let url = Url::parse(value).map_err(|_| {
            AppError::BadRequest(
                format!("{field} must be an absolute URL on the configured frontend origin").into(),
            )
        })?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.origin() != self.0
        {
            return Err(AppError::BadRequest(
                format!("{field} must use the configured frontend origin").into(),
            ));
        }
        Ok(())
    }
}

/// Steps 1–3 of the shared gate (see module docs).
async fn require_billing_admin(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
) -> Result<(), AppError> {
    if !state.stripe.is_configured() {
        return Err(AppError::NotFound("billing is not enabled".into()));
    }
    require_org_billing_admin(&state.pool, user, org_id).await
}

/// An organization owner or admin: non-members see a 404.
pub(crate) async fn require_org_billing_admin(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<(), AppError> {
    let role = user_org_role(pool, user, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    // Assignment lookup failures are ignored in Go (`assignments, _ :=`).
    let assignments = user_assignments(pool, org_id, &user.user_id)
        .await
        .unwrap_or_default();
    if !can_admin(&role, &assignments) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Org name + owner email for customer creation (checkout errors when
/// either is missing, like the Go `QueryRow().Scan` error path).
async fn org_identity(pool: &PgPool, org_id: &str) -> Result<(String, String), AppError> {
    let name: String = sqlx::query_scalar(r#"SELECT name FROM organizations WHERE id = $1"#)
        .bind(org_id)
        .fetch_one(pool)
        .await?;
    let owner_email: String = sqlx::query_scalar(
        r#"SELECT u.email FROM org_members m JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1 AND m.role = 'owner' ORDER BY m.created_at ASC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    Ok((name, owner_email))
}

async fn existing_managed_org_subscription(
    pool: &PgPool,
    org_id: &str,
) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar(
        r#"SELECT stripe_subscription_id
           FROM org_subscriptions
           WHERE org_id = $1
             AND stripe_subscription_id IS NOT NULL
             AND stripe_subscription_id <> ''
             AND status IN ('active', 'trialing', 'past_due', 'unpaid', 'incomplete', 'paused')
           ORDER BY updated_at DESC
           LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?)
}

/// Shared checkout-session operation used by the Connect adapter.
pub async fn create_checkout_session(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    body: CheckoutRequest,
) -> AppResult<String> {
    require_billing_admin(state, user, org_id).await?;
    if body.plan.is_empty() {
        return Err(AppError::BadRequest("plan is required".into()));
    }
    if body.success_url.is_empty() || body.cancel_url.is_empty() {
        return Err(AppError::BadRequest(
            "success_url and cancel_url are required".into(),
        ));
    }
    state
        .frontend_origin
        .validate_redirect("success_url", &body.success_url)?;
    state
        .frontend_origin
        .validate_redirect("cancel_url", &body.cancel_url)?;
    if existing_managed_org_subscription(&state.pool, org_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "organization already has a Stripe subscription; use the billing portal to manage it"
                .into(),
        ));
    }

    match build_checkout(state, org_id, &body).await {
        Ok(url) => Ok(url),
        Err(e) => {
            tracing::error!(error = ?e, "billing: org checkout session failed");
            Err(AppError::InternalMsg(
                "failed to create checkout session".into(),
            ))
        }
    }
}

/// The Go handler collapses every CreateOrgCheckoutSession error into a
/// logged 500; this helper carries the underlying causes.
async fn build_checkout(
    state: &BillingState,
    org_id: &str,
    body: &CheckoutRequest,
) -> Result<String, AppError> {
    let pool = &state.pool;

    // Plan validation against the org catalog (billing.GetOrgPlan).
    let plan: Option<(bool, bool)> = sqlx::query_as(
        r#"SELECT is_contact_us, archived_at IS NOT NULL
           FROM billing_catalog_plans WHERE resource_type = 'org' AND plan_key = $1"#,
    )
    .bind(&body.plan)
    .fetch_optional(pool)
    .await?;
    let (is_contact_us, archived) =
        plan.ok_or_else(|| AppError::Internal(anyhow::anyhow!("unknown plan: {}", body.plan)))?;
    if archived {
        return Err(AppError::Internal(anyhow::anyhow!(
            "plan is archived: {}",
            body.plan
        )));
    }
    if is_contact_us {
        return Err(AppError::Internal(anyhow::anyhow!(
            "enterprise plan requires contacting sales"
        )));
    }

    let mode = state.stripe.stripe_mode();
    let price_id: Option<String> = sqlx::query_scalar(
        r#"SELECT stripe_price_id FROM billing_catalog_prices
           WHERE resource_type = 'org' AND plan_key = $1 AND stripe_mode = $2
             AND price_kind = 'subscription' AND archived_at IS NULL"#,
    )
    .bind(&body.plan)
    .bind(mode)
    .fetch_optional(pool)
    .await?;
    let price_id = price_id.filter(|p| !p.is_empty()).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "no Stripe price configured for plan: {}",
            body.plan
        ))
    })?;
    let seat_price_id: Option<String> = sqlx::query_scalar(
        r#"SELECT stripe_price_id FROM billing_catalog_prices
           WHERE resource_type = 'org' AND stripe_mode = $1
             AND price_kind = 'seat_addon' AND archived_at IS NULL
           LIMIT 1"#,
    )
    .bind(mode)
    .fetch_optional(pool)
    .await?;

    let (org_name, owner_email) = org_identity(pool, org_id).await?;
    let customer_idempotency_key = billing_idempotency_key("customer", &[org_id]);
    let customer_id = run_organization_billing_mutation(pool, org_id, async {
        state
            .stripe
            .ensure_customer(
                pool,
                org_id,
                &org_name,
                &owner_email,
                &customer_idempotency_key,
            )
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;

    // Remaining trial days (ceil), like the Go handler.
    let trial_ends_at: Option<Option<chrono::NaiveDateTime>> =
        sqlx::query_scalar(r#"SELECT trial_ends_at FROM organizations WHERE id = $1"#)
            .bind(org_id)
            .fetch_optional(pool)
            .await?;
    let trial_days = trial_ends_at.flatten().and_then(|end| {
        let end = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end, chrono::Utc);
        let remaining = (end - chrono::Utc::now()).num_seconds() as f64 / 86400.0;
        let days = remaining.ceil() as i64;
        (days > 0).then_some(days as u32)
    });

    run_organization_billing_mutation(pool, org_id, async {
        state
            .stripe
            .create_org_checkout_session(
                &customer_id,
                org_id,
                &body.plan,
                &price_id,
                seat_price_id.as_deref(),
                trial_days,
                &body.success_url,
                &body.cancel_url,
            )
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await
}

fn billing_idempotency_key(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("cw-{kind}-{}", hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Shared portal-session operation used by the Connect adapter.
pub async fn create_portal_session(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    body: PortalRequest,
) -> AppResult<String> {
    require_billing_admin(state, user, org_id).await?;
    if body.return_url.is_empty() {
        return Err(AppError::BadRequest("return_url is required".into()));
    }
    state
        .frontend_origin
        .validate_redirect("return_url", &body.return_url)?;

    let customer_id: Option<Option<String>> =
        sqlx::query_scalar(r#"SELECT stripe_customer_id FROM organizations WHERE id = $1"#)
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await?;
    let result = match customer_id.flatten().filter(|c| !c.is_empty()) {
        Some(customer) => {
            run_organization_billing_mutation(&state.pool, org_id, async {
                state
                    .stripe
                    .create_portal_session(&customer, &body.return_url)
                    .await
                    .map_err(OrganizationBillingMutationError::ambiguous)
            })
            .await
        }
        None => Err(AppError::Internal(anyhow::anyhow!(
            "no stripe customer for org {org_id}"
        ))),
    };
    match result {
        Ok(url) => Ok(url),
        Err(e) => {
            tracing::error!(error = ?e, "billing: portal session failed");
            Err(AppError::InternalMsg(
                "failed to create portal session".into(),
            ))
        }
    }
}

/// Shared setup-session operation used by the Connect adapter.
pub async fn create_setup_session(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    body: SetupRequest,
) -> AppResult<String> {
    require_billing_admin(state, user, org_id).await?;
    if body.success_url.is_empty() || body.cancel_url.is_empty() {
        return Err(AppError::BadRequest(
            "success_url and cancel_url are required".into(),
        ));
    }
    state
        .frontend_origin
        .validate_redirect("success_url", &body.success_url)?;
    state
        .frontend_origin
        .validate_redirect("cancel_url", &body.cancel_url)?;

    let result = async {
        let (org_name, owner_email) = org_identity(&state.pool, org_id).await?;
        let customer_idempotency_key = billing_idempotency_key("customer", &[org_id]);
        let customer_id = run_organization_billing_mutation(&state.pool, org_id, async {
            state
                .stripe
                .ensure_customer(
                    &state.pool,
                    org_id,
                    &org_name,
                    &owner_email,
                    &customer_idempotency_key,
                )
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)
        })
        .await?;
        run_organization_billing_mutation(&state.pool, org_id, async {
            state
                .stripe
                .create_setup_session(&customer_id, &body.success_url, &body.cancel_url, org_id)
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)
        })
        .await
    }
    .await;

    match result {
        Ok(url) => Ok(url),
        Err(e) => {
            tracing::error!(error = ?e, "billing: setup session failed");
            Err(AppError::InternalMsg(
                "failed to create setup session".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frontend_origin_accepts_only_absolute_same_origin_http_urls() {
        let origin = FrontendOrigin::parse("https://app.codewire.test:443/base").unwrap();
        for value in [
            "https://app.codewire.test/success",
            "https://app.codewire.test:443/cancel?checkout=1#done",
        ] {
            origin.validate_redirect("return_url", value).unwrap();
        }

        for value in [
            "/relative",
            "http://app.codewire.test/insecure",
            "https://other.codewire.test/cross-origin",
            "https://app.codewire.test:444/wrong-port",
            "https://user@app.codewire.test/userinfo",
            "javascript:alert(1)",
        ] {
            let error = origin
                .validate_redirect("return_url", value)
                .expect_err(value);
            assert!(
                matches!(error, AppError::BadRequest(_)),
                "{value}: {error:?}"
            );
        }
    }

    #[test]
    fn frontend_origin_rejects_invalid_configuration() {
        for value in [
            "app.codewire.test",
            "ftp://app.codewire.test",
            "https://user@app.codewire.test",
        ] {
            assert!(FrontendOrigin::parse(value).is_err(), "{value}");
        }
    }
}
