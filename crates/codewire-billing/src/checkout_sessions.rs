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

    /// The organization's Billing page in the dashboard, which billing
    /// emails link to (#4553).
    /// The organization's Billing page, or the dashboard, which lists the
    /// person's organizations, when the slug is unknown (#4553).
    pub fn billing_url(&self, org_slug: Option<&str>) -> String {
        match org_slug {
            Some(slug) => format!("{}/{slug}/billing/", self.0.ascii_serialization()),
            None => format!("{}/dashboard/", self.0.ascii_serialization()),
        }
    }

    /// Admin → Organizations, and one organization's page there, which the
    /// operator's purchase notices link to (#5358).
    pub fn admin_organizations_url(&self) -> String {
        format!("{}/admin/organizations/", self.0.ascii_serialization())
    }

    pub fn admin_organization_url(&self, organization_id: &str) -> String {
        format!(
            "{}/admin/organizations/{organization_id}/",
            self.0.ascii_serialization()
        )
    }

    pub(crate) fn validate_redirect(&self, field: &str, value: &str) -> Result<(), AppError> {
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
pub(crate) async fn require_billing_admin(
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
pub(crate) async fn org_identity(
    pool: &PgPool,
    org_id: &str,
) -> Result<(String, String), AppError> {
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

pub(crate) fn billing_idempotency_key(kind: &str, parts: &[&str]) -> String {
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
    fn the_billing_page_is_on_the_frontend_origin() {
        for configured in ["https://app.codewire.test", "https://app.codewire.test/"] {
            assert_eq!(
                FrontendOrigin::parse(configured)
                    .unwrap()
                    .billing_url(Some("acme")),
                "https://app.codewire.test/acme/billing/"
            );
            assert_eq!(
                FrontendOrigin::parse(configured).unwrap().billing_url(None),
                "https://app.codewire.test/dashboard/"
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
