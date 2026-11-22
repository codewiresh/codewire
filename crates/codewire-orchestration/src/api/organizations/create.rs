//! Creating an organization: its row, its owner, and its sign-up credit.
//! Split out of `organizations.rs` (#3297).

use super::*;

/// Counts one organization create by `user_id` (#3297): each organization
/// brings its own quota, so how many one account makes is bounded too, five a
/// day unless an admin sets another count.
async fn admit_organization_create(pool: &sqlx::PgPool, user_id: &str) -> AppResult<()> {
    super::super::environments::take_user_rate_limit(
        pool,
        &codewire_server_core::rate_limit::ORG_CREATE,
        user_id,
        "organization creates",
    )
    .await
}

pub(crate) async fn create_organization_core(
    state: ApiState,
    user: AuthUser,
    body: CreateOrgBody,
) -> AppResult<Organization> {
    // An API key acts only inside its own organization, and each new one
    // brings its own sign-up credit (#5863, docs/dev/AUTH-POLICY.md).
    if user.via_api_key {
        return Err(AppError::Coded {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "api_key_scope_violation",
            detail: "organizations are made from a sign-in, not with an API key".into(),
        });
    }
    let name = body.name.trim();
    let slug = body.slug.trim().to_lowercase();
    let slug = slug.as_str();
    if name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    if slug.is_empty() {
        return Err(AppError::BadRequest("slug is required".into()));
    }
    if !codewire_server_core::organization_slug::valid_organization_slug(slug) {
        return Err(AppError::BadRequest(
            "slug is reserved or does not match the canonical route-safe format".into(),
        ));
    }

    let (organization, signup_credit_nano_eur) =
        create_organization(&state.pool, &user.user_id, name, slug).await?;

    log_audit(
        &state,
        "org.created",
        &user.user_id,
        serde_json::json!({
            "org_id": organization.id,
            "name": name,
            "slug": slug,
            "signup_credit_nano_eur": signup_credit_nano_eur.unwrap_or(0),
        }),
        "info",
    )
    .await;

    Ok(organization)
}

/// Writes an organization, its owner and its sign-up credit in one
/// transaction, once the create is admitted. A taken slug is refused
/// before the create counts, so it never spends one of the day's creates
/// (#3297).
pub(crate) async fn create_organization(
    pool: &sqlx::PgPool,
    user_id: &str,
    name: &str,
    slug: &str,
) -> AppResult<(Organization, Option<i64>)> {
    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)")
            .bind(slug)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "organizations: slug lookup failed");
                AppError::InternalMsg("failed to create organization".into())
            })?;
    if taken {
        return Err(AppError::Conflict(
            "organization slug already exists".into(),
        ));
    }
    admit_organization_create(pool, user_id).await?;

    let org_id = uuid::Uuid::new_v4().simple().to_string();
    let member_id = uuid::Uuid::new_v4().simple().to_string();
    let now = chrono::Utc::now().naive_utc();

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: create begin tx failed");
        AppError::InternalMsg("failed to begin transaction".into())
    })?;
    sqlx::query(
        r#"INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $5)"#,
    )
    .bind(&org_id)
    .bind(name)
    .bind(slug)
    .bind(user_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique constraint") {
            return AppError::Conflict("organization slug already exists".into());
        }
        tracing::error!(error = %e, "organizations: create failed");
        AppError::InternalMsg("failed to create organization".into())
    })?;
    sqlx::query(
        r#"INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
           VALUES ($1, $2, $3, 'owner', $4, $4)"#,
    )
    .bind(&member_id)
    .bind(&org_id)
    .bind(user_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "organizations: add owner failed");
        AppError::InternalMsg("failed to add owner membership".into())
    })?;
    // It commits with the organization, so neither exists without the other.
    let signup_credit_nano_eur = grant_signup_credit(&mut tx, &org_id).await.map_err(|e| {
        tracing::error!(error = %e, "organizations: sign-up credit failed");
        AppError::InternalMsg("failed to grant the sign-up credit".into())
    })?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "organizations: create commit failed");
        AppError::InternalMsg("failed to commit transaction".into())
    })?;

    Ok((
        Organization {
            id: org_id,
            name: name.to_string(),
            slug: slug.to_string(),
            created_by: user_id.to_owned(),
            created_at: format_time(now),
            updated_at: format_time(now),
        },
        signup_credit_nano_eur,
    ))
}

/// Grants a new organization the sign-up credit current now, once (#3381,
/// owner, 2026-11-10), and returns it in nano-euros. A platform admin sets it
/// on the admin Billing page; 0 is off and grants nothing.
pub(super) async fn grant_signup_credit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        r#"INSERT INTO billing_credit_ledger
               (organization_id, entry_kind, amount_nano_eur, idempotency_key, reason)
           SELECT $1, 'grant', int_value::int8 * 10000000, 'signup_credit', 'Sign-up credit'
             FROM billing_catalog_settings
            WHERE setting_key = 'signup_credit_cents' AND int_value > 0
           RETURNING amount_nano_eur"#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **tx)
    .await
}
