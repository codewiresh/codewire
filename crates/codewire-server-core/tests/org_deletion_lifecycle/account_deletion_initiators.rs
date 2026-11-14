//! DB-backed account deletion by an admin and by the purge of email sign-ups
//! that never verify (#4541): who may ask, what is recorded, that the purge
//! keeps every account that holds something, and that an address verified
//! between the selection and the deletion keeps its account.

use codewire_server_core::AppError;
use codewire_server_core::account_deletion::{
    Holding, Initiator, KeptReason, PurgeMode, PurgeOutcome, UNVERIFIED_SIGNUP_LIFETIME_SECS,
    account_deletion_operation, advance_personal_organizations, begin_account_deletion_in,
    complete_account_deletion, finalize_account_deletion_database, purge_unverified_signup,
    record_stripe_customers_deleted, unverified_signup_candidates,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::pool;

/// An email sign-up: a password sign-in, unverified, `age_days` old. An
/// access request (no invite code) is also disabled.
async fn sign_up(pool: &PgPool, label: &str, age_days: i32, access_request: bool) -> String {
    let id = format!("u_purge_{label}_{}", Uuid::new_v4().simple());
    sqlx::query(
        r#"INSERT INTO users (id, email, name, email_verified, enabled, access_reason, created_at)
           VALUES ($1, $1 || '@example.test', 'Purge fixture', false, $2,
                   CASE WHEN $2 THEN NULL ELSE 'Build things' END,
                   NOW()::timestamp - make_interval(days => $3))"#,
    )
    .bind(&id)
    .bind(!access_request)
    .bind(age_days)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, account_id) VALUES ($1, $2, 'credential', $2)",
    )
    .bind(Uuid::new_v4().simple().to_string())
    .bind(&id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO verifications (id, identifier, expires_at, purpose, token_hash) \
         VALUES ($1, $2 || '@example.test', NOW()::timestamp - interval '1 day', \
                 'email_verification', $3)",
    )
    .bind(Uuid::new_v4().simple().to_string())
    .bind(&id)
    .bind(format!("{:064x}", Uuid::new_v4().as_u128()))
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn admin(pool: &PgPool) -> String {
    let id = format!("u_purge_admin_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, is_admin) \
         VALUES ($1, $1 || '@example.test', 'Admin', true, true)",
    )
    .bind(&id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn execute(pool: &PgPool, sql: &str, bind: &str) {
    sqlx::query(sql).bind(bind).execute(pool).await.unwrap();
}

async fn exists(pool: &PgPool, user_id: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn by_admin(
    pool: &PgPool,
    actor: &str,
    user_id: &str,
    confirm_email: &str,
) -> Result<codewire_server_core::account_deletion::AccountDeletionOperation, AppError> {
    let mut tx = pool.begin().await.unwrap();
    let operation = begin_account_deletion_in(
        &mut tx,
        user_id,
        Initiator::Admin {
            actor_user_id: actor,
            confirm_email,
        },
    )
    .await?;
    tx.commit().await.unwrap();
    Ok(operation)
}

/// The audit entry a request wrote: (actor, target, initiator).
async fn requested_audit(
    pool: &PgPool,
    operation_id: &str,
) -> (Option<String>, Option<String>, String) {
    sqlx::query_as(
        r#"SELECT user_id, target_user_id, metadata->>'initiator' FROM audit_logs
           WHERE action = 'account.deletion_requested' AND metadata->>'operation_id' = $1"#,
    )
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Run the workflow's phases for an account that holds no organization.
async fn finish(pool: &PgPool, operation_id: &str) {
    assert!(
        advance_personal_organizations(pool, operation_id)
            .await
            .unwrap()
    );
    record_stripe_customers_deleted(pool, operation_id)
        .await
        .unwrap();
    finalize_account_deletion_database(pool, operation_id)
        .await
        .unwrap();
    complete_account_deletion(pool, operation_id).await.unwrap();
}

#[tokio::test]
async fn an_admin_deletes_an_access_request_and_is_recorded_as_its_actor() {
    let Some(pool) = pool().await else { return };
    let actor = admin(&pool).await;
    let request = sign_up(&pool, "admin_target", 1, true).await;
    let email = format!("{request}@example.test");

    let operation = by_admin(&pool, &actor, &request, &email.to_uppercase())
        .await
        .unwrap();
    assert_eq!(operation.initiator, "admin");
    assert_eq!(operation.actor_user_id.as_deref(), Some(actor.as_str()));
    assert_eq!(
        operation.actor_email.as_deref(),
        Some(format!("{actor}@example.test").as_str())
    );
    assert!(
        !operation.notify_email,
        "an unverified address gets no mail"
    );
    assert_eq!(
        requested_audit(&pool, &operation.id).await,
        (Some(actor.clone()), Some(request.clone()), "admin".into())
    );

    // Repeating it returns the same deletion.
    let again = by_admin(&pool, &actor, &request, &email).await.unwrap();
    assert_eq!(again.id, operation.id);

    finish(&pool, &operation.id).await;
    assert!(!exists(&pool, &request).await);
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM verifications WHERE identifier = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(links, 0, "no link outlives the account");
    // The admin stays the actor after the account is gone.
    assert_eq!(
        requested_audit(&pool, &operation.id).await.0,
        Some(actor.clone())
    );
}

#[tokio::test]
async fn an_admin_cannot_delete_themselves_another_admin_or_without_the_address() {
    let Some(pool) = pool().await else { return };
    let actor = admin(&pool).await;
    let other_admin = admin(&pool).await;
    let not_admin = sign_up(&pool, "not_admin", 1, false).await;
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(&not_admin)
        .execute(&pool)
        .await
        .unwrap();
    let target = sign_up(&pool, "guarded", 1, false).await;
    let target_email = format!("{target}@example.test");

    let refusals = [
        (
            actor.as_str(),
            actor.as_str(),
            format!("{actor}@example.test"),
        ),
        (
            actor.as_str(),
            other_admin.as_str(),
            format!("{other_admin}@example.test"),
        ),
        (not_admin.as_str(), target.as_str(), target_email.clone()),
        (
            actor.as_str(),
            target.as_str(),
            "someone@example.test".to_owned(),
        ),
        (
            actor.as_str(),
            "deleted-user",
            "deleted-user@deleted.codewire.invalid".to_owned(),
        ),
    ];
    for (who, whom, confirm) in &refusals {
        let error = by_admin(&pool, who, whom, confirm).await.unwrap_err();
        assert!(
            matches!(
                error,
                AppError::BadRequest(_) | AppError::Precondition(_) | AppError::Forbidden
            ),
            "{who} deleting {whom}: {error:?}"
        );
    }
    assert!(exists(&pool, &other_admin).await);
    assert!(exists(&pool, &target).await);
    let operations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_deletion_operations WHERE user_id = ANY($1)",
    )
    .bind([actor.clone(), other_admin.clone(), target.clone()])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(operations, 0);
}

#[tokio::test]
async fn the_purge_selects_only_old_unverified_email_sign_ups_that_hold_nothing() {
    let Some(pool) = pool().await else { return };
    let old = sign_up(&pool, "old", 8, true).await;
    let young = sign_up(&pool, "young", 6, true).await;
    let verified = sign_up(&pool, "verified", 8, false).await;
    execute(
        &pool,
        "UPDATE users SET email_verified = true WHERE id = $1",
        &verified,
    )
    .await;
    let admin_signup = sign_up(&pool, "admin_signup", 8, false).await;
    execute(
        &pool,
        "UPDATE users SET is_admin = true WHERE id = $1",
        &admin_signup,
    )
    .await;
    let provider = sign_up(&pool, "provider", 8, false).await;
    execute(
        &pool,
        "INSERT INTO accounts (id, user_id, provider_id, account_id) \
         VALUES ('acc_' || $1, $1, 'github', $1)",
        &provider,
    )
    .await;
    let member = sign_up(&pool, "member", 8, false).await;
    let org = format!("org_{member}");
    execute(
        &pool,
        "INSERT INTO organizations (id, name, slug, created_by) VALUES ('org_' || $1, 'Held', 'held-' || md5($1), $1)",
        &member,
    )
    .await;
    execute(
        &pool,
        "INSERT INTO org_members (id, org_id, user_id, role) VALUES (md5($1), 'org_' || $1, $1, 'owner')",
        &member,
    )
    .await;

    let candidates = unverified_signup_candidates(&pool, UNVERIFIED_SIGNUP_LIFETIME_SECS, 1_000)
        .await
        .unwrap();
    assert!(candidates.contains(&old));
    for kept in [&young, &verified, &admin_signup, &provider, &member] {
        assert!(!candidates.contains(kept), "{kept} is not a candidate");
    }

    // Asked directly, each kept account says why, and nothing changes.
    for (user, reason) in [
        (&young, KeptReason::Young),
        (&verified, KeptReason::Verified),
        (&admin_signup, KeptReason::Admin),
        (&provider, KeptReason::Holds(Holding::ProviderSignIn)),
        (&member, KeptReason::Holds(Holding::OrganizationMembership)),
    ] {
        let outcome = purge_unverified_signup(
            &pool,
            user,
            UNVERIFIED_SIGNUP_LIFETIME_SECS,
            PurgeMode::Enforce,
        )
        .await
        .unwrap();
        assert_eq!(outcome, PurgeOutcome::Kept(reason), "{user}");
        assert!(exists(&pool, user).await);
    }
    execute(&pool, "DELETE FROM org_members WHERE org_id = $1", &org).await;
    execute(&pool, "DELETE FROM organizations WHERE id = $1", &org).await;
}

#[tokio::test]
async fn the_purge_reports_then_deletes_without_mail_and_frees_the_address() {
    let Some(pool) = pool().await else { return };
    let user = sign_up(&pool, "purged", 8, true).await;
    let email = format!("{user}@example.test");

    let report = purge_unverified_signup(
        &pool,
        &user,
        UNVERIFIED_SIGNUP_LIFETIME_SECS,
        PurgeMode::Report,
    )
    .await
    .unwrap();
    assert_eq!(report, PurgeOutcome::WouldDelete);
    assert!(exists(&pool, &user).await, "report mode deletes nothing");

    let PurgeOutcome::Deleted(operation) = purge_unverified_signup(
        &pool,
        &user,
        UNVERIFIED_SIGNUP_LIFETIME_SECS,
        PurgeMode::Enforce,
    )
    .await
    .unwrap() else {
        panic!("the purge deletes an old unverified sign-up");
    };
    assert_eq!(operation.initiator, "unverified_purge");
    assert!(!operation.notify_email);
    assert_eq!(operation.actor_user_id, None);
    assert_eq!(
        requested_audit(&pool, &operation.id).await,
        (None, Some(user.clone()), "unverified_purge".into())
    );

    finish(&pool, &operation.id).await;
    assert!(!exists(&pool, &user).await);
    let done = account_deletion_operation(&pool, &operation.id)
        .await
        .unwrap();
    assert_eq!(done.state, "completed");

    // The address signs up again.
    sqlx::query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Again')")
        .bind(format!("{user}_again"))
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_address_verified_after_the_selection_keeps_its_account() {
    let Some(pool) = pool().await else { return };
    let user = sign_up(&pool, "late_verify", 8, false).await;
    let candidates = unverified_signup_candidates(&pool, UNVERIFIED_SIGNUP_LIFETIME_SECS, 1_000)
        .await
        .unwrap();
    assert!(candidates.contains(&user));

    // The link is opened after the selection and before the deletion.
    execute(
        &pool,
        "UPDATE users SET email_verified = true WHERE id = $1",
        &user,
    )
    .await;
    let outcome = purge_unverified_signup(
        &pool,
        &user,
        UNVERIFIED_SIGNUP_LIFETIME_SECS,
        PurgeMode::Enforce,
    )
    .await
    .unwrap();
    assert_eq!(outcome, PurgeOutcome::Kept(KeptReason::Verified));
    assert!(exists(&pool, &user).await);
}

#[tokio::test]
async fn each_holding_keeps_an_unverified_sign_up() {
    let Some(pool) = pool().await else { return };
    let owner = admin(&pool).await;
    let org = format!("org_holdings_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, 'Holdings', $2, $3)",
    )
    .bind(&org)
    .bind(format!("holdings-{}", Uuid::new_v4().simple()))
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();
    let preset = format!("preset_{org}");
    sqlx::query(
        r#"INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
           VALUES ($1, $2, 'Holdings', $3,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&preset)
    .bind(&org)
    .bind(format!("holdings-preset-{}", Uuid::new_v4().simple()))
    .execute(&pool)
    .await
    .unwrap();

    let sandbox = sign_up(&pool, "sandbox", 8, false).await;
    sqlx::query(
        r#"INSERT INTO environments
               (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
           VALUES ('env_' || $1, $2, $1, 'sandbox', 'running', 'started', $3,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&sandbox)
    .bind(&org)
    .bind(&preset)
    .execute(&pool)
    .await
    .unwrap();
    let api_key = sign_up(&pool, "api_key", 8, false).await;
    sqlx::query(
        "INSERT INTO api_keys (user_id, org_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, 'held', md5($1), 'cw_held')",
    )
    .bind(&api_key)
    .bind(&org)
    .execute(&pool)
    .await
    .unwrap();

    for (user, holding) in [(&sandbox, Holding::Sandbox), (&api_key, Holding::ApiKey)] {
        let outcome = purge_unverified_signup(
            &pool,
            user,
            UNVERIFIED_SIGNUP_LIFETIME_SECS,
            PurgeMode::Enforce,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            PurgeOutcome::Kept(KeptReason::Holds(holding)),
            "{user}"
        );
        assert!(exists(&pool, user).await);
    }
}

/// On a server with no mail an admin vouches for an address instead of a
/// link proving it (#4121). The account stays unverified by design, and the
/// purge keeps it.
#[tokio::test]
async fn an_address_an_admin_vouched_for_is_never_purged() {
    let Some(pool) = pool().await else { return };
    let user = sign_up(&pool, "vouched", 8, false).await;
    execute(
        &pool,
        "UPDATE users SET email_vouched_by = 'invitation' WHERE id = $1",
        &user,
    )
    .await;
    let candidates = unverified_signup_candidates(&pool, UNVERIFIED_SIGNUP_LIFETIME_SECS, 1_000)
        .await
        .unwrap();
    assert!(!candidates.contains(&user));
    let outcome = purge_unverified_signup(
        &pool,
        &user,
        UNVERIFIED_SIGNUP_LIFETIME_SECS,
        PurgeMode::Enforce,
    )
    .await
    .unwrap();
    assert_eq!(outcome, PurgeOutcome::Kept(KeptReason::Vouched));
    assert!(exists(&pool, &user).await);
}

/// An admin vouches for an address after the purge selected it and before
/// the deletion: the locked re-check keeps it.
#[tokio::test]
async fn an_address_vouched_after_the_selection_keeps_its_account() {
    let Some(pool) = pool().await else { return };
    let user = sign_up(&pool, "late_vouch", 8, true).await;
    let candidates = unverified_signup_candidates(&pool, UNVERIFIED_SIGNUP_LIFETIME_SECS, 1_000)
        .await
        .unwrap();
    assert!(candidates.contains(&user));

    execute(
        &pool,
        "UPDATE users SET email_vouched_by = 'admin' WHERE id = $1",
        &user,
    )
    .await;
    let outcome = purge_unverified_signup(
        &pool,
        &user,
        UNVERIFIED_SIGNUP_LIFETIME_SECS,
        PurgeMode::Enforce,
    )
    .await
    .unwrap();
    assert_eq!(outcome, PurgeOutcome::Kept(KeptReason::Vouched));
    assert!(exists(&pool, &user).await);
}
