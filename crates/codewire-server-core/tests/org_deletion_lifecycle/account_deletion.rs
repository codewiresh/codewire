//! DB-backed account deletion (#3679): the refusal, the request that
//! disables the account at once, each workflow phase, a failure between and
//! inside phases, and a fresh sign-up with the same email afterwards.

use codewire_server_core::AppError;
use codewire_server_core::account_deletion::{
    AccountDeletionOperation, DELETED_USER_ID, account_deletion_operation, account_deletion_plan,
    account_stripe_customer_ids, advance_personal_organizations, begin_account_deletion,
    complete_account_deletion, finalize_account_deletion_database,
    pending_account_deletion_operations, record_stripe_customers_deleted,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::pool;

struct Account {
    namespace: String,
    user_id: String,
    email: String,
    /// An organization only this user belongs to.
    personal_org: String,
    /// An organization this user created and owns with another owner.
    shared_org: String,
    other_owner: String,
    /// An environment this user created in the shared organization.
    shared_environment: String,
}

async fn insert_user(pool: &PgPool, id: &str, email: &str) {
    sqlx::query("INSERT INTO users (id, email, name, email_verified) VALUES ($1, $2, $3, true)")
        .bind(id)
        .bind(email)
        .bind(format!("Account deletion {id}"))
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_org(pool: &PgPool, id: &str, created_by: &str, customer: Option<&str>) {
    sqlx::query(
        r#"INSERT INTO organizations (id, name, slug, created_by, stripe_customer_id)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(id)
    .bind(format!("Org {id}"))
    .bind(format!("ad-{}", Uuid::new_v4().simple()))
    .bind(created_by)
    .bind(customer)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_member(pool: &PgPool, org_id: &str, user_id: &str, role: &str) {
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4().simple().to_string())
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
}

async fn seed(pool: &PgPool) -> Account {
    let namespace = Uuid::new_v4().simple().to_string();
    let user_id = format!("u_acctdel_{namespace}");
    let email = format!("{namespace}-account@example.test");
    let other_owner = format!("u_acctdel_{namespace}_other");
    let personal_org = format!("org_acctdel_{namespace}_personal");
    let shared_org = format!("org_acctdel_{namespace}_shared");
    let shared_environment = format!("env_acctdel_{namespace}");

    insert_user(pool, &user_id, &email).await;
    insert_user(
        pool,
        &other_owner,
        &format!("{namespace}-other@example.test"),
    )
    .await;
    insert_org(
        pool,
        &personal_org,
        &user_id,
        Some(&format!("cus_{namespace}")),
    )
    .await;
    insert_member(pool, &personal_org, &user_id, "owner").await;
    insert_org(pool, &shared_org, &user_id, None).await;
    insert_member(pool, &shared_org, &user_id, "owner").await;
    insert_member(pool, &shared_org, &other_owner, "owner").await;

    let preset_id = format!("preset_acctdel_{namespace}");
    sqlx::query(
        r#"INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
           VALUES ($1, $2, 'Account deletion preset', $3,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&preset_id)
    .bind(&shared_org)
    .bind(format!("acctdel-preset-{namespace}"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO environments
               (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
           VALUES ($1, $2, $3, 'sandbox', 'running', 'started', $4,
                   '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
    )
    .bind(&shared_environment)
    .bind(&shared_org)
    .bind(&user_id)
    .bind(&preset_id)
    .execute(pool)
    .await
    .unwrap();

    // What the request must revoke at once.
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + interval '1 hour')",
    )
    .bind(format!("sess_acctdel_{namespace}"))
    .bind(&user_id)
    .bind(namespace.repeat(2))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix, scopes)
           VALUES ($1, $2, $3, 'account deletion fixture', $4, 'cw_test', ARRAY[]::text[])"#,
    )
    .bind(format!("ak_acctdel_{namespace}"))
    .bind(&user_id)
    .bind(&personal_org)
    .bind(format!("key-hash-{namespace}"))
    .execute(pool)
    .await
    .unwrap();

    // What the user deletion must remove: a user secret and its DEK.
    let dek_id = format!("dek_acctdel_{namespace}");
    sqlx::query(
        r#"INSERT INTO tenant_secret_deks
               (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek)
           VALUES ($1, 'user', $2, 'openbao-transit', 'tenant-dek', 1, 'vault:v1:AAAAAAAAAAAA')"#,
    )
    .bind(&dek_id)
    .bind(&user_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO tenant_secrets
               (path, key, dek_id, scope, scope_id, ciphertext, nonce, storage_contract_version)
           VALUES ($1, 'TOKEN', $2, 'user', $3, $4, $5, 1)"#,
    )
    .bind(format!("/users/{user_id}"))
    .bind(&dek_id)
    .bind(&user_id)
    .bind(vec![7_u8; 16])
    .bind(vec![1_u8; 12])
    .execute(pool)
    .await
    .unwrap();

    // What the user deletion must anonymise: an entry naming them.
    sqlx::query(
        r#"INSERT INTO audit_logs
               (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
           VALUES ($1, NOW(), 'user.secret.created', $2, '203.0.113.7', 'fixture',
                   jsonb_build_object('email', $3::text, 'key', 'TOKEN'), 'info')"#,
    )
    .bind(format!("audit_acctdel_{namespace}"))
    .bind(&user_id)
    .bind(&email)
    .execute(pool)
    .await
    .unwrap();

    Account {
        namespace,
        user_id,
        email,
        personal_org,
        shared_org,
        other_owner,
        shared_environment,
    }
}

async fn user_enabled(pool: &PgPool, user_id: &str) -> Option<bool> {
    sqlx::query_scalar("SELECT enabled FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn scalar_i64(pool: &PgPool, sql: &str, bind: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Stand in for the organization deletion workflow: remove the personal
/// organization the way its final database phase does.
async fn complete_personal_org_deletion(pool: &PgPool, org_id: &str) {
    for statement in [
        "DELETE FROM api_keys WHERE org_id = $1",
        "DELETE FROM org_members WHERE org_id = $1",
        "DELETE FROM organizations WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind(org_id)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn request(pool: &PgPool, account: &Account) -> AccountDeletionOperation {
    begin_account_deletion(pool, &account.user_id, &account.email.to_uppercase())
        .await
        .expect("account deletion request")
}

#[tokio::test]
async fn a_sole_owner_of_a_shared_organization_is_refused_and_keeps_the_account() {
    let Some(pool) = pool().await else { return };
    let account = seed(&pool).await;
    // The other owner leaves the shared organization, with a member in it.
    let member = format!("u_acctdel_{}_member", account.namespace);
    insert_user(
        &pool,
        &member,
        &format!("{}-member@example.test", account.namespace),
    )
    .await;
    insert_member(&pool, &account.shared_org, &member, "member").await;
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(&account.shared_org)
        .bind(&account.other_owner)
        .execute(&pool)
        .await
        .unwrap();

    let plan = account_deletion_plan(&pool, &account.user_id)
        .await
        .unwrap();
    let blocking: Vec<&str> = plan.blocking.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(blocking, [account.shared_org.as_str()]);
    let personal: Vec<&str> = plan.personal.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(personal, [account.personal_org.as_str()]);

    let error = begin_account_deletion(&pool, &account.user_id, &account.email)
        .await
        .expect_err("a sole owner of a shared organization is refused");
    assert!(
        matches!(&error, AppError::Precondition(detail) if detail.contains(&format!("Org {}", account.shared_org))),
        "{error:?}"
    );
    assert_eq!(user_enabled(&pool, &account.user_id).await, Some(true));
    let deleting: String =
        sqlx::query_scalar("SELECT deletion_state FROM organizations WHERE id = $1")
            .bind(&account.personal_org)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(deleting, "active", "a refused request changes nothing");
}

#[tokio::test]
async fn the_request_needs_the_account_email() {
    let Some(pool) = pool().await else { return };
    let account = seed(&pool).await;
    let error = begin_account_deletion(&pool, &account.user_id, "someone@example.test")
        .await
        .expect_err("a different address is refused");
    assert!(matches!(error, AppError::BadRequest(_)), "{error:?}");
    assert_eq!(user_enabled(&pool, &account.user_id).await, Some(true));
}

#[tokio::test]
async fn the_request_disables_the_account_and_revokes_it_at_once() {
    let Some(pool) = pool().await else { return };
    let account = seed(&pool).await;
    let operation = request(&pool, &account).await;

    assert_eq!(operation.state, "pending_start");
    assert_eq!(operation.phase, "requested");
    assert_eq!(
        operation.personal_organization_ids,
        std::slice::from_ref(&account.personal_org)
    );
    assert_eq!(
        operation.stripe_customer_ids,
        [format!("cus_{}", account.namespace)]
    );
    assert_eq!(operation.email.as_deref(), Some(account.email.as_str()));
    assert_eq!(user_enabled(&pool, &account.user_id).await, Some(false));
    assert_eq!(
        scalar_i64(
            &pool,
            "SELECT count(*) FROM sessions WHERE user_id = $1",
            &account.user_id
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            &pool,
            "SELECT count(*) FROM api_keys WHERE user_id = $1 AND disabled_at IS NULL",
            &account.user_id
        )
        .await,
        0
    );
    let state: String =
        sqlx::query_scalar("SELECT deletion_state FROM organizations WHERE id = $1")
            .bind(&account.personal_org)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "deleting");
    assert_eq!(
        scalar_i64(
            &pool,
            &format!(
                "SELECT count(*) FROM org_members WHERE user_id = $1 AND org_id = '{}'",
                account.shared_org
            ),
            &account.user_id
        )
        .await,
        0,
        "the shared membership is removed"
    );
    assert_eq!(
        scalar_i64(
            &pool,
            "SELECT count(*) FROM audit_logs WHERE action = 'account.deletion_requested' AND user_id = $1",
            &account.user_id
        )
        .await,
        1
    );
    assert!(
        pending_account_deletion_operations(&pool, 1000)
            .await
            .unwrap()
            .iter()
            .any(|pending| pending.id == operation.id)
    );

    // Nothing re-enables the account while it is being deleted.
    let error = sqlx::query("UPDATE users SET enabled = true WHERE id = $1")
        .bind(&account.user_id)
        .execute(&pool)
        .await
        .expect_err("an account being deleted stays disabled");
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );

    // Repeating the request returns the same operation.
    let again = begin_account_deletion(&pool, &account.user_id, "")
        .await
        .expect("a repeated request");
    assert_eq!(again.id, operation.id);
}

#[tokio::test]
async fn each_phase_resumes_and_the_email_can_sign_up_again() {
    let Some(pool) = pool().await else { return };
    let account = seed(&pool).await;
    let operation = request(&pool, &account).await;

    // Out of order: nothing moves before the personal organization is gone.
    assert!(
        finalize_account_deletion_database(&pool, &operation.id)
            .await
            .is_err()
    );
    assert!(
        record_stripe_customers_deleted(&pool, &operation.id)
            .await
            .is_err()
    );
    assert!(
        !advance_personal_organizations(&pool, &operation.id)
            .await
            .unwrap()
    );
    assert_eq!(
        account_deletion_operation(&pool, &operation.id)
            .await
            .unwrap()
            .phase,
        "requested"
    );

    complete_personal_org_deletion(&pool, &account.personal_org).await;
    assert!(
        advance_personal_organizations(&pool, &operation.id)
            .await
            .unwrap()
    );
    assert!(
        advance_personal_organizations(&pool, &operation.id)
            .await
            .unwrap()
    );
    assert_eq!(
        account_stripe_customer_ids(&pool, &operation.id)
            .await
            .unwrap(),
        [format!("cus_{}", account.namespace)]
    );
    record_stripe_customers_deleted(&pool, &operation.id)
        .await
        .unwrap();
    record_stripe_customers_deleted(&pool, &operation.id)
        .await
        .unwrap();

    let deleted = finalize_account_deletion_database(&pool, &operation.id)
        .await
        .unwrap();
    assert_eq!(deleted.phase, "user_deleted");
    assert_eq!(deleted.user_id, None);
    assert_eq!(user_enabled(&pool, &account.user_id).await, None);
    // The shared organization the user created survives them, and so does
    // the environment they created in it.
    let (shared_creator, environment_creator): (String, String) = sqlx::query_as(
        "SELECT (SELECT created_by FROM organizations WHERE id = $1), \
                (SELECT created_by FROM environments WHERE id = $2)",
    )
    .bind(&account.shared_org)
    .bind(&account.shared_environment)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(shared_creator, DELETED_USER_ID);
    assert_eq!(environment_creator, DELETED_USER_ID);
    assert_eq!(
        scalar_i64(
            &pool,
            "SELECT count(*) FROM tenant_secrets WHERE scope_id = $1",
            &account.user_id
        )
        .await
            + scalar_i64(
                &pool,
                "SELECT count(*) FROM tenant_secret_deks WHERE scope_id = $1",
                &account.user_id
            )
            .await,
        0
    );
    let (actor, ip, metadata): (String, Option<String>, serde_json::Value) =
        sqlx::query_as("SELECT user_id, ip_address, metadata FROM audit_logs WHERE id = $1")
            .bind(format!("audit_acctdel_{}", account.namespace))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(actor, DELETED_USER_ID);
    assert_eq!(ip, None);
    assert_eq!(metadata, serde_json::json!({"key": "TOKEN"}));
    assert_eq!(
        scalar_i64(
            &pool,
            "SELECT count(*) FROM audit_logs WHERE action = 'account.deleted' \
             AND metadata->>'operation_id' = $1",
            &operation.id
        )
        .await,
        1
    );

    // Repeating the phase is harmless.
    let again = finalize_account_deletion_database(&pool, &operation.id)
        .await
        .unwrap();
    assert_eq!(again.phase, "user_deleted");

    complete_account_deletion(&pool, &operation.id)
        .await
        .unwrap();
    complete_account_deletion(&pool, &operation.id)
        .await
        .unwrap();
    let completed = account_deletion_operation(&pool, &operation.id)
        .await
        .unwrap();
    assert_eq!(
        (completed.state.as_str(), completed.phase.as_str()),
        ("completed", "completed")
    );
    assert_eq!(completed.email, None);

    // The same address signs up fresh.
    insert_user(
        &pool,
        &format!("u_acctdel_{}_again", account.namespace),
        &account.email,
    )
    .await;
}

#[tokio::test]
async fn a_failed_personal_organization_deletion_is_begun_again() {
    let Some(pool) = pool().await else { return };
    let account = seed(&pool).await;
    let operation = request(&pool, &account).await;
    let generation: i64 =
        sqlx::query_scalar("SELECT deletion_generation FROM organizations WHERE id = $1")
            .bind(&account.personal_org)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE organizations SET deletion_state = 'delete_failed', \
         deletion_failure_code = 'environment_cleanup_failed' WHERE id = $1",
    )
    .bind(&account.personal_org)
    .execute(&pool)
    .await
    .unwrap();

    assert!(
        !advance_personal_organizations(&pool, &operation.id)
            .await
            .unwrap()
    );
    let (state, next): (String, i64) = sqlx::query_as(
        "SELECT deletion_state, deletion_generation FROM organizations WHERE id = $1",
    )
    .bind(&account.personal_org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((state.as_str(), next), ("deleting", generation + 1));
}

/// A failure inside the user deletion rolls the whole phase back: the account
/// stays disabled and whole, the operation stays where it was, and the next
/// attempt completes it.
#[tokio::test]
async fn a_failure_inside_the_user_deletion_leaves_no_half_deleted_account() {
    let Some(pool) = pool().await else { return };
    let account = seed(&pool).await;
    let operation = request(&pool, &account).await;
    complete_personal_org_deletion(&pool, &account.personal_org).await;
    assert!(
        advance_personal_organizations(&pool, &operation.id)
            .await
            .unwrap()
    );
    record_stripe_customers_deleted(&pool, &operation.id)
        .await
        .unwrap();

    // Refuse this one user's row delete, after every statement before it ran.
    let function = format!("acctdel_refuse_{}", account.namespace);
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF OLD.id = '{user}' THEN RAISE EXCEPTION 'injected failure'; END IF; \
         RETURN OLD; END; $$; \
         CREATE TRIGGER {function} BEFORE DELETE ON users \
         FOR EACH ROW EXECUTE FUNCTION {function}();",
        user = account.user_id,
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = finalize_account_deletion_database(&pool, &operation.id).await;
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {function} ON users; DROP FUNCTION {function}();"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(failed.is_err());

    assert_eq!(user_enabled(&pool, &account.user_id).await, Some(false));
    let creator: String = sqlx::query_scalar("SELECT created_by FROM organizations WHERE id = $1")
        .bind(&account.shared_org)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(creator, account.user_id, "the repointing rolled back too");
    assert_eq!(
        scalar_i64(
            &pool,
            "SELECT count(*) FROM tenant_secrets WHERE scope_id = $1",
            &account.user_id
        )
        .await,
        1
    );
    let unchanged = account_deletion_operation(&pool, &operation.id)
        .await
        .unwrap();
    assert_eq!(unchanged.phase, "stripe_customers_deleted");
    assert_eq!(unchanged.user_id.as_deref(), Some(account.user_id.as_str()));

    let deleted = finalize_account_deletion_database(&pool, &operation.id)
        .await
        .unwrap();
    assert_eq!(deleted.phase, "user_deleted");
    assert_eq!(user_enabled(&pool, &account.user_id).await, None);
}
