//! Plan gating, monthly compute allowance admission, per-plan VM/sandbox
//! quotas, and team-member caps (#6659).

use codewire_server_core::auth::AuthUser;
use codewire_server_core::credit_enforcement::CreditEnforcement;

use super::*;
use crate::api::organizations::{InviteMemberBody, create_invitation};
use crate::api::runtime_lease_test_support::LeaseFixture;
use crate::runtime::RuntimeBackend;

fn coded_code(err: &AppError) -> Option<&str> {
    match err {
        AppError::Coded { code, .. } => Some(code),
        _ => None,
    }
}

fn coded_detail(err: &AppError) -> Option<&str> {
    match err {
        AppError::Coded { detail, .. } => Some(detail.as_ref()),
        _ => None,
    }
}

async fn upsert_subscription(pool: &PgPool, org_id: &str, plan: &str, status: &str) {
    sqlx::query(
        r#"INSERT INTO org_subscriptions (org_id, plan, status)
           VALUES ($1, $2, $3)
           ON CONFLICT (org_id) DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status"#,
    )
    .bind(org_id)
    .bind(plan)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_plan_allowance_and_quotas_govern_admission() {
    let fixture = LeaseFixture::seed("synthetic-plan-admission").await;
    let pool = &fixture.pool;
    let org_id = fixture.id.as_str();

    // Active monthly allowance with an active subscription admits a zero-balance org.
    upsert_subscription(pool, org_id, "pro", "active").await;
    let invoice_id = format!("{org_id}-allowance");
    let allowance_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO billing_plan_allowances
               (organization_id, plan_key, stripe_invoice_id,
                period_start, period_end, granted_nano_usd, drawn_nano_usd)
           VALUES ($1, 'pro', $2,
                   now() - interval '1 hour', now() + interval '1 day',
                   100000000000, 0)
           RETURNING id"#,
    )
    .bind(org_id)
    .bind(&invoice_id)
    .fetch_one(pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    admission::check_credit_in(&mut tx, org_id)
        .await
        .expect("active allowance with active sub must admit zero-balance org");
    tx.rollback().await.unwrap();

    // Canceled subscription must NOT be admitted by leftover cycle allowance in check_credit_in.
    upsert_subscription(pool, org_id, "pro", "canceled").await;
    let mut tx = pool.begin().await.unwrap();
    let err = admission::check_credit_in(&mut tx, org_id)
        .await
        .expect_err("canceled subscription cannot draw leftover cycle allowance");
    assert_eq!(coded_code(&err), Some("credit_exhausted"));
    tx.rollback().await.unwrap();
    upsert_subscription(pool, org_id, "pro", "active").await;

    // Exhausting the monthly allowance falls back to prepaid balance ($0 -> 402).
    sqlx::query(
        "UPDATE billing_plan_allowances SET drawn_nano_usd = granted_nano_usd WHERE id = $1",
    )
    .bind(allowance_id)
    .execute(pool)
    .await
    .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let err = admission::check_credit_in(&mut tx, org_id)
        .await
        .expect_err("exhausted allowance with $0 prepaid must refuse");
    assert_eq!(coded_code(&err), Some("credit_exhausted"));
    tx.rollback().await.unwrap();

    let req = |cpu_millicores: i32,
               memory_mb: i32,
               backend: RuntimeBackend,
               credit_enforcement: CreditEnforcement| QuotaRequest {
        credit_enforcement,
        quota: NO_QUOTA,
        env_type: "sandbox",
        backend,
        cpu_millicores,
        memory_mb,
        disk_gb: 10,
    };

    // Pay as you go: 3 sandboxes, 8 vCPU / 16 GB RAM max.
    upsert_subscription(pool, org_id, "payg", "active").await;
    let payg_quota = get_org_quota(pool, org_id).await.unwrap();
    assert_eq!(payg_quota.max_concurrent_sandbox, 3);
    assert_eq!(payg_quota.max_concurrent_environments, 3);

    let mut tx = pool.begin().await.unwrap();
    admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 2,
            active_sandbox: 2,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(
            8_000,
            16_384,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect("PAYG admits 8 vCPU / 16 GB at 2 active sandboxes");

    let err = admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 2,
            active_sandbox: 2,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(
            16_000,
            16_384,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect_err("PAYG refuses 16 vCPU");
    assert_eq!(coded_code(&err), Some("plan_vm_size_exceeded"));

    // Resize VM-size check admits at the plan cap (100 GB disk) and refuses growth past it (200 GB).
    admission::check_plan_vm_size_in(
        &mut tx,
        org_id,
        CreditEnforcement::On,
        RuntimeBackend::Kubernetes,
        4_000,
        8_192,
        100,
    )
    .await
    .expect("PAYG resize admits 100 GB disk");
    let err = admission::check_plan_vm_size_in(
        &mut tx,
        org_id,
        CreditEnforcement::On,
        RuntimeBackend::Kubernetes,
        4_000,
        8_192,
        200,
    )
    .await
    .expect_err("PAYG resize refuses 200 GB disk");
    assert_eq!(coded_code(&err), Some("plan_vm_size_exceeded"));
    admission::check_plan_vm_size_in(
        &mut tx,
        org_id,
        CreditEnforcement::On,
        RuntimeBackend::Host,
        32_000,
        65_536,
        500,
    )
    .await
    .expect("host resize bypasses cloud plan VM cap");

    let err = admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 3,
            active_sandbox: 3,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(
            4_000,
            8_192,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect_err("PAYG refuses 4th concurrent sandbox");
    assert_eq!(coded_code(&err), Some("plan_sandbox_limit_reached"));

    // Non-platform (local/host) runtimes are never restricted by cloud plans.
    admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 10,
            active_sandbox: 10,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(32_000, 65_536, RuntimeBackend::Host, CreditEnforcement::On),
    )
    .await
    .expect("host runtime bypasses cloud plan caps");
    tx.rollback().await.unwrap();

    // Pro: 10 sandboxes, 8 vCPU / 16 GB RAM max.
    upsert_subscription(pool, org_id, "pro", "active").await;
    let pro_quota = get_org_quota(pool, org_id).await.unwrap();
    assert_eq!(pro_quota.max_concurrent_sandbox, 10);

    let mut tx = pool.begin().await.unwrap();
    let err = admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 10,
            active_sandbox: 10,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(
            8_000,
            16_384,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect_err("Pro refuses 11th concurrent sandbox");
    assert_eq!(coded_code(&err), Some("plan_sandbox_limit_reached"));
    tx.rollback().await.unwrap();

    // Max: unlimited concurrent sandboxes, 16 vCPU / 32 GB RAM max.
    upsert_subscription(pool, org_id, "max", "active").await;
    let max_quota = get_org_quota(pool, org_id).await.unwrap();
    assert_eq!(max_quota.max_concurrent_sandbox, -1);
    assert_eq!(max_quota.max_concurrent_environments, -1);
    assert_eq!(max_quota.max_cpu_millicores, -1);
    assert_eq!(max_quota.max_memory_mb, -1);

    let mut tx = pool.begin().await.unwrap();
    admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 50,
            active_sandbox: 50,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(
            16_000,
            32_768,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect("Max admits 50 concurrent sandboxes at 16 vCPU / 32 GB");

    let err = admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage {
            active_total: 1,
            active_sandbox: 1,
            total_cpu: 0,
            total_memory_mb: 0,
        },
        &req(
            32_000,
            32_768,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect_err("Max refuses 32 vCPU");
    assert_eq!(coded_code(&err), Some("plan_vm_size_exceeded"));
    tx.rollback().await.unwrap();

    // Canceled subscription refuses cloud creates (via check_quota_in BEFORE credit_exhausted)
    // and refuses cloud resizes with plan_required.
    upsert_subscription(pool, org_id, "pro", "canceled").await;
    let mut tx = pool.begin().await.unwrap();
    let err = admission::check_quota_in(
        &mut tx,
        org_id,
        req(
            2_000,
            4_096,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect_err(
        "canceled subscription with $0 credit must return plan_required before credit_exhausted",
    );
    assert_eq!(coded_code(&err), Some("plan_required"));
    let detail = coded_detail(&err).unwrap_or_default();
    assert!(detail.contains("/onboarding/plan"), "{detail}");
    assert!(detail.contains("cw create --local"), "{detail}");

    let err = admission::check_plan_vm_size_in(
        &mut tx,
        org_id,
        CreditEnforcement::On,
        RuntimeBackend::Kubernetes,
        16_000,
        32_768,
        200,
    )
    .await
    .expect_err("canceled subscription refuses cloud resize");
    assert_eq!(coded_code(&err), Some("plan_required"));
    tx.rollback().await.unwrap();

    // Unlimited rate card bypasses plan_required and plan caps.
    sqlx::query("UPDATE organizations SET rate_card = 'unlimited' WHERE id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    admission::check_plan_in(
        &mut tx,
        org_id,
        OrgEnvironmentUsage::default(),
        &req(
            32_000,
            65_536,
            RuntimeBackend::Kubernetes,
            CreditEnforcement::On,
        ),
    )
    .await
    .expect("unlimited rate card bypasses plan gating");
    tx.rollback().await.unwrap();

    sqlx::query("DELETE FROM billing_plan_allowances WHERE organization_id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM org_subscriptions WHERE org_id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_plan_team_member_cap_enforces_payg_pro_and_max() {
    let fixture = LeaseFixture::seed("synthetic-plan-team-cap").await;
    let pool = &fixture.pool;
    let org_id = fixture.id.as_str();
    let owner = AuthUser {
        user_id: fixture.id.clone(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };

    let invite = |suffix: &str| {
        let email = format!("{org_id}-{suffix}@example.test");
        create_invitation(
            pool,
            &owner,
            org_id,
            "owner",
            InviteMemberBody {
                email,
                role: "member".to_owned(),
                assignments: Vec::new(),
            },
        )
    };

    // PAYG: max 1 member (owner already occupies the slot).
    upsert_subscription(pool, org_id, "payg", "active").await;
    let err = invite("one")
        .await
        .expect_err("PAYG must refuse inviting a second member");
    assert_eq!(coded_code(&err), Some("team_member_limit_reached"));

    // Pro: max 5 members (owner + 4 pending invitations allowed; 5th refused).
    upsert_subscription(pool, org_id, "pro", "active").await;
    for suffix in ["m2", "m3", "m4", "m5"] {
        invite(suffix)
            .await
            .unwrap_or_else(|e| panic!("Pro should allow {suffix}: {e:?}"));
    }
    let err = invite("m6")
        .await
        .expect_err("Pro must refuse 6th member/pending invitation");
    assert_eq!(coded_code(&err), Some("team_member_limit_reached"));

    // Canceled subscription refuses invitations (never treated as unlimited).
    upsert_subscription(pool, org_id, "pro", "canceled").await;
    let err = invite("canceled")
        .await
        .expect_err("canceled subscription must refuse invitations");
    assert_eq!(coded_code(&err), Some("team_member_limit_reached"));

    // Pending invitation issued while on Pro cannot be accepted after downgrading to PAYG (cap 1).
    let invitee_id = format!("{org_id}-invitee");
    let invitee_email = format!("{org_id}-m2@example.test");
    sqlx::query(
        "INSERT INTO users (id, email, email_verified, enabled) VALUES ($1, $2, true, true)",
    )
    .bind(&invitee_id)
    .bind(&invitee_email)
    .execute(pool)
    .await
    .unwrap();
    let inv_id: String = sqlx::query_scalar(
        "SELECT id FROM org_invitations WHERE org_id = $1 AND email = $2 AND status = 'pending'",
    )
    .bind(org_id)
    .bind(&invitee_email)
    .fetch_one(pool)
    .await
    .unwrap();
    upsert_subscription(pool, org_id, "payg", "active").await;
    let invitee = AuthUser {
        user_id: invitee_id.clone(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    };
    let err = crate::api::organizations::accept_invitation(
        pool,
        &invitee,
        crate::api::organizations::AcceptInvitationBy::Id(inv_id.clone()),
    )
    .await
    .expect_err("accepting pre-downgrade pending invitation on PAYG must refuse");
    assert_eq!(coded_code(&err), Some("team_member_limit_reached"));
    let still_pending: String =
        sqlx::query_scalar("SELECT status FROM org_invitations WHERE id = $1")
            .bind(&inv_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(still_pending, "pending");

    // Max: unlimited members.
    upsert_subscription(pool, org_id, "max", "active").await;
    invite("m6")
        .await
        .expect("Max must allow inviting beyond 5 members");

    sqlx::query("DELETE FROM org_invitations WHERE org_id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&invitee_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rate_limit WHERE key IN ($1, $2)")
        .bind(format!("org_invite_org:{org_id}"))
        .bind(format!("org_invite_user:{org_id}"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM org_subscriptions WHERE org_id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
    fixture.cleanup().await;
}
