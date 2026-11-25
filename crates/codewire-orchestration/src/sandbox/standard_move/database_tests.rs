//! Disposable-PostgreSQL proof for moving an organization onto `standard`
//! (#5602): the flag and its audit entry commit together, a repeat records
//! nothing, the list shows it, and the create reads it. Only synthetic rows in
//! an isolated test database are used.

use anyhow::{Result, ensure};
use codewire_server_core::auth::AuthUser;
use sqlx::PgPool;

use super::*;
use crate::egress::own_mode::HostedEgress;
use crate::test_database_support::TestDatabase;

const ADMIN: &str = "standard-move-admin";
const ORGANIZATION: &str = "standard-move-organization";

fn admin() -> AuthUser {
    AuthUser {
        user_id: ADMIN.into(),
        org_id: None,
        is_admin: true,
        via_api_key: false,
    }
}

/// A deployment that makes `standard` available.
fn available_cfg() -> SandboxWorkerCfg {
    let canonical = crate::sandbox::canonical_workspace_runtime_image();
    let (_, digest) = canonical.rsplit_once('@').unwrap();
    let runtime = StandardRuntime::parse(
        "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        &format!(
            "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 \
             3333333333333333333333333333333333333333333333333333333333333333 \
             44444444444444444444444444444444 \
             registry.example.invalid/codewire/workspace@{digest}"
        ),
    )
    .unwrap();
    SandboxWorkerCfg {
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        standard_runtime: runtime,
        hosted_egress: HostedEgress::on(crate::sandbox::template::HostedEgressTemplate {
            stream_addr: "10.44.0.89:8089".into(),
            binding_addr: "10.44.0.87:8087".into(),
            fence_revision: "4".into(),
            gateway: crate::sandbox::template::GatewayPeer {
                namespace: "gateway-proxies".into(),
                gateway_name: "public".into(),
                gateway_namespace: "gateway".into(),
                port: 10443,
            },
            derp_tls_port: 8443,
            gateway_addr: "10.44.0.43:443".into(),
            derp_addr: "derp.example.test=10.44.0.84:8443".into(),
            cluster_dns_ip: "10.44.0.10".into(),
        }),
        ..SandboxWorkerCfg::default()
    }
}

/// The audit entries, oldest first, as (user, metadata).
async fn audit_entries(pool: &PgPool) -> Result<Vec<(String, serde_json::Value)>> {
    Ok(sqlx::query_as(
        "SELECT user_id, metadata FROM audit_logs \
         WHERE action = $1 AND severity = 'warn' ORDER BY timestamp, id",
    )
    .bind(AUDIT_ACTION)
    .fetch_all(pool)
    .await?)
}

fn app_error(error: AppError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_move_and_its_audit_entry_commit_together_and_a_repeat_records_nothing() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        let cfg = available_cfg();
        ensure!(
            !organization_moved(pool, ORGANIZATION)
                .await
                .map_err(app_error)?
        );
        ensure!(
            list_core(pool, &admin())
                .await
                .map_err(app_error)?
                .is_empty()
        );

        // Setting the value it already has changes and records nothing.
        let previous = set_core(pool, &cfg, &admin(), ORGANIZATION, false)
            .await
            .map_err(app_error)?;
        ensure!(!previous);
        ensure!(audit_entries(pool).await?.is_empty());

        let previous = set_core(pool, &cfg, &admin(), ORGANIZATION, true)
            .await
            .map_err(app_error)?;
        ensure!(!previous);
        ensure!(
            organization_moved(pool, ORGANIZATION)
                .await
                .map_err(app_error)?
        );
        let entries = audit_entries(pool).await?;
        ensure!(entries.len() == 1, "{entries:?}");
        ensure!(entries[0].0 == ADMIN);
        ensure!(entries[0].1["organization_id"] == ORGANIZATION);
        ensure!(entries[0].1["previous"] == false, "{}", entries[0].1);
        ensure!(
            entries[0].1["standard_runtime_enabled"] == true,
            "{}",
            entries[0].1
        );
        let listed = list_core(pool, &admin()).await.map_err(app_error)?;
        ensure!(
            listed
                .iter()
                .map(|o| o.organization_id.as_str())
                .eq([ORGANIZATION]),
            "{listed:?}"
        );

        // Moving back is allowed whether or not the deployment has
        // `standard`, and is audited too.
        let previous = set_core(
            pool,
            &SandboxWorkerCfg::default(),
            &admin(),
            ORGANIZATION,
            false,
        )
        .await
        .map_err(app_error)?;
        ensure!(previous);
        let entries = audit_entries(pool).await?;
        ensure!(entries.len() == 2, "{entries:?}");
        ensure!(entries[1].1["previous"] == true, "{}", entries[1].1);
        ensure!(
            entries[1].1["standard_runtime_enabled"] == false,
            "{}",
            entries[1].1
        );

        // An unknown organization is refused and records nothing.
        let error = set_core(pool, &cfg, &admin(), "no-such-organization", true)
            .await
            .expect_err("an unknown organization");
        ensure!(matches!(error, AppError::NotFound(_)), "{error:?}");
        ensure!(audit_entries(pool).await?.len() == 2);
        Ok(())
    }
    .await;
    db.finish(result).await
}
