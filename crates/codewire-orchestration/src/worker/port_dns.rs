//! Port preview DNS jobs, mirroring `worker/handler_port_dns.go`.

use super::activity_authority::{ActivityAuthority, await_external_mutation};
use super::{JobPayload, WorkerContext};

/// Mirrors `HandlePortDNSCreate`: CNAME `{label}-{env5}-{orgslug}.{base}`
/// → base domain, for every port without a dns_record_id. Per-record
/// failures are logged and skipped, like Go's `continue`.
pub async fn handle_port_dns_create(
    ctx: &WorkerContext,
    payload: &JobPayload,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "port.dns.create received");

    let Some(cf) = &ctx.cloudflare else {
        tracing::warn!("port.dns.create: cloudflare not configured, skipping");
        return Ok(());
    };
    if ctx.preview_base_domain.is_empty() {
        tracing::warn!("port.dns.create: PREVIEW_BASE_DOMAIN not configured, skipping");
        return Ok(());
    }
    let base_domain = &ctx.preview_base_domain;

    let org_slug: String = sqlx::query_scalar(
        r#"SELECT o.slug FROM organizations o
           JOIN environments e ON e.org_id = o.id
           WHERE e.id = $1"#,
    )
    .bind(env_id)
    .fetch_one(&ctx.pool)
    .await
    .map_err(|e| anyhow::anyhow!("lookup org slug: {e}"))?;

    let target = base_domain;

    let ports: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT id, label FROM environment_ports
           WHERE environment_id = $1
             AND dns_record_id IS NULL
             AND deletion_requested_at IS NULL"#,
    )
    .bind(env_id)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query ports: {e}"))?;

    let env_prefix = if env_id.len() > 5 {
        &env_id[..5]
    } else {
        env_id
    };

    for (port_id, label) in ports {
        let hostname = format!("{label}-{env_prefix}-{org_slug}.{base_domain}");
        let record_id = match cf.create_cname_returning_id(&hostname, target).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(hostname, error = %e, "port.dns.create: failed to create CNAME");
                continue;
            }
        };
        if let Err(e) =
            sqlx::query(r#"UPDATE environment_ports SET dns_record_id = $1 WHERE id = $2"#)
                .bind(&record_id)
                .bind(&port_id)
                .execute(&ctx.pool)
                .await
        {
            tracing::error!(port_id, error = %e, "port.dns.create: failed to store record id");
        }
    }
    Ok(())
}

/// Delete every retained provider record before removing port rows whose
/// public deletion was requested.
pub async fn handle_port_dns_delete(
    ctx: &WorkerContext,
    payload: &JobPayload,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "port.dns.delete received");
    delete_port_dns_records(ctx, env_id).await
}

/// Remove every DNS record registered for an environment's ports. A provider
/// failure retains both the record identifier and the port discovery row.
pub(crate) async fn delete_port_dns_records(
    ctx: &WorkerContext,
    env_id: &str,
) -> anyhow::Result<()> {
    let ports: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT id, dns_record_id FROM environment_ports
           WHERE environment_id = $1 AND dns_record_id IS NOT NULL"#,
    )
    .bind(env_id)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query ports for DNS delete: {e}"))?;

    if ports.is_empty() {
        sqlx::query(
            r#"DELETE FROM environment_ports
               WHERE environment_id = $1
                 AND deletion_requested_at IS NOT NULL
                 AND dns_record_id IS NULL"#,
        )
        .bind(env_id)
        .execute(&ctx.pool)
        .await?;
        return Ok(());
    }
    let cf = ctx.cloudflare.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Cloudflare is not configured while retained port DNS records require deletion"
        )
    })?;

    for (port_id, record_id) in ports {
        await_external_mutation(cf.delete_dns_record_by_id(&record_id)).await?;
        sqlx::query(r#"UPDATE environment_ports SET dns_record_id = NULL WHERE id = $1"#)
            .bind(&port_id)
            .execute(&ctx.pool)
            .await?;
    }
    sqlx::query(
        r#"DELETE FROM environment_ports
           WHERE environment_id = $1
             AND deletion_requested_at IS NOT NULL
             AND dns_record_id IS NULL"#,
    )
    .bind(env_id)
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

/// Lifecycle-owned DNS cleanup. The environment row stays locked across each
/// Cloudflare delete and the matching `dns_record_id` clear so a replacement
/// start cannot commit between external truth and durable truth. The update
/// also compares the record ID, preserving a concurrently-created replacement
/// record if a standalone port-DNS workflow was already in flight.
pub(crate) async fn delete_port_dns_records_authoritative(
    ctx: &WorkerContext,
    env_id: &str,
    authority: &ActivityAuthority,
    states: &[&str],
    remove_all_ports: bool,
) -> anyhow::Result<()> {
    let port_ids: Vec<String> = sqlx::query_scalar(
        r#"SELECT id FROM environment_ports
           WHERE environment_id = $1 AND dns_record_id IS NOT NULL"#,
    )
    .bind(env_id)
    .fetch_all(&ctx.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query ports for authoritative DNS delete: {e}"))?;

    let cf = if port_ids.is_empty() {
        None
    } else {
        Some(ctx.cloudflare.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Cloudflare is not configured while retained port DNS records require deletion"
            )
        })?)
    };

    for port_id in port_ids {
        let mut guard = authority.begin_external_mutation(states).await?;
        let record_id: Option<String> = await_external_mutation(async {
            Ok(sqlx::query_scalar(
                r#"SELECT dns_record_id FROM environment_ports
                   WHERE id = $1 AND environment_id = $2 AND dns_record_id IS NOT NULL
                   FOR UPDATE"#,
            )
            .bind(&port_id)
            .bind(env_id)
            .fetch_optional(&mut **guard.transaction())
            .await?)
        })
        .await?;
        let Some(record_id) = record_id else {
            guard.commit().await?;
            continue;
        };

        await_external_mutation(
            cf.expect("retained DNS identifiers require a configured provider")
                .delete_dns_record_by_id(&record_id),
        )
        .await
        .map_err(|error| anyhow::anyhow!("delete retained port DNS record {record_id}: {error}"))?;
        await_external_mutation(async {
            sqlx::query(
                r#"UPDATE environment_ports SET dns_record_id = NULL
                   WHERE id = $1 AND environment_id = $2 AND dns_record_id = $3"#,
            )
            .bind(&port_id)
            .bind(env_id)
            .bind(&record_id)
            .execute(&mut **guard.transaction())
            .await?;
            Ok(())
        })
        .await?;
        guard.commit().await?;
    }
    let deletion = if remove_all_ports {
        sqlx::query(
            r#"DELETE FROM environment_ports
               WHERE environment_id = $1 AND dns_record_id IS NULL"#,
        )
        .bind(env_id)
    } else {
        sqlx::query(
            r#"DELETE FROM environment_ports
               WHERE environment_id = $1
                 AND deletion_requested_at IS NOT NULL
                 AND dns_record_id IS NULL"#,
        )
        .bind(env_id)
    };
    authority.execute_for_states(states, deletion).await?;
    Ok(())
}
