//! Attachment, enrollment and membership statements. Each decision is one
//! statement over the attachment, the environment, the attaching user and,
//! for a named Pod, its live workspace binding, read the same way the
//! workspace-binding listener reads it.

use sqlx::{PgPool, Postgres, Transaction};

use super::{ENROLLMENT_LIFETIME_SECS, MAX_OUTSTANDING_ENROLLMENTS};

/// The network an environment joins and the node name it takes there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub org_id: String,
    pub network_id: String,
    pub node_name: String,
}

/// One admitted member, as redeemed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Member {
    pub environment_id: String,
    pub org_id: String,
    pub network_id: String,
    pub node_name: String,
    pub pod_uid: String,
    pub operation_generation: i64,
    pub attached_by_user_id: String,
}

/// A member Mesh holds. An empty `pod_uid` names a registered node with no
/// open stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Incarnation {
    pub environment_id: String,
    pub org_id: String,
    pub network_id: String,
    pub pod_uid: String,
    pub operation_generation: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemberStatus {
    Live,
    Stale,
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueOutcome {
    Issued,
    NotAttached,
    Exhausted,
}

/// What a daemon reported about its Pod's membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentReport {
    Attached,
    Revoked,
    /// One of the stored failure reasons.
    Failed(&'static str),
}

/// The live-binding condition for `pod` of `environment`, matching
/// `PgBindingStore::live_binding`: the binding is unreleased and is the
/// backend's current Pod, and the environment is bindable.
macro_rules! live_binding_sql {
    ($environment:literal, $pod:literal, $env_row:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM sandbox_workspace_bindings w ",
            "JOIN sandbox_environment_backend b ON b.environment_id = w.environment_id AND b.pod_uid = w.pod_uid ",
            "WHERE w.environment_id = ", $environment, " AND w.pod_uid = ", $pod, " ",
            "AND w.released_at IS NULL AND w.credential_scope = 'pod' ",
            "AND b.namespace = w.namespace AND b.bound_at IS NOT NULL) ",
            "AND ", $env_row, ".type = 'sandbox' ",
            "AND ", $env_row, ".state IN ('pending', 'creating', 'starting', 'running', 'resizing') ",
            "AND (", $env_row, ".desired_state = 'started' OR (", $env_row, ".state = 'resizing' AND ", $env_row, ".desired_state = 'resized')) ",
            "AND ", $env_row, ".deletion_requested_at IS NULL"
        )
    };
}

/// The attaching user is enabled and still a member of the organization.
macro_rules! attacher_sql {
    ($attachment:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM users u JOIN org_members m ON m.user_id = u.id ",
            "WHERE u.id = ",
            $attachment,
            ".attached_by_user_id AND u.enabled ",
            "AND m.org_id = ",
            $attachment,
            ".org_id)"
        )
    };
}

/// Records the attachment of a just-inserted environment, in its create
/// transaction.
pub(crate) async fn insert_attachment(
    transaction: &mut Transaction<'_, Postgres>,
    environment_id: &str,
    attachment: &Attachment,
    attached_by_user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO environment_mesh_attachments
               (environment_id, org_id, network_id, node_name, attached_by_user_id)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(environment_id)
    .bind(&attachment.org_id)
    .bind(&attachment.network_id)
    .bind(&attachment.node_name)
    .bind(attached_by_user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The environment's attachment, if it joins a network.
pub(crate) async fn attachment_for(
    pool: &PgPool,
    environment_id: &str,
) -> Result<Option<Attachment>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        r#"SELECT org_id, network_id, node_name FROM environment_mesh_attachments
            WHERE environment_id = $1"#,
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(org_id, network_id, node_name)| Attachment {
        org_id,
        network_id,
        node_name,
    }))
}

/// Stores one code for `pod_uid` at `operation_generation`. The caller has
/// already confirmed that Pod is the environment's live binding. Expired and
/// used codes of the environment are removed first.
pub(crate) async fn issue_enrollment(
    pool: &PgPool,
    environment_id: &str,
    pod_uid: &str,
    operation_generation: i64,
    code_sha256: &str,
) -> Result<IssueOutcome, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let attached: Option<(String,)> = sqlx::query_as(
        r#"SELECT environment_id FROM environment_mesh_attachments
            WHERE environment_id = $1 FOR UPDATE"#,
    )
    .bind(environment_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if attached.is_none() {
        return Ok(IssueOutcome::NotAttached);
    }
    sqlx::query(
        r#"DELETE FROM environment_mesh_enrollments
            WHERE environment_id = $1
              AND (consumed_at IS NOT NULL OR expires_at <= now())"#,
    )
    .bind(environment_id)
    .execute(&mut *transaction)
    .await?;
    let outstanding: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM environment_mesh_enrollments WHERE environment_id = $1"#,
    )
    .bind(environment_id)
    .fetch_one(&mut *transaction)
    .await?;
    if outstanding >= MAX_OUTSTANDING_ENROLLMENTS {
        return Ok(IssueOutcome::Exhausted);
    }
    sqlx::query(
        r#"INSERT INTO environment_mesh_enrollments
               (code_sha256, environment_id, pod_uid, operation_generation,
                org_id, network_id, node_name, issued_at, expires_at)
           SELECT $1, a.environment_id, $2, $3, a.org_id, a.network_id, a.node_name,
                  now(), now() + make_interval(secs => $4)
             FROM environment_mesh_attachments a
            WHERE a.environment_id = $5"#,
    )
    .bind(code_sha256)
    .bind(pod_uid)
    .bind(operation_generation)
    .bind(ENROLLMENT_LIFETIME_SECS as f64)
    .bind(environment_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(IssueOutcome::Issued)
}

/// Consumes the code with `code_sha256` for exactly `org_id` and
/// `network_id` and returns its member, or `None` when it is unknown,
/// expired, used, for another network, its attaching user no longer
/// qualifies, or its Pod and generation are no longer the live binding. One
/// statement: two concurrent redemptions cannot both succeed.
pub(crate) async fn redeem_enrollment(
    pool: &PgPool,
    code_sha256: &str,
    org_id: &str,
    network_id: &str,
) -> Result<Option<Member>, sqlx::Error> {
    let row: Option<(String, String, String, String, String, i64, String)> =
        sqlx::query_as(concat!(
            "UPDATE environment_mesh_enrollments en SET consumed_at = now() ",
            "FROM environment_mesh_attachments a, environments e ",
            "WHERE en.code_sha256 = $1 AND en.org_id = $2 AND en.network_id = $3 ",
            "AND en.consumed_at IS NULL AND en.expires_at > now() ",
            "AND a.environment_id = en.environment_id AND a.org_id = en.org_id ",
            "AND a.network_id = en.network_id AND a.node_name = en.node_name ",
            "AND e.id = en.environment_id AND e.org_id = a.org_id ",
            "AND e.environment_operation_generation = en.operation_generation ",
            "AND ",
            attacher_sql!("a"),
            " AND ",
            live_binding_sql!("en.environment_id", "en.pod_uid", "e"),
            " RETURNING en.environment_id, en.org_id, en.network_id, en.node_name, ",
            "en.pod_uid, en.operation_generation, a.attached_by_user_id"
        ))
        .bind(code_sha256)
        .bind(org_id)
        .bind(network_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(
        |(
            environment_id,
            org_id,
            network_id,
            node_name,
            pod_uid,
            operation_generation,
            attached_by_user_id,
        )| Member {
            environment_id,
            org_id,
            network_id,
            node_name,
            pod_uid,
            operation_generation,
            attached_by_user_id,
        },
    ))
}

/// The status of each member, in order.
pub(crate) async fn check_members(
    pool: &PgPool,
    members: &[Incarnation],
) -> Result<Vec<MemberStatus>, sqlx::Error> {
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let column = |field: fn(&Incarnation) -> &str| -> Vec<String> {
        members
            .iter()
            .map(|member| field(member).to_owned())
            .collect()
    };
    let generations: Vec<i64> = members
        .iter()
        .map(|member| member.operation_generation)
        .collect();
    let rows: Vec<(i64, String)> = sqlx::query_as(concat!(
        "SELECT r.ord, CASE ",
        "WHEN a.environment_id IS NULL OR e.id IS NULL OR e.state IN ('destroying', 'destroyed') ",
        "OR e.deletion_requested_at IS NOT NULL OR NOT ",
        attacher_sql!("a"),
        " THEN 'gone' ",
        "WHEN r.pod_uid = '' THEN 'live' ",
        "WHEN e.environment_operation_generation = r.generation AND ",
        live_binding_sql!("r.environment_id", "r.pod_uid", "e"),
        " THEN 'live' ELSE 'stale' END ",
        "FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[]) ",
        "WITH ORDINALITY AS r(environment_id, org_id, network_id, pod_uid, generation, ord) ",
        "LEFT JOIN environment_mesh_attachments a ON a.environment_id = r.environment_id ",
        "AND a.org_id = r.org_id AND a.network_id = r.network_id ",
        "LEFT JOIN environments e ON e.id = a.environment_id AND e.org_id = a.org_id ",
        "ORDER BY r.ord"
    ))
    .bind(column(|member| &member.environment_id))
    .bind(column(|member| &member.org_id))
    .bind(column(|member| &member.network_id))
    .bind(column(|member| &member.pod_uid))
    .bind(generations)
    .fetch_all(pool)
    .await?;
    if rows.len() != members.len() {
        return Err(sqlx::Error::RowNotFound);
    }
    rows.into_iter()
        .map(|(_, status)| match status.as_str() {
            "live" => Ok(MemberStatus::Live),
            "stale" => Ok(MemberStatus::Stale),
            "gone" => Ok(MemberStatus::Gone),
            _ => Err(sqlx::Error::RowNotFound),
        })
        .collect()
}

/// Records `report` for `pod_uid`, which the caller confirmed is the
/// environment's live binding. False when the environment joins no network.
pub(crate) async fn report_attachment(
    pool: &PgPool,
    environment_id: &str,
    pod_uid: &str,
    report: AttachmentReport,
) -> Result<bool, sqlx::Error> {
    let (status, failure) = match report {
        AttachmentReport::Attached => ("attached", ""),
        AttachmentReport::Revoked => ("revoked", ""),
        AttachmentReport::Failed(reason) => ("failed", reason),
    };
    let updated = sqlx::query(
        r#"UPDATE environment_mesh_attachments
              SET status = $2, failure = $3, status_pod_uid = $4, status_changed_at = now()
            WHERE environment_id = $1"#,
    )
    .bind(environment_id)
    .bind(status)
    .bind(failure)
    .bind(pod_uid)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated == 1)
}
