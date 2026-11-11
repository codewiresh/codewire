//! Hosts (#3609, slice 1): computers that organization members enroll to
//! provide VMs, behind `HostService`.
//!
//! A host belongs to its organization and to the member who enrolled it, its
//! owner. Any member may read the organization's hosts. Only the owner may
//! change what a host provides or who may use it, or remove it; the owner or
//! an organization owner or admin may revoke it, which is final. Enrolling
//! grants nothing (design §4.2): providing is a separate opt-in with limits,
//! and a grant names a member or the whole organization, never implied by
//! membership.
//!
//! Whether a host is online is the database's view of its session, so every
//! replica answers the same: online when `last_seen_at` is within
//! [`OFFLINE_AFTER_SECS`] of the database's clock.

use std::borrow::Cow;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::{can_admin, user_assignments, user_org_role};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::{FromRow, PgPool};

use super::environments::coded;

#[cfg(test)]
mod database_tests;

/// A host unheard for this long is offline: the Mesh rule (#2697), with the
/// host session pinging every 15 seconds.
pub const OFFLINE_AFTER_SECS: i32 = 45;
/// Hosts one organization may hold that are not revoked. Revoking one frees
/// its place, so an organization admin is never stuck behind a member who
/// filled them.
pub const MAX_LIVE_HOSTS_PER_ORG: i64 = 100;
/// Host records one member may hold in an organization, revoked ones
/// included. A revoked record stays for good (removing it would free its key
/// to enroll again), so this is what bounds one member's rows and the
/// unpaginated list.
pub const MAX_HOST_RECORDS_PER_OWNER: i64 = 100;
/// The first line of the statement a computer signs to enroll.
pub const ENROLLMENT_STATEMENT_CONTEXT: &str = "codewire-host-enroll-v1";

const COLUMNS: &str = "id, org_id, owner_user_id, name, platform, capability_version, public_key, \
     provide, max_vms, max_vcpus, max_memory_mib, max_disk_gib, organization_grant, created_at, \
     last_seen_at, revoked_at, \
     CASE WHEN revoked_at IS NOT NULL THEN 'revoked' \
          WHEN last_seen_at > now() - make_interval(secs => 45) THEN 'online' \
          ELSE 'offline' END AS state";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPlatform {
    LinuxX86_64Kvm,
    DarwinArm64Vz,
}

impl HostPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64Kvm => "linux-x86_64-kvm",
            Self::DarwinArm64Vz => "darwin-arm64-vz",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "linux-x86_64-kvm" => Some(Self::LinuxX86_64Kvm),
            "darwin-arm64-vz" => Some(Self::DarwinArm64Vz),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostState {
    Online,
    Offline,
    Revoked,
}

/// The owner's limits on what a host provides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostLimits {
    pub max_vms: u32,
    pub max_vcpus: Option<u32>,
    pub max_memory_mib: Option<u64>,
    pub max_disk_gib: Option<u64>,
}

#[derive(Clone, Debug, FromRow)]
pub struct HostRow {
    pub id: String,
    pub org_id: String,
    pub owner_user_id: String,
    pub name: String,
    pub platform: String,
    pub capability_version: i32,
    pub public_key: Vec<u8>,
    pub provide: bool,
    pub max_vms: Option<i32>,
    pub max_vcpus: Option<i32>,
    pub max_memory_mib: Option<i64>,
    pub max_disk_gib: Option<i64>,
    pub organization_grant: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    state: String,
}

impl HostRow {
    pub fn state(&self) -> HostState {
        match self.state.as_str() {
            "revoked" => HostState::Revoked,
            "online" => HostState::Online,
            _ => HostState::Offline,
        }
    }

    /// The stored limits, once the host has provided.
    pub fn limits(&self) -> Option<HostLimits> {
        Some(HostLimits {
            max_vms: u32::try_from(self.max_vms?).ok()?,
            max_vcpus: self.max_vcpus.and_then(|value| u32::try_from(value).ok()),
            max_memory_mib: self
                .max_memory_mib
                .and_then(|value| u64::try_from(value).ok()),
            max_disk_gib: self
                .max_disk_gib
                .and_then(|value| u64::try_from(value).ok()),
        })
    }
}

/// One host, with the members granted it by name.
#[derive(Clone, Debug)]
pub struct HostView {
    pub host: HostRow,
    pub granted_user_ids: Vec<String>,
}

/// Who a grant names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grantee<'a> {
    User(&'a str),
    Organization,
}

#[derive(Clone, Copy, Debug)]
pub struct NewHost<'a> {
    pub name: &'a str,
    pub platform: Option<HostPlatform>,
    pub capability_version: u32,
    pub public_key: &'a [u8],
    pub enrollment_signature: &'a [u8],
}

fn issue(path: &'static str, message: &'static str) -> ValidationIssue {
    ValidationIssue {
        path: Cow::Borrowed(path),
        message: Cow::Borrowed(message),
    }
}

fn invalid(path: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![issue(path, message)],
    }
}

/// The same rule as the table's `hosts_name_check`: a DNS label.
pub fn valid_host_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// The bytes a computer signs to enroll `public_key` for `user_id` in
/// `org_id`.
pub fn enrollment_statement(org_id: &str, user_id: &str, public_key: &[u8]) -> Vec<u8> {
    let key: String = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{ENROLLMENT_STATEMENT_CONTEXT}\n{org_id}\n{user_id}\n{key}\n").into_bytes()
}

/// Field checks before any database access; each matches a table
/// constraint, so a refusal names the field instead of failing an insert.
pub fn validate_limits(limits: &HostLimits) -> AppResult<()> {
    let mut errors = Vec::new();
    if !(1..=1024).contains(&limits.max_vms) {
        errors.push(issue("/limits/max_vms", "must be 1 to 1024"));
    }
    if limits
        .max_vcpus
        .is_some_and(|value| !(1..=4096).contains(&value))
    {
        errors.push(issue("/limits/max_vcpus", "must be 1 to 4096"));
    }
    if limits
        .max_memory_mib
        .is_some_and(|value| !(256..=64 * 1024 * 1024).contains(&value))
    {
        errors.push(issue("/limits/max_memory_mib", "must be 256 MiB to 64 TiB"));
    }
    if limits
        .max_disk_gib
        .is_some_and(|value| !(1..=1024 * 1024).contains(&value))
    {
        errors.push(issue("/limits/max_disk_gib", "must be 1 GiB to 1 PiB"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

/// Checks a new host's fields and that the computer holds its key.
fn validate_new_host(org_id: &str, user_id: &str, host: &NewHost<'_>) -> AppResult<()> {
    let mut errors = Vec::new();
    if !valid_host_name(host.name) {
        errors.push(issue(
            "/name",
            "must be 1 to 63 lowercase letters, digits and '-', starting and ending with a letter or digit",
        ));
    }
    if host.platform.is_none() {
        errors.push(issue("/platform", "must be a supported host platform"));
    }
    if host.capability_version < 1 || i32::try_from(host.capability_version).is_err() {
        errors.push(issue("/capability_version", "must be at least 1"));
    }
    let key = <[u8; 32]>::try_from(host.public_key)
        .ok()
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
    if key.is_none() {
        errors.push(issue("/public_key", "must be a 32-byte Ed25519 public key"));
    }
    let signature = <[u8; 64]>::try_from(host.enrollment_signature)
        .ok()
        .map(|bytes| Signature::from_bytes(&bytes));
    if signature.is_none() {
        errors.push(issue(
            "/enrollment_signature",
            "must be a 64-byte Ed25519 signature",
        ));
    }
    if !errors.is_empty() {
        return Err(AppError::Validation { errors });
    }
    let (Some(key), Some(signature)) = (key, signature) else {
        unreachable!("checked above");
    };
    let statement = enrollment_statement(org_id, user_id, host.public_key);
    if key.verify_strict(&statement, &signature).is_err() {
        return Err(invalid(
            "/enrollment_signature",
            "does not sign this enrollment with the host's key",
        ));
    }
    Ok(())
}

/// The caller's role in the organization, or `organization not found`.
async fn member_role(pool: &PgPool, user: &AuthUser, org_id: &str) -> AppResult<String> {
    user_org_role(pool, user, org_id).await?.ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        )
    })
}

fn not_found() -> AppError {
    coded(StatusCode::NOT_FOUND, "host_not_found", "host not found")
}

fn not_owner() -> AppError {
    coded(
        StatusCode::FORBIDDEN,
        "not_host_owner",
        "only the host's owner may do this",
    )
}

fn revoked() -> AppError {
    AppError::Precondition("the host is revoked".into())
}

async fn fetch_host(pool: &PgPool, org_id: &str, host_id: &str) -> AppResult<HostRow> {
    // Every host ID is a UUID; anything else names no host.
    if uuid::Uuid::parse_str(host_id).is_err() {
        return Err(not_found());
    }
    sqlx::query_as::<_, HostRow>(&format!(
        "SELECT {COLUMNS} FROM hosts WHERE id = $1 AND org_id = $2"
    ))
    .bind(host_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(not_found)
}

async fn granted_user_ids(pool: &PgPool, host_id: &str) -> AppResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT user_id FROM host_grants WHERE host_id = $1 ORDER BY created_at, user_id",
    )
    .bind(host_id)
    .fetch_all(pool)
    .await?)
}

async fn view(pool: &PgPool, host: HostRow) -> AppResult<HostView> {
    let granted_user_ids = granted_user_ids(pool, &host.id).await?;
    Ok(HostView {
        host,
        granted_user_ids,
    })
}

/// The host, if the caller is a member and the host's owner.
async fn owned_host(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
) -> AppResult<HostRow> {
    member_role(pool, user, org_id).await?;
    let host = fetch_host(pool, org_id, host_id).await?;
    if host.owner_user_id != user.user_id {
        return Err(not_owner());
    }
    Ok(host)
}

/// Registers the caller's computer as a host they own.
pub async fn enroll_host(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host: &NewHost<'_>,
) -> AppResult<HostView> {
    member_role(pool, user, org_id).await?;
    validate_new_host(org_id, &user.user_id, host)?;
    let platform = host.platform.expect("validated").as_str();

    // One enrollment per organization at a time, so two cannot both pass the
    // bounds. The lock ends with the transaction.
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('hosts:' || $1, 0))")
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    let (live, owned): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE revoked_at IS NULL),
                count(*) FILTER (WHERE owner_user_id = $2)
           FROM hosts WHERE org_id = $1",
    )
    .bind(org_id)
    .bind(&user.user_id)
    .fetch_one(&mut *tx)
    .await?;
    if live >= MAX_LIVE_HOSTS_PER_ORG {
        return Err(coded(
            StatusCode::CONFLICT,
            "host_limit_reached",
            "this organization has the most hosts it can; remove or revoke one first",
        ));
    }
    if owned >= MAX_HOST_RECORDS_PER_OWNER {
        return Err(coded(
            StatusCode::CONFLICT,
            "host_limit_reached",
            "you have the most hosts one member can hold in this organization, revoked ones included",
        ));
    }
    let inserted = sqlx::query_as::<_, HostRow>(&format!(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, public_key)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING {COLUMNS}"
    ))
    .bind(org_id)
    .bind(&user.user_id)
    .bind(host.name)
    .bind(platform)
    .bind(host.capability_version as i32)
    .bind(host.public_key)
    .fetch_one(&mut *tx)
    .await;
    let inserted = match inserted {
        Ok(row) => row,
        Err(sqlx::Error::Database(error)) if error.constraint() == Some("hosts_org_name_key") => {
            return Err(coded(
                StatusCode::CONFLICT,
                "host_name_taken",
                "this organization already has a host with this name",
            ));
        }
        Err(sqlx::Error::Database(error)) if error.constraint() == Some("hosts_public_key_key") => {
            return Err(coded(
                StatusCode::CONFLICT,
                "host_key_enrolled",
                "this host key is already enrolled",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    tx.commit().await?;
    Ok(HostView {
        host: inserted,
        granted_user_ids: Vec::new(),
    })
}

/// The organization's hosts, oldest first.
pub async fn list_hosts(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    page_token: &str,
) -> AppResult<Vec<HostRow>> {
    member_role(pool, user, org_id).await?;
    if !page_token.is_empty() {
        return Err(invalid(
            "/page_token",
            "must be empty: every host comes in one page",
        ));
    }
    Ok(sqlx::query_as::<_, HostRow>(&format!(
        "SELECT {COLUMNS} FROM hosts WHERE org_id = $1 ORDER BY created_at, id"
    ))
    .bind(org_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_host(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
) -> AppResult<HostView> {
    member_role(pool, user, org_id).await?;
    let host = fetch_host(pool, org_id, host_id).await?;
    view(pool, host).await
}

/// Turns providing on with `limits`, or off. Turning it off keeps the stored
/// limits unless new ones are given.
pub async fn update_provide(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
    provide: bool,
    limits: Option<HostLimits>,
) -> AppResult<HostView> {
    let host = owned_host(pool, user, org_id, host_id).await?;
    if host.revoked_at.is_some() {
        return Err(revoked());
    }
    match (provide, &limits) {
        (true, None) => return Err(invalid("/limits", "are required to provide")),
        (_, Some(limits)) => validate_limits(limits)?,
        (false, None) => {}
    }
    let updated = sqlx::query_as::<_, HostRow>(&format!(
        "UPDATE hosts SET provide = $3,
                max_vms = CASE WHEN $4 THEN $5 ELSE max_vms END,
                max_vcpus = CASE WHEN $4 THEN $6 ELSE max_vcpus END,
                max_memory_mib = CASE WHEN $4 THEN $7 ELSE max_memory_mib END,
                max_disk_gib = CASE WHEN $4 THEN $8 ELSE max_disk_gib END,
                updated_at = now()
          WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL
          RETURNING {COLUMNS}"
    ))
    .bind(&host.id)
    .bind(org_id)
    .bind(provide)
    .bind(limits.is_some())
    .bind(limits.map(|limits| limits.max_vms as i32))
    .bind(
        limits
            .and_then(|limits| limits.max_vcpus)
            .map(|value| value as i32),
    )
    .bind(
        limits
            .and_then(|limits| limits.max_memory_mib)
            .map(|value| value as i64),
    )
    .bind(
        limits
            .and_then(|limits| limits.max_disk_gib)
            .map(|value| value as i64),
    )
    .fetch_optional(pool)
    .await?
    // Revoked between the read and the write.
    .ok_or_else(revoked)?;
    view(pool, updated).await
}

/// Lets one more member, or the whole organization, use the host. Granting
/// what is already granted changes nothing.
pub async fn grant_host(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
    grantee: Grantee<'_>,
) -> AppResult<HostView> {
    let host = owned_host(pool, user, org_id, host_id).await?;
    if host.revoked_at.is_some() {
        return Err(revoked());
    }
    match grantee {
        Grantee::Organization => {
            sqlx::query(
                "UPDATE hosts SET organization_grant = true, updated_at = now()
                  WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(&host.id)
            .execute(pool)
            .await?;
        }
        Grantee::User(grantee) => {
            if grantee == host.owner_user_id {
                return Err(invalid(
                    "/user_id",
                    "is the host's owner, who needs no grant",
                ));
            }
            let member: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)",
            )
            .bind(org_id)
            .bind(grantee)
            .fetch_one(pool)
            .await?;
            if !member {
                return Err(coded(
                    StatusCode::NOT_FOUND,
                    "member_not_found",
                    "no member of this organization has that user ID",
                ));
            }
            sqlx::query(
                "INSERT INTO host_grants (host_id, user_id)
                 SELECT id, $2 FROM hosts WHERE id = $1 AND revoked_at IS NULL
                 ON CONFLICT (host_id, user_id) DO NOTHING",
            )
            .bind(&host.id)
            .bind(grantee)
            .execute(pool)
            .await?;
        }
    }
    let view = get_host(pool, user, org_id, host_id).await?;
    // Revoked between the read and the write, so nothing was granted.
    if view.host.revoked_at.is_some() {
        return Err(revoked());
    }
    Ok(view)
}

/// Takes a grant back. Taking back what was not granted changes nothing.
pub async fn revoke_grant(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
    grantee: Grantee<'_>,
) -> AppResult<HostView> {
    let host = owned_host(pool, user, org_id, host_id).await?;
    match grantee {
        Grantee::Organization => {
            sqlx::query(
                "UPDATE hosts SET organization_grant = false, updated_at = now() WHERE id = $1",
            )
            .bind(&host.id)
            .execute(pool)
            .await?;
        }
        Grantee::User(grantee) => {
            sqlx::query("DELETE FROM host_grants WHERE host_id = $1 AND user_id = $2")
                .bind(&host.id)
                .bind(grantee)
                .execute(pool)
                .await?;
        }
    }
    get_host(pool, user, org_id, host_id).await
}

/// Marks the host revoked, for good. The owner or an organization owner or
/// admin. Revoking a revoked host changes nothing.
pub async fn revoke_host(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
) -> AppResult<HostView> {
    let role = member_role(pool, user, org_id).await?;
    let host = fetch_host(pool, org_id, host_id).await?;
    if host.owner_user_id != user.user_id
        && !can_admin(&role, &user_assignments(pool, org_id, &user.user_id).await?)
    {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "not_host_owner_or_admin",
            "only the host's owner or an organization owner or admin may revoke it",
        ));
    }
    sqlx::query(
        "UPDATE hosts SET revoked_at = now(), revoked_by = $2, updated_at = now()
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(&host.id)
    .bind(&user.user_id)
    .execute(pool)
    .await?;
    get_host(pool, user, org_id, host_id).await
}

/// Removes the host's record. A revoked host's record stays: removing it
/// would free its key to enroll again and undo the revocation. Nothing can
/// be placed on a host yet (slice 2 adds placement, and with it the refusal
/// while environments are there), so there is nothing else to wait for.
pub async fn leave_host(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    host_id: &str,
) -> AppResult<()> {
    let host = owned_host(pool, user, org_id, host_id).await?;
    let removed =
        sqlx::query("DELETE FROM hosts WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL")
            .bind(&host.id)
            .bind(org_id)
            .execute(pool)
            .await?;
    if removed.rows_affected() == 0 {
        return Err(AppError::Precondition(
            "the host is revoked; its record stays".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn signed(key: &SigningKey, org_id: &str, user_id: &str) -> Vec<u8> {
        let public = key.verifying_key().to_bytes();
        key.sign(&enrollment_statement(org_id, user_id, &public))
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn host_names_are_dns_labels() {
        for name in ["a", "build-box", "mac-1", &"a".repeat(63)] {
            assert!(valid_host_name(name), "{name}");
        }
        for name in ["", "-a", "a-", "Build", "a_b", "a.b", &"a".repeat(64)] {
            assert!(!valid_host_name(name), "{name}");
        }
    }

    #[test]
    fn the_enrollment_statement_binds_organization_user_and_key() {
        assert_eq!(
            enrollment_statement("org-1", "user-1", &[0xab, 0x01]),
            b"codewire-host-enroll-v1\norg-1\nuser-1\nab01\n"
        );
    }

    #[test]
    fn a_signature_enrolls_only_its_own_organization_and_user() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key().to_bytes();
        let signature = signed(&key, "org-1", "user-1");
        let host = NewHost {
            name: "build-box",
            platform: Some(HostPlatform::LinuxX86_64Kvm),
            capability_version: 1,
            public_key: &public,
            enrollment_signature: &signature,
        };
        validate_new_host("org-1", "user-1", &host).unwrap();
        for (org, user) in [("org-2", "user-1"), ("org-1", "user-2")] {
            let error = validate_new_host(org, user, &host).unwrap_err();
            assert!(
                matches!(&error, AppError::Validation { errors } if errors[0].path == "/enrollment_signature"),
                "{error:?}"
            );
        }
        // Another key's signature proves nothing about this one.
        let other = SigningKey::from_bytes(&[8; 32]);
        let foreign = signed(&other, "org-1", "user-1");
        let error = validate_new_host(
            "org-1",
            "user-1",
            &NewHost {
                enrollment_signature: &foreign,
                ..host
            },
        )
        .unwrap_err();
        assert!(matches!(error, AppError::Validation { .. }));
    }

    #[test]
    fn malformed_fields_are_named() {
        let error = validate_new_host(
            "org-1",
            "user-1",
            &NewHost {
                name: "Build Box",
                platform: None,
                capability_version: 0,
                public_key: &[1; 31],
                enrollment_signature: &[1; 63],
            },
        )
        .unwrap_err();
        let AppError::Validation { errors } = error else {
            panic!("expected validation");
        };
        let paths: Vec<_> = errors.iter().map(|issue| issue.path.as_ref()).collect();
        assert_eq!(
            paths,
            [
                "/name",
                "/platform",
                "/capability_version",
                "/public_key",
                "/enrollment_signature"
            ]
        );
    }

    #[test]
    fn limits_match_the_table_constraints() {
        let mut limits = HostLimits {
            max_vms: 2,
            max_vcpus: Some(8),
            max_memory_mib: Some(8192),
            max_disk_gib: Some(200),
        };
        validate_limits(&limits).unwrap();
        limits.max_vms = 0;
        limits.max_memory_mib = Some(255);
        let AppError::Validation { errors } = validate_limits(&limits).unwrap_err() else {
            panic!("expected validation");
        };
        let paths: Vec<_> = errors.iter().map(|issue| issue.path.as_ref()).collect();
        assert_eq!(paths, ["/limits/max_vms", "/limits/max_memory_mib"]);
    }

    #[test]
    fn the_online_window_is_the_offline_constant() {
        assert!(COLUMNS.contains(&format!("make_interval(secs => {OFFLINE_AFTER_SECS})")));
    }

    #[test]
    fn platforms_round_trip_their_stored_names() {
        for platform in [HostPlatform::LinuxX86_64Kvm, HostPlatform::DarwinArm64Vz] {
            assert_eq!(HostPlatform::parse(platform.as_str()), Some(platform));
        }
        assert_eq!(HostPlatform::parse("windows"), None);
    }
}
