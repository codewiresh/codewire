//! Where a create runs, and a create's request ID (#3609 slice 2).
//!
//! A create names a host by name or ID. [`resolve_host`] admits it under the
//! organization row lock the create already holds, so two creates for one
//! host are counted one after the other (a host belongs to one organization).
//! Who may place is checked at each create, never stored (design §4.5): the
//! host isn't revoked, its owner is still a member, and the caller is the
//! owner, or the organization grant is on, or the caller has a named grant.
//! Then the host must be providing, online and new enough, the request must
//! be one a host runs today, and the host's own limits must leave room. The
//! host's own refusal, later, still wins. Nothing falls back to another
//! placement.

use axum::http::StatusCode;
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use sqlx::{Postgres, Transaction};

use super::environments::{coded, coded_owned};
use super::hosts::HostState;

/// The host capability a create needs: lifecycle operations (#4510).
pub(crate) const HOST_LIFECYCLE_CAPABILITY: i32 = 2;

/// A create's request ID: 16 to 64 letters, digits, '-' or '_', the same
/// rule as billing's Add credit request IDs.
pub(crate) fn valid_request_id(value: &str) -> bool {
    (16..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// What a host create asks for, beyond its shape.
pub(crate) struct HostRequest<'a> {
    pub isolation_tier: &'a str,
    /// The spec's image; a host runs only its own default, so only the
    /// canonical workspace image (which the host replaces) is accepted.
    pub image: &'a str,
    pub repositories: usize,
    /// Application secrets or a credential profile were selected.
    pub secrets: bool,
    pub credentials: bool,
    pub network: bool,
    /// A platform network policy was selected (#4000).
    pub network_policy: bool,
    pub source_snapshot: bool,
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
}

/// Why an environment on a host can't select a platform network policy, at
/// create or after.
pub(crate) fn network_policy_unsupported() -> codewire_server_core::AppError {
    coded(
        StatusCode::BAD_REQUEST,
        "host_network_policy_unsupported",
        "environments on a host can't select a network policy yet; the host's own network applies",
    )
}

/// What a host create can't have yet, named. Checked before any read.
pub(crate) fn refuse_unsupported(request: &HostRequest<'_>) -> AppResult<()> {
    let unsupported = |code: &'static str, detail: &'static str| {
        Err(coded(StatusCode::BAD_REQUEST, code, detail))
    };
    if request.isolation_tier == "confidential" {
        return unsupported(
            "host_isolation_unsupported",
            "a host can't run the confidential tier; create it on the platform",
        );
    }
    if !request.image.is_empty()
        && request.image != crate::sandbox::canonical_workspace_runtime_image()
    {
        return unsupported(
            "host_image_unsupported",
            "a host runs its own default image; leave the image unset",
        );
    }
    if request.secrets || request.credentials {
        return unsupported(
            "host_credentials_unsupported",
            "environments on a host can't use application secrets or a credential profile yet",
        );
    }
    if request.repositories > 0 {
        return unsupported(
            "host_repository_unsupported",
            "environments on a host start with an empty workspace for now; repositories come later",
        );
    }
    if request.network {
        return unsupported(
            "host_network_unsupported",
            "environments on a host can't join a Mesh network yet",
        );
    }
    if request.network_policy {
        return Err(network_policy_unsupported());
    }
    if request.source_snapshot {
        return unsupported(
            "host_snapshot_unsupported",
            "environments on a host can't start from a hosted snapshot",
        );
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct Candidate {
    id: String,
    owner_user_id: String,
    provide: bool,
    organization_grant: bool,
    capability_version: i32,
    state: String,
    max_vms: Option<i32>,
    max_vcpus: Option<i32>,
    max_memory_mib: Option<i64>,
    max_disk_gib: Option<i64>,
    owner_is_member: bool,
    caller_granted: bool,
    placed_vms: i64,
    placed_cpu_millicores: i64,
    placed_memory_mib: i64,
    placed_disk_gib: i64,
}

impl Candidate {
    fn state(&self) -> HostState {
        match self.state.as_str() {
            "revoked" => HostState::Revoked,
            "online" => HostState::Online,
            _ => HostState::Offline,
        }
    }
}

/// Admits a create on the host `host` (a name or an ID) of `org_id`, inside
/// the create's transaction and after its organization row lock. Returns
/// the host's ID.
pub(crate) async fn resolve_host(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
    user: &AuthUser,
    host: &str,
    request: &HostRequest<'_>,
) -> AppResult<String> {
    refuse_unsupported(request)?;
    // The host's environments that hold a VM, or may: every row placed on
    // it that isn't gone, except one in error that the host reports no VM
    // for and has no operation open.
    let candidate: Option<Candidate> = sqlx::query_as(
        r#"SELECT h.id, h.owner_user_id, h.provide, h.organization_grant,
                  h.capability_version, h.max_vms, h.max_vcpus, h.max_memory_mib,
                  h.max_disk_gib,
                  CASE WHEN h.revoked_at IS NOT NULL THEN 'revoked'
                       WHEN h.last_seen_at > now() - make_interval(secs => $4) THEN 'online'
                       ELSE 'offline' END AS state,
                  EXISTS (SELECT 1 FROM org_members m
                           WHERE m.org_id = h.org_id AND m.user_id = h.owner_user_id)
                      AS owner_is_member,
                  EXISTS (SELECT 1 FROM host_grants g
                           WHERE g.host_id = h.id AND g.user_id = $3) AS caller_granted,
                  COUNT(e.id) AS placed_vms,
                  COALESCE(SUM(e.cpu_millicores), 0)::bigint AS placed_cpu_millicores,
                  COALESCE(SUM(e.memory_mb), 0)::bigint AS placed_memory_mib,
                  COALESCE(SUM(e.disk_gb), 0)::bigint AS placed_disk_gib
             FROM hosts h
             LEFT JOIN environments e
               ON e.host_id = h.id
              AND e.state NOT IN ('destroyed', 'archived')
              AND (e.state <> 'error'
                   OR EXISTS (SELECT 1 FROM host_environments he
                               WHERE he.host_id = h.id AND he.environment_id = e.id
                                 AND he.state <> 'absent')
                   OR EXISTS (SELECT 1 FROM host_operations o
                               WHERE o.environment_id = e.id
                                 AND o.state IN ('pending', 'sent')))
            WHERE h.org_id = $1 AND (h.id = $2 OR h.name = $2)
            GROUP BY h.id"#,
    )
    .bind(org_id)
    .bind(host)
    .bind(&user.user_id)
    .bind(super::hosts::OFFLINE_AFTER_SECS)
    .fetch_optional(&mut **transaction)
    .await?;
    let candidate = admit(candidate, user, host)?;
    check_room(&candidate, request)?;
    Ok(candidate.id)
}

fn admit(candidate: Option<Candidate>, user: &AuthUser, host: &str) -> AppResult<Candidate> {
    let not_found = || {
        coded_owned(
            StatusCode::NOT_FOUND,
            "host_not_found",
            format!("no host {host:?} in this organization; `cw hosts` lists them"),
        )
    };
    let Some(candidate) = candidate else {
        return Err(not_found());
    };
    let may_use = candidate.owner_user_id == user.user_id
        || candidate.organization_grant
        || candidate.caller_granted;
    // A host the caller may not use reads as absent, as `cw hosts` would.
    if !may_use {
        return Err(not_found());
    }
    let refuse =
        |code: &'static str, detail: String| Err(coded_owned(StatusCode::CONFLICT, code, detail));
    if candidate.state() == HostState::Revoked {
        return refuse("host_revoked", format!("host {host:?} was revoked"));
    }
    if !candidate.owner_is_member {
        return refuse(
            "host_owner_left",
            format!("host {host:?}'s owner is no longer a member of this organization"),
        );
    }
    if !candidate.provide {
        return refuse(
            "host_not_providing",
            format!("host {host:?} isn't offering VMs; its owner runs `cw host provide`"),
        );
    }
    if candidate.state() != HostState::Online {
        return refuse(
            "host_offline",
            format!("host {host:?} is offline; its agent isn't connected"),
        );
    }
    if candidate.capability_version < HOST_LIFECYCLE_CAPABILITY {
        return refuse(
            "host_upgrade_required",
            format!("host {host:?} runs a `cw` too old to create environments; upgrade it there"),
        );
    }
    Ok(candidate)
}

fn check_room(candidate: &Candidate, request: &HostRequest<'_>) -> AppResult<()> {
    let full = |what: &str, placed: i64, adding: i64, limit: i64| -> AppResult<()> {
        if placed + adding > limit {
            return Err(coded_owned(
                StatusCode::CONFLICT,
                "host_full",
                format!("the host's {what} limit would be exceeded ({placed}+{adding} > {limit})"),
            ));
        }
        Ok(())
    };
    // Providing needs a VM count (the table's own check).
    let Some(max_vms) = candidate.max_vms else {
        return Err(coded(
            StatusCode::CONFLICT,
            "host_not_providing",
            "the host has no VM limit, so it isn't providing",
        ));
    };
    full("VM", candidate.placed_vms, 1, i64::from(max_vms))?;
    if let Some(max) = candidate.max_vcpus {
        full(
            "vCPU",
            candidate.placed_cpu_millicores,
            i64::from(request.cpu_millicores),
            i64::from(max) * 1000,
        )?;
    }
    if let Some(max) = candidate.max_memory_mib {
        full(
            "memory (MiB)",
            candidate.placed_memory_mib,
            i64::from(request.memory_mib),
            max,
        )?;
    }
    if let Some(max) = candidate.max_disk_gib {
        full(
            "disk (GiB)",
            candidate.placed_disk_gib,
            i64::from(request.disk_gib),
            max,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
