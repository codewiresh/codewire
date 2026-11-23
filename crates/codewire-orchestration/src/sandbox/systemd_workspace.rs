//! Orchestration's checks for a systemd workspace (docs/dev/SYSTEMD-WORKSPACE.md,
//! "When an environment is a systemd workspace" and "Where it is checked").
//!
//! These are product policy: which environments may be one, and when. The
//! privilege boundary is the cluster's admission rule for the systemd Pod
//! shape, which refuses that shape on its own.

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};

use super::runtime_images::{RuntimeImages, SystemdWorkspaceImage};
use super::template::{RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_STANDARD};

/// A refusal, as the API returns it and the worker records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: &'static str,
}

impl From<Refusal> for AppError {
    fn from(refusal: Refusal) -> Self {
        AppError::Coded {
            status: refusal.status,
            code: refusal.code,
            detail: refusal.detail.into(),
        }
    }
}

const NOT_OFFERED: Refusal = Refusal {
    status: StatusCode::SERVICE_UNAVAILABLE,
    code: "systemd_workspace_not_offered",
    detail: "this deployment does not offer systemd workspaces",
};
const UNPINNED: Refusal = Refusal {
    status: StatusCode::BAD_REQUEST,
    code: "systemd_workspace_image_unpinned",
    detail: "a systemd workspace image must be pinned by digest, as REPOSITORY@sha256:DIGEST",
};
const CONFIDENTIAL: Refusal = Refusal {
    status: StatusCode::BAD_REQUEST,
    code: "systemd_workspace_confidential",
    detail: "a systemd workspace cannot be a confidential environment",
};
const NEEDS_VM_RUNTIME: Refusal = Refusal {
    status: StatusCode::SERVICE_UNAVAILABLE,
    code: "systemd_workspace_needs_vm_runtime",
    detail: "a systemd workspace needs a VM runtime, which this deployment does not run sandboxes on",
};
/// The refusal that names the opt-in, for a member of the organization only.
pub const NOT_ENABLED: Refusal = Refusal {
    status: StatusCode::FORBIDDEN,
    code: "systemd_workspace_not_enabled",
    detail: "systemd environments are not enabled for this organization",
};
/// Anyone else gets the same refusal as for an organization they are not in.
const ORGANIZATION_NOT_FOUND: Refusal = Refusal {
    status: StatusCode::NOT_FOUND,
    code: "org_not_found",
    detail: "organization not found",
};

/// The deployment's checks for a systemd workspace with `image`: the
/// repository is set, the image is pinned from it, the runtime profile its
/// Pod renders on ([`super::template::runtime_profile_of`]) is `commodity` or
/// `standard`, and the environment is not confidential.
pub fn deployment_refusal(
    images: &RuntimeImages,
    image: &str,
    isolation_tier: &str,
    runtime_profile: &str,
) -> Option<Refusal> {
    match images.systemd_workspace(image) {
        SystemdWorkspaceImage::No => Some(NOT_OFFERED),
        SystemdWorkspaceImage::Unpinned => Some(UNPINNED),
        SystemdWorkspaceImage::Pinned if isolation_tier == "confidential" => Some(CONFIDENTIAL),
        SystemdWorkspaceImage::Pinned
            if !matches!(
                runtime_profile.trim(),
                RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_STANDARD
            ) =>
        {
            Some(NEEDS_VM_RUNTIME)
        }
        SystemdWorkspaceImage::Pinned => None,
    }
}

/// The profile an existing systemd workspace's Pod renders on, on a
/// deployment of `deployment_profile`. On a `standard` deployment it is the
/// one its create recorded (`environments.systemd_runtime_profile`), never
/// re-derived from the current disk, so a republished disk never moves it;
/// one created before the record existed has none and is `commodity`, which
/// needs the opt-in. On any other deployment it is the deployment's own,
/// which the deployment's checks then judge.
pub fn existing_profile<'a>(deployment_profile: &'a str, recorded: Option<&str>) -> &'a str {
    if deployment_profile.trim() != RUNTIME_PROFILE_STANDARD {
        return deployment_profile;
    }
    match recorded {
        Some(RUNTIME_PROFILE_STANDARD) => RUNTIME_PROFILE_STANDARD,
        _ => RUNTIME_PROFILE_COMMODITY,
    }
}

/// Whether a systemd workspace on `runtime_profile` needs its organization's
/// opt-in: on `commodity` only, whose Pod is loosened for it. A `standard`
/// Pod is not loosened, and systemd is that profile's default.
pub fn needs_opt_in(runtime_profile: &str) -> bool {
    runtime_profile.trim() == RUNTIME_PROFILE_COMMODITY
}

/// Every check a systemd workspace's Pod needs on `runtime_profile`, the
/// profile it renders on: the deployment's, then its organization's opt-in
/// (`opted_in`) where that profile needs one.
pub fn bring_up_refusal(
    images: &RuntimeImages,
    image: &str,
    isolation_tier: &str,
    runtime_profile: &str,
    opted_in: bool,
) -> Option<Refusal> {
    deployment_refusal(images, image, isolation_tier, runtime_profile)
        .or_else(|| (needs_opt_in(runtime_profile) && !opted_in).then_some(NOT_ENABLED))
}

/// Whether a create of `image` makes a systemd workspace. It is one exactly
/// when the image names the configured repository; such a create is refused
/// unless every deployment check holds. Every later Pod renders from this
/// answer as the environment records it, never from the image again.
pub fn kind_at_create(
    images: &RuntimeImages,
    image: &str,
    isolation_tier: &str,
    runtime_profile: &str,
) -> Result<bool, Refusal> {
    if images.systemd_workspace(image) == SystemdWorkspaceImage::No {
        return Ok(false);
    }
    match deployment_refusal(images, image, isolation_tier, runtime_profile) {
        Some(refusal) => Err(refusal),
        None => Ok(true),
    }
}

/// What a create records, admitted: `None` for a plain environment, or the
/// profile a systemd workspace's Pod renders on (`environments.systemd_workspace`
/// and `systemd_runtime_profile`). A fork from a snapshot takes its source
/// environment's kind, so a fork never turns a plain workspace into a systemd
/// one; any other create takes [`kind_at_create`]. Either way a systemd
/// workspace then passes [`require_bring_up`] for this caller on that
/// profile, and is never placed on a host.
pub async fn admit_create<'a>(
    pool: &sqlx::PgPool,
    user: &AuthUser,
    org_id: &str,
    create: CreateKind<'a>,
) -> AppResult<Option<&'a str>> {
    let images = super::runtime_images::configured();
    let systemd_workspace = match create.source_snapshot_id {
        Some(snapshot_id) => sqlx::query_scalar(
            "SELECT e.systemd_workspace FROM hosted_snapshots s
               JOIN environments e ON e.id = s.source_environment_id
              WHERE s.id = $1 AND s.org_id = $2",
        )
        .bind(snapshot_id)
        .bind(org_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(false),
        None => kind_at_create(
            images,
            create.image,
            create.isolation_tier,
            create.runtime_profile,
        )?,
    };
    if systemd_workspace && create.placed_on_host {
        return Err(NEEDS_VM_RUNTIME.into());
    }
    require_bring_up_with(
        pool,
        images,
        user,
        org_id,
        BringUp {
            systemd_workspace,
            image: create.image,
            isolation_tier: create.isolation_tier,
            runtime_profile: create.runtime_profile,
        },
    )
    .await?;
    Ok(systemd_workspace.then_some(create.runtime_profile))
}

/// The create [`admit_create`] decides for.
#[derive(Clone, Copy, Debug)]
pub struct CreateKind<'a> {
    pub image: &'a str,
    pub isolation_tier: &'a str,
    /// The profile its Pod renders on, from the deployment's current disk
    /// ([`super::template::runtime_profile_of`]): only a create derives it.
    pub runtime_profile: &'a str,
    pub source_snapshot_id: Option<&'a str>,
    pub placed_on_host: bool,
}

/// What an operation that brings up a systemd workspace's Pod must find:
/// every deployment check, then, where the profile needs it, the
/// organization's opt-in. The opt-in is read only for a member the caller may
/// act for, after the operation's ordinary checks; anyone else gets the
/// refusal for an organization they are not in, so nobody learns another
/// organization's flag. Stop, delete and removal never call this.
pub async fn require_bring_up<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    user: &AuthUser,
    org_id: &str,
    environment: BringUp<'_>,
) -> AppResult<()> {
    require_bring_up_with(
        executor,
        super::runtime_images::configured(),
        user,
        org_id,
        environment,
    )
    .await
}

pub(crate) async fn require_bring_up_with<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    images: &RuntimeImages,
    user: &AuthUser,
    org_id: &str,
    environment: BringUp<'_>,
) -> AppResult<()> {
    if !environment.systemd_workspace {
        return Ok(());
    }
    if let Some(refusal) = deployment_refusal(
        images,
        environment.image,
        environment.isolation_tier,
        environment.runtime_profile,
    ) {
        return Err(refusal.into());
    }
    if !needs_opt_in(environment.runtime_profile) {
        return Ok(());
    }
    let organization: Option<(bool, bool)> = if user.permits_organization(org_id) {
        sqlx::query_as(
            r#"SELECT o.systemd_environments_enabled,
                      EXISTS (SELECT 1 FROM org_members m
                               WHERE m.org_id = o.id AND m.user_id = $2)
                 FROM organizations o
                WHERE o.id = $1 AND o.deletion_state = 'active'"#,
        )
        .bind(org_id)
        .bind(&user.user_id)
        .fetch_optional(executor)
        .await?
    } else {
        None
    };
    match organization {
        Some((true, true)) => Ok(()),
        Some((false, true)) => Err(NOT_ENABLED.into()),
        _ => Err(ORGANIZATION_NOT_FOUND.into()),
    }
}

/// The environment an operation is bringing up, as the gate reads it.
#[derive(Clone, Copy, Debug)]
pub struct BringUp<'a> {
    /// `environments.systemd_workspace`, or a create's [`kind_at_create`].
    pub systemd_workspace: bool,
    pub image: &'a str,
    pub isolation_tier: &'a str,
    /// The profile its Pod renders on: a create's
    /// [`CreateKind::runtime_profile`], or an existing environment's
    /// [`existing_profile`], never derived from the current disk again.
    pub runtime_profile: &'a str,
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests {
    use super::*;

    const REPOSITORY: &str = "registry.example.invalid/codewire/workspace-systemd";

    fn images() -> RuntimeImages {
        RuntimeImages::example()
            .with_systemd_workspace_repository(REPOSITORY)
            .unwrap()
    }

    fn pinned() -> String {
        format!("{REPOSITORY}@sha256:{}", "0123456789abcdef".repeat(4))
    }

    #[test]
    fn a_create_is_a_systemd_workspace_only_for_a_pinned_image_of_the_repository() {
        let images = images();
        let kind = |image: &str, tier, profile| {
            kind_at_create(&images, image, tier, profile).map_err(|refusal| refusal.code)
        };
        assert_eq!(kind(&pinned(), "standard", "commodity"), Ok(true));
        // The tier is `standard` here; the profile is the second.
        assert_eq!(kind(&pinned(), "standard", "standard"), Ok(true));
        assert_eq!(kind("python:3.12", "confidential", "runc"), Ok(false));
        assert_eq!(
            kind(&format!("{REPOSITORY}:latest"), "standard", "commodity"),
            Err("systemd_workspace_image_unpinned")
        );
        assert_eq!(
            kind(&pinned(), "confidential", "commodity"),
            Err("systemd_workspace_confidential")
        );
        // Every runtime that is not a VM profile, a diagnostic one included.
        for profile in ["runc", "none", "", "confidential", "kata-qemu"] {
            assert_eq!(
                kind(&pinned(), "standard", profile),
                Err("systemd_workspace_needs_vm_runtime"),
                "{profile:?}"
            );
        }
        // With no repository set, no image is one.
        assert_eq!(
            kind_at_create(
                &RuntimeImages::example(),
                &pinned(),
                "standard",
                "commodity"
            ),
            Ok(false)
        );
    }

    /// The record is written once, by the create's insert: no statement in
    /// the server's crates updates it.
    #[test]
    fn no_statement_rewrites_the_recorded_kind() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut offenders = Vec::new();
        for krate in [
            "codewire-orchestration",
            "codewire-billing",
            "codewire-server-core",
        ] {
            let mut dirs = vec![crates.join(krate).join("src")];
            while let Some(dir) = dirs.pop() {
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        dirs.push(path);
                        continue;
                    }
                    // Production code only: a test may set up any row.
                    let name = path.to_string_lossy();
                    if path.extension().is_none_or(|extension| extension != "rs")
                        || name.contains("/tests/")
                        || name.ends_with("tests.rs")
                    {
                        continue;
                    }
                    let text = std::fs::read_to_string(&path).unwrap();
                    let upper = text.to_ascii_uppercase();
                    for (at, _) in upper.match_indices("UPDATE ") {
                        // The statement, to the end of its string literal.
                        let statement = &text[at..];
                        let statement =
                            &statement[..statement.find('"').unwrap_or(statement.len())];
                        let target = statement[7..].trim_start().to_ascii_lowercase();
                        if (target.starts_with("environments")
                            || target.starts_with("public.environments"))
                            && (statement.contains("systemd_workspace")
                                || statement.contains("systemd_runtime_profile"))
                        {
                            offenders.push(path.display().to_string());
                        }
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the systemd record is rewritten in {offenders:?}"
        );
    }

    #[test]
    fn an_existing_systemd_workspace_keeps_the_profile_its_create_recorded() {
        for (deployment, recorded, expected) in [
            ("standard", Some("standard"), "standard"),
            ("standard", Some("commodity"), "commodity"),
            // Created before the record: `commodity`, which needs the opt-in.
            ("standard", None, "commodity"),
            ("standard", Some("Standard"), "commodity"),
            // Any other deployment renders its own profile, which the
            // deployment's checks judge.
            ("commodity", Some("standard"), "commodity"),
            ("runc", Some("standard"), "runc"),
        ] {
            assert_eq!(
                existing_profile(deployment, recorded),
                expected,
                "{deployment} {recorded:?}"
            );
        }
    }

    #[test]
    fn only_a_commodity_systemd_workspace_needs_its_organizations_opt_in() {
        let images = images();
        let refusal = |profile, opted_in| {
            bring_up_refusal(&images, &pinned(), "standard", profile, opted_in)
                .map(|refusal| refusal.code)
        };
        assert_eq!(refusal("commodity", true), None);
        assert_eq!(
            refusal("commodity", false),
            Some("systemd_workspace_not_enabled")
        );
        // A `standard` Pod is not loosened for it.
        assert_eq!(refusal("standard", false), None);
        assert_eq!(refusal("standard", true), None);
        // The deployment's checks come first, opted in or not.
        assert_eq!(
            bring_up_refusal(&images, &pinned(), "confidential", "standard", true)
                .map(|refusal| refusal.code),
            Some("systemd_workspace_confidential")
        );
        assert_eq!(
            bring_up_refusal(
                &RuntimeImages::example(),
                &pinned(),
                "standard",
                "standard",
                false
            )
            .map(|refusal| refusal.code),
            Some("systemd_workspace_not_offered")
        );
    }

    #[test]
    fn a_recorded_systemd_workspace_is_refused_once_the_deployment_stops_offering_it() {
        let refusal = |images: &RuntimeImages, image: &str| {
            deployment_refusal(images, image, "standard", "commodity").map(|refusal| refusal.code)
        };
        assert_eq!(refusal(&images(), &pinned()), None);
        // The repository unset: the start is refused, never rendered as a
        // plain custom image.
        assert_eq!(
            refusal(&RuntimeImages::example(), &pinned()),
            Some("systemd_workspace_not_offered")
        );
        // The repository moved: the recorded image is no longer from it.
        let moved = RuntimeImages::example()
            .with_systemd_workspace_repository("registry.example.invalid/codewire/other")
            .unwrap();
        assert_eq!(
            refusal(&moved, &pinned()),
            Some("systemd_workspace_not_offered")
        );
    }
}
