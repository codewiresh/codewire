//! A create's preset, and the defaults it fills into the request.

use super::*;

/// The create's preset, with the saved repository configuration's, the
/// preset's and the platform's defaults filled into what `body` leaves out.
/// Only a disk the request itself names is held to; any other grows to fit
/// its source snapshot (#6276), so the request's disk is read before any
/// default fills it.
pub(super) async fn resolve_create_defaults(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
    body: &mut CreateEnvironmentBody,
    isolation_tier: &str,
) -> AppResult<Preset> {
    let disk_named = body.project_spec.resources.disk_gib.is_some();
    let preset: Preset = if body.preset_id.as_deref().is_some_and(|s| !s.is_empty()) {
        let preset_id = body.preset_id.clone().unwrap();
        let preset = get_preset(pool, &preset_id).await.map_err(|_| {
            coded(
                StatusCode::BAD_REQUEST,
                "preset_not_found",
                "preset not found",
            )
        })?;
        validate_preset_scope(&preset, org_id)?;
        preset
    } else if !body.project_spec.preset.is_empty() || !body.project_spec.image.is_empty() {
        resolve_project_preset(pool, org_id, &body.project_spec).await?
    } else if let Some(repository_source) = body
        .project_spec
        .repositories
        .first()
        .map(|repository| repository.source.clone())
    {
        match resolve_from_repo_config(pool, org_id, &repository_source).await? {
            Some((saved_preset, saved_spec)) => {
                tracing::info!(
                    repo_url = repository_source,
                    "smart create: using saved repo config"
                );
                merge_environment_defaults(body, &saved_spec)?;
                match saved_preset {
                    Some(preset) => {
                        validate_preset_scope(&preset, org_id)?;
                        preset
                    }
                    None if body.project_spec.image.is_empty()
                        && body.project_spec.preset.is_empty() =>
                    {
                        return Err(repository_analysis_pending());
                    }
                    None => {
                        // Saved workload defaults must be executable
                        // before image resolution can write a preset.
                        ensure_current_platform_runtime_support(body)?;
                        resolve_project_preset(pool, org_id, &body.project_spec).await?
                    }
                }
            }
            None => return Err(repository_analysis_pending()),
        }
    } else {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "missing_input",
            "project_spec must select a preset, image, or repository",
        ));
    };

    ensure_no_preset_secret_delivery(&preset)?;
    merge_environment_defaults(body, &preset.project_spec)?;
    apply_environment_resource_defaults(&mut body.project_spec, isolation_tier);
    if !disk_named {
        fit_disk_to_source_snapshot(pool, org_id, &user.user_id, body).await?;
    }
    Ok(preset)
}
