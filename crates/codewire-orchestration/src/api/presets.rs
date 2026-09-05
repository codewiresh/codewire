//! Presets CRUD (#38 slice 4) — port of the preset handlers in
//! `environment_routes.go` plus `updatePreset` from
//! `environment_db.go`. Admin gate mirrors `canAdmin` (org owner/admin
//! or a `super_admin` assignment).

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult};
use schemars::JsonSchema;
use serde::Deserialize;
use sqlx::PgPool;

use super::ApiState;
use super::create::{ensure_no_secret_delivery, sanitize_image_name};
use super::environments::{coded, coded_owned, require_org_member};
use super::prepare::{PresetWire, get_preset_wire, list_presets};

/// Mirrors `getUserAssignments`.
async fn get_user_assignments(pool: &PgPool, org_id: &str, user_id: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT a.assignment FROM org_member_assignments a
           JOIN org_members m ON m.id = a.org_member_id
           WHERE m.org_id = $1 AND m.user_id = $2"#,
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Mirrors `canAdmin`: owner/admin role or super_admin assignment.
pub(crate) async fn can_admin(pool: &PgPool, user: &AuthUser, org_id: &str, role: &str) -> bool {
    if role == "owner" || role == "admin" {
        return true;
    }
    get_user_assignments(pool, org_id, &user.user_id)
        .await
        .iter()
        .any(|a| a == "super_admin")
}

/// Org-role gate returning the role (handlers need it for canAdmin).
async fn require_org_role(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<String, AppError> {
    match user_org_role(pool, user, org_id).await? {
        Some(role) => Ok(role),
        None => Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        )),
    }
}

fn valid_agent_type(agent: &str) -> bool {
    crate::worker::agents::is_supported_agent(agent)
}

async fn insert_preset_db(
    pool: &PgPool,
    org_id: &str,
    name: &str,
    body: &CreatePresetBody,
    project_spec: &serde_json::Value,
) -> anyhow::Result<String> {
    let mut transaction = pool.begin().await?;
    let slug = (!body.slug.is_empty()).then_some(body.slug.as_str());
    let id: String = sqlx::query_scalar(
        r#"INSERT INTO environment_presets
              (org_id, name, slug, description, default_ttl_seconds, project_spec)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
    )
    .bind(org_id)
    .bind(name)
    .bind(slug)
    .bind(&body.description)
    .bind(body.default_ttl_seconds)
    .bind(project_spec)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| anyhow::anyhow!("insert preset: {error}"))?;

    if !body.project_spec.image.is_empty() {
        let sandbox_name = sanitize_image_name(&body.project_spec.image);
        sqlx::query(
            r#"INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
               VALUES ($1, $2, $3)"#,
        )
        .bind(&id)
        .bind(&body.project_spec.image)
        .bind(&sandbox_name)
        .execute(&mut *transaction)
        .await
        .map_err(|error| anyhow::anyhow!("insert sandbox_template_config: {error}"))?;
    }

    transaction.commit().await?;
    Ok(id)
}

// ── Create ──────────────────────────────────────────────────────────────

/// Preset metadata plus its one canonical project configuration.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreatePresetBody {
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_ttl_seconds: Option<i32>,
    #[schemars(with = "serde_json::Value")]
    pub project_spec: codewire_project::ProjectSpec,
}

fn validate_preset_project_spec(spec: &codewire_project::ProjectSpec) -> AppResult<()> {
    spec.validate().map_err(|error| {
        coded_owned(
            StatusCode::BAD_REQUEST,
            "invalid_project_spec",
            error.to_string(),
        )
    })?;
    if !spec.preset.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_project_spec",
            "a preset project_spec cannot select another preset",
        ));
    }
    ensure_no_secret_delivery(spec)?;
    for agent in &spec.agents.tools {
        if !valid_agent_type(agent) {
            return Err(coded_owned(
                StatusCode::BAD_REQUEST,
                "unsupported_agent",
                format!("unsupported agent: {agent}"),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn create_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    body: CreatePresetBody,
) -> AppResult<PresetWire> {
    let pool = &state.pool;
    let role = require_org_role(pool, user, org_id).await?;
    if !can_admin(pool, user, org_id, &role).await {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only owner or admin can create presets",
        ));
    }
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "name_required",
            "name is required",
        ));
    }
    validate_preset_project_spec(&body.project_spec)?;
    let project_spec = serde_json::to_value(&body.project_spec).map_err(|_| {
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to serialize preset project specification",
        )
    })?;

    run_organization_database_mutation(pool, org_id, async {
        let id = match insert_preset_db(pool, org_id, &name, &body, &project_spec).await {
            Ok(id) => id,
            Err(e) if e.to_string().contains("idx_presets_slug_org") => {
                return Err(coded(
                    StatusCode::CONFLICT,
                    "preset_slug_conflict",
                    "preset with this slug already exists",
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "insert preset failed");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to create preset",
                ));
            }
        };

        let preset = get_preset_wire(pool, &id).await.map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read created preset",
            )
        })?;
        Ok(preset)
    })
    .await
}

// ── Read ────────────────────────────────────────────────────────────────

pub(crate) async fn list_presets_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<PresetWire>> {
    require_org_member(&state.pool, user, org_id).await?;
    let presets = list_presets(&state.pool, org_id).await.map_err(|e| {
        tracing::error!(error = %e, "list presets failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list presets",
        )
    })?;
    Ok(presets)
}

pub(crate) async fn get_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    preset_id: &str,
) -> AppResult<PresetWire> {
    require_org_member(&state.pool, user, org_id).await?;
    let preset = get_preset_wire(&state.pool, preset_id).await.map_err(|_| {
        coded(
            StatusCode::NOT_FOUND,
            "preset_not_found",
            "preset not found",
        )
    })?;
    if preset.org_id.as_deref() != Some(org_id) && !preset.official {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "preset_not_found",
            "preset not found",
        ));
    }
    Ok(preset)
}

// ── Update ──────────────────────────────────────────────────────────────

/// Metadata patch plus optional whole-value canonical configuration replacement.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdatePresetBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub default_ttl_seconds: Option<i32>,
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub project_spec: Option<codewire_project::ProjectSpec>,
}

/// Replace metadata fields and, when present, the complete canonical spec.
async fn update_preset_db(pool: &PgPool, id: &str, body: &UpdatePresetBody) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;

    // Dynamic SET clauses. sqlx can't bind heterogenous Vec<dyn>, so
    // build the query with explicit positional binds per branch.
    let mut sets: Vec<String> = Vec::new();
    let mut texts: Vec<Option<String>> = Vec::new();
    let mut ints: Vec<(usize, i32)> = Vec::new(); // (set index, value)
    let mut jsons: Vec<(usize, serde_json::Value)> = Vec::new();

    let push_text = |sets: &mut Vec<String>,
                     texts: &mut Vec<Option<String>>,
                     col: &str,
                     val: Option<String>| {
        sets.push(col.to_string());
        texts.push(val);
    };

    if let Some(name) = &body.name {
        push_text(&mut sets, &mut texts, "name", Some(name.clone()));
    }
    if let Some(desc) = &body.description {
        push_text(&mut sets, &mut texts, "description", Some(desc.clone()));
    }
    if let Some(slug) = &body.slug {
        let v = (!slug.is_empty()).then(|| slug.clone());
        push_text(&mut sets, &mut texts, "slug", v);
    }
    if let Some(v) = body.default_ttl_seconds {
        sets.push("default_ttl_seconds".into());
        texts.push(None);
        ints.push((sets.len() - 1, v));
    }

    if let Some(project_spec) = &body.project_spec {
        sets.push("project_spec".into());
        texts.push(None);
        jsons.push((sets.len() - 1, serde_json::to_value(project_spec)?));
        // Once a user replaces the canonical specification, this is a manual
        // preset rather than the internal identity for image-only resolution.
        // Clear the identity in the same statement so it can never disagree
        // with the canonical source.
        sets.push("auto_image_ref".into());
        texts.push(None);
    }

    if !sets.is_empty() {
        let clauses: Vec<String> = sets
            .iter()
            .enumerate()
            .map(|(i, col)| format!("{col} = ${}", i + 1))
            .collect();
        let sql = format!(
            "UPDATE environment_presets SET {} WHERE id = ${}",
            clauses.join(", "),
            sets.len() + 1
        );
        let mut q = sqlx::query(&sql);
        for (i, text) in texts.iter().enumerate() {
            if let Some((_, v)) = ints.iter().find(|(idx, _)| *idx == i) {
                q = q.bind(*v);
            } else if let Some((_, v)) = jsons.iter().find(|(idx, _)| *idx == i) {
                q = q.bind(v.clone());
            } else {
                q = q.bind(text.clone());
            }
        }
        q = q.bind(id);
        q.execute(&mut *transaction)
            .await
            .map_err(|e| anyhow::anyhow!("update preset: {e}"))?;
    }

    // Keep the runtime template projection derived from the canonical image.
    if let Some(project_spec) = &body.project_spec {
        if project_spec.image.is_empty() {
            sqlx::query("DELETE FROM sandbox_template_config WHERE preset_id = $1")
                .bind(id)
                .execute(&mut *transaction)
                .await
                .map_err(|e| anyhow::anyhow!("delete sandbox_template_config: {e}"))?;
        } else {
            sqlx::query(
                r#"INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (preset_id) DO UPDATE
                   SET image_ref = EXCLUDED.image_ref,
                       sandbox_template_name = EXCLUDED.sandbox_template_name"#,
            )
            .bind(id)
            .bind(&project_spec.image)
            .bind(sanitize_image_name(&project_spec.image))
            .execute(&mut *transaction)
            .await
            .map_err(|e| anyhow::anyhow!("update sandbox_template_config: {e}"))?;
        }
    }

    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn update_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    preset_id: &str,
    body: UpdatePresetBody,
) -> AppResult<PresetWire> {
    let pool = &state.pool;
    let role = require_org_role(pool, user, org_id).await?;
    if !can_admin(pool, user, org_id, &role).await {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only owner or admin can update presets",
        ));
    }
    if let Some(project_spec) = &body.project_spec {
        validate_preset_project_spec(project_spec)?;
    }
    run_organization_database_mutation(pool, org_id, async {
        let preset = get_preset_wire(pool, preset_id).await.map_err(|_| {
            coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            )
        })?;
        if preset.org_id.as_deref() != Some(org_id) {
            return Err(coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            ));
        }

        if let Err(e) = update_preset_db(pool, &preset.id, &body).await {
            if e.to_string().contains("idx_presets_slug_org") {
                return Err(coded(
                    StatusCode::CONFLICT,
                    "preset_slug_conflict",
                    "preset with this slug already exists",
                ));
            }
            tracing::error!(error = %e, "update preset");
            return Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to update preset",
            ));
        }

        let updated = get_preset_wire(pool, &preset.id).await.map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read updated preset",
            )
        })?;
        Ok(updated)
    })
    .await
}

// ── Delete ──────────────────────────────────────────────────────────────

pub(crate) async fn delete_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    preset_id: &str,
) -> AppResult<()> {
    let pool = &state.pool;
    let role = require_org_role(pool, user, org_id).await?;
    if !can_admin(pool, user, org_id, &role).await {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only owner or admin can delete presets",
        ));
    }
    run_organization_database_mutation(pool, org_id, async {
        let preset = get_preset_wire(pool, preset_id).await.map_err(|_| {
            coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            )
        })?;
        if preset.org_id.as_deref() != Some(org_id) {
            return Err(coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            ));
        }

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environments WHERE preset_id = $1 AND state != 'destroyed'",
        )
        .bind(&preset.id)
        .fetch_one(pool)
        .await
        .map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to check preset usage",
            )
        })?;
        if active_count > 0 {
            return Err(coded_owned(
                StatusCode::CONFLICT,
                "preset_in_use",
                format!(
                    "preset is used by {active_count} active environment(s) — delete them first"
                ),
            ));
        }

        sqlx::query("DELETE FROM environments WHERE preset_id = $1 AND state = 'destroyed'")
            .bind(&preset.id)
            .execute(pool)
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to clean up destroyed environments",
                )
            })?;

        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset.id)
            .execute(pool)
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to delete preset",
                )
            })?;

        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn create_preset_schema_requires_canonical_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(CreatePresetBody)).unwrap();

        assert_eq!(
            schema["required"],
            serde_json::json!(["name", "project_spec"]),
            "preset creation requires a name and one canonical project specification"
        );
    }

    #[test]
    fn create_preset_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreatePresetBody>(serde_json::json!({
                "project_spec": {
                    "schema_version": 1,
                    "working_directory": "/workspace"
                }
            }))
        else {
            panic!("expected missing name to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("name"));
    }

    #[test]
    fn create_preset_validation_accepts_a_minimal_project_spec() {
        let parsed = validate_value::<CreatePresetBody>(serde_json::json!({
            "name": "Default",
            "project_spec": {
                "schema_version": 1,
                "working_directory": "/workspace"
            }
        }))
        .expect("minimal canonical project specification should validate");

        assert_eq!(parsed.name, "Default");
        assert!(parsed.project_spec.image.is_empty());
    }

    #[test]
    fn preset_mutations_reject_removed_agent_env() {
        assert!(
            validate_value::<CreatePresetBody>(serde_json::json!({
                "name": "Default",
                "agent_env": {"TOKEN": "synthetic"}
            }))
            .is_err()
        );
        assert!(
            validate_value::<UpdatePresetBody>(serde_json::json!({
                "agent_env": {"TOKEN": "synthetic"}
            }))
            .is_err()
        );
    }

    #[test]
    fn update_preset_schema_has_no_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(UpdatePresetBody)).unwrap();

        assert!(
            schema.get("required").is_none(),
            "PATCH body stays all-optional"
        );
    }

    #[test]
    fn rest_update_replaces_the_whole_project_spec_when_present() {
        let absent: UpdatePresetBody = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(absent.slug.is_none());
        assert!(absent.project_spec.is_none());

        let empty: UpdatePresetBody = serde_json::from_value(serde_json::json!({
            "slug": "",
            "project_spec": {
                "schema_version": 1,
                "working_directory": "/workspace"
            }
        }))
        .unwrap();
        assert_eq!(empty.slug.as_deref(), Some(""));
        assert_eq!(
            empty.project_spec,
            Some(codewire_project::ProjectSpec::default())
        );

        let value: UpdatePresetBody = serde_json::from_value(serde_json::json!({
            "slug": "rust",
            "project_spec": {
                "schema_version": 1,
                "working_directory": "/workspace",
                "environment": {"RUST_LOG": "debug"}
            }
        }))
        .unwrap();
        assert_eq!(value.slug.as_deref(), Some("rust"));
        assert_eq!(
            value
                .project_spec
                .as_ref()
                .and_then(|spec| spec.environment.get("RUST_LOG"))
                .map(String::as_str),
            Some("debug")
        );
    }

    #[test]
    fn update_preset_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdatePresetBody>(serde_json::json!({
                "project_spec": {
                    "schema_version": 1,
                    "working_directory": "/workspace",
                    "resources": {"cpu_millicores": "2000"}
                }
            }))
        else {
            panic!("expected type-invalid CPU to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("u32"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_preset_source_and_runtime_projection_commit_atomically() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("user_preset_atomic_{suffix}");
        let org_id = format!("org_preset_atomic_{suffix}");
        let function_name = format!("cw_fail_preset_projection_{suffix}");
        let trigger_name = format!("cw_fail_preset_projection_{suffix}");
        let failing_image = format!("ghcr.io/example/failing-{suffix}:1");
        let original_image = format!("ghcr.io/example/original-{suffix}:1");

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&org_id)
        .bind(format!("Preset atomic {suffix}"))
        .bind(format!("preset-atomic-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            r#"CREATE FUNCTION {function_name}() RETURNS trigger
               LANGUAGE plpgsql AS $function$
               BEGIN
                   IF NEW.image_ref = '{failing_image}' THEN
                       RAISE EXCEPTION 'synthetic preset projection failure';
                   END IF;
                   RETURN NEW;
               END
               $function$"#,
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            r#"CREATE TRIGGER {trigger_name}
               BEFORE INSERT OR UPDATE ON sandbox_template_config
               FOR EACH ROW EXECUTE FUNCTION {function_name}()"#,
        ))
        .execute(&pool)
        .await
        .unwrap();

        let failing_spec = codewire_project::ProjectSpec {
            image: failing_image.clone(),
            ..Default::default()
        };
        let failing_body = CreatePresetBody {
            name: "Must roll back".to_owned(),
            project_spec: failing_spec.clone(),
            ..Default::default()
        };
        let serialized_failing = serde_json::to_value(&failing_spec).unwrap();
        let insert_error = insert_preset_db(
            &pool,
            &org_id,
            &failing_body.name,
            &failing_body,
            &serialized_failing,
        )
        .await
        .expect_err("projection failure must abort preset creation");
        let failed_insert_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_presets WHERE org_id = $1 AND name = $2",
        )
        .bind(&org_id)
        .bind(&failing_body.name)
        .fetch_one(&pool)
        .await
        .unwrap();

        let original_spec = codewire_project::ProjectSpec {
            image: original_image.clone(),
            ..Default::default()
        };
        let original_body = CreatePresetBody {
            name: "Original".to_owned(),
            project_spec: original_spec.clone(),
            ..Default::default()
        };
        let original_json = serde_json::to_value(&original_spec).unwrap();
        let preset_id = insert_preset_db(
            &pool,
            &org_id,
            &original_body.name,
            &original_body,
            &original_json,
        )
        .await
        .unwrap();
        let update_error = update_preset_db(
            &pool,
            &preset_id,
            &UpdatePresetBody {
                name: Some("Must also roll back".to_owned()),
                project_spec: Some(failing_spec),
                ..Default::default()
            },
        )
        .await
        .expect_err("projection failure must abort preset update");
        let stored: (String, serde_json::Value, String) = sqlx::query_as(
            r#"SELECT ep.name, ep.project_spec, stc.image_ref
               FROM environment_presets ep
               JOIN sandbox_template_config stc ON stc.preset_id = ep.id
               WHERE ep.id = $1"#,
        )
        .bind(&preset_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        sqlx::query(&format!(
            "DROP TRIGGER {trigger_name} ON sandbox_template_config",
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            insert_error
                .to_string()
                .contains("synthetic preset projection failure")
        );
        assert_eq!(failed_insert_count, 0);
        assert!(
            update_error
                .to_string()
                .contains("synthetic preset projection failure")
        );
        assert_eq!(stored.0, "Original");
        assert_eq!(stored.1, original_json);
        assert_eq!(stored.2, original_image);
    }
}
