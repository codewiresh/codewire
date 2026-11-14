//! Disposable-PostgreSQL proof for launch-selection capture and publication.
//! No protected material, provider call, or product database is used here.

use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use anyhow::{Context, Result, ensure};
use codewire_project::{CredentialBinding, ProjectSpec, StoragePlacement};
use serde_json::to_value;
use tokio::sync::oneshot;

use super::*;

use crate::test_database_support as support;
use support::TestDatabase;

const CREATOR: &str = "projection-capture-creator";
const ENVIRONMENT: &str = "ba4dde58-6a47-4ae9-aedd-2df7d52062c4";
const GENERATION: i64 = 7;
const ORGANIZATION: &str = "projection-capture-organization";
const PRESET: &str = "projection-capture-preset";
const PROFILE: &str = "7f27afe8-a869-4d2c-b582-f8406493609a";

async fn seed_environment(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Projection capture','projection-capture',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(to_value(ProjectSpec::default())?)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
         environment_operation_generation,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'creating','started',$5,$6)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(GENERATION)
    .bind(to_value(ProjectSpec::default())?)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn store_project(db: &TestDatabase, project: &ProjectSpec) -> Result<()> {
    project.validate()?;
    sqlx::query("UPDATE environments SET project_spec=$2 WHERE id=$1")
        .bind(ENVIRONMENT)
        .bind(to_value(project)?)
        .execute(&db.pool)
        .await?;
    Ok(())
}

fn app_project() -> ProjectSpec {
    let mut project = ProjectSpec {
        environment: BTreeMap::from([
            (
                "APP_MODE".to_owned(),
                "synthetic-app-mode-value-never-captured".to_owned(),
            ),
            (
                "DATABASE_URL".to_owned(),
                "synthetic-database-value-never-captured".to_owned(),
            ),
        ]),
        ..Default::default()
    };
    project.secrets.organization = true;
    project
}

fn template_opts(env: &EnvironmentRow) -> Result<TemplateOpts> {
    let cfg = SandboxWorkerCfg {
        credential_runtime: Some(
            crate::sandbox::template::CredentialRuntimeTemplateConfig::synthetic(
                "projection-capture",
            ),
        ),
        ..Default::default()
    };
    environment_template_opts(
        &cfg,
        "ghcr.io/codewiresh/workspace:synthetic",
        "workspace",
        env,
        GENERATION,
    )
}

/// The environment's intent, once [`template_opts`] renders it.
fn template_intent(env: &EnvironmentRow) -> Result<RenderingIntent> {
    template_opts(env)?;
    environment_rendering_intent(
        "ghcr.io/codewiresh/workspace:synthetic",
        "workspace",
        env,
        GENERATION,
    )
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn database_capture_distinguishes_no_sources_from_app_only_metadata() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_environment(&db).await?;

        let empty = load_environment(&db.pool, ENVIRONMENT).await?;
        assert_eq!(empty.source_snapshot_id, None);
        sqlx::query("UPDATE environments SET source_snapshot_id = 'snapshot-one' WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        assert_eq!(
            load_environment(&db.pool, ENVIRONMENT)
                .await?
                .source_snapshot_id
                .as_deref(),
            Some("snapshot-one")
        );
        sqlx::query("UPDATE environments SET source_snapshot_id = NULL WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        ensure!(empty.projection_selection == Ok(None));

        let project = app_project();
        store_project(&db, &project).await?;
        let mut connection = db.pool.acquire().await?;
        let selected = load_environment_in(&mut connection, ENVIRONMENT).await?;
        let selection = selected
            .projection_selection
            .as_ref()
            .map_err(|_| anyhow::anyhow!("app-only selection was rejected"))?
            .as_ref()
            .context("app-only sources did not produce launch metadata")?;
        ensure!(selection.profile.is_none());
        ensure!(selection.organization_selected);
        ensure!(
            selection.ordinary_keys
                == BTreeSet::from(["APP_MODE".to_owned(), "DATABASE_URL".to_owned()])
        );
        let metadata = format!("{selection:?}");
        for value in project.environment.values() {
            ensure!(
                !metadata.contains(value),
                "selection capture included an application value"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn database_capture_pins_binding_revision_and_keeps_cleanup_rows_loadable() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_environment(&db).await?;
        let credential_v1 = uuid::Uuid::new_v4().to_string();
        let credential_v2 = uuid::Uuid::new_v4().to_string();
        for (credential, display_name, provider) in [
            (credential_v1.as_str(), "Synthetic Codex", "openai"),
            (credential_v2.as_str(), "Synthetic GitHub", "github"),
        ] {
            sqlx::query(
                "INSERT INTO platform_credentials \
                 (id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
                 VALUES ($1,$2,$4,'oauth',$3,'active',1,1)",
            )
            .bind(credential)
            .bind(CREATOR)
            .bind(display_name)
            .bind(provider)
            .execute(&db.pool)
            .await?;
        }
        let mut tx = db.pool.begin().await?;
        sqlx::query(
            "INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
             VALUES ($1,$2,'synthetic',1)",
        )
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ($1,1)",
        )
        .bind(PROFILE)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_access_profile_entries \
             (profile_id,revision,capability_slot,credential_id) VALUES ($1,1,'codex',$2)",
        )
        .bind(PROFILE)
        .bind(credential_v1)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,1,$3)",
        )
        .bind(ENVIRONMENT)
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let project = ProjectSpec {
            credentials: Some(CredentialBinding {
                profile: format!("platform:id:{PROFILE}"),
            }),
            ..Default::default()
        };
        store_project(&db, &project).await?;
        let pinned = load_environment(&db.pool, ENVIRONMENT).await?;
        let pinned_selection = pinned
            .projection_selection
            .as_ref()
            .map_err(|_| anyhow::anyhow!("pinned profile selection was rejected"))?
            .clone()
            .context("profile binding produced no selection")?;
        ensure!(pinned_selection.profile == Some((PROFILE.to_owned(), 1)));
        let pinned_digest = pinned_selection.sha256()?;

        let mut tx = db.pool.begin().await?;
        sqlx::query(
            "INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ($1,2)",
        )
        .bind(PROFILE)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_access_profile_entries \
             (profile_id,revision,capability_slot,credential_id) VALUES ($1,2,'ssh',$2)",
        )
        .bind(PROFILE)
        .bind(credential_v2)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE platform_access_profiles SET current_revision=2 WHERE id=$1")
            .bind(PROFILE)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        let after_advance = load_environment(&db.pool, ENVIRONMENT).await?;
        let after_advance = after_advance
            .projection_selection
            .as_ref()
            .map_err(|_| anyhow::anyhow!("pinned profile was invalidated by current revision"))?
            .as_ref()
            .context("pinned profile disappeared after current revision advanced")?;
        ensure!(after_advance.profile == Some((PROFILE.to_owned(), 1)));
        ensure!(after_advance.sha256()? == pinned_digest);

        sqlx::query(
            "DELETE FROM platform_environment_access_bindings WHERE environment_id=$1",
        )
        .bind(ENVIRONMENT)
        .execute(&db.pool)
        .await?;
        let removed_binding = load_environment(&db.pool, ENVIRONMENT).await?;
        ensure!(removed_binding.projection_selection.is_err());

        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,1,$3)",
        )
        .bind(ENVIRONMENT)
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;
        sqlx::query("UPDATE environments SET environment_operation_generation=0 WHERE id=$1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        let generation_zero = load_environment(&db.pool, ENVIRONMENT).await?;
        ensure!(generation_zero.projection_selection.is_err());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn database_capture_selects_github_client_only_while_connected() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_environment(&db).await?;
        let codex = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
             VALUES ($1,$2,'openai','oauth','Synthetic Codex','active',1,1)",
        )
        .bind(&codex)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;
        let mut tx = db.pool.begin().await?;
        sqlx::query(
            "INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
             VALUES ($1,$2,'synthetic',1)",
        )
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ($1,1)",
        )
        .bind(PROFILE)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_access_profile_entries \
             (profile_id,revision,capability_slot,credential_id) VALUES ($1,1,'codex',$2)",
        )
        .bind(PROFILE)
        .bind(&codex)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,1,$3)",
        )
        .bind(ENVIRONMENT)
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        store_project(
            &db,
            &ProjectSpec {
                credentials: Some(CredentialBinding {
                    profile: format!("platform:id:{PROFILE}"),
                }),
                ..Default::default()
            },
        )
        .await?;

        let capture = |label: &'static str| {
            let pool = db.pool.clone();
            async move {
                let row = load_environment(&pool, ENVIRONMENT).await?;
                let selection = row
                    .projection_selection
                    .map_err(|_| anyhow::anyhow!("{label}: selection was rejected"))?
                    .with_context(|| format!("{label}: profile produced no selection"))?;
                let clients = row
                    .managed_credential_clients
                    .map_err(|_| anyhow::anyhow!("{label}: managed clients were rejected"))?
                    .encode();
                anyhow::Ok((selection.sha256()?, selection.reserved_keys, clients))
            }
        };
        let reserved = codewire_project::platform_projection_reserved_keys(["codex", "github"])?;

        // A personal profile without a connection omits the managed GitHub
        // client but still reserves GitHub's names under the bound digest.
        let (missing_digest, missing_reserved, missing_clients) = capture("missing").await?;
        ensure!(missing_clients == "v1:codex", "missing: {missing_clients}");
        ensure!(missing_reserved == reserved);

        let github = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
             VALUES ($1,$2,'github','oauth','Synthetic GitHub','active',1,1)",
        )
        .bind(&github)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;
        let (connected_digest, connected_reserved, connected_clients) =
            capture("connected").await?;
        ensure!(
            connected_clients == "v2:11",
            "connected: {connected_clients}"
        );
        ensure!(connected_reserved == reserved);
        ensure!(connected_digest == missing_digest);

        sqlx::query(
            "UPDATE platform_credentials \
             SET expires_at_unix=floor(extract(epoch FROM clock_timestamp()))::bigint-60 \
             WHERE id=$1",
        )
        .bind(&github)
        .execute(&db.pool)
        .await?;
        let (expired_digest, _, expired_clients) = capture("expired").await?;
        ensure!(expired_clients == "v1:codex", "expired: {expired_clients}");
        ensure!(expired_digest == missing_digest);

        sqlx::query("DELETE FROM platform_credentials WHERE id=$1")
            .bind(&github)
            .execute(&db.pool)
            .await?;
        let (deleted_digest, _, deleted_clients) = capture("deleted").await?;
        ensure!(deleted_clients == "v1:codex", "deleted: {deleted_clients}");
        ensure!(deleted_digest == missing_digest);

        // Without a profile, a selected GitHub repository uses the creator's
        // connection while it is active, and reserves no GitHub names.
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        store_project(
            &db,
            &ProjectSpec {
                repositories: vec![codewire_project::RepositorySpec {
                    source: "https://github.com/synthetic-user/private.git".into(),
                    destination: "/workspace/private".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        )
        .await?;
        let disconnected = load_environment(&db.pool, ENVIRONMENT).await?;
        ensure!(matches!(disconnected.projection_selection, Ok(None)));
        ensure!(disconnected.managed_credential_clients == Ok(Default::default()));
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
             VALUES ($1,$2,'github','oauth','Synthetic GitHub','active',1,1)",
        )
        .bind(&github)
        .bind(CREATOR)
        .execute(&db.pool)
        .await?;
        let (_, account_reserved, account_clients) = capture("account").await?;
        ensure!(account_clients == "v2:10", "account: {account_clients}");
        ensure!(account_reserved == codewire_project::platform_projection_reserved_keys([])?);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn database_capture_selects_the_anthropic_form_of_the_pinned_credential() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_environment(&db).await?;
        let api_key = uuid::Uuid::new_v4().to_string();
        let subscription = uuid::Uuid::new_v4().to_string();
        let sign_in = uuid::Uuid::new_v4().to_string();
        for (credential, kind, name) in [
            (api_key.as_str(), "api_key", "Synthetic Anthropic key"),
            (subscription.as_str(), "oauth", "Synthetic Claude subscription"),
            (sign_in.as_str(), "claude_sign_in", "Synthetic Claude sign-in"),
        ] {
            sqlx::query(
                "INSERT INTO platform_credentials \
                 (id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) \
                 VALUES ($1,$2,'anthropic',$3,$4,'active',1,1)",
            )
            .bind(credential)
            .bind(CREATOR)
            .bind(kind)
            .bind(name)
            .execute(&db.pool)
            .await?;
        }
        let mut tx = db.pool.begin().await?;
        sqlx::query(
            "INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
             VALUES ($1,$2,'synthetic',3)",
        )
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&mut *tx)
        .await?;
        for (revision, credential) in [(1_i64, &api_key), (2, &subscription), (3, &sign_in)] {
            sqlx::query(
                "INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ($1,$2)",
            )
            .bind(PROFILE)
            .bind(revision)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO platform_access_profile_entries \
                 (profile_id,revision,capability_slot,credential_id) VALUES ($1,$2,'anthropic',$3)",
            )
            .bind(PROFILE)
            .bind(revision)
            .bind(credential)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,1,$3)",
        )
        .bind(ENVIRONMENT)
        .bind(PROFILE)
        .bind(CREATOR)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        store_project(
            &db,
            &ProjectSpec {
                credentials: Some(CredentialBinding {
                    profile: format!("platform:id:{PROFILE}"),
                }),
                ..Default::default()
            },
        )
        .await?;

        let capture = |label: &'static str| {
            let pool = db.pool.clone();
            async move {
                let row = load_environment(&pool, ENVIRONMENT).await?;
                let selection = row
                    .projection_selection
                    .clone()
                    .map_err(|_| anyhow::anyhow!("{label}: selection was rejected"))?
                    .with_context(|| format!("{label}: profile produced no selection"))?;
                let clients = row
                    .managed_credential_clients
                    .map_err(|_| anyhow::anyhow!("{label}: managed clients were rejected"))?;
                let environment = template_opts(&row)?
                    .managed_credential_clients
                    .for_placement(
                        codewire_access::ManagedCredentialClientPlacement::Platform,
                    )
                    .environment;
                anyhow::Ok((selection.reserved_keys, clients.encode(), environment))
            }
        };
        let reserved = codewire_project::platform_projection_reserved_keys(["anthropic", "github"])?;

        // The pinned API key keeps the API-key form and its exact projection.
        let (key_reserved, key_clients, key_environment) = capture("api key").await?;
        ensure!(key_clients == "v1:anthropic", "api key: {key_clients}");
        ensure!(key_reserved == reserved);
        ensure!(key_environment.get("ANTHROPIC_AUTH_TOKEN").map(String::as_str) == Some("codewire-managed"));
        // The other form's names are reserved but never rendered.
        for name in ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"] {
            ensure!(!key_environment.contains_key(name), "{name}");
        }

        // The pinned subscription token selects Claude Code's subscription
        // form; the reserved names are unchanged.
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET profile_revision=2 WHERE environment_id=$1",
        )
        .bind(ENVIRONMENT)
        .execute(&db.pool)
        .await?;
        let (token_reserved, token_clients, token_environment) =
            capture("subscription").await?;
        ensure!(token_clients == "v2:24", "subscription: {token_clients}");
        ensure!(token_reserved == reserved);
        ensure!(
            token_environment.get("CLAUDE_CODE_OAUTH_TOKEN").map(String::as_str)
                == Some("codewire-managed")
        );
        for name in ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"] {
            ensure!(!token_environment.contains_key(name), "{name}");
        }
        ensure!(
            token_environment.get("ANTHROPIC_BASE_URL").map(String::as_str)
                == Some("http://127.0.0.1:38081/_codewire/anthropic")
        );

        // A Claude sign-in selects the sign-in form: the base URL alone, so
        // Claude Code reads the login the daemon writes. Every Anthropic name
        // stays reserved.
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET profile_revision=3 WHERE environment_id=$1",
        )
        .bind(ENVIRONMENT)
        .execute(&db.pool)
        .await?;
        let (sign_in_reserved, sign_in_clients, sign_in_environment) =
            capture("sign-in").await?;
        ensure!(sign_in_clients == "v2:44", "sign-in: {sign_in_clients}");
        ensure!(sign_in_reserved == reserved);
        for name in ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"] {
            ensure!(!sign_in_environment.contains_key(name), "{name}");
        }
        ensure!(
            sign_in_environment.get("ANTHROPIC_BASE_URL").map(String::as_str)
                == Some("http://127.0.0.1:38081/_codewire/anthropic")
        );

        // The form follows the pinned revision, never the profile's current
        // one: binding revision 1 again restores the API-key form.
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET profile_revision=1 WHERE environment_id=$1",
        )
        .bind(ENVIRONMENT)
        .execute(&db.pool)
        .await?;
        let (_, restored, _) = capture("pinned api key").await?;
        ensure!(restored == "v1:anthropic", "pinned api key: {restored}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn template_publication_revalidates_capture_before_poll_and_holds_row_lock() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_environment(&db).await?;
        let original_project = app_project();
        store_project(&db, &original_project).await?;
        let captured = load_environment(&db.pool, ENVIRONMENT).await?;
        let opts = template_intent(&captured)?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;

        let mut changed_source = original_project.clone();
        changed_source.secrets.organization = false;
        changed_source.secrets.user = Some(StoragePlacement::Platform);
        store_project(&db, &changed_source).await?;
        let stale_polled = Arc::new(AtomicBool::new(false));
        let observed = stale_polled.clone();
        let stale_result = run_template_mutation(
            &authority,
            &opts,
            &["creating"],
            poll_fn(move |_| {
                observed.store(true, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }),
        )
        .await;
        let error = match stale_result {
            Ok(()) => anyhow::bail!("changed source was published"),
            Err(error) => error,
        };
        ensure!(super::super::activity_authority::is_authority_lost(&error));
        ensure!(
            !stale_polled.load(Ordering::SeqCst),
            "stale source capture polled the publication future"
        );

        store_project(&db, &original_project).await?;
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let current_authority = authority.clone();
        let current_opts = opts.clone();
        let task = tokio::spawn(async move {
            run_template_mutation(
                &current_authority,
                &current_opts,
                &["creating"],
                async move {
                    entered_tx
                        .send(())
                        .map_err(|_| anyhow::anyhow!("publication observer dropped"))?;
                    release_rx
                        .await
                        .map_err(|_| anyhow::anyhow!("publication release dropped"))?;
                    Ok(())
                },
            )
            .await
        });
        tokio::time::timeout(support::TIMEOUT, entered_rx)
            .await
            .context("current publication did not enter mutation future")??;
        let mut competing = db.pool.begin().await?;
        let lock_result = sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(ENVIRONMENT)
            .fetch_one(&mut *competing)
            .await;
        let lock_code = lock_result.err().and_then(|error| {
            error
                .as_database_error()
                .and_then(|error| error.code())
                .map(|code| code.into_owned())
        });
        competing.rollback().await?;
        release_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("current publication ended before release"))?;
        tokio::time::timeout(support::TIMEOUT, task)
            .await
            .context("current publication did not finish")???;
        ensure!(lock_code.as_deref() == Some("55P03"));

        sqlx::query("UPDATE environments SET environment_operation_generation=8 WHERE id=$1")
            .bind(ENVIRONMENT)
            .execute(&db.pool)
            .await?;
        let generation_polled = Arc::new(AtomicBool::new(false));
        let observed = generation_polled.clone();
        let generation_result = run_template_mutation(
            &authority,
            &opts,
            &["creating"],
            poll_fn(move |_| {
                observed.store(true, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }),
        )
        .await;
        let error = match generation_result {
            Ok(()) => anyhow::bail!("lost generation was published"),
            Err(error) => error,
        };
        ensure!(super::super::activity_authority::is_authority_lost(&error));
        ensure!(
            !generation_polled.load(Ordering::SeqCst),
            "lost generation polled the publication future"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
