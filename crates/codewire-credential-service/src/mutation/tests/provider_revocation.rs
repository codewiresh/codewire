//! Revoking a credential asks its provider too (#4717), against a fake
//! provider and synthetic tokens. Codewire's revoke commits first; the
//! provider's answer only changes what the response reports.

use super::*;

use std::time::Duration;

use base64::Engine as _;
use codewire_access::CredentialStatus;
use codewire_platform_credentials::{PlatformCredentialError, RevocationFence};
use reqwest::StatusCode;
use uuid::Uuid;

const REFRESH_TOKEN: &str = "synthetic-codex-refresh-token";

fn jwt(payload: Value) -> String {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.synthetic-signature",
        encode(br#"{"alg":"none"}"#),
        encode(&serde_json::to_vec(&payload).unwrap())
    )
}

/// An active Codex sign-in with a real stored bundle.
async fn codex(h: &Harness) -> Result<CredentialRecord> {
    codex_named(h, "openai-revocation").await
}

async fn codex_named(h: &Harness, name: &str) -> Result<CredentialRecord> {
    let (bundle, _) = codewire_credential_broker::import_codex_tokens(
        zeroize::Zeroizing::new(jwt(json!({
            "email": "developer@example.test",
            "https://api.openai.com/auth": { "chatgpt_account_id": "synthetic-account" }
        }))),
        zeroize::Zeroizing::new(jwt(json!({ "exp": 4_000_000_000_u64 }))),
        zeroize::Zeroizing::new(REFRESH_TOKEN.to_owned()),
    )?
    .into_parts();
    existing_named(
        h,
        "openai",
        CredentialAuthKind::OAuth,
        bundle.as_bytes(),
        name,
    )
    .await
}

async fn existing(
    h: &Harness,
    provider: &str,
    kind: CredentialAuthKind,
    material: &[u8],
) -> Result<CredentialRecord> {
    existing_named(
        h,
        provider,
        kind,
        material,
        &format!("{provider}-revocation"),
    )
    .await
}

async fn existing_named(
    h: &Harness,
    provider: &str,
    kind: CredentialAuthKind,
    material: &[u8],
    name: &str,
) -> Result<CredentialRecord> {
    Ok(h.store
        .create(
            &Owner::User(OwnerId::parse(ALICE)?),
            CredentialRegistration {
                provider: ProviderId::parse(provider)?,
                authentication_kind: kind,
                display_name: name.to_owned(),
                account_hint: None,
                expires_at_unix: Some(4_000_000_000),
            },
            &ProtectedValue::from_slice(material)?,
        )
        .await?)
}

async fn revoke(
    h: &Harness,
    record: &CredentialRecord,
    revision: u64,
) -> Result<(StatusCode, Value)> {
    h.rpc
        .lifecycle(
            "RevokeCredential",
            Auth::Alice,
            record.metadata.id.as_str(),
            revision,
        )
        .await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn revoking_codex_asks_openai_after_codewire_revokes_it() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        provider.observe(h.db.pool.clone(), record.metadata.id.as_str());
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(value["credential"]["status"] == "CREDENTIAL_STATUS_REVOKED");
        // OpenAI was asked only once Codewire's revoke had committed.
        ensure!(provider.seen() == ["revoked"], "seen {:?}", provider.seen());
        ensure!(
            value["providerRevocation"]["outcome"] == "PROVIDER_REVOCATION_OUTCOME_CONFIRMED",
            "{value}"
        );
        ensure!(material_count(&h.db.pool, record.metadata.id.as_str()).await? == 0);
        let sent = provider.sent();
        ensure!(sent.len() == 1, "one request: {}", sent.len());
        ensure!(sent[0].0 == http::Method::POST);
        ensure!(sent[0].1 == "https://auth.openai.com/api/accounts/oauth/revoke");
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&sent[0].2)
            .into_owned()
            .collect();
        ensure!(form.contains(&("token".to_owned(), REFRESH_TOKEN.to_owned())));
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_provider_that_refuses_leaves_the_credential_revoked() -> Result<()> {
    let (h, provider) =
        Harness::with_provider_revocation(http::StatusCode::SERVICE_UNAVAILABLE).await?;
    let result = async {
        let record = codex(&h).await?;
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(value["credential"]["status"] == "CREDENTIAL_STATUS_REVOKED");
        let reported = &value["providerRevocation"];
        ensure!(
            reported["outcome"] == "PROVIDER_REVOCATION_OUTCOME_FAILED",
            "{value}"
        );
        ensure!(
            reported["failure"] == "PROVIDER_REVOCATION_FAILURE_UNAVAILABLE",
            "{value}"
        );
        ensure!(material_count(&h.db.pool, record.metadata.id.as_str()).await? == 0);
        ensure!(provider.sent().len() == 1, "asked once, never retried");
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn codewire_failing_to_revoke_asks_the_provider_nothing() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        // A stale revision: Codewire refuses the revoke.
        h.rpc
            .lifecycle_error(
                "RevokeCredential",
                Auth::Alice,
                record.metadata.id.as_str(),
                2,
                "failed_precondition",
            )
            .await?;
        ensure!(provider.sent().is_empty(), "the provider was asked");
        ensure!(material_count(&h.db.pool, record.metadata.id.as_str()).await? == 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_provider_without_revocation_is_reported_as_not_available() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = existing(
            &h,
            "anthropic",
            CredentialAuthKind::ApiKey,
            b"synthetic-anthropic-api-key",
        )
        .await?;
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(
            value["providerRevocation"]["outcome"] == "PROVIDER_REVOCATION_OUTCOME_NOT_AVAILABLE",
            "{value}"
        );
        ensure!(provider.sent().is_empty());
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_repeated_revoke_asks_nothing_and_reports_nothing() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        revoke(&h, &record, 1).await?;
        let (status, value) = revoke(&h, &record, 2).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(value.get("providerRevocation").is_none(), "{value}");
        ensure!(provider.sent().len() == 1, "only the first revoke asked");
        Ok(())
    }
    .await;
    h.finish(result).await
}

const GITHUB_ACCESS_TOKEN: &str = "ghu_synthetic_revocation_access_token";

/// A stored GitHub App connection whose access token expires at `expires`.
fn app_bundle(expires: u64) -> Vec<u8> {
    let mut bundle = b"codewire-github-app-user-v1:".to_vec();
    bundle.extend(
        serde_json::to_vec(&json!({
            "version": 1,
            "access_token": GITHUB_ACCESS_TOKEN,
            "access_expires_at_unix": expires,
            "refresh_token": "ghr_synthetic_revocation_refresh_token",
            "refresh_expires_at_unix": expires + 15_897_600,
            "user_id": 7,
            "app_slug": "codewire-synthetic",
            "installation_id": 9,
        }))
        .unwrap(),
    );
    bundle
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_github_app_connection_is_revoked_at_github_with_the_apps_secret() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::NO_CONTENT).await?;
    let result = async {
        let record = existing(
            &h,
            "github",
            CredentialAuthKind::OAuth,
            &app_bundle(4_000_000_000),
        )
        .await?;
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(
            value["providerRevocation"]["outcome"] == "PROVIDER_REVOCATION_OUTCOME_CONFIRMED",
            "{value}"
        );
        let sent = provider.sent();
        ensure!(sent.len() == 1, "one request: {}", sent.len());
        ensure!(sent[0].0 == http::Method::DELETE);
        ensure!(
            sent[0].1 == format!("https://api.github.com/applications/{GITHUB_APP_CLIENT}/token")
        );
        ensure!(
            serde_json::from_slice::<Value>(&sent[0].2)?
                == json!({ "access_token": GITHUB_ACCESS_TOKEN })
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn an_expired_github_sign_in_is_reported_without_asking_github() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::NO_CONTENT).await?;
    let result = async {
        let record = existing(
            &h,
            "github",
            CredentialAuthKind::OAuth,
            &app_bundle(1_700_000_000),
        )
        .await?;
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        let reported = &value["providerRevocation"];
        ensure!(
            reported["outcome"] == "PROVIDER_REVOCATION_OUTCOME_FAILED",
            "{value}"
        );
        ensure!(
            reported["failure"] == "PROVIDER_REVOCATION_FAILURE_EXPIRED",
            "{value}"
        );
        ensure!(provider.sent().is_empty(), "GitHub was asked");
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_raw_github_token_is_reported_as_not_available() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::NO_CONTENT).await?;
    let result = async {
        let record = existing(
            &h,
            "github",
            CredentialAuthKind::OAuth,
            b"gho_synthetic_raw_cli_token",
        )
        .await?;
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(
            value["providerRevocation"]["outcome"] == "PROVIDER_REVOCATION_OUTCOME_NOT_AVAILABLE",
            "{value}"
        );
        ensure!(provider.sent().is_empty());
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_token_codewire_cannot_read_is_reported_and_the_provider_is_not_asked() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        h.provider.fail_unwrap.store(true, Ordering::SeqCst);
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(value["credential"]["status"] == "CREDENTIAL_STATUS_REVOKED");
        let reported = &value["providerRevocation"];
        ensure!(
            reported["outcome"] == "PROVIDER_REVOCATION_OUTCOME_FAILED",
            "{value}"
        );
        ensure!(
            reported["failure"] == "PROVIDER_REVOCATION_FAILURE_NOT_READ",
            "{value}"
        );
        ensure!(provider.sent().is_empty(), "OpenAI was asked");
        Ok(())
    }
    .await;
    h.finish(result).await
}

fn alice() -> Result<Owner> {
    Ok(Owner::User(OwnerId::parse(ALICE)?))
}

async fn attempt_state(h: &Harness, record: &CredentialRecord) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT state FROM platform_credential_refresh_attempts WHERE credential_id=$1",
    )
    .bind(record.metadata.id.as_str())
    .fetch_optional(&h.db.pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_refresh_already_started_is_not_asked_about_and_reports_not_read() -> Result<()> {
    // The started exchange may have rotated the stored token: OpenAI would
    // answer 200 about a token it no longer knows (#4717).
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        let prepared = h
            .store
            .begin_oauth_refresh(
                &alice()?,
                &record.metadata.id,
                record.version,
                Uuid::new_v4(),
            )
            .await?;
        let _started = h.store.start_oauth_refresh(prepared).await?;
        let (status, value) = revoke(&h, &record, 1).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(value["credential"]["status"] == "CREDENTIAL_STATUS_REVOKED");
        let reported = &value["providerRevocation"];
        ensure!(
            reported["outcome"] == "PROVIDER_REVOCATION_OUTCOME_FAILED",
            "{value}"
        );
        ensure!(
            reported["failure"] == "PROVIDER_REVOCATION_FAILURE_NOT_READ",
            "{value}"
        );
        ensure!(provider.sent().is_empty(), "OpenAI was asked");
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_fence_replaces_an_unstarted_reservation_and_holds_off_new_refreshes() -> Result<()> {
    let (h, _provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let owner = alice()?;
        let record = codex(&h).await?;
        let id = &record.metadata.id;
        let reserved = h
            .store
            .begin_oauth_refresh(&owner, id, record.version, Uuid::new_v4())
            .await?;
        let RevocationFence::Fenced { attempt_id } = h
            .store
            .fence_oauth_refresh_for_revocation(&owner, id, record.version)
            .await?
        else {
            anyhow::bail!("an unstarted reservation was not fenced");
        };
        // The replaced refresher sent nothing and now cannot start.
        ensure!(matches!(
            h.store.start_oauth_refresh(reserved).await,
            Err(PlatformCredentialError::StaleRefresh)
        ));
        ensure!(matches!(
            h.store
                .begin_oauth_refresh(&owner, id, record.version, Uuid::new_v4())
                .await,
            Err(PlatformCredentialError::RefreshInProgress)
        ));
        h.store
            .cancel_oauth_refresh(&owner, id, record.version, attempt_id)
            .await?;
        h.store
            .begin_oauth_refresh(&owner, id, record.version, Uuid::new_v4())
            .await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_revoke_that_does_not_commit_releases_its_fence() -> Result<()> {
    // A bound shorter than the revoke: it fences, then cannot publish.
    let (h, provider) =
        Harness::with_provider_revocation_bounded(http::StatusCode::OK, Duration::from_millis(1))
            .await?;
    let result = async {
        let record = codex(&h).await?;
        let _ = revoke(&h, &record, 1).await?;
        let mut state = attempt_state(&h, &record).await?;
        for _ in 0..100 {
            if state.as_deref() == Some("cancelled") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            state = attempt_state(&h, &record).await?;
        }
        ensure!(
            state.as_deref() == Some("cancelled"),
            "fence left {state:?}"
        );
        ensure!(
            h.store
                .record(&alice()?, &record.metadata.id)
                .await?
                .metadata
                .status
                == CredentialStatus::Active
        );
        ensure!(provider.sent().is_empty(), "the provider was asked");
        // A refresh can begin at once.
        h.store
            .begin_oauth_refresh(
                &alice()?,
                &record.metadata.id,
                record.version,
                Uuid::new_v4(),
            )
            .await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_codex_sign_in_that_is_not_stored_is_revoked_at_openai() -> Result<()> {
    // #4904: OpenAI approved it, so it must not stay live unstored.
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let mut first = h.rpc.enroll(Auth::Alice, "work").await?;
        first.challenge().await?;
        h.release()?;
        first.committed().await?;
        h.drained().await?;
        ensure!(provider.sent().is_empty(), "a stored sign-in was revoked");
        h.reset_login().await?;
        // The name is taken: the second sign-in is approved, then not stored.
        let mut second = h.rpc.enroll(Auth::Alice, "WORK").await?;
        second.challenge().await?;
        h.release()?;
        second.error("already_exists").await?;
        h.drained().await?;
        let sent = provider.sent();
        ensure!(sent.len() == 1, "one request: {}", sent.len());
        ensure!(sent[0].1 == "https://auth.openai.com/api/accounts/oauth/revoke");
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&sent[0].2)
            .into_owned()
            .collect();
        let unstored = format!("{REFRESH}-");
        ensure!(
            form.iter()
                .any(|(key, value)| key == "token" && value.starts_with(&unstored)),
            "the unstored sign-in's refresh token was not the one revoked"
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

/// A journal attempt in `state`, written as a refresher's transitions leave
/// it. `live` says whether a reservation is still within its 60 s.
async fn journal(h: &Harness, record: &CredentialRecord, state: &str, live: bool) -> Result<Uuid> {
    let attempt = Uuid::new_v4();
    let started = !matches!(state, "reserved" | "cancelled");
    sqlx::query(
        "INSERT INTO platform_credential_refresh_attempts \
         (credential_id,attempt_id,expected_revocation_generation,expected_material_generation,\
          state,reserved_until,started_at,started_until) \
         VALUES ($1,$2,$3,$4,$5,\
          clock_timestamp() + CASE WHEN $6 THEN interval '60 seconds' ELSE interval '-1 second' END,\
          CASE WHEN $7 THEN clock_timestamp() END,\
          CASE WHEN $7 THEN clock_timestamp() + interval '90 seconds' END)",
    )
    .bind(record.metadata.id.as_str())
    .bind(attempt)
    .bind(i64::try_from(record.version.revocation_generation)?)
    .bind(i64::try_from(record.version.material_generation)?)
    .bind(state)
    .bind(live)
    .bind(started)
    .execute(&h.db.pool)
    .await?;
    Ok(attempt)
}

async fn journal_row(
    h: &Harness,
    record: &CredentialRecord,
) -> Result<Option<(Uuid, String, bool)>> {
    Ok(sqlx::query_as(
        "SELECT attempt_id, state, reserved_until > clock_timestamp() \
         FROM platform_credential_refresh_attempts WHERE credential_id=$1",
    )
    .bind(record.metadata.id.as_str())
    .fetch_optional(&h.db.pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn the_fence_replaces_only_attempts_that_sent_nothing() -> Result<()> {
    // A started, staged or unknown exchange may have rotated the token, so it
    // is left alone; every other state has sent nothing (cw-network).
    let h = Harness::new().await?;
    let result = async {
        let owner = alice()?;
        for (state, live, fenced) in [
            (None, false, true),
            (Some("committed"), false, true),
            (Some("cancelled"), false, true),
            (Some("reserved"), false, true),
            (Some("reserved"), true, true),
            (Some("started"), false, false),
            (Some("staged"), false, false),
            (Some("unknown"), false, false),
        ] {
            let case = format!("{}-{live}", state.unwrap_or("none"));
            let record = codex_named(&h, &format!("fence-{case}")).await?;
            let before = match state {
                Some(state) => Some(journal(&h, &record, state, live).await?),
                None => None,
            };
            let answer = h
                .store
                .fence_oauth_refresh_for_revocation(&owner, &record.metadata.id, record.version)
                .await?;
            let row = journal_row(&h, &record).await?;
            match answer {
                RevocationFence::Fenced { attempt_id } => {
                    ensure!(
                        fenced,
                        "{case}: an exchange that may have rotated was fenced"
                    );
                    ensure!(
                        row == Some((attempt_id, "reserved".to_owned(), true)),
                        "{case}: the fence row is {row:?}"
                    );
                    ensure!(
                        Some(attempt_id) != before,
                        "{case}: the fence reused an attempt"
                    );
                }
                RevocationFence::RotationPossible => {
                    ensure!(
                        !fenced,
                        "{case}: an attempt that sent nothing was not fenced"
                    );
                    ensure!(
                        row.as_ref().map(|(id, state, _)| (*id, state.as_str()))
                            == before.map(|id| (id, state.unwrap_or_default())),
                        "{case}: the attempt was changed to {row:?}"
                    );
                }
            }
        }
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_fence_replaced_before_the_commit_reports_not_read() -> Result<()> {
    // cw-review: a revoke slower than its fence's 60 s lets a refresh begin
    // and start; the commit finds the fence gone and asks nobody.
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let owner = alice()?;
        let record = codex(&h).await?;
        h.provider.unwrap_gate.arm();
        let replace = async {
            // The revoke has fenced and is reading the token.
            h.provider.unwrap_gate.wait().await?;
            sqlx::query(
                "UPDATE platform_credential_refresh_attempts \
                 SET reserved_until = clock_timestamp() - interval '1 second' WHERE credential_id=$1",
            )
            .bind(record.metadata.id.as_str())
            .execute(&h.db.pool)
            .await?;
            let prepared = h
                .store
                .begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::new_v4())
                .await?;
            let started = h.store.start_oauth_refresh(prepared).await?;
            h.provider.unwrap_gate.release();
            anyhow::Ok(started)
        };
        let (revoked, started) = tokio::join!(revoke(&h, &record, 1), replace);
        let _started = started?;
        let (status, value) = revoked?;
        ensure!(status.is_success(), "{value}");
        ensure!(value["credential"]["status"] == "CREDENTIAL_STATUS_REVOKED");
        ensure!(
            value["providerRevocation"]["failure"] == "PROVIDER_REVOCATION_FAILURE_NOT_READ",
            "{value}"
        );
        ensure!(provider.sent().is_empty(), "OpenAI was asked");
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn an_unstored_github_app_sign_in_is_revoked_with_the_apps_secret() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::NO_CONTENT).await?;
    let result = async {
        let transports = h
            .owner
            .shared
            .revocation
            .clone()
            .context("revocation transports")?;
        crate::mutation::provider_revocation::ask_unstored(
            &transports,
            h.owner.shared.github_app_authorization.as_deref(),
            "github",
            &ProtectedValue::from_slice(&app_bundle(4_000_000_000))?,
        )
        .await;
        let sent = provider.sent();
        ensure!(sent.len() == 1, "one request: {}", sent.len());
        ensure!(sent[0].0 == http::Method::DELETE);
        ensure!(
            sent[0].1 == format!("https://api.github.com/applications/{GITHUB_APP_CLIENT}/token")
        );
        ensure!(
            serde_json::from_slice::<Value>(&sent[0].2)?
                == json!({ "access_token": GITHUB_ACCESS_TOKEN })
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_reconnect_that_cannot_publish_revokes_only_its_new_sign_in() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let mut first = h.rpc.enroll(Auth::Alice, "work").await?;
        first.challenge().await?;
        h.release()?;
        let stored = first.committed().await?;
        h.drained().await?;
        let id = stored["id"].as_str().context("stored id")?.to_owned();
        h.reset_login().await?;
        let mut reconnect = h
            .rpc
            .enroll_request(
                Auth::Alice,
                json!({"name": "work", "credentialId": id, "expectedRevocationGeneration": "1"}),
            )
            .await?;
        reconnect.challenge().await?;
        // The credential changes while the person approves: the reconnect
        // can no longer publish at the revision it named.
        sqlx::query("UPDATE platform_credentials SET revocation_generation = 2 WHERE id=$1")
            .bind(&id)
            .execute(&h.db.pool)
            .await?;
        h.release()?;
        reconnect.error("failed_precondition").await?;
        h.drained().await?;
        let sent = provider.sent();
        ensure!(sent.len() == 1, "one request: {}", sent.len());
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&sent[0].2)
            .into_owned()
            .collect();
        let unstored = format!("{REFRESH}-");
        ensure!(
            form.iter()
                .any(|(key, value)| key == "token" && value.starts_with(&unstored)),
            "the new sign-in's refresh token was not the one revoked"
        );
        // The stored sign-in is untouched in Codewire.
        ensure!(material_count(&h.db.pool, &id).await? == 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[test]
fn only_a_publication_that_did_not_happen_revokes_its_sign_in() {
    use crate::mutation::enrollment::Outcome;
    use crate::mutation::publication::revokes_unstored;
    assert!(revokes_unstored(Outcome::NotPublished));
    assert!(!revokes_unstored(Outcome::Published));
    assert!(
        !revokes_unstored(Outcome::Unknown),
        "an unknown outcome may have stored it"
    );
}

/// A revoke-first delete (#6211): the same worker and fence as a revoke,
/// with the in-use check, the revoke and the delete in one transaction.
async fn delete_revoking(h: &Harness, record: &CredentialRecord) -> Result<(StatusCode, Value)> {
    h.rpc
        .delete_revoking(
            Auth::Alice,
            record.metadata.id.as_str(),
            record.metadata.revocation_generation,
        )
        .await
}

/// Nothing about a refused delete changed: the credential is active at its
/// revision with its material, the provider wasn't asked, and the fence the
/// delete took no longer holds refreshes off.
async fn unchanged(
    h: &Harness,
    provider: &RevocationProvider,
    record: &CredentialRecord,
) -> Result<()> {
    let current = h.store.record(&alice()?, &record.metadata.id).await?;
    ensure!(current.metadata.status == CredentialStatus::Active);
    ensure!(current.version == record.version, "{:?}", current.version);
    ensure!(material_count(&h.db.pool, record.metadata.id.as_str()).await? == 1);
    ensure!(provider.sent().is_empty(), "the provider was asked");
    let mut state = attempt_state(h, record).await?;
    for _ in 0..100 {
        if state.as_deref() == Some("cancelled") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        state = attempt_state(h, record).await?;
    }
    ensure!(
        state.as_deref() == Some("cancelled"),
        "fence left {state:?}"
    );
    Ok(())
}

fn refused_in_use(status: StatusCode, value: &Value) -> Result<()> {
    ensure!(
        !status.is_success() && value["code"] == "failed_precondition",
        "{value}"
    );
    ensure!(
        value["message"] == "credential is referenced by a profile or binding",
        "{value}"
    );
    let detail = value["details"][0]["value"].as_str().unwrap_or_default();
    let info = base64::engine::general_purpose::STANDARD_NO_PAD.decode(detail)?;
    ensure!(
        info.windows(17)
            .any(|reason| reason == b"CREDENTIAL_IN_USE"),
        "no closed reason: {value}"
    );
    Ok(())
}

/// Alice's default profile, then "daily" selecting `credential` as codex.
async fn daily(
    h: &Harness,
    credential: &CredentialRecord,
) -> Result<(PlatformAccessProfileStore, codewire_access::AccessProfile)> {
    let manager = PlatformAccessProfileStore::new(h.db.pool.clone(), builtin_provider_catalog());
    let owner = alice()?;
    manager
        .create(
            &owner,
            AccessProfileName::parse("default")?,
            BTreeMap::new(),
        )
        .await?;
    let profile = manager
        .create(
            &owner,
            AccessProfileName::parse("daily")?,
            BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
        )
        .await?;
    Ok((manager, profile))
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_revoke_first_delete_revokes_deletes_and_then_asks_the_provider() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        provider.observe(h.db.pool.clone(), record.metadata.id.as_str());
        let (status, value) = delete_revoking(&h, &record).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(
            value
                == json!({"providerRevocation": {"outcome": "PROVIDER_REVOCATION_OUTCOME_CONFIRMED"}}),
            "{value}"
        );
        // OpenAI was asked only once the delete had committed.
        ensure!(provider.seen() == ["deleted"], "seen {:?}", provider.seen());
        ensure!(h.count().await? == 0);
        let sent = provider.sent();
        ensure!(sent.len() == 1, "one request: {}", sent.len());
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&sent[0].2)
            .into_owned()
            .collect();
        ensure!(form.contains(&("token".to_owned(), REFRESH_TOKEN.to_owned())));
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_revoke_first_delete_a_profile_selects_is_refused_and_asks_nothing() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        daily(&h, &record).await?;
        let (status, value) = delete_revoking(&h, &record).await?;
        refused_in_use(status, &value)?;
        unchanged(&h, &provider, &record).await
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_revoke_first_delete_a_sandbox_holds_on_an_earlier_revision_is_refused() -> Result<()> {
    // #6211: after `unset`, a Sandbox bound to the earlier revision still
    // uses the credential; the delete changes nothing, revoke included.
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let record = codex(&h).await?;
        let (manager, profile) = daily(&h, &record).await?;
        let environment = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
            VALUES ('synthetic-preset','mutation-org','Synthetic','synthetic','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
            .execute(&h.db.pool).await?;
        sqlx::query("INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
            VALUES ($1,'mutation-org',$2,'sandbox','synthetic-preset','running','started',7,'{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
            .bind(&environment).bind(ALICE).execute(&h.db.pool).await?;
        let context = codewire_access::GrantContext {
            environment_id: codewire_access::EnvironmentId::parse(&environment)?,
            environment_generation: 7,
            placement: codewire_access::GrantPlacement::Platform,
            user_id: OwnerId::parse(ALICE)?,
            organization_id: Some(OwnerId::parse("mutation-org")?),
            allow_personal_credentials: true,
            authorized_credentials: [record.metadata.id.clone()].into_iter().collect(),
        };
        let binding = codewire_access::EnvironmentAccessBinding {
            environment_id: context.environment_id.clone(),
            profile_id: profile.id.clone(),
            profile_revision: profile.revision,
        };
        manager
            .create_binding(&context, binding.clone(), Some(&context.user_id))
            .await?;
        // `unset`: the profile as it is now no longer selects it.
        manager
            .update(&alice()?, &profile.id, profile.revision, BTreeMap::new())
            .await?;
        let (status, value) = delete_revoking(&h, &record).await?;
        refused_in_use(status, &value)?;
        unchanged(&h, &provider, &record).await?;
        // Once the Sandbox lets go, the same delete goes through.
        manager.delete_binding(&context, &binding).await?;
        let (status, value) = delete_revoking(&h, &record).await?;
        ensure!(status.is_success(), "{value}");
        ensure!(provider.sent().len() == 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_revoke_first_delete_racing_a_refresh_deletes_and_asks_nobody() -> Result<()> {
    // The fence lapses and a refresh starts before the delete commits: the
    // token read may no longer be the live one, so nobody is asked.
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::OK).await?;
    let result = async {
        let owner = alice()?;
        let record = codex(&h).await?;
        h.provider.unwrap_gate.arm();
        let replace = async {
            h.provider.unwrap_gate.wait().await?;
            sqlx::query(
                "UPDATE platform_credential_refresh_attempts \
                 SET reserved_until = clock_timestamp() - interval '1 second' WHERE credential_id=$1",
            )
            .bind(record.metadata.id.as_str())
            .execute(&h.db.pool)
            .await?;
            let prepared = h
                .store
                .begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::new_v4())
                .await?;
            let started = h.store.start_oauth_refresh(prepared).await?;
            h.provider.unwrap_gate.release();
            anyhow::Ok(started)
        };
        let (deleted, started) = tokio::join!(delete_revoking(&h, &record), replace);
        let _started = started?;
        let (status, value) = deleted?;
        ensure!(status.is_success(), "{value}");
        ensure!(
            value["providerRevocation"]["failure"] == "PROVIDER_REVOCATION_FAILURE_NOT_READ",
            "{value}"
        );
        ensure!(h.count().await? == 0);
        ensure!(provider.sent().is_empty(), "OpenAI was asked");
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn a_revoke_first_delete_reports_a_refusal_without_the_providers_text() -> Result<()> {
    let (h, provider) = Harness::with_provider_revocation(http::StatusCode::FORBIDDEN).await?;
    let result = async {
        provider.answer_body(b"{\"error\":\"synthetic-provider-detail\"}");
        let record = codex(&h).await?;
        let (status, value) = delete_revoking(&h, &record).await?;
        ensure!(status.is_success(), "{value}");
        // The closed outcome and the HTTP status, and nothing else.
        ensure!(
            value
                == json!({"providerRevocation": {
                    "outcome": "PROVIDER_REVOCATION_OUTCOME_FAILED",
                    "failure": "PROVIDER_REVOCATION_FAILURE_REFUSED",
                    "httpStatus": 403,
                }}),
            "{value}"
        );
        ensure!(!value.to_string().contains("synthetic-provider-detail"));
        ensure!(h.count().await? == 0);
        Ok(())
    }
    .await;
    h.finish(result).await
}
