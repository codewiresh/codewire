//! Revoking a credential asks its provider too (#4717), against a fake
//! provider and synthetic tokens. Codewire's revoke commits first; the
//! provider's answer only changes what the response reports.

use super::*;

use base64::Engine as _;
use reqwest::StatusCode;

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
    let (bundle, _) = codewire_credential_broker::import_codex_tokens(
        zeroize::Zeroizing::new(jwt(json!({
            "email": "developer@example.test",
            "https://api.openai.com/auth": { "chatgpt_account_id": "synthetic-account" }
        }))),
        zeroize::Zeroizing::new(jwt(json!({ "exp": 4_000_000_000_u64 }))),
        zeroize::Zeroizing::new(REFRESH_TOKEN.to_owned()),
    )?
    .into_parts();
    existing(h, "openai", CredentialAuthKind::OAuth, bundle.as_bytes()).await
}

async fn existing(
    h: &Harness,
    provider: &str,
    kind: CredentialAuthKind,
    material: &[u8],
) -> Result<CredentialRecord> {
    Ok(h.store
        .create(
            &Owner::User(OwnerId::parse(ALICE)?),
            CredentialRegistration {
                provider: ProviderId::parse(provider)?,
                authentication_kind: kind,
                display_name: format!("{provider}-revocation"),
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
