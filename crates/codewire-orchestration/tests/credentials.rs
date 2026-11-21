//! Personal metadata API over its actual restricted login and generated listener.

#[path = "credentials_support/mod.rs"]
mod support;

use anyhow::{Context, Result, ensure};
use codewire_access::{Owner, OwnerId, builtin_provider_catalog};
use codewire_platform_credentials::{CredentialMetadataReader, PlatformCredentialError};
use serde_json::json;
use support::*;

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_credentials_preserve_personal_selectors_pagination_auth_and_exact_metadata()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        for method in ["ListCredentials", "GetCredential"] {
            for auth in [Auth::Missing, Auth::Expired] {
                h.error(method, auth, json!({}), "unauthenticated").await?;
            }
            for auth in [Auth::ApiKey, Auth::WrongScope] {
                h.error(method, auth, json!({}), "permission_denied")
                    .await?;
            }
        }
        let alice = h
            .ok(
                "GetCredential",
                Auth::Alice,
                json!({"credentialId":ALICE_CREDENTIAL}),
            )
            .await?;
        ensure!(alice["credential"]["name"] == "Work Codex");
        ensure!(alice["credential"]["provider"] == "openai");
        ensure!(
            alice["credential"]["authenticationKind"] == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH"
        );
        ensure!(alice["credential"]["revocationGeneration"] == "9007199254740993");
        ensure!(alice["credential"].get("accountHint").is_none());
        ensure!(alice["credential"].get("expiresAtUnix").is_none());
        let named = h
            .ok("GetCredential", Auth::Cookie, json!({"name":"wOrK cOdEx"}))
            .await?;
        ensure!(named == alice);
        let bob = h
            .ok("GetCredential", Auth::Bob, json!({"name":"WORK CODEX"}))
            .await?;
        ensure!(bob["credential"]["id"] == BOB_CREDENTIAL);
        for id in [BOB_CREDENTIAL, ORG_CREDENTIAL] {
            h.error(
                "GetCredential",
                Auth::Alice,
                json!({"credentialId":id}),
                "not_found",
            )
            .await?;
        }
        h.error(
            "GetCredential",
            Auth::Bob,
            json!({"credentialId":ALICE_CREDENTIAL}),
            "not_found",
        )
        .await?;
        for selector in [
            json!({}),
            json!({"credentialId":"invalid id"}),
            json!({"name":""}),
            json!({"name":" Work Codex"}),
            json!({"name":"Work\nCodex"}),
            json!({"name":"x".repeat(257)}),
        ] {
            h.error("GetCredential", Auth::Alice, selector, "invalid_argument")
                .await?;
        }
        for name in ["Work", "%", "Work Code_"] {
            h.error(
                "GetCredential",
                Auth::Alice,
                json!({"name":name}),
                "not_found",
            )
            .await?;
        }
        let mut cursor = String::new();
        let mut credentials = Vec::new();
        for page_index in 0..4 {
            let page = h
                .ok(
                    "ListCredentials",
                    Auth::Alice,
                    json!({"pageSize":1,"pageToken":cursor}),
                )
                .await?;
            let records = page["credentials"]
                .as_array()
                .context("missing metadata page")?;
            ensure!(records.len() == 1);
            credentials.push(records[0].clone());
            cursor = page["nextPageToken"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            ensure!(cursor.is_empty() == (page_index == 3));
        }
        let ids: Vec<_> = credentials
            .iter()
            .map(|value| value["id"].as_str().unwrap())
            .collect();
        ensure!(
            ids == vec![
                ALICE_CREDENTIAL,
                "credential-c",
                "credential-d",
                "credential-e"
            ]
        );
        ensure!(credentials[1]["accountHint"] == "Synthetic account");
        ensure!(credentials[1]["expiresAtUnix"] == i64::MAX.to_string());
        ensure!(credentials[1]["authenticationKind"] == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY");
        for (record, expected) in credentials.iter().zip([
            "CREDENTIAL_STATUS_ACTIVE",
            "CREDENTIAL_STATUS_REVOKED",
            "CREDENTIAL_STATUS_EXPIRED",
            "CREDENTIAL_STATUS_REFRESH_FAILED",
        ]) {
            ensure!(record["status"] == expected);
            for absent in [
                "owner",
                "organizationId",
                "userId",
                "materialGeneration",
                "wrappedDek",
                "ciphertext",
                "keyName",
            ] {
                ensure!(record.get(absent).is_none());
            }
        }
        let default = h.ok("ListCredentials", Auth::Alice, json!({})).await?;
        ensure!(default["credentials"].as_array().unwrap() == &credentials);
        for body in [
            json!({"pageSize":-1}),
            json!({"pageSize":101}),
            json!({"pageToken":"invalid cursor"}),
        ] {
            h.error("ListCredentials", Auth::Alice, body, "invalid_argument")
                .await?;
        }
        let empty = h
            .ok(
                "ListCredentials",
                Auth::Alice,
                json!({"pageSize":100,"pageToken":"zzzz"}),
            )
            .await?;
        ensure!(
            empty["credentials"]
                .as_array()
                .is_none_or(|values| values.is_empty())
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_credentials_restricted_login_has_no_material_lifecycle_or_helper_authority()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let identity: (String,String) = sqlx::query_as("SELECT current_user::text,session_user::text").fetch_one(&h.reader).await?;
        ensure!(identity == (h.role.clone(), h.role.clone()));
        let admin: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&h.db).await?;
        denied(&h.reader, &format!("SET ROLE \"{}\"", admin.replace('"',"\"\""))).await?;
        sqlx::query("RESET ROLE").execute(&h.reader).await?;
        for sql in [
            "SELECT * FROM platform_credential_material LIMIT 0",
            "SELECT * FROM platform_credential_refresh_attempts LIMIT 0",
            "SELECT * FROM tenant_secrets LIMIT 0",
            "SELECT * FROM platform_credential_refresh_material LIMIT 0",
            "SELECT * FROM tenant_secret_deks LIMIT 0",
            "SELECT * FROM oidc_refresh_tokens LIMIT 0",
            "SELECT * FROM jwks LIMIT 0",
            "SELECT secret FROM oidc_clients LIMIT 0",
            "UPDATE platform_credentials SET display_name='forbidden' WHERE false",
            "DELETE FROM platform_credentials WHERE false",
            "SELECT id FROM platform_credentials FOR SHARE",
            "SELECT public.codewire_platform_lock_owner('user','metadata-alice')",
            "SELECT public.codewire_platform_lock_credential('credential-a','metadata-alice',NULL)",
        ] { denied(&h.reader, sql).await?; }
        h.ok("ListCredentials", Auth::Cookie, json!({})).await?;
        h.ok("GetCredential", Auth::Alice, json!({"name":"WORK CODEX"})).await?;
        h.absent_mutation_routes().await?;
        sqlx::query("UPDATE platform_credentials SET provider='synthetic-metadata-canary-invalid' WHERE id=$1").bind(ALICE_CREDENTIAL).execute(&h.db).await?;
        h.error("GetCredential", Auth::Alice, json!({"credentialId":ALICE_CREDENTIAL}), "unavailable").await?;
        sqlx::query("UPDATE platform_credentials SET provider='openai' WHERE id=$1").bind(ALICE_CREDENTIAL).execute(&h.db).await?;
        sqlx::query("UPDATE oidc_clients SET disabled=true WHERE id='metadata-client'").execute(&h.db).await?;
        h.error("ListCredentials", Auth::Alice, json!({}), "unauthenticated").await?;
        h.ok("ListCredentials", Auth::Cookie, json!({})).await?;
        sqlx::query("UPDATE oidc_clients SET disabled=false WHERE id='metadata-client'").execute(&h.db).await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE user_id=$1").bind(ALICE).execute(&h.db).await?;
        h.error("ListCredentials", Auth::Alice, json!({}), "unauthenticated").await?;
        sqlx::query("DELETE FROM sessions WHERE id='metadata-session'").execute(&h.db).await?;
        h.error("ListCredentials", Auth::Cookie, json!({}), "unauthenticated").await?;
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn metadata_name_resolution_keeps_owner_kind_exact_matching_and_active_owner_fences()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let reader = CredentialMetadataReader::new(h.reader.clone(), builtin_provider_catalog());
        let user = Owner::User(OwnerId::parse(ALICE)?);
        let organization = Owner::Organization(OwnerId::parse(ALICE)?);
        ensure!(reader.resolve(&user,"WORK CODEX",None).await?.id.as_str() == ALICE_CREDENTIAL);
        ensure!(reader.resolve(&organization,"work codex",None).await?.id.as_str() == ORG_CREDENTIAL);
        for name in ["Work","%","Work Code_"] { ensure!(reader.resolve(&user,name,None).await == Err(PlatformCredentialError::NotFound.into())); }
        for name in [""," Work Codex","Work Codex ","Work\nCodex"] { ensure!(reader.resolve(&user,name,None).await == Err(PlatformCredentialError::InvalidInput.into())); }
        ensure!(reader.resolve(&user,&"é".repeat(129),None).await == Err(PlatformCredentialError::InvalidInput.into()));
        sqlx::query("UPDATE organizations SET deletion_state='deleting',deletion_generation=1, \
            deletion_requested_at=now(),deletion_requested_by=$1,deletion_phase='write_fenced', \
            deletion_operation_id='synthetic-delete',deletion_workflow_id='synthetic-delete' WHERE id=$1")
            .bind(ALICE).execute(&h.db).await?;
        ensure!(reader.resolve(&organization,"Work Codex",None).await == Err(PlatformCredentialError::NotFound.into()));
        ensure!(reader.resolve(&user,"Work Codex",None).await?.id.as_str() == ALICE_CREDENTIAL);
        // Resolve must be a plain metadata read, not a SHARE-lock acquisition.
        let mut locked = h.db.begin().await?;
        sqlx::query("SELECT id FROM platform_credentials WHERE id=$1 FOR UPDATE")
            .bind(ALICE_CREDENTIAL).fetch_one(&mut *locked).await?;
        let found = tokio::time::timeout(std::time::Duration::from_secs(1), reader.resolve(&user,"Work Codex",None)).await??;
        ensure!(found.id.as_str() == ALICE_CREDENTIAL);
        locked.rollback().await?;
        sqlx::query("DELETE FROM users WHERE id=$1").bind(BOB).execute(&h.db).await?;
        ensure!(reader.resolve(&Owner::User(OwnerId::parse(BOB)?),"Work Codex",None).await == Err(PlatformCredentialError::NotFound.into()));
        ensure!(reader.resolve(&user,"Work Codex",None).await?.id.as_str() == ALICE_CREDENTIAL);
        Ok(())
    }.await;
    h.finish(result).await
}

/// The ErrorInfo of a refusal, decoded from the Connect JSON error body.
fn error_info(body: &serde_json::Value) -> Result<codewire_proto::google::rpc::ErrorInfo> {
    use base64::Engine as _;
    use buffa::Message as _;
    let detail = body["details"]
        .as_array()
        .and_then(|details| {
            details
                .iter()
                .find(|detail| detail["type"] == "google.rpc.ErrorInfo")
        })
        .context("refusal lacks an ErrorInfo")?;
    let encoded = detail["value"].as_str().context("ErrorInfo value")?;
    let bytes =
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.trim_end_matches('='))?;
    Ok(codewire_proto::google::rpc::ErrorInfo::decode_from_slice(
        &bytes,
    )?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_name_two_providers_share_needs_its_provider_and_reaches_only_its_owner() -> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        // Alice's "Work Codex" is an OpenAI credential; a Claude one may share
        // the name, and so may two of hers that Bob has no name like.
        for (id, provider, kind, name) in [
            ("credential-anthropic", "anthropic", "api_key", "WORK CODEX"),
            ("credential-shared-openai", "openai", "api_key", "Shared"),
            ("credential-shared-github", "github", "oauth", "shared"),
        ] {
            sqlx::query("INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status,revocation_generation,material_generation) VALUES ($1,$2,$3,$4,$5,'active',1,1)")
                .bind(id).bind(ALICE).bind(provider).bind(kind).bind(name).execute(&h.db).await?;
        }
        for (name, providers) in [("work codex", "anthropic,openai"), ("SHARED", "github,openai")] {
            let (status, body) = h
                .call("GetCredential", Auth::Alice, json!({"name":name}))
                .await?;
            ensure!(!status.is_success() && body["code"] == "failed_precondition", "{status}: {body}");
            let info = error_info(&body)?;
            ensure!(info.reason == "CREDENTIAL_NAME_AMBIGUOUS" && info.domain == "codewire.sh");
            ensure!(info.metadata.get("providers").map(String::as_str) == Some(providers));
            for id in [ALICE_CREDENTIAL, "credential-anthropic", "credential-shared-openai", "credential-shared-github"] {
                ensure!(!body.to_string().contains(id), "the refusal names {id}");
            }
        }
        for (provider, id) in [("openai", ALICE_CREDENTIAL), ("anthropic", "credential-anthropic")] {
            let found = h
                .ok("GetCredential", Auth::Alice, json!({"name":"work codex","provider":provider}))
                .await?;
            ensure!(found["credential"]["id"] == id);
        }
        h.error("GetCredential", Auth::Alice, json!({"name":"work codex","provider":"github"}), "not_found").await?;
        for provider in ["OpenAI", "gitlab", ""] {
            h.error("GetCredential", Auth::Alice, json!({"name":"work codex","provider":provider}), "invalid_argument").await?;
        }
        h.error("GetCredential", Auth::Alice, json!({"credentialId":ALICE_CREDENTIAL,"provider":"openai"}), "invalid_argument").await?;
        // Bob's own "Work Codex" is his only one: he gets it, and never learns
        // that Alice's name is shared.
        let bob = h.ok("GetCredential", Auth::Bob, json!({"name":"work codex"})).await?;
        ensure!(bob["credential"]["id"] == BOB_CREDENTIAL);
        h.error("GetCredential", Auth::Bob, json!({"name":"shared"}), "not_found").await?;
        h.error("GetCredential", Auth::Bob, json!({"name":"shared","provider":"github"}), "not_found").await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}
