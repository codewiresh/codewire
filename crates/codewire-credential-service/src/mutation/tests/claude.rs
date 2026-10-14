//! Claude sign-in by pasted code at the real isolated RPC mount, against a
//! synthetic Claude token endpoint and OAuth profile.

use super::*;
use codewire_access::CredentialAuthKind;
use codewire_platform_credentials::CredentialRegistration;
use codewire_protected_store::ProtectedValue;

/// Start a sign-in as `auth` and return its handle and the state Claude would
/// show after `#`.
async fn start(h: &Harness, auth: Auth) -> Result<(String, String)> {
    let (status, response) = h.rpc.start_claude_sign_in(auth).await?;
    ensure!(status.is_success(), "{response}");
    let url = url::Url::parse(response["authorizeUrl"].as_str().context("authorize URL")?)?;
    ensure!(url.host_str() == Some("claude.com") && url.path() == "/cai/oauth/authorize");
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .context("state")?;
    let handle = response["signIn"].as_str().context("handle")?.to_owned();
    // The handle is sealed: it carries neither the state nor the verifier in
    // the clear, only its version and issue time.
    let issued_at: u64 = handle
        .strip_prefix("cwcs2.")
        .and_then(|rest| rest.split('.').next())
        .context("handle version")?
        .parse()?;
    ensure!(
        !handle.contains(&state)
            && response["expiresAtUnix"].as_str() == Some(&(issued_at + 900).to_string())
    );
    Ok((handle, state))
}

/// `handle` with its issue time replaced by `issued_at`, its seal unchanged.
fn restamped(handle: &str, issued_at: u64) -> String {
    let mut parts = handle.splitn(3, '.');
    let (version, _, sealed) = (parts.next().unwrap(), parts.next(), parts.next().unwrap());
    format!("{version}.{issued_at}.{sealed}")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_claude_sign_in_is_personal_write_only_and_reconnects_exactly() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        for auth in [Auth::Missing, Auth::CookieWrongOrigin, Auth::ApiKey] {
            let (status, response) = h.rpc.start_claude_sign_in(auth).await?;
            ensure!(!status.is_success() && response["code"] == auth.denial_code());
            let (status, response) = h
                .rpc
                .complete_claude_sign_in(
                    auth,
                    json!({"name":"denied","signIn":"cwcs1.x.y.1"}),
                    "code#state",
                )
                .await?;
            ensure!(!status.is_success() && response["code"] == auth.denial_code());
        }

        // A code from another sign-in, or a malformed paste or handle, is
        // refused before Claude is contacted, and nothing is stored. So is a
        // handle that is altered, restamped, expired, from the future, of the
        // former unsealed form, or another person's.
        let (handle, state) = start(&h, Auth::Alice).await?;
        let (_, other_state) = start(&h, Auth::Alice).await?;
        let mut altered = handle.clone();
        let last = altered.pop().unwrap();
        altered.push(if last == '0' { '1' } else { '0' });
        let issued_at: u64 = handle.split('.').nth(1).unwrap().parse()?;
        for (signed_in, code) in [
            (altered, "invalid_argument"),
            (restamped(&handle, issued_at + 1), "invalid_argument"),
            (restamped(&handle, now_unix() - 901), "failed_precondition"),
            (restamped(&handle, now_unix() + 3_600), "invalid_argument"),
            (format!("cwcs1.{state}.verifier.{issued_at}"), "invalid_argument"),
        ] {
            let (status, response) = h
                .rpc
                .complete_claude_sign_in(
                    Auth::Alice,
                    json!({"name":"Claude","signIn":signed_in}),
                    &format!("{CLAUDE_CODE}#{state}"),
                )
                .await?;
            ensure!(!status.is_success() && response["code"] == code, "{response}");
        }
        let (status, response) = h
            .rpc
            .complete_claude_sign_in(
                Auth::Bob,
                json!({"name":"Claude","signIn":handle}),
                &format!("{CLAUDE_CODE}#{state}"),
            )
            .await?;
        // Another person's handle opens nothing. Here the authenticated
        // associated data refuses it; OpenBao refuses even to unwrap its data
        // key under another person's context, which reads as unavailable.
        ensure!(
            !status.is_success()
                && matches!(
                    response["code"].as_str(),
                    Some("invalid_argument" | "unavailable")
                ),
            "{response}"
        );
        for (body, pasted, code) in [
            (
                json!({"name":"Claude","signIn":handle}),
                format!("{CLAUDE_CODE}#{other_state}"),
                "invalid_argument",
            ),
            (json!({"name":"Claude","signIn":handle}), CLAUDE_CODE.to_owned(), "invalid_argument"),
            (
                json!({"name":"Claude","signIn":"cwcs1.not.a.handle"}),
                format!("{CLAUDE_CODE}#{state}"),
                "invalid_argument",
            ),
            (
                json!({"name":" padded","signIn":handle}),
                format!("{CLAUDE_CODE}#{state}"),
                "invalid_argument",
            ),
            (
                json!({"name":"half","signIn":handle,"credentialId":"x"}),
                format!("{CLAUDE_CODE}#{state}"),
                "invalid_argument",
            ),
        ] {
            let (status, response) = h
                .rpc
                .complete_claude_sign_in(Auth::Alice, body, &pasted)
                .await?;
            ensure!(!status.is_success() && response["code"] == code, "{response}");
        }
        // Claude refuses a code it did not issue: the attempt failed.
        let (status, response) = h
            .rpc
            .complete_claude_sign_in(
                Auth::Alice,
                json!({"name":"Claude","signIn":handle}),
                &format!("refused-code#{state}"),
            )
            .await?;
        ensure!(
            !status.is_success() && response["code"] == "failed_precondition",
            "{response}"
        );
        ensure!(h.device.claude_exchanges() == 1);
        ensure!(h.count().await? == 0);

        // Create: the anthropic provider's CLAUDE_SIGN_IN kind, the profile's
        // email as the hint, no hard expiry, and nothing echoed.
        let (status, response) = h
            .rpc
            .complete_claude_sign_in(
                Auth::Alice,
                json!({"name":"Claude","signIn":handle}),
                &format!("{CLAUDE_CODE}#{state}"),
            )
            .await?;
        ensure!(status.is_success(), "{response}");
        let metadata = &response["credential"];
        ensure!(
            metadata["provider"] == "anthropic"
                && metadata["authenticationKind"] == "CREDENTIAL_AUTHENTICATION_KIND_CLAUDE_SIGN_IN"
                && metadata["status"] == "CREDENTIAL_STATUS_ACTIVE"
                && metadata["revocationGeneration"] == "1"
                && metadata["name"] == "Claude"
                && metadata["accountHint"] == "person@example.test"
                && metadata.get("expiresAtUnix").is_none()
        );
        let id = CredentialId::parse(id(metadata)?)?;
        let record = h.store.record(&owner, &id).await?;
        let material = h
            .store
            .read_for_broker(&owner, &id, record.version)
            .await?;
        let envelope: Value = serde_json::from_slice(material.expose_secret())?;
        ensure!(
            envelope["access_token"] == ACCESS
                && envelope["refresh_token"] == REFRESH
                && envelope["subscription_type"] == "max"
                && envelope["rate_limit_tier"] == "default_claude_max_20x"
        );
        let (handle, state) = start(&h, Auth::Alice).await?;
        let (status, duplicate) = h
            .rpc
            .complete_claude_sign_in(
                Auth::Alice,
                json!({"name":"claude","signIn":handle}),
                &format!("{CLAUDE_CODE}#{state}"),
            )
            .await?;
        ensure!(!status.is_success() && duplicate["code"] == "already_exists");

        // Reconnect names the exact identity, name and generation of a sign-in.
        let api_key = h
            .store
            .create(
                &owner,
                CredentialRegistration {
                    provider: codewire_access::ProviderId::parse("anthropic")?,
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "Anthropic key".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                &ProtectedValue::from_slice(b"synthetic-anthropic-api-key")?,
            )
            .await?;
        let replace = |name: &str, credential: &str, generation: &str| {
            json!({"name":name,"credentialId":credential,"expectedRevocationGeneration":generation})
        };
        for (auth, body, code) in [
            (Auth::Bob, replace("Claude", id.as_str(), "1"), "not_found"),
            (Auth::Alice, replace("Renamed", id.as_str(), "1"), "invalid_argument"),
            (Auth::Alice, replace("Claude", id.as_str(), "2"), "failed_precondition"),
            (
                Auth::Alice,
                replace("Anthropic key", api_key.metadata.id.as_str(), "1"),
                "invalid_argument",
            ),
        ] {
            let (handle, state) = start(&h, auth).await?;
            let mut body = body;
            body["signIn"] = json!(handle);
            let (status, response) = h
                .rpc
                .complete_claude_sign_in(auth, body, &format!("{CLAUDE_CODE}#{state}"))
                .await?;
            ensure!(!status.is_success() && response["code"] == code, "{response}");
        }
        ensure!(h.store.record(&owner, &id).await? == record);
        let (handle, state) = start(&h, Auth::Alice).await?;
        let mut body = replace("Claude", id.as_str(), "1");
        body["signIn"] = json!(handle);
        let (status, response) = h
            .rpc
            .complete_claude_sign_in(Auth::Alice, body, &format!("{CLAUDE_CODE}#{state}"))
            .await?;
        ensure!(status.is_success(), "{response}");
        ensure!(response["credential"]["id"] == id.as_str());
        ensure!(response["credential"]["revocationGeneration"] == "2");
        Ok(())
    }
    .await;
    h.finish(result).await
}
