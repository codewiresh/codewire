//! User tokens: a saved `cw login` sign-in exchanged at the IdP's token
//! endpoint for one OAuth access token that an SDK or a script carries in
//! `CODEWIRE_JWT_TOKEN` (docs/dev/AUTH-POLICY.md, "User tokens and the CLI").

use std::str::FromStr;

use super::*;

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// The longest lifetime a user token may be given, in days.
pub const USER_TOKEN_MAX_DAYS: u16 = 3650;

/// How long a requested user token lives: a whole number of days from 1 to
/// [`USER_TOKEN_MAX_DAYS`], or until it is revoked. Leaving the lifetime out
/// of a request takes the server's default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserTokenLifetime(Lifetime);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifetime {
    Days(u16),
    Never,
}

impl UserTokenLifetime {
    pub const NEVER: Self = Self(Lifetime::Never);

    /// `days` days, or `None` outside 1 to [`USER_TOKEN_MAX_DAYS`].
    pub fn days(days: u16) -> Option<Self> {
        (1..=USER_TOKEN_MAX_DAYS)
            .contains(&days)
            .then_some(Self(Lifetime::Days(days)))
    }

    fn form_value(self) -> String {
        match self.0 {
            Lifetime::Days(days) => days.to_string(),
            Lifetime::Never => "never".to_owned(),
        }
    }
}

/// A lifetime that is neither a whole number of days in range nor `never`.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("a user token lives a whole number of days from 1 to {USER_TOKEN_MAX_DAYS}, or never")]
pub struct UserTokenLifetimeError;

impl FromStr for UserTokenLifetime {
    type Err = UserTokenLifetimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "never" {
            return Ok(Self::NEVER);
        }
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(UserTokenLifetimeError);
        }
        value
            .parse::<u16>()
            .ok()
            .and_then(Self::days)
            .ok_or(UserTokenLifetimeError)
    }
}

/// One issued user token. Its `Debug` output is redacted; the token itself
/// is reached only through [`expose_secret`](Self::expose_secret).
#[derive(Clone, Debug)]
pub struct UserToken {
    token: BearerToken,
    expires_in: Option<u64>,
}

impl UserToken {
    pub fn expose_secret(&self) -> &str {
        self.token.expose_secret()
    }

    /// Seconds until it expires, or `None` for one that never does.
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }
}

/// The token exchange's success body. It has no `Debug`: its token is
/// credential material.
#[derive(Deserialize)]
struct UserTokenResponse {
    access_token: String,
    issued_token_type: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl OAuthClient {
    /// Exchange the access token of `sign_in` for a user token. The token is
    /// renewed first when it is about to expire, as for any call. When the
    /// IdP answers `invalid_grant`, the sign-in is renewed once and the
    /// exchange tried once more; every other answer is returned as it is,
    /// `slow_down` included.
    pub async fn issue_user_token(
        &self,
        sign_in: &dyn TokenProvider,
        lifetime: Option<UserTokenLifetime>,
    ) -> Result<UserToken, AuthClientError> {
        let subject = sign_in.token().await?;
        match self.exchange_for_user_token(&subject, lifetime).await {
            Err(error) if error.oauth_code() == Some("invalid_grant") => {
                match sign_in.after_refusal(&subject).await? {
                    Some(renewed) => self.exchange_for_user_token(&renewed, lifetime).await,
                    None => Err(error),
                }
            }
            result => result,
        }
    }

    /// One token-exchange request for `subject`, a live access token of
    /// this client's sign-in.
    pub async fn exchange_for_user_token(
        &self,
        subject: &BearerToken,
        lifetime: Option<UserTokenLifetime>,
    ) -> Result<UserToken, AuthClientError> {
        let lifetime = lifetime.map(UserTokenLifetime::form_value);
        let mut form = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("client_id", CODEWIRE_CLI_OAUTH_CLIENT_ID),
            ("subject_token", subject.expose_secret()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ];
        if let Some(days) = &lifetime {
            form.push(("codewire_expires_in_days", days.as_str()));
        }
        let response = self
            .json_request(self.http.post(self.token_endpoint.clone()).form(&form))
            .send()
            .await?;
        let body = check_oauth_response(response).await?.bytes().await?;
        // Decoded here rather than by `reqwest`, whose decode error carries
        // serde's, which can quote a field of the body.
        let response = serde_json::from_slice::<UserTokenResponse>(&body)
            .map_err(|_| invalid_user_token_response())?;
        if !response.token_type.eq_ignore_ascii_case("bearer")
            || response.issued_token_type != ACCESS_TOKEN_TYPE
        {
            return Err(invalid_user_token_response());
        }
        let token =
            BearerToken::new(response.access_token).map_err(|_| invalid_user_token_response())?;
        Ok(UserToken {
            token,
            expires_in: response.expires_in,
        })
    }
}

fn invalid_user_token_response() -> AuthClientError {
    AuthClientError::Response {
        message: "the token endpoint's answer was not a user token".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    const ISSUED: &str = "synthetic-user-token-5688";

    fn exchange_for(subject: &str) -> wiremock::MockBuilder {
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/token"))
            .and(matchers::body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            ))
            .and(matchers::body_string_contains(format!(
                "subject_token={subject}&"
            )))
    }

    fn issued() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": ISSUED,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": 2_592_000,
            "scope": "codewire.api"
        }))
    }

    fn oauth_error(code: &str) -> ResponseTemplate {
        ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": code,
            "error_description": "synthetic description"
        }))
    }

    async fn refresh_once(server: &MockServer, calls: u64) {
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/token"))
            .and(matchers::body_string_contains("grant_type=refresh_token"))
            .and(matchers::body_string_contains("refresh_token=old-refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh",
                "scope": CODEWIRE_CLI_OAUTH_SCOPES
            })))
            .expect(calls)
            .mount(server)
            .await;
    }

    /// A saved sign-in whose access token `old-access` expires at
    /// `expires_at_unix`, and the provider that renews it.
    fn saved_sign_in(
        server: &MockServer,
        directory: &Path,
        expires_at_unix: u64,
    ) -> (OAuthClient, RefreshingTokenProvider) {
        let store = FileCredentialStore::new(directory);
        let credentials = OAuthCredentials::new(
            server.uri(),
            CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "old-access",
            "old-refresh",
            expires_at_unix,
            CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .expect("credentials");
        store.save(&credentials).expect("save credentials");
        let client = OAuthClient::for_server_url(server.uri()).expect("oauth client");
        let provider =
            RefreshingTokenProvider::from_store(client.clone(), store).expect("provider");
        (client, provider)
    }

    fn live() -> u64 {
        now_unix() + 3600
    }

    #[test]
    fn a_lifetime_is_whole_days_from_one_to_3650_or_never() {
        for (value, form) in [
            ("1", "1"),
            ("30", "30"),
            ("3650", "3650"),
            ("never", "never"),
        ] {
            let lifetime = value.parse::<UserTokenLifetime>().expect(value);
            assert_eq!(lifetime.form_value(), form);
        }
        for refused in [
            "", "0", "3651", "65536", "-1", "+1", " 1", "1.5", "1d", "Never", "forever",
        ] {
            assert_eq!(
                refused.parse::<UserTokenLifetime>(),
                Err(UserTokenLifetimeError),
                "{refused:?} was accepted"
            );
        }
        assert_eq!(UserTokenLifetime::days(0), None);
        assert_eq!(UserTokenLifetime::days(USER_TOKEN_MAX_DAYS + 1), None);
    }

    #[tokio::test]
    async fn the_exchange_sends_the_contract_form_fields() {
        let server = MockServer::start().await;
        let body = |lifetime: &str| {
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &client_id=codewire-cli&subject_token=old-access\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token{lifetime}"
            )
        };
        for (lifetime, suffix) in [
            (None, String::new()),
            (
                UserTokenLifetime::days(30),
                "&codewire_expires_in_days=30".to_owned(),
            ),
            (
                Some(UserTokenLifetime::NEVER),
                "&codewire_expires_in_days=never".to_owned(),
            ),
        ] {
            let mock = Mock::given(matchers::method("POST"))
                .and(matchers::path("/api/oauth/token"))
                .and(matchers::header(
                    "content-type",
                    "application/x-www-form-urlencoded",
                ))
                .and(matchers::body_string(body(&suffix)))
                .respond_with(issued())
                .expect(1)
                .mount_as_scoped(&server)
                .await;
            let client = OAuthClient::for_server_url(server.uri()).expect("oauth client");
            let subject = BearerToken::new("old-access").expect("subject");
            let token = client
                .exchange_for_user_token(&subject, lifetime)
                .await
                .expect("user token");
            assert_eq!(token.expose_secret(), ISSUED);
            assert_eq!(token.expires_in(), Some(2_592_000));
            drop(mock);
        }
    }

    #[tokio::test]
    async fn an_expired_sign_in_is_renewed_before_the_exchange() {
        let server = MockServer::start().await;
        refresh_once(&server, 1).await;
        exchange_for("old-access")
            .respond_with(oauth_error("invalid_grant"))
            .expect(0)
            .mount(&server)
            .await;
        exchange_for("new-access")
            .respond_with(issued())
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().expect("credential directory");
        let (client, sign_in) = saved_sign_in(&server, directory.path(), 0);
        let token = client
            .issue_user_token(&sign_in, None)
            .await
            .expect("user token");
        assert_eq!(token.expose_secret(), ISSUED);
    }

    #[tokio::test]
    async fn invalid_grant_renews_the_sign_in_once_and_retries_once() {
        let server = MockServer::start().await;
        refresh_once(&server, 1).await;
        exchange_for("old-access")
            .respond_with(oauth_error("invalid_grant"))
            .expect(1)
            .mount(&server)
            .await;
        exchange_for("new-access")
            .respond_with(issued())
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().expect("credential directory");
        let (client, sign_in) = saved_sign_in(&server, directory.path(), live());
        let token = client
            .issue_user_token(&sign_in, UserTokenLifetime::days(30))
            .await
            .expect("user token after one renewal");
        assert_eq!(token.expose_secret(), ISSUED);
    }

    #[tokio::test]
    async fn invalid_grant_after_the_renewal_is_returned_without_another_try() {
        let server = MockServer::start().await;
        refresh_once(&server, 1).await;
        for subject in ["old-access", "new-access"] {
            exchange_for(subject)
                .respond_with(oauth_error("invalid_grant"))
                .expect(1)
                .mount(&server)
                .await;
        }
        let directory = tempfile::tempdir().expect("credential directory");
        let (client, sign_in) = saved_sign_in(&server, directory.path(), live());
        let error = client
            .issue_user_token(&sign_in, None)
            .await
            .expect_err("a second invalid_grant");
        assert_eq!(error.oauth_code(), Some("invalid_grant"));
    }

    #[tokio::test]
    async fn slow_down_is_returned_with_no_renewal_or_retry() {
        let server = MockServer::start().await;
        refresh_once(&server, 0).await;
        exchange_for("old-access")
            .respond_with(oauth_error("slow_down"))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().expect("credential directory");
        let (client, sign_in) = saved_sign_in(&server, directory.path(), live());
        let error = client
            .issue_user_token(&sign_in, None)
            .await
            .expect_err("slow_down");
        assert_eq!(error.oauth_code(), Some("slow_down"));
    }

    #[tokio::test]
    async fn an_answer_that_is_not_a_user_token_never_quotes_it() {
        let marker = "synthetic-token-must-not-leak";
        for body in [
            serde_json::json!({
                "access_token": marker,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "mac",
            }),
            serde_json::json!({
                "access_token": marker,
                "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
                "token_type": "Bearer",
            }),
            serde_json::json!({
                "access_token": marker,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": marker,
            }),
            serde_json::json!({ "access_token": [marker] }),
            serde_json::json!({
                "access_token": format!("{marker} with space"),
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
            }),
        ] {
            let server = MockServer::start().await;
            exchange_for("old-access")
                .respond_with(ResponseTemplate::new(200).set_body_json(&body))
                .expect(1)
                .mount(&server)
                .await;
            let client = OAuthClient::for_server_url(server.uri()).expect("oauth client");
            let subject = BearerToken::new("old-access").expect("subject");
            let error = client
                .exchange_for_user_token(&subject, None)
                .await
                .expect_err("not a user token");
            for shown in [error.to_string(), format!("{error:?}")] {
                assert!(!shown.contains(marker), "{body} leaked into {shown}");
                assert!(!shown.contains("old-access"), "{body} leaked into {shown}");
            }
        }
    }

    #[test]
    fn a_user_token_debugs_redacted() {
        let token = UserToken {
            token: BearerToken::new(ISSUED).expect("token"),
            expires_in: None,
        };
        assert!(!format!("{token:?}").contains(ISSUED));
    }
}
