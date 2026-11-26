use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use super::*;
use crate::config::{CW_CONFIG_DIR_ENV, MapEnv, PlatformConfig};

const SAVED_ACCESS: &str = "synthetic-saved-access-5688";
const ISSUED: &str = "synthetic-user-token-5688";

fn globals() -> Globals {
    Globals {
        server: None,
        member: None,
        placement: None,
        org: None,
    }
}

/// A scratch home whose config folder holds a sign-in for `server` (when
/// `signed_in`), and the environment that points `cw` at it.
struct Home {
    _dir: tempfile::TempDir,
    env: MapEnv,
}

fn home(server: &MockServer, signed_in: bool, extra: &[(&str, &str)]) -> Home {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("cfg");
    std::fs::create_dir(&config).unwrap();
    config::save_platform_config(
        &config,
        &PlatformConfig {
            server_url: server.uri(),
            ..PlatformConfig::default()
        },
    )
    .unwrap();
    if signed_in {
        let credentials = codewire_client::OAuthCredentials::new(
            server.uri(),
            "codewire-cli",
            SAVED_ACCESS,
            "synthetic-saved-refresh-5688",
            u64::try_from(chrono::Utc::now().timestamp()).unwrap() + 3600,
            "openid codewire.api",
        )
        .unwrap();
        codewire_client::CredentialStore::save(
            &FileCredentialStore::at(config::oauth_credentials_path(&config)),
            &credentials,
        )
        .unwrap();
    }
    let mut vars = vec![
        ("HOME".to_owned(), dir.path().display().to_string()),
        (CW_CONFIG_DIR_ENV.to_owned(), config.display().to_string()),
    ];
    vars.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    Home {
        _dir: dir,
        env: MapEnv::new(vars),
    }
}

/// A scratch home with nothing saved at all.
fn empty_home() -> Home {
    let dir = tempfile::tempdir().unwrap();
    let env = MapEnv::new([
        ("HOME", dir.path().display().to_string()),
        (
            CW_CONFIG_DIR_ENV,
            dir.path().join("cfg").display().to_string(),
        ),
    ]);
    Home { _dir: dir, env }
}

/// The token endpoint's exchange grant, answering `response` `calls` times.
async fn exchange(server: &MockServer, response: ResponseTemplate, calls: u64) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/oauth/token"))
        .and(matchers::body_string_contains(
            "grant-type%3Atoken-exchange",
        ))
        .respond_with(response)
        .expect(calls)
        .mount(server)
        .await;
}

async fn no_refresh(server: &MockServer) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/oauth/token"))
        .and(matchers::body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server)
        .await;
}

fn issued() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": ISSUED,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 86_400,
        "scope": "codewire.api"
    }))
}

fn oauth_error(code: &str, description: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(serde_json::json!({
        "error": code,
        "error_description": description
    }))
}

/// Run the command into a buffer, as a pipe or a terminal would get it.
async fn run(env: &MapEnv, terminal: bool) -> (anyhow::Result<()>, String) {
    let mut out = Vec::new();
    let result = print_user_token(&globals(), env, None, terminal, &mut out).await;
    (result, String::from_utf8(out).unwrap())
}

fn shown(error: &anyhow::Error) -> String {
    format!(
        "{}\n{error:#}\n{error:?}",
        crate::error_report::render(
            error,
            crate::output::Style::new(false, crate::output::Charset::Ascii)
        )
    )
}

#[tokio::test]
async fn into_a_pipe_it_prints_the_token_alone() {
    let server = MockServer::start().await;
    exchange(&server, issued(), 1).await;
    let home = home(&server, true, &[]);
    let (result, out) = run(&home.env, false).await;
    result.unwrap();
    assert_eq!(out, format!("{ISSUED}\n"));
}

#[tokio::test]
async fn invalid_grant_renews_the_saved_sign_in_once_then_prints_the_token() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/oauth/token"))
        .and(matchers::body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-renewed-access-5688",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "synthetic-renewed-refresh-5688",
            "scope": "openid codewire.api"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/oauth/token"))
        .and(matchers::body_string_contains(format!(
            "subject_token={SAVED_ACCESS}&"
        )))
        .respond_with(oauth_error("invalid_grant", "synthetic"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/oauth/token"))
        .and(matchers::body_string_contains(
            "subject_token=synthetic-renewed-access-5688&",
        ))
        .respond_with(issued())
        .expect(1)
        .mount(&server)
        .await;
    let home = home(&server, true, &[]);
    let (result, out) = run(&home.env, false).await;
    result.unwrap();
    assert_eq!(out, format!("{ISSUED}\n"));
}

#[tokio::test]
async fn invalid_grant_after_the_renewal_says_to_sign_in_again() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/oauth/token"))
        .and(matchers::body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-renewed-access-5688",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "synthetic-renewed-refresh-5688",
            "scope": "openid codewire.api"
        })))
        .expect(1)
        .mount(&server)
        .await;
    exchange(&server, oauth_error("invalid_grant", "synthetic"), 2).await;
    let home = home(&server, true, &[]);
    let (result, out) = run(&home.env, false).await;
    let error = result.unwrap_err();
    assert_eq!(out, "");
    assert_eq!(
        crate::error_report::sentence(&error),
        "your sign-in can't issue a user token; sign in again"
    );
    assert_eq!(
        crate::error_report::next_step(&error).as_deref(),
        Some("cw login")
    );
}

#[tokio::test]
async fn at_a_terminal_it_refuses_and_prints_no_token() {
    let server = MockServer::start().await;
    exchange(&server, issued(), 0).await;
    let home = home(&server, true, &[]);
    let (result, out) = run(&home.env, true).await;
    let error = result.unwrap_err();
    assert_eq!(out, "");
    assert_eq!(
        crate::error_report::sentence(&error),
        "a user token is never printed to a terminal; capture it or pipe it"
    );
    assert_eq!(
        crate::error_report::next_step(&error).as_deref(),
        Some("export CODEWIRE_JWT_TOKEN=$(cw auth token --expires 30)")
    );
}

#[tokio::test]
async fn signed_out_it_refuses_and_names_cw_login() {
    let server = MockServer::start().await;
    exchange(&server, issued(), 0).await;
    for home in [home(&server, false, &[]), empty_home()] {
        let (result, out) = run(&home.env, false).await;
        let error = result.unwrap_err();
        assert_eq!(out, "");
        assert!(
            crate::error_report::sentence(&error).starts_with("not signed in"),
            "{error:#}"
        );
        assert_eq!(
            crate::error_report::next_step(&error).as_deref(),
            Some("cw login")
        );
    }
}

#[tokio::test]
async fn with_an_api_key_set_it_refuses_before_any_request() {
    let server = MockServer::start().await;
    exchange(&server, issued(), 0).await;
    let home = home(
        &server,
        true,
        &[(
            config::CODEWIRE_API_KEY_ENV,
            "an-api-key-from-the-environment",
        )],
    );
    let (result, out) = run(&home.env, false).await;
    let error = result.unwrap_err();
    assert_eq!(out, "");
    let sentence = crate::error_report::sentence(&error);
    assert!(
        sentence.starts_with("CODEWIRE_API_KEY is set, and an API key can't be exchanged"),
        "{sentence}"
    );
    assert!(!shown(&error).contains("an-api-key-from-the-environment"));
}

#[test]
fn a_bad_expires_is_refused_by_the_parser() {
    let expires = |value: &str| {
        crate::Cli::try_parse_from(["cw", "auth", "token", "--expires", value]).map(|cli| {
            let crate::Command::Auth {
                command: AuthCommand::Token(args),
            } = cli.command
            else {
                panic!("not cw auth token");
            };
            args.expires
        })
    };
    assert_eq!(expires("30").unwrap(), UserTokenLifetime::days(30));
    assert_eq!(expires("3650").unwrap(), UserTokenLifetime::days(3650));
    assert_eq!(expires("never").unwrap(), Some(UserTokenLifetime::NEVER));
    for refused in ["0", "3651", "1.5", "forever"] {
        let error = expires(refused).expect_err(refused).to_string();
        assert!(
            error.contains("from 1 to 3650, or never"),
            "{refused:?}: {error}"
        );
    }
    let cli = crate::Cli::try_parse_from(["cw", "auth", "token"]).unwrap();
    assert!(matches!(
        cli.command,
        crate::Command::Auth {
            command: AuthCommand::Token(AuthTokenArgs { expires: None })
        }
    ));
}

#[tokio::test]
async fn slow_down_says_so_and_does_not_retry() {
    let server = MockServer::start().await;
    no_refresh(&server).await;
    exchange(&server, oauth_error("slow_down", "synthetic"), 1).await;
    let home = home(&server, true, &[]);
    let (result, out) = run(&home.env, false).await;
    let error = result.unwrap_err();
    assert_eq!(out, "");
    assert_eq!(
        crate::error_report::sentence(&error),
        "too many user tokens were issued for your account lately; try again later"
    );
}

#[tokio::test]
async fn a_server_without_user_tokens_says_so() {
    for code in ["unsupported_grant_type", "unauthorized_client"] {
        let server = MockServer::start().await;
        no_refresh(&server).await;
        exchange(&server, oauth_error(code, "synthetic"), 1).await;
        let home = home(&server, true, &[]);
        let (result, out) = run(&home.env, false).await;
        assert_eq!(out, "");
        assert_eq!(
            crate::error_report::sentence(&result.unwrap_err()),
            "the Codewire server at 127.0.0.1 doesn't issue user tokens yet"
        );
    }
}

#[tokio::test]
async fn no_error_carries_a_token() {
    // A server that quotes the presented token back in its description, for
    // every answer the command words itself.
    for code in [
        "invalid_grant",
        "slow_down",
        "invalid_request",
        "unsupported_grant_type",
        "server_error",
    ] {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/token"))
            .and(matchers::body_string_contains("grant_type=refresh_token"))
            .respond_with(oauth_error("invalid_grant", SAVED_ACCESS))
            .mount(&server)
            .await;
        exchange(
            &server,
            oauth_error(code, &format!("{SAVED_ACCESS} {ISSUED}")),
            1,
        )
        .await;
        let home = home(&server, true, &[]);
        let (result, out) = run(&home.env, false).await;
        assert_eq!(out, "");
        let shown = shown(&result.unwrap_err());
        assert!(!shown.contains(SAVED_ACCESS), "{code}: {shown}");
        assert!(!shown.contains(ISSUED), "{code}: {shown}");
    }
}
