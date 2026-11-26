//! `cw auth token`: a user token from the saved `cw login` sign-in, for an
//! SDK or a script (docs/dev/AUTH-POLICY.md, "User tokens and the CLI";
//! journey docs/journeys/sdk-sign-in.md, `user-token`).

use std::io::Write;

use codewire_client::{
    AuthClientError, ErrorCode, FileCredentialStore, RefreshingTokenProvider, UserToken,
    UserTokenLifetime,
};

use super::*;
use crate::error_report::with_next_step;

#[derive(Debug, Subcommand)]
pub(crate) enum AuthCommand {
    #[command(
        about = "Print a user token for an SDK or a script",
        long_about = "Issue a user token from your `cw login` sign-in and print it, for an SDK or a script that acts as you:\n  export CODEWIRE_JWT_TOKEN=$(cw auth token --expires 30)\n\nThe token is printed only into a pipe or a variable, never to a terminal. With no --expires it lasts 1 day. Signing out of `cw`, a password reset, disabling the account, or revoking it on the API keys page ends it. An API key in CODEWIRE_API_KEY can't be exchanged for one."
    )]
    Token(AuthTokenArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AuthTokenArgs {
    #[arg(
        long,
        value_name = "DAYS|never",
        help = "How long the token lasts: 1 to 3650 days, or never (default: 1 day)"
    )]
    pub(crate) expires: Option<UserTokenLifetime>,
}

pub(crate) async fn handle_auth_command(
    globals: &Globals,
    command: AuthCommand,
) -> anyhow::Result<()> {
    match command {
        AuthCommand::Token(args) => {
            let mut stdout = std::io::stdout();
            let terminal = stdout.is_terminal();
            print_user_token(globals, &OsEnv, args.expires, terminal, &mut stdout).await
        }
    }
}

/// Write one user token, and nothing else, to `out`. Every refusal comes
/// before any request, and no error carries the token.
async fn print_user_token(
    globals: &Globals,
    env: &impl config::Env,
    lifetime: Option<UserTokenLifetime>,
    stdout_is_terminal: bool,
    out: &mut (impl Write + Send),
) -> anyhow::Result<()> {
    let token = issue_user_token(globals, env, lifetime, stdout_is_terminal).await?;
    writeln!(out, "{}", token.expose_secret())
        .and_then(|()| out.flush())
        .context("write the user token")
}

async fn issue_user_token(
    globals: &Globals,
    env: &impl config::Env,
    lifetime: Option<UserTokenLifetime>,
    stdout_is_terminal: bool,
) -> anyhow::Result<UserToken> {
    if stdout_is_terminal {
        return Err(with_next_step(
            anyhow::anyhow!("a user token is never printed to a terminal; capture it or pipe it"),
            "export CODEWIRE_JWT_TOKEN=$(cw auth token --expires 30)",
        ));
    }
    if config::Env::var(env, config::CODEWIRE_API_KEY_ENV).is_some_and(|key| !key.trim().is_empty())
    {
        return Err(with_next_step(
            anyhow::anyhow!(
                "CODEWIRE_API_KEY is set, and an API key can't be exchanged for a user token; \
                 a user token comes from a `cw login` sign-in"
            ),
            "env -u CODEWIRE_API_KEY cw auth token",
        ));
    }
    let paths = ResolvePaths::from_env(env)?;
    let platform = resolve_platform(globals, &paths, env)?;
    let Some(credentials) = platform.oauth_credentials_path.clone() else {
        return Err(not_signed_in(anyhow::anyhow!("not signed in")));
    };
    let oauth = platform.oauth_client()?;
    let sign_in =
        RefreshingTokenProvider::from_store(oauth.clone(), FileCredentialStore::at(credentials))
            .map_err(|error| not_signed_in(anyhow::Error::new(error).context("not signed in")))?;
    oauth
        .issue_user_token(&sign_in, lifetime)
        .await
        .map_err(|error| user_token_error(error, &server_host(&platform.server_url)))
}

fn not_signed_in(error: anyhow::Error) -> anyhow::Error {
    with_next_step(error, "cw login")
}

/// The IdP's answer in the user's terms. None of these carries the
/// server's description: the sentence names what to do instead.
fn user_token_error(error: AuthClientError, host: &str) -> anyhow::Error {
    match error {
        AuthClientError::OAuth { code, .. } => match code.as_str() {
            "invalid_grant" => not_signed_in(anyhow::anyhow!(
                "your sign-in can't issue a user token; sign in again"
            )),
            "slow_down" => anyhow::anyhow!(
                "too many user tokens were issued for your account lately; try again later"
            ),
            "unsupported_grant_type" | "unauthorized_client" => {
                anyhow::anyhow!("the Codewire server at {host} doesn't issue user tokens yet")
            }
            "invalid_request" => anyhow::anyhow!("the server refused the token's lifetime"),
            _ => anyhow::anyhow!("the server refused to issue a user token ({code})"),
        },
        AuthClientError::Unauthenticated => not_accepted(),
        AuthClientError::Client(error) if error.code() == ErrorCode::Unauthenticated => {
            not_accepted()
        }
        AuthClientError::Request(error) if error.is_connect() || error.is_timeout() => {
            anyhow::anyhow!("couldn't reach {host} to issue a user token")
        }
        AuthClientError::RateLimited => {
            anyhow::anyhow!("the server at {host} is busy; try again shortly")
        }
        error => anyhow::Error::new(error).context("couldn't issue a user token"),
    }
}

fn not_accepted() -> anyhow::Error {
    not_signed_in(anyhow::anyhow!(
        "not signed in: your saved sign-in is no longer accepted"
    ))
}

fn server_host(server_url: &str) -> String {
    url::Url::parse(server_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| server_url.to_owned())
}

#[cfg(test)]
mod tests;
