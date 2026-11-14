//! `codewire-idp` — entry point.
//!
//! Assembles the OIDC [`Provider`](codewire_oidc::Provider) from the Postgres
//! stores + Codewire glue and serves it: discovery, JWKS, authorize, token
//! (authorization_code + refresh_token), userinfo, introspection, revocation,
//! end_session, and RFC 8628 device flow, plus the Codewire resume-after-login
//! callback and browser device-verification route — alongside
//! health/readiness.

use anyhow::Context as _;
use codewire_server_core::auth::AuthState;
use codewire_server_core::{AppBuilder, ServiceConfig};
use std::ffi::OsString;
use std::net::SocketAddr;

/// Where `/metrics` is served on its own (#4546). Prometheus runs on host
/// networking, which no NetworkPolicy peer can name, so the port Prometheus
/// scrapes admits any source and serves nothing but metrics, while the API
/// port admits only the edge and the dashboard.
const METRICS_ADDR_ENV: &str = "IDP_METRICS_ADDR";
const DEFAULT_METRICS_ADDR: &str = "0.0.0.0:8092";

fn metrics_addr(value: Option<&str>) -> anyhow::Result<SocketAddr> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_METRICS_ADDR)
        .parse()
        .with_context(|| {
            format!("{METRICS_ADDR_ENV} must be a socket address such as {DEFAULT_METRICS_ADDR}")
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandMode {
    Serve,
    RewrapSigningKeks,
    /// Setup makes the server's admin (#4121); the password is on stdin.
    CreateAdmin {
        email: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_command(std::env::args_os().skip(1))? {
        CommandMode::Serve => serve().await,
        CommandMode::RewrapSigningKeks => rewrap_signing_keks().await,
        CommandMode::CreateAdmin { email } => create_admin(&email).await,
    }
}

fn parse_command(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<CommandMode> {
    let mut args = args.into_iter();
    match (args.next(), args.next(), args.next(), args.next()) {
        (None, None, None, None) => Ok(CommandMode::Serve),
        (Some(command), None, None, None) if command == "rewrap-signing-keks" => {
            Ok(CommandMode::RewrapSigningKeks)
        }
        (Some(command), Some(flag), Some(email), None)
            if command == "create-admin" && flag == "--email" =>
        {
            let email = email
                .into_string()
                .map_err(|_| anyhow::anyhow!("the admin's email must be UTF-8"))?;
            Ok(CommandMode::CreateAdmin { email })
        }
        _ => anyhow::bail!(
            "usage: codewire-idp [rewrap-signing-keks | create-admin --email <address>]"
        ),
    }
}

async fn rewrap_signing_keks() -> anyhow::Result<()> {
    let database_url = codewire_server_core::config::database_url_from_env()
        .map_err(|_| anyhow::anyhow!("jwk-rewrap failure_class=missing-database-url"))?;
    let keyring = codewire_idp::SigningKekKeyring::from_env()
        .map_err(|_| anyhow::anyhow!("jwk-rewrap failure_class=keyring-invalid"))?;
    let pool = codewire_server_core::db::connect(&database_url)
        .await
        .map_err(|_| anyhow::anyhow!("jwk-rewrap failure_class=database-unavailable"))?;
    let report = codewire_idp::PgKeyStore::new(pool.clone(), keyring)
        .rewrap_signing_envelopes()
        .await
        .map_err(|error| anyhow::anyhow!(error.0))?;

    println!("{}", format_rewrap_report(&report));
    pool.close().await;
    Ok(())
}

/// `codewire-idp create-admin --email <address>`: makes the server's admin
/// with the password read from stdin, so it never appears in a process list
/// or a shell history. A second run changes nothing.
async fn create_admin(email: &str) -> anyhow::Result<()> {
    use std::io::Read as _;
    let database_url = codewire_server_core::config::database_url_from_env()?;
    codewire_server_core::migrate::ensure_schema_logged(&database_url).await?;
    let pool = codewire_server_core::db::connect(&database_url).await?;
    let idp_cfg = codewire_idp::IdpConfig::from_env()?;
    let mail = codewire_email::EmailClient::from_env().await?;
    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\n', '\r']);
    let outcome = codewire_idp::admin_bootstrap::create_admin(
        &pool,
        email,
        password,
        &mail,
        &idp_cfg.frontend_url,
    )
    .await;
    pool.close().await;
    match outcome? {
        codewire_idp::admin_bootstrap::CreateAdmin::Created {
            verification_sent: true,
        } => println!("created the admin {email}; open the verification email before signing in"),
        codewire_idp::admin_bootstrap::CreateAdmin::Created {
            verification_sent: false,
        } => println!("created the admin {email}"),
        codewire_idp::admin_bootstrap::CreateAdmin::AdminExists => {
            println!("this server already has an admin; nothing changed")
        }
    }
    Ok(())
}

fn format_rewrap_report(report: &codewire_idp::SigningKekRewrapReport) -> String {
    format!(
        "jwk-rewrap active_kek_id={} total={} signing={} rewrapped={} already_active={} public_only={}",
        report.active_kek_id,
        report.total,
        report.signing,
        report.rewrapped,
        report.already_active,
        report.public_only,
    )
}

async fn serve() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("idp")?;
    codewire_server_core::obs::init(&cfg)?;

    codewire_server_core::migrate::ensure_schema_logged(&cfg.database_url).await?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;
    let idp_cfg = codewire_idp::IdpConfig::from_env()?;
    let email = codewire_email::EmailClient::from_env().await?;
    let signing_keyring = codewire_idp::SigningKekKeyring::from_env()?;

    // Seed built-in public clients. Existing registrations converge their
    // grants and scope allowlists intentionally.
    if let Err(e) = codewire_idp::provisioning::ensure_desktop_client(&pool).await {
        tracing::warn!(error = %e, "oidc: failed to seed desktop client");
    }
    if let Err(e) = codewire_idp::provisioning::ensure_ios_client(&pool).await {
        tracing::warn!(error = %e, "oidc: failed to seed iOS client");
    }
    if let Err(e) = codewire_idp::provisioning::ensure_cli_client(&pool).await {
        tracing::warn!(error = %e, "oidc: failed to seed CLI client");
    }

    let provider = codewire_idp::build_provider(
        pool.clone(),
        &idp_cfg,
        signing_keyring,
        cfg.session_secret.clone(),
    )
    .await?;
    let oidc = codewire_idp::service::router(provider.clone());

    let auth_state = AuthState { pool: pool.clone() };
    let device_verification =
        codewire_idp::device_verification::router(provider.clone(), auth_state.clone());

    // Session-core credential auth (`/api/auth/{sign-up,sign-in,sign-out,
    // get-session}`). Cookies are `Secure` only for HTTPS frontends.
    let secure = idp_cfg.frontend_url.starts_with("https");
    let signup_mode =
        codewire_idp::auth_session::signup_policy::mode_router(&idp_cfg.signup_invite_policy);
    let session_auth = codewire_idp::auth_session::router_with_signup_delivery(
        pool.clone(),
        secure,
        idp_cfg.signup_invite_policy.clone(),
        idp_cfg.frontend_url.clone(),
        email.clone(),
        idp_cfg.turnstile_secret_key.clone(),
        idp_cfg.turnstile_bypass_email.clone(),
    );
    // Sign in with GitHub or Google: off unless a provider's client pair is
    // configured; half a pair stops startup.
    let oauth_providers = codewire_idp::oauth::OAuthProviders::from_env()?;
    tracing::info!(
        providers = ?oauth_providers
            .configured()
            .into_iter()
            .map(codewire_idp::oauth::Provider::as_str)
            .collect::<Vec<_>>(),
        "oauth sign-in providers"
    );
    let oauth = codewire_idp::oauth::router(
        pool.clone(),
        secure,
        idp_cfg.signup_invite_policy.clone(),
        idp_cfg.frontend_url.clone(),
        email.clone(),
        idp_cfg.turnstile_secret_key.clone(),
        idp_cfg.turnstile_bypass_email.clone(),
        oauth_providers,
        codewire_server_core::internal_hmac::derive_internal_hmac_secret(
            &cfg.session_secret,
            codewire_idp::oauth::CLIENT_ADDRESS_KEY_LABEL,
        )
        .map_err(|_| anyhow::anyhow!("the session secret for OAuth sign-in is not set"))?,
    );
    let email_password = codewire_idp::email_password::router(
        pool.clone(),
        idp_cfg.frontend_url.clone(),
        email.clone(),
        auth_state.clone(),
    );
    let access_admin = codewire_idp::access_admin::router(
        pool.clone(),
        idp_cfg.frontend_url.clone(),
        email.clone(),
        auth_state.clone(),
    );
    let two_factor = codewire_idp::two_factor::router(
        pool.clone(),
        cfg.session_secret.clone(),
        secure,
        auth_state.clone(),
    );
    // An admin deletes an account with a fresh second factor (#4541).
    let account_admin_delete = codewire_idp::account_admin_delete::router(
        pool.clone(),
        cfg.session_secret.clone(),
        idp_cfg.frontend_url.clone(),
        auth_state,
    );
    // Fresh-proof authenticator replacement and recovery-code regeneration:
    // cookie-only, exact-Origin account controls.
    // Organization invitation emails that orchestration queued (#3847).
    codewire_idp::invitation_email::spawn(
        pool.clone(),
        std::sync::Arc::new(codewire_idp::invitation_email::EmailInvitationMailer(
            email.clone(),
        )),
        &idp_cfg.frontend_url,
    );
    let two_factor_replacement = codewire_idp::two_factor::replacement_router(
        pool.clone(),
        cfg.session_secret.clone(),
        secure,
        idp_cfg.frontend_url.clone(),
        email,
    );

    let app = AppBuilder::new("codewire-idp")
        .with_health_and_db(pool)
        .into_router()
        .merge(oidc)
        .merge(device_verification)
        .merge(session_auth)
        .merge(signup_mode)
        .merge(oauth)
        .merge(email_password)
        .merge(access_admin)
        .merge(account_admin_delete)
        .merge(two_factor)
        .merge(two_factor_replacement);

    let metrics_bind = metrics_addr(std::env::var(METRICS_ADDR_ENV).ok().as_deref())?;
    let metrics = codewire_server_core::metrics::router("codewire-idp");

    tracing::info!(
        bind = %cfg.bind_addr,
        metrics = %metrics_bind,
        issuer = %idp_cfg.issuer,
        "codewire-idp starting"
    );
    tokio::try_join!(
        codewire_server_core::serve(app, cfg.bind_addr),
        codewire_server_core::serve(metrics, metrics_bind),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_listen_on_their_own_port_unless_set() {
        assert_eq!(metrics_addr(None).unwrap(), "0.0.0.0:8092".parse().unwrap());
        assert_eq!(
            metrics_addr(Some(" ")).unwrap(),
            "0.0.0.0:8092".parse().unwrap()
        );
        assert_eq!(
            metrics_addr(Some("127.0.0.1:9100")).unwrap(),
            "127.0.0.1:9100".parse().unwrap()
        );
        assert!(metrics_addr(Some("8092")).is_err());
    }

    #[test]
    fn no_arguments_preserve_server_mode() {
        assert_eq!(parse_command(Vec::new()).unwrap(), CommandMode::Serve);
    }

    #[test]
    fn create_admin_takes_only_an_email() {
        assert_eq!(
            parse_command(["create-admin", "--email", "admin@example.test"].map(OsString::from))
                .unwrap(),
            CommandMode::CreateAdmin {
                email: "admin@example.test".into()
            }
        );
        for args in [
            vec!["create-admin"],
            vec!["create-admin", "--email"],
            vec!["create-admin", "--password", "secret"],
            vec![
                "create-admin",
                "--email",
                "admin@example.test",
                "--password",
            ],
        ] {
            assert!(parse_command(args.into_iter().map(OsString::from)).is_err());
        }
    }

    #[test]
    fn rewrap_requires_one_exact_explicit_command() {
        assert_eq!(
            parse_command([OsString::from("rewrap-signing-keks")]).unwrap(),
            CommandMode::RewrapSigningKeks
        );
        assert!(parse_command([OsString::from("unknown")]).is_err());
        assert!(
            parse_command([
                OsString::from("rewrap-signing-keks"),
                OsString::from("extra")
            ])
            .is_err()
        );
    }

    #[test]
    fn rewrap_report_contains_only_value_blind_fields() {
        let report = codewire_idp::SigningKekRewrapReport {
            active_kek_id: "v2".into(),
            total: 3,
            signing: 2,
            rewrapped: 1,
            already_active: 1,
            public_only: 1,
        };
        assert_eq!(
            format_rewrap_report(&report),
            "jwk-rewrap active_kek_id=v2 total=3 signing=2 rewrapped=1 already_active=1 public_only=1"
        );
    }
}
