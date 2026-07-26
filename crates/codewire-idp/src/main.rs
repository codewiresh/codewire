//! `codewire-idp` — entry point.
//!
//! Assembles the OIDC [`Provider`](codewire_oidc::Provider) from the Postgres
//! stores + Codewire glue and serves it: discovery, JWKS, authorize, token
//! (authorization_code + refresh_token), userinfo, introspection, revocation,
//! end_session, and RFC 8628 device flow, plus the Codewire resume-after-login
//! callback and browser device-verification route — alongside
//! health/readiness.

use codewire_server_core::auth::AuthState;
use codewire_server_core::{AppBuilder, ServiceConfig};
use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandMode {
    Serve,
    RewrapSigningKeks,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_command(std::env::args_os().skip(1))? {
        CommandMode::Serve => serve().await,
        CommandMode::RewrapSigningKeks => rewrap_signing_keks().await,
    }
}

fn parse_command(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<CommandMode> {
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (None, None) => Ok(CommandMode::Serve),
        (Some(command), None) if command == "rewrap-signing-keks" => {
            Ok(CommandMode::RewrapSigningKeks)
        }
        _ => anyhow::bail!("usage: codewire-idp [rewrap-signing-keks]"),
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
    let signing_keyring = codewire_idp::SigningKekKeyring::from_env()?;

    // Seed built-in public clients. Existing registrations converge their
    // grants and scope allowlists intentionally.
    if let Err(e) = codewire_idp::provisioning::ensure_desktop_client(&pool).await {
        tracing::warn!(error = %e, "oidc: failed to seed desktop client");
    }
    if let Err(e) = codewire_idp::provisioning::ensure_cli_client(&pool).await {
        tracing::warn!(error = %e, "oidc: failed to seed CLI client");
    }

    let provider = codewire_idp::build_provider(pool.clone(), &idp_cfg, signing_keyring).await?;
    let oidc = codewire_idp::service::router(provider.clone());

    let auth_state = AuthState { pool: pool.clone() };
    let device_verification =
        codewire_idp::device_verification::router(provider.clone(), auth_state.clone());

    // Session-core credential auth (`/api/auth/{sign-up,sign-in,sign-out,
    // get-session}`). Cookies are `Secure` only for HTTPS frontends.
    let secure = idp_cfg.frontend_url.starts_with("https");
    let session_auth = codewire_idp::auth_session::router(pool.clone(), secure);
    let email_password = codewire_idp::email_password::router(
        pool.clone(),
        idp_cfg.frontend_url.clone(),
        idp_cfg.resend_api_key.clone(),
        auth_state.clone(),
    );
    let two_factor = codewire_idp::two_factor::router(
        pool.clone(),
        cfg.session_secret.clone(),
        secure,
        auth_state,
    );

    let app = AppBuilder::new("codewire-idp")
        .with_health_and_db(pool)
        .into_router()
        .merge(oidc)
        .merge(device_verification)
        .merge(session_auth)
        .merge(email_password)
        .merge(two_factor);

    tracing::info!(
        bind = %cfg.bind_addr,
        issuer = %idp_cfg.issuer,
        "codewire-idp starting"
    );
    codewire_server_core::serve(app, cfg.bind_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_preserve_server_mode() {
        assert_eq!(parse_command(Vec::new()).unwrap(), CommandMode::Serve);
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
