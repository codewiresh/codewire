//! Sandbox identity: Codewire as a per-org OIDC issuer, so a sandbox can prove
//! which org's sandbox it is to a verifier that org trusts.
//!
//! This part publishes each org's issuer: OIDC discovery and the JWKS on a
//! dedicated listener ([`discovery`]), from an OpenBao transit key that never
//! leaves OpenBao ([`transit`]), with the rotation job's rules ([`keys`],
//! [`rotate`]). Nothing here mints a token. It is off unless
//! `CODEWIRE_IDENTITY_ENABLED=true` ([`config`]).
//!
//! [`audience`] and [`groups`] are the names a registration and a Sandbox's
//! groups hold, parsed once for the records API and for minting alike.

pub mod audience;
pub mod config;
pub mod discovery;
pub mod groups;
pub mod keys;
pub mod rotate;
pub mod transit;

use std::sync::Arc;

use anyhow::Context;
use codewire_protected_store::openbao_workload_identity::KubernetesOpenBaoWorkloadIdentity;

pub use config::{IdentityConfig, IdentitySettings, SignerConfig, TransitKeyConfig};
use transit::TransitKeyClient;

/// The transit key client for this Pod's role, logging in with a Pod-bound
/// token whose OpenBao audience is `SANDBOX_IDENTITY_BAO_AUDIENCE`.
pub fn transit_key_client(
    config: &TransitKeyConfig,
    kube: kube::Client,
) -> anyhow::Result<TransitKeyClient> {
    let identity = KubernetesOpenBaoWorkloadIdentity::from_env(kube, config::BAO_AUDIENCE_ENV)?;
    TransitKeyClient::new(config.clone(), Arc::new(identity))
}

/// The identity listener's router for enabled settings. It serves only
/// per-org discovery and the JWKS ([`discovery`]), and logs in to OpenBao with
/// this Pod's own token, so it needs the cluster: without a Kubernetes client
/// startup fails.
pub fn discovery_router(
    settings: &IdentitySettings,
    kube: Option<kube::Client>,
    database_url: &str,
) -> anyhow::Result<axum::Router> {
    let kube = kube.context("sandbox identity is enabled but no Kubernetes client is available")?;
    let SignerConfig::OpenBaoTransit(transit) = &settings.signer;
    let keys = Arc::new(transit_key_client(transit, kube)?);
    let orgs = Arc::new(discovery::PgOrgDirectory::connect_lazy(database_url)?);
    Ok(discovery::router(discovery::DiscoveryState::new(
        settings.issuer_base.clone(),
        orgs,
        keys,
    )))
}

/// Serve the issuer on its own listener, under its own limits, until shutdown;
/// nothing while identity is off. A router without a listener, or the
/// reverse, is an error, so a mismatch never silently stops the issuer.
pub async fn serve(
    app: Option<axum::Router>,
    listener: Option<tokio::net::TcpListener>,
) -> anyhow::Result<()> {
    match (app, listener) {
        (Some(app), Some(listener)) => {
            codewire_server_core::bounded_http1::serve_bounded_http1(
                app,
                listener,
                discovery::LISTENER_LIMITS,
            )
            .await
        }
        (None, None) => Ok(()),
        (Some(_), None) => anyhow::bail!("sandbox identity has a router but no listener"),
        (None, Some(_)) => anyhow::bail!("sandbox identity has a listener but no router"),
    }
}

/// Whether the command line asks for `identity rotate`. No arguments serve;
/// anything else is a usage error.
pub fn rotate_requested(mut args: impl Iterator<Item = String>) -> anyhow::Result<bool> {
    match (args.next().as_deref(), args.next().as_deref(), args.next()) {
        (None, ..) => Ok(false),
        (Some("identity"), Some("rotate"), None) => Ok(true),
        _ => anyhow::bail!("usage: codewire-orchestration [identity rotate]"),
    }
}

/// `codewire-orchestration identity rotate`: one run of the rotation job.
pub async fn rotate_command() -> anyhow::Result<()> {
    let IdentityConfig::Enabled(settings) = IdentityConfig::from_env()? else {
        anyhow::bail!(
            "{} is not true; there is no key to rotate",
            config::IDENTITY_ENABLED_ENV
        );
    };
    let SignerConfig::OpenBaoTransit(transit) = &settings.signer;
    let kube = codewire_server_core::span_free::kube_client_default().await?;
    let client = transit_key_client(transit, kube)?;
    let outcome = rotate::run(&client, chrono::Utc::now()).await?;
    println!(
        "sandbox identity key: version {} signs; retired below {}; rotated: {}",
        outcome
            .signing_version
            .map_or_else(|| "none yet".to_owned(), |version| version.to_string()),
        outcome
            .retired_below
            .map_or_else(|| "nothing".to_owned(), |version| version.to_string()),
        outcome.rotated,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::rotate_requested;

    fn args(list: &[&str]) -> std::vec::IntoIter<String> {
        list.iter()
            .map(|arg| (*arg).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[tokio::test]
    async fn serving_needs_both_the_router_and_the_listener_or_neither() {
        assert!(super::serve(None, None).await.is_ok());
        assert!(super::serve(Some(axum::Router::new()), None).await.is_err());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(super::serve(None, Some(listener)).await.is_err());
    }

    #[test]
    fn no_arguments_serve_and_only_identity_rotate_rotates() {
        assert!(!rotate_requested(args(&[])).unwrap());
        assert!(rotate_requested(args(&["identity", "rotate"])).unwrap());
        for usage in [
            &["identity"][..],
            &["identity", "rotate", "now"],
            &["rotate"],
            &["serve"],
        ] {
            assert!(rotate_requested(args(usage)).is_err(), "{usage:?}");
        }
    }
}
