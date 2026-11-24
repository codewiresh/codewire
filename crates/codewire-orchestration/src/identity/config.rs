//! Sandbox identity configuration. The feature is off unless
//! `CODEWIRE_IDENTITY_ENABLED` is `true`; turning it on needs an issuer base
//! the install serves and an explicitly chosen signer, never a fallback.

use std::fmt;

use url::{Host, Url};

use crate::openbao::{
    parse_https_origin, required_env, valid_openbao_authority, valid_openbao_role,
    valid_openbao_segment,
};

pub const IDENTITY_ENABLED_ENV: &str = "CODEWIRE_IDENTITY_ENABLED";
pub const IDENTITY_ISSUER_BASE_ENV: &str = "CODEWIRE_IDENTITY_ISSUER_BASE";
pub const IDENTITY_SIGNER_ENV: &str = "CODEWIRE_IDENTITY_SIGNER";
pub const ORCHESTRATION_IDENTITY_PORT_ENV: &str = "ORCHESTRATION_IDENTITY_PORT";
/// The operator's circuit breaker for minting: `off` stops every mint.
pub const IDENTITY_MINTING_ENV: &str = "CODEWIRE_IDENTITY_MINTING";
/// The identity listener's default port, beside 8084 (public), 8087
/// (workspace binding) and 8088 (internal TLS).
pub const IDENTITY_PORT: u16 = 8089;

const BAO_ADDR_ENV: &str = "SANDBOX_IDENTITY_BAO_ADDR";
const BAO_AUTH_MOUNT_ENV: &str = "SANDBOX_IDENTITY_BAO_AUTH_MOUNT";
const BAO_ROLE_ENV: &str = "SANDBOX_IDENTITY_BAO_ROLE";
const BAO_TRANSIT_MOUNT_ENV: &str = "SANDBOX_IDENTITY_BAO_TRANSIT_MOUNT";
const BAO_EXPECTED_CLUSTER_ID_ENV: &str = "SANDBOX_IDENTITY_BAO_EXPECTED_CLUSTER_ID";
/// The OpenBao audience of the Pod-bound token this process logs in with.
pub const BAO_AUDIENCE_ENV: &str = "SANDBOX_IDENTITY_BAO_AUDIENCE";

/// The one transit key name, in an environment's own mount.
pub const TRANSIT_KEY_NAME: &str = "sandbox-identity";

#[derive(Debug, thiserror::Error)]
pub enum IdentityConfigError {
    #[error("{IDENTITY_ENABLED_ENV} must be `true` or `false`")]
    InvalidSwitch,
    #[error("{0} is required when {IDENTITY_ENABLED_ENV}=true")]
    Missing(&'static str),
    #[error(
        "{IDENTITY_ISSUER_BASE_ENV} must be an https URL with a DNS host name and no \
         credentials, query, fragment or trailing slash"
    )]
    InvalidIssuerBase,
    #[error("{IDENTITY_SIGNER_ENV}={0:?} is not a supported signer; use `openbao-transit`")]
    UnsupportedSigner(String),
    #[error("invalid sandbox identity OpenBao configuration: {0}")]
    InvalidOpenBao(String),
    #[error("{IDENTITY_MINTING_ENV} must be `on` or `off`")]
    InvalidMintingSwitch,
}

/// The operator's switch for minting. Unset or empty is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintingSwitch {
    On,
    Off,
}

impl MintingSwitch {
    pub fn from_env() -> Result<Self, IdentityConfigError> {
        Self::parse(std::env::var(IDENTITY_MINTING_ENV).ok().as_deref())
    }

    fn parse(value: Option<&str>) -> Result<Self, IdentityConfigError> {
        match value.map(str::trim) {
            None | Some("" | "on") => Ok(Self::On),
            Some("off") => Ok(Self::Off),
            Some(_) => Err(IdentityConfigError::InvalidMintingSwitch),
        }
    }
}

/// Whether this install issues sandbox identity, and how.
#[derive(Clone, Debug)]
pub enum IdentityConfig {
    Disabled,
    Enabled(Box<IdentitySettings>),
}

#[derive(Clone, Debug)]
pub struct IdentitySettings {
    pub issuer_base: IssuerBase,
    pub signer: SignerConfig,
}

/// Where the signing key lives. Each variant is chosen by name.
#[derive(Clone, Debug)]
pub enum SignerConfig {
    OpenBaoTransit(TransitKeyConfig),
}

/// The OpenBao transit key and the Kubernetes-auth role that reaches it.
#[derive(Clone, Debug)]
pub struct TransitKeyConfig {
    pub address: Url,
    pub auth_mount: String,
    pub role: String,
    pub transit_mount: String,
    pub expected_cluster_id: String,
}

/// The issuer base: `https://identity.example.com`, or a self-hosted
/// `https://codewire.example.com/identity`. Each org's issuer is
/// `{base}/orgs/{org id}`, built from this configuration alone.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuerBase(String);

impl IssuerBase {
    pub fn parse(value: &str) -> Result<Self, IdentityConfigError> {
        let invalid = || IdentityConfigError::InvalidIssuerBase;
        let url = Url::parse(value).map_err(|_| invalid())?;
        let dns_host = matches!(url.host(), Some(Host::Domain(host)) if host.contains('.'));
        if url.scheme() != "https"
            || !dns_host
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || (url.path() != "/" && url.path().ends_with('/'))
        {
            return Err(invalid());
        }
        // `Url` lowercases the scheme and host and drops a default port; the
        // stored form never ends in a slash, so `{base}/orgs/…` has one.
        let serialized = url.as_str();
        Ok(Self(
            serialized
                .strip_suffix('/')
                .unwrap_or(serialized)
                .to_owned(),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IssuerBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl IdentityConfig {
    pub fn from_env() -> Result<Self, IdentityConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, IdentityConfigError> {
        let present = |name: &'static str| lookup(name).filter(|value| !value.trim().is_empty());
        match present(IDENTITY_ENABLED_ENV).as_deref().map(str::trim) {
            None | Some("false") => return Ok(Self::Disabled),
            Some("true") => {}
            Some(_) => return Err(IdentityConfigError::InvalidSwitch),
        }
        let required = |name: &'static str| present(name).ok_or(IdentityConfigError::Missing(name));
        let issuer_base = IssuerBase::parse(required(IDENTITY_ISSUER_BASE_ENV)?.trim())?;
        let signer = match required(IDENTITY_SIGNER_ENV)?.trim() {
            "openbao-transit" => {
                SignerConfig::OpenBaoTransit(TransitKeyConfig::from_lookup(|name| {
                    present(name).map(|value| value.trim().to_owned())
                })?)
            }
            other => return Err(IdentityConfigError::UnsupportedSigner(other.to_owned())),
        };
        Ok(Self::Enabled(Box::new(IdentitySettings {
            issuer_base,
            signer,
        })))
    }
}

impl TransitKeyConfig {
    fn from_lookup(
        lookup: impl Fn(&'static str) -> Option<String>,
    ) -> Result<Self, IdentityConfigError> {
        let required = |name: &'static str| lookup(name).ok_or(IdentityConfigError::Missing(name));
        let invalid = |error: anyhow::Error| IdentityConfigError::InvalidOpenBao(error.to_string());
        // HTTPS only, in the cluster too: the login JWT, the token and the
        // cluster ID check never travel in clear.
        let address =
            parse_https_origin(BAO_ADDR_ENV, &required(BAO_ADDR_ENV)?).map_err(invalid)?;
        let config = Self {
            address,
            auth_mount: required(BAO_AUTH_MOUNT_ENV)?,
            role: required(BAO_ROLE_ENV)?,
            transit_mount: required(BAO_TRANSIT_MOUNT_ENV)?,
            expected_cluster_id: required(BAO_EXPECTED_CLUSTER_ID_ENV)?,
        };
        if !valid_openbao_segment(&config.auth_mount)
            || !valid_openbao_segment(&config.transit_mount)
            || !valid_openbao_role(&config.role)
            || !valid_openbao_authority(&config.expected_cluster_id)
        {
            return Err(IdentityConfigError::InvalidOpenBao(
                "mount, role or cluster id has an invalid shape".to_owned(),
            ));
        }
        Ok(config)
    }

    /// Required by the rotate command, which reads the same settings.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self::from_lookup(|name| {
            required_env(name).ok().map(|value| value.trim().to_owned())
        })?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn enabled_env() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            (IDENTITY_ENABLED_ENV, "true"),
            (IDENTITY_ISSUER_BASE_ENV, "https://identity.example.test"),
            (IDENTITY_SIGNER_ENV, "openbao-transit"),
            (BAO_ADDR_ENV, "https://openbao.example.test"),
            (BAO_AUTH_MOUNT_ENV, "cw-dev-k8s"),
            (BAO_ROLE_ENV, "sandbox-identity-signer-cw-dev"),
            (BAO_TRANSIT_MOUNT_ENV, "codewire-identity-dev"),
            (BAO_EXPECTED_CLUSTER_ID_ENV, "cluster-dev"),
        ])
    }

    fn parse(
        env: &HashMap<&'static str, &'static str>,
    ) -> Result<IdentityConfig, IdentityConfigError> {
        IdentityConfig::from_lookup(|name| env.get(name).map(|value| (*value).to_owned()))
    }

    #[test]
    fn minting_is_on_unless_switched_off() {
        for (value, switch) in [
            (None, MintingSwitch::On),
            (Some(""), MintingSwitch::On),
            (Some("on"), MintingSwitch::On),
            (Some("off"), MintingSwitch::Off),
            (Some(" off "), MintingSwitch::Off),
        ] {
            assert_eq!(MintingSwitch::parse(value).unwrap(), switch, "{value:?}");
        }
        for value in ["OFF", "false", "0", "disabled"] {
            assert!(
                matches!(
                    MintingSwitch::parse(Some(value)),
                    Err(IdentityConfigError::InvalidMintingSwitch)
                ),
                "{value}"
            );
        }
    }

    #[test]
    fn identity_is_off_unless_switched_on() {
        let mut env = enabled_env();
        env.remove(IDENTITY_ENABLED_ENV);
        assert!(matches!(parse(&env), Ok(IdentityConfig::Disabled)));
        env.insert(IDENTITY_ENABLED_ENV, "false");
        assert!(matches!(parse(&env), Ok(IdentityConfig::Disabled)));
        env.insert(IDENTITY_ENABLED_ENV, "yes");
        assert!(matches!(
            parse(&env),
            Err(IdentityConfigError::InvalidSwitch)
        ));
    }

    #[test]
    fn the_signer_and_rotator_reach_openbao_only_over_https() {
        // Confidential storage still admits in-cluster HTTP; the issuer never.
        for address in [
            "http://openbao.openbao.svc.cluster.local:8200",
            "http://127.0.0.1:8200",
            "http://openbao.example.test",
        ] {
            let mut env = enabled_env();
            env.insert(BAO_ADDR_ENV, address);
            assert!(
                matches!(parse(&env), Err(IdentityConfigError::InvalidOpenBao(_))),
                "{address}"
            );
        }
        let mut env = enabled_env();
        env.insert(
            BAO_ADDR_ENV,
            "https://openbao.openbao.svc.cluster.local:8200",
        );
        assert!(matches!(parse(&env), Ok(IdentityConfig::Enabled(_))));
    }

    #[test]
    fn switching_identity_on_needs_an_issuer_and_an_explicit_signer() {
        let Ok(IdentityConfig::Enabled(settings)) = parse(&enabled_env()) else {
            panic!("the complete configuration enables identity");
        };
        assert_eq!(
            settings.issuer_base.as_str(),
            "https://identity.example.test"
        );
        for name in [IDENTITY_ISSUER_BASE_ENV, IDENTITY_SIGNER_ENV, BAO_ROLE_ENV] {
            let mut env = enabled_env();
            env.remove(name);
            assert!(
                matches!(parse(&env), Err(IdentityConfigError::Missing(missing)) if missing == name),
                "{name} is required"
            );
        }
        let mut env = enabled_env();
        env.insert(IDENTITY_SIGNER_ENV, "local-key");
        assert!(matches!(
            parse(&env),
            Err(IdentityConfigError::UnsupportedSigner(_))
        ));
    }

    #[test]
    fn the_issuer_base_is_an_https_dns_origin_with_an_optional_path() {
        for (value, expected) in [
            (
                "https://identity.example.test",
                "https://identity.example.test",
            ),
            (
                "https://identity.example.test/",
                "https://identity.example.test",
            ),
            (
                "HTTPS://Identity.Example.TEST:443",
                "https://identity.example.test",
            ),
            (
                "https://codewire.example.test/identity",
                "https://codewire.example.test/identity",
            ),
            (
                "https://codewire.example.test:8443/identity",
                "https://codewire.example.test:8443/identity",
            ),
        ] {
            assert_eq!(
                IssuerBase::parse(value).unwrap().as_str(),
                expected,
                "{value}"
            );
        }
        for value in [
            "http://identity.example.test",
            "https://10.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://user@identity.example.test",
            "https://identity.example.test/?a=b",
            "https://identity.example.test/#f",
            "https://codewire.example.test/identity/",
            "identity.example.test",
        ] {
            assert!(IssuerBase::parse(value).is_err(), "{value} is refused");
        }
    }
}
