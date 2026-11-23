//! The Trustee key broker a confidential guest attests to (#4000).
//!
//! A broker-mode workspace resolves no names, so its guest may dial the key
//! broker at a fixed address rather than a Service name. Such a URL names no
//! namespace, and a policy rule on a ClusterIP never matches: Cilium applies
//! policy after it translates the Service address. So the egress rule names
//! the key broker's Pods, a namespace and Pod labels matched together, from
//! deployment configuration.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::{Value, json};

/// `NAMESPACE:key=value[,key=value...]`: the key broker's Pods.
const KBS_PEER_ENV: &str = "SANDBOX_KATA_COCO_KBS_PEER";

/// The key broker's Pods, the one peer a confidential workspace's KBS rule
/// names when it is configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KbsPeer {
    pub namespace: String,
    pub labels: BTreeMap<String, String>,
}

impl KbsPeer {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let (namespace, labels) = value
            .trim()
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("{KBS_PEER_ENV} must be NAMESPACE:key=value,..."))?;
        anyhow::ensure!(
            is_dns_label(namespace),
            "{KBS_PEER_ENV} namespace {namespace:?} is not a namespace name"
        );
        let mut parsed = BTreeMap::new();
        for pair in labels.split(',') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("{KBS_PEER_ENV} label {pair:?} is not key=value"))?;
            anyhow::ensure!(
                is_label_key(key) && is_label_name(value),
                "{KBS_PEER_ENV} label {pair:?} is not a Kubernetes label"
            );
            anyhow::ensure!(
                parsed.insert(key.to_string(), value.to_string()).is_none(),
                "{KBS_PEER_ENV} names label {key:?} twice"
            );
        }
        Ok(Self {
            namespace: namespace.to_string(),
            labels: parsed,
        })
    }

    /// One peer, so the namespace AND the labels must both match: a Pod in
    /// the namespace without the labels is not admitted.
    pub(super) fn egress_rule(&self, kbs_url: &str) -> Option<Value> {
        let port = url::Url::parse(kbs_url.trim())
            .ok()?
            .port_or_known_default()?;
        Some(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": self.namespace } },
                    "podSelector": { "matchLabels": self.labels },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": i64::from(port) },
            ],
        }))
    }
}

/// The key-broker settings orchestration renders into confidential
/// templates, read once at startup.
pub struct KbsSettings {
    pub url: String,
    pub ca_pem: String,
    pub peer: Option<KbsPeer>,
}

impl KbsSettings {
    /// Panics on settings no confidential workspace could boot with, so a bad
    /// deployment fails at rollout rather than at the first create.
    pub fn from_env(getenv: &dyn Fn(&str, &str) -> String) -> Self {
        let url = getenv(
            "SANDBOX_KATA_COCO_KBS_URL",
            &getenv("CONFIDENTIAL_STORAGE_KBS_URL", ""),
        );
        let ca_path = getenv("CONFIDENTIAL_STORAGE_KBS_CA_PATH", "");
        let ca_pem = if ca_path.is_empty() {
            String::new()
        } else {
            std::fs::read_to_string(&ca_path).unwrap_or_else(|error| {
                panic!("failed to read public confidential-storage KBS CA at {ca_path}: {error}")
            })
        };
        let peer = Some(getenv(KBS_PEER_ENV, ""))
            .filter(|value| !value.is_empty())
            .map(|value| KbsPeer::parse(&value).unwrap_or_else(|error| panic!("{error}")));
        if let Err(error) = require_peer_for_address(&url, peer.as_ref()) {
            panic!("{error}");
        }
        Self { url, ca_pem, peer }
    }
}

/// A URL whose host is an address names no namespace, so without a
/// configured peer its workspace would get no path to the key broker.
fn require_peer_for_address(kbs_url: &str, peer: Option<&KbsPeer>) -> anyhow::Result<()> {
    let Ok(parsed) = url::Url::parse(kbs_url.trim()) else {
        return Ok(());
    };
    let is_address = parsed
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .is_some_and(|host| host.parse::<IpAddr>().is_ok());
    anyhow::ensure!(
        !is_address || peer.is_some(),
        "SANDBOX_KATA_COCO_KBS_URL is an address, so {KBS_PEER_ENV} must name the key broker's Pods"
    );
    Ok(())
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// A label name or value: at most 63 characters, alphanumeric at both ends,
/// with `-`, `_` and `.` between. Empty is refused here.
fn is_label_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && value
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric())
}

/// An optional DNS-subdomain prefix and `/`, then a label name.
fn is_label_key(key: &str) -> bool {
    match key.split_once('/') {
        Some((prefix, name)) => {
            prefix.len() <= 253 && prefix.split('.').all(is_dns_label) && is_label_name(name)
        }
        None => is_label_name(key),
    }
}

#[cfg(test)]
#[path = "kbs_tests.rs"]
mod tests;
