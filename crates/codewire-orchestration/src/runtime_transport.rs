//! Runtime transport-zone registry (#339).
//!
//! Infra declares zone capabilities; Codewire stores the validated catalog and
//! selects a zone after Kubernetes places the workspace Pod.

use std::collections::BTreeSet;
use std::net::IpAddr;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

pub const RUNTIME_REGION_LABEL: &str = "node.codewire.sh/runtime-region";
pub const TRANSPORT_ZONE_LABEL: &str = "node.codewire.sh/transport-zone";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeTransportCatalog {
    #[serde(default = "catalog_version")]
    pub version: i32,
    #[serde(default)]
    pub zones: Vec<RuntimeTransportZone>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeTransportZone {
    pub name: String,
    pub runtime_region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_relay: Option<PeerRelayTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_udp: Option<DirectUdpTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun: Option<EndpointList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp: Option<EndpointList>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRelayTransport {
    #[serde(default)]
    pub public_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    #[serde(default)]
    pub allocator_url: String,
    #[serde(default)]
    pub bind_addrs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectUdpTransport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_start: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_end: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointList {
    #[serde(default)]
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeTransportBinding {
    pub runtime_region: String,
    pub transport_zone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_relay: Option<PeerRelayTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_udp: Option<DirectUdpTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun: Option<EndpointList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derp: Option<EndpointList>,
}

fn catalog_version() -> i32 {
    1
}

fn default_enabled() -> bool {
    true
}

impl RuntimeTransportZone {
    pub fn binding(&self) -> RuntimeTransportBinding {
        RuntimeTransportBinding {
            runtime_region: self.runtime_region.clone(),
            transport_zone: self.name.clone(),
            peer_relay: self.peer_relay.clone(),
            direct_udp: self.direct_udp.clone(),
            stun: self.stun.clone(),
            derp: self.derp.clone(),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        let name = self.name.trim();
        anyhow::ensure!(!name.is_empty(), "runtime transport zone name is required");
        anyhow::ensure!(
            !self.runtime_region.trim().is_empty(),
            "runtime transport zone {name} requires runtime_region"
        );

        if let Some(peer_relay) = &self.peer_relay {
            for endpoint in &peer_relay.public_endpoints {
                validate_host_port("peer_relay.public_endpoints", endpoint)
                    .with_context(|| format!("runtime transport zone {name}"))?;
            }
            if !peer_relay.allocator_url.trim().is_empty() {
                let url = url::Url::parse(peer_relay.allocator_url.trim()).with_context(|| {
                    format!("runtime transport zone {name} peer_relay.allocator_url")
                })?;
                anyhow::ensure!(
                    matches!(url.scheme(), "http" | "https"),
                    "runtime transport zone {name} peer_relay.allocator_url must be http(s)"
                );
            }
            for bind_addr in &peer_relay.bind_addrs {
                validate_host_port("peer_relay.bind_addrs", bind_addr)
                    .with_context(|| format!("runtime transport zone {name}"))?;
            }
        }

        if let Some(direct_udp) = &self.direct_udp {
            if let Some(vip) = direct_udp.vip.as_deref() {
                let vip = vip.trim();
                anyhow::ensure!(
                    !vip.is_empty(),
                    "runtime transport zone {name} direct_udp.vip is empty"
                );
                vip.parse::<IpAddr>()
                    .with_context(|| format!("runtime transport zone {name} direct_udp.vip"))?;
            }
            if let (Some(start), Some(end)) = (direct_udp.port_start, direct_udp.port_end) {
                validate_udp_port(start, "direct_udp.port_start")
                    .with_context(|| format!("runtime transport zone {name}"))?;
                validate_udp_port(end, "direct_udp.port_end")
                    .with_context(|| format!("runtime transport zone {name}"))?;
                anyhow::ensure!(
                    start <= end,
                    "runtime transport zone {name} direct_udp port_start is greater than port_end"
                );
            }
        }

        if let Some(stun) = &self.stun {
            for endpoint in &stun.endpoints {
                validate_host_port("stun.endpoints", endpoint)
                    .with_context(|| format!("runtime transport zone {name}"))?;
            }
        }
        if let Some(derp) = &self.derp {
            for endpoint in &derp.endpoints {
                anyhow::ensure!(
                    !endpoint.trim().is_empty(),
                    "runtime transport zone {name} derp endpoint is empty"
                );
            }
        }

        Ok(())
    }
}

pub fn parse_catalog(raw: &str) -> anyhow::Result<RuntimeTransportCatalog> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(RuntimeTransportCatalog::default());
    }
    let catalog: RuntimeTransportCatalog =
        serde_json::from_str(raw).context("parse CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON")?;
    anyhow::ensure!(
        catalog.version == 1,
        "CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON version {} is not supported",
        catalog.version
    );

    let mut names = BTreeSet::new();
    for zone in &catalog.zones {
        zone.validate()?;
        anyhow::ensure!(
            names.insert(zone.name.clone()),
            "duplicate runtime transport zone {}",
            zone.name
        );
    }
    Ok(catalog)
}

pub async fn sync_catalog_json(
    pool: &PgPool,
    raw: &str,
) -> anyhow::Result<Vec<RuntimeTransportZone>> {
    let catalog = parse_catalog(raw)?;
    for zone in &catalog.zones {
        let peer_relay = serde_json::to_value(&zone.peer_relay)
            .context("serialize runtime transport peer_relay")?;
        let direct_udp =
            serde_json::to_value(&zone.direct_udp).context("serialize runtime direct_udp")?;
        let stun = serde_json::to_value(&zone.stun).context("serialize runtime stun")?;
        let derp = serde_json::to_value(&zone.derp).context("serialize runtime derp")?;

        sqlx::query(
            r#"INSERT INTO runtime_transport_zones
                   (name, runtime_region, peer_relay, direct_udp, stun, derp, enabled)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (name) DO UPDATE SET
                   runtime_region = EXCLUDED.runtime_region,
                   peer_relay = EXCLUDED.peer_relay,
                   direct_udp = EXCLUDED.direct_udp,
                   stun = EXCLUDED.stun,
                   derp = EXCLUDED.derp,
                   enabled = EXCLUDED.enabled,
                   updated_at = now()"#,
        )
        .bind(&zone.name)
        .bind(&zone.runtime_region)
        .bind(peer_relay)
        .bind(direct_udp)
        .bind(stun)
        .bind(derp)
        .bind(zone.enabled)
        .execute(pool)
        .await
        .with_context(|| format!("upsert runtime transport zone {}", zone.name))?;
    }
    Ok(catalog.zones)
}

pub async fn load_enabled_zone(
    pool: &PgPool,
    name: &str,
) -> anyhow::Result<Option<RuntimeTransportZone>> {
    let row: Option<(
        String,
        String,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
        bool,
    )> = sqlx::query_as(
        r#"SELECT name, runtime_region, peer_relay, direct_udp, stun, derp, enabled
           FROM runtime_transport_zones
           WHERE name = $1 AND enabled = true"#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await
    .with_context(|| format!("load runtime transport zone {name}"))?;

    row.map(
        |(name, runtime_region, peer_relay, direct_udp, stun, derp, enabled)| -> anyhow::Result<_> {
            let zone = RuntimeTransportZone {
                name,
                runtime_region,
                peer_relay: serde_json::from_value(peer_relay)
                    .context("decode runtime transport peer_relay")?,
                direct_udp: serde_json::from_value(direct_udp)
                    .context("decode runtime transport direct_udp")?,
                stun: serde_json::from_value(stun).context("decode runtime transport stun")?,
                derp: serde_json::from_value(derp).context("decode runtime transport derp")?,
                enabled,
            };
            zone.validate()?;
            Ok(zone)
        },
    )
    .transpose()
}

fn validate_host_port(field: &str, endpoint: &str) -> anyhow::Result<()> {
    let endpoint = endpoint.trim();
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("{field} entry {endpoint:?} must be host:port"))?;
    anyhow::ensure!(
        !host.trim().is_empty(),
        "{field} entry {endpoint:?} has empty host"
    );
    let port = port
        .parse::<i32>()
        .with_context(|| format!("{field} entry {endpoint:?} has invalid port"))?;
    validate_udp_port(port, field)
}

fn validate_udp_port(port: i32, field: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=65535).contains(&port),
        "{field} must be a UDP port from 1 to 65535"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_CATALOG: &str = r#"{
      "version": 1,
      "zones": [
        {
          "name": "example-zone",
          "runtime_region": "dev-eu",
          "peer_relay": {
            "public_endpoints": ["203.0.113.35:41641"],
            "dns": "example-zone.mesh.codewire-dev.sh",
            "allocator_url": "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations",
            "bind_addrs": ["codewire-udp-relay.dev.svc.cluster.local:41641"]
          },
          "direct_udp": {
            "vip": "203.0.113.36",
            "port_start": 32000,
            "port_end": 60999
          },
          "stun": { "endpoints": ["stun.codewire-dev.sh:3478"] },
          "derp": { "endpoints": ["derp.codewire-dev.sh"] }
        }
      ]
    }"#;

    #[test]
    fn parses_dev_catalog() {
        let catalog = parse_catalog(DEV_CATALOG).unwrap();
        assert_eq!(catalog.zones.len(), 1);
        let zone = &catalog.zones[0];
        assert_eq!(zone.name, "example-zone");
        assert_eq!(zone.runtime_region, "dev-eu");
        assert_eq!(
            zone.peer_relay.as_ref().unwrap().public_endpoints,
            vec!["203.0.113.35:41641"]
        );
        assert_eq!(zone.binding().transport_zone, "example-zone");
    }

    #[test]
    fn rejects_duplicate_zone_names() {
        let raw = r#"{
          "version": 1,
          "zones": [
            {"name":"example-zone","runtime_region":"dev-eu"},
            {"name":"example-zone","runtime_region":"dev-eu"}
          ]
        }"#;
        assert!(parse_catalog(raw).is_err());
    }

    #[test]
    fn rejects_bad_peer_relay_endpoint() {
        let raw = r#"{
          "version": 1,
          "zones": [
            {
              "name":"example-zone",
              "runtime_region":"dev-eu",
              "peer_relay": {"public_endpoints":["203.0.113.35"]}
            }
          ]
        }"#;
        assert!(parse_catalog(raw).is_err());
    }
}
