//! The deployment settings for hosted egress (#4000) and hosted interception
//! (#4001). All are read once at startup; a value that does not parse fails
//! startup.

use std::net::Ipv4Addr;

use crate::sandbox::template::{GatewayPeer, HostedEgressTemplate};

/// Serves `EgressService` when `true`. Off unless a deployment turns it on.
pub const SWITCH: &str = "CODEWIRE_HOSTED_EGRESS_ENABLED";
/// Destinations every broker-mode sandbox would reach whatever its policy.
/// No deployment sets one: a broker-mode daemon reaches the platform's own
/// services inside the cluster (decided 2026-11-15 on #4000). Nothing
/// enforces an entry yet, so while hosted egress is on a non-empty list stops
/// startup rather than look configured and do nothing.
pub const PLATFORM_ALLOWS: &str = "CODEWIRE_EGRESS_PLATFORM_ALLOWS";
/// Turns on credential interception for broker-mode sandboxes when `true`
/// (#4001). Off unless a deployment turns it on, and only with hosted egress
/// on: interception runs in cw-egress's front door. Hosted has no per-host
/// switch; this is its rollout.
pub const INTERCEPTION_SWITCH: &str = "CODEWIRE_HOSTED_INTERCEPTION_ENABLED";

/// The public gateway's proxy Pods, as the warm-pool admission policy reads
/// them from the same ConfigMap.
pub const GATEWAY_NAMESPACE: &str = "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAMESPACE";
pub const GATEWAY_NAME: &str = "CODEWIRE_HOSTED_EGRESS_GATEWAY_NAME";
pub const GATEWAY_OWNER_NAMESPACE: &str = "CODEWIRE_HOSTED_EGRESS_GATEWAY_OWNER_NAMESPACE";
pub const GATEWAY_PORT: &str = "CODEWIRE_HOSTED_EGRESS_GATEWAY_PORT";
/// The gateway Service's ClusterIP, which deploy pins on the Service and
/// asserts equal to this value (cw-security, 2026-11-19 on #4000).
pub const GATEWAY_CLUSTER_IP: &str = "CODEWIRE_HOSTED_EGRESS_GATEWAY_CLUSTER_IP";
/// The gateway Service orchestration reads to hold that address equal to its
/// ClusterIP, in the proxies' namespace (`GATEWAY_NAMESPACE`).
pub const GATEWAY_SERVICE: &str = "CODEWIRE_HOSTED_EGRESS_GATEWAY_SERVICE";
/// The infra#1822 fence revision the cluster runs.
pub const FENCE_REVISION: &str = "CODEWIRE_HOSTED_EGRESS_FENCE_REVISION";
/// The cluster DNS Service's IPv4 address, for the self-check's DNS probe.
pub const CLUSTER_DNS_IP: &str = "CODEWIRE_CLUSTER_DNS_IP";
/// Every `codewire-hosted-egress` key whose absence stops orchestration's
/// startup while hosted egress is on, and no other. A deployment's policy can
/// read this list from the source it delivers and refuse a switch-on whose
/// ConfigMap lacks one (#4000: a switch-on with two missing crash-looped
/// orchestration). The test below holds it to [`startup`], the one read.
/// With the switch off, these are the broker settings: read only when every
/// one is set (#6070), so a deployment that keeps them serves its broker
/// Sandboxes, and one without any of them serves none.
pub const REQUIRED_WHEN_ON: [&str; 8] = [
    GATEWAY_NAMESPACE,
    GATEWAY_NAME,
    GATEWAY_OWNER_NAMESPACE,
    GATEWAY_PORT,
    GATEWAY_CLUSTER_IP,
    GATEWAY_SERVICE,
    FENCE_REVISION,
    CLUSTER_DNS_IP,
];

/// The Services in orchestration's own namespace a broker-mode Sandbox dials,
/// each as Kubernetes names its Service-link variables: the Service's name
/// and the port's.
const STREAM_LINK: (&str, &str) = ("CODEWIRE_EGRESS", "STREAM");
const BINDING_LINK: (&str, &str) = ("CODEWIRE_ORCHESTRATION_WORKSPACE_BINDING", "WORKSPACE_BIND");
const DERP_LINK: (&str, &str) = ("CODEWIRE_DERP", "HTTPS");

/// Everything orchestration reads for hosted egress, read once at startup: the
/// switches, what every broker-mode template renders, and the gateway Service
/// its address is held to. Startup reads hosted egress only through
/// [`startup`], so a setting this read refuses to go without is one startup
/// refuses to go without.
#[derive(Debug)]
pub struct Startup {
    pub settings: EgressSettings,
    /// `None` while the broker settings are not read ([`broker_configured`]).
    pub template: Option<HostedEgressTemplate>,
    /// `None` while the broker settings are not read.
    pub gateway: Option<crate::egress::gateway_check::GatewayService>,
}

/// [`Startup`] from the process environment. A switch or list that is not
/// UTF-8 is refused rather than read as unset.
pub fn startup(derp_host: &str) -> anyhow::Result<Startup> {
    for key in [SWITCH, PLATFORM_ALLOWS, INTERCEPTION_SWITCH] {
        crate::confidential_storage::env_setting(key)?;
    }
    startup_from(|key| std::env::var(key).ok(), derp_host)
}

fn startup_from(get: impl Fn(&str) -> Option<String>, derp_host: &str) -> anyhow::Result<Startup> {
    let missing = missing_broker_settings(&get);
    if !broker_configured(&get)? && missing.len() < REQUIRED_WHEN_ON.len() {
        tracing::info!(
            ?missing,
            "hosted egress is off and its broker settings are set only in part: broker-mode Sandboxes are not served"
        );
    }
    Ok(Startup {
        settings: EgressSettings::from_values(
            get(SWITCH).as_deref(),
            get(PLATFORM_ALLOWS).as_deref(),
            get(INTERCEPTION_SWITCH).as_deref(),
        )?,
        template: template_from(&get, derp_host)?,
        gateway: gateway_service_from(&get)?,
    })
}

/// A setting's value, trimmed; an empty one is unset.
fn set(get: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The keys of [`REQUIRED_WHEN_ON`] that are not set.
fn missing_broker_settings(get: &impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    REQUIRED_WHEN_ON
        .into_iter()
        .filter(|key| set(get, key).is_none())
        .collect()
}

/// Whether the broker settings are read (#6070): always with the switch on,
/// where each is required, and with it off only when every one is set. Then
/// they are read and checked exactly as with it on, so a broker Sandbox is
/// rendered and served from them whatever the switch says. Removing any of
/// them with the switch off stops broker egress (`own_mode`).
fn broker_configured(get: &impl Fn(&str) -> Option<String>) -> anyhow::Result<bool> {
    Ok(
        crate::confidential_storage::parse_bool(SWITCH, set(get, SWITCH).as_deref(), false)?
            || missing_broker_settings(get).is_empty(),
    )
}

/// The gateway Service and its configured address, which
/// `egress::gateway_check` holds equal while the broker settings are read;
/// `None` while they are not.
fn gateway_service_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<crate::egress::gateway_check::GatewayService>> {
    let value = |key: &str| set(&get, key);
    if !broker_configured(&get)? {
        return Ok(None);
    }
    let required = |key: &str| {
        value(key).ok_or_else(|| anyhow::anyhow!("{SWITCH} is on but {key} is not set"))
    };
    let address = required(GATEWAY_CLUSTER_IP)?;
    Ok(Some(crate::egress::gateway_check::GatewayService {
        namespace: required(GATEWAY_NAMESPACE)?,
        name: required(GATEWAY_SERVICE)?,
        cluster_ip: address.parse().map_err(|_| {
            anyhow::anyhow!("{GATEWAY_CLUSTER_IP} must be a bare IPv4 address, not {address:?}")
        })?,
    }))
}

/// What every broker-mode template renders, or `None` while the broker
/// settings are not read (#4000, item 3; [`broker_configured`]). Once they
/// are, a missing or malformed setting fails startup, named. The three in-namespace Services come from the Service
/// links Kubernetes gives orchestration's Pod when it starts, so no Service is
/// read through the API. A link that is absent leaves its address empty, and
/// every broker-mode render then fails naming the Service
/// (`TemplateOpts::validate_hosted_egress`); a Service created or re-created
/// later is seen at orchestration's next rollout, and until then new
/// Sandboxes fail closed.
fn template_from(
    get: impl Fn(&str) -> Option<String>,
    derp_host: &str,
) -> anyhow::Result<Option<HostedEgressTemplate>> {
    let value = |key: &str| set(&get, key);
    if !broker_configured(&get)? {
        return Ok(None);
    }
    let required = |key: &str| {
        value(key).ok_or_else(|| anyhow::anyhow!("{SWITCH} is on but {key} is not set"))
    };
    let ipv4 = |key: &str| -> anyhow::Result<Ipv4Addr> {
        let raw = required(key)?;
        raw.parse()
            .map_err(|_| anyhow::anyhow!("{key} must be a bare IPv4 address, not {raw:?}"))
    };
    let port = |key: &str, raw: &str| -> anyhow::Result<u16> {
        raw.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| anyhow::anyhow!("{key} must be a port, not {raw:?}"))
    };
    let fence_revision = required(FENCE_REVISION)?;
    anyhow::ensure!(
        fence_revision.bytes().all(|byte| byte.is_ascii_digit()),
        "{FENCE_REVISION} must be the fence's revision number, not {fence_revision:?}"
    );
    anyhow::ensure!(
        !derp_host.is_empty(),
        "the hosted egress broker settings are read but DERP_HOST is not set"
    );
    let gateway = GatewayPeer {
        namespace: required(GATEWAY_NAMESPACE)?,
        gateway_name: required(GATEWAY_NAME)?,
        gateway_namespace: required(GATEWAY_OWNER_NAMESPACE)?,
        port: port(GATEWAY_PORT, &required(GATEWAY_PORT)?)?,
    };
    // A link is its ClusterIP and the named port; one present but malformed
    // fails startup, one absent leaves the address empty.
    let link = |(service, port_name): (&str, &str)| -> anyhow::Result<Option<(Ipv4Addr, u16)>> {
        let host_key = format!("{service}_SERVICE_HOST");
        let port_key = format!("{service}_SERVICE_PORT_{port_name}");
        match (value(&host_key), value(&port_key)) {
            (None, None) => Ok(None),
            (Some(host), Some(raw)) => {
                let ip = host
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{host_key} must be a ClusterIP, not {host:?}"))?;
                Ok(Some((ip, port(&port_key, &raw)?)))
            }
            _ => anyhow::bail!("{host_key} and {port_key} must come together"),
        }
    };
    let addr = |found: Option<(Ipv4Addr, u16)>| {
        found
            .map(|(ip, port)| format!("{ip}:{port}"))
            .unwrap_or_default()
    };
    let derp = link(DERP_LINK)?;
    Ok(Some(HostedEgressTemplate {
        stream_addr: addr(link(STREAM_LINK)?),
        binding_addr: addr(link(BINDING_LINK)?),
        fence_revision,
        gateway,
        derp_tls_port: derp.map(|(_, port)| port).unwrap_or_default(),
        gateway_addr: format!("{}:443", ipv4(GATEWAY_CLUSTER_IP)?),
        derp_addr: derp
            .map(|(ip, port)| format!("{derp_host}={ip}:{port}"))
            .unwrap_or_default(),
        cluster_dns_ip: ipv4(CLUSTER_DNS_IP)?.to_string(),
    }))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressSettings {
    pub enabled: bool,
    /// Whether a broker-mode sandbox's bind response turns interception on.
    pub interception: bool,
}

impl EgressSettings {
    fn from_values(
        enabled: Option<&str>,
        platform: Option<&str>,
        interception: Option<&str>,
    ) -> anyhow::Result<Self> {
        let enabled = crate::confidential_storage::parse_bool(SWITCH, enabled, false)?;
        let interception =
            crate::confidential_storage::parse_bool(INTERCEPTION_SWITCH, interception, false)?;
        if interception && !enabled {
            anyhow::bail!("{INTERCEPTION_SWITCH} is on but {SWITCH} is off");
        }
        if !enabled {
            // The list is read only where it is used: a deployment with hosted
            // egress off never fails on it.
            return Ok(Self::default());
        }
        let named = platform
            .unwrap_or_default()
            .split(',')
            .any(|entry| !entry.trim().is_empty());
        if named {
            anyhow::bail!(
                "{PLATFORM_ALLOWS} names a destination, but platform allows are not enforced yet; leave it unset"
            );
        }
        Ok(Self {
            enabled,
            interception,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    const DERP_HOST: &str = "derp.codewire-dev.sh";

    /// A deployment with hosted egress on and every Service linked.
    fn on() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            (SWITCH, "true"),
            (GATEWAY_NAMESPACE, "gateway-proxies"),
            (GATEWAY_NAME, "public"),
            (GATEWAY_OWNER_NAMESPACE, "gateway"),
            (GATEWAY_PORT, "10443"),
            (GATEWAY_CLUSTER_IP, "10.44.0.43"),
            (FENCE_REVISION, "2"),
            (CLUSTER_DNS_IP, "10.44.0.10"),
            ("CODEWIRE_EGRESS_SERVICE_HOST", "10.44.0.89"),
            ("CODEWIRE_EGRESS_SERVICE_PORT_STREAM", "8089"),
            (
                "CODEWIRE_ORCHESTRATION_WORKSPACE_BINDING_SERVICE_HOST",
                "10.44.0.87",
            ),
            (
                "CODEWIRE_ORCHESTRATION_WORKSPACE_BINDING_SERVICE_PORT_WORKSPACE_BIND",
                "8087",
            ),
            ("CODEWIRE_DERP_SERVICE_HOST", "10.44.0.84"),
            ("CODEWIRE_DERP_SERVICE_PORT_HTTPS", "8443"),
        ])
    }

    fn read(values: &HashMap<&str, &str>) -> anyhow::Result<Option<HostedEgressTemplate>> {
        template_from(|key| values.get(key).map(|v| (*v).to_owned()), DERP_HOST)
    }

    #[test]
    fn the_gateway_service_is_read_with_its_address_and_named_when_missing() {
        let mut values = on();
        values.insert(GATEWAY_SERVICE, "envoy-codewire-public");
        fn get(
            values: &HashMap<&'static str, &'static str>,
        ) -> impl Fn(&str) -> Option<String> + use<> {
            let values = values.clone();
            move |key: &str| values.get(key).map(|v| (*v).to_owned())
        }
        assert_eq!(
            gateway_service_from(get(&values)).unwrap(),
            Some(crate::egress::gateway_check::GatewayService {
                namespace: "gateway-proxies".into(),
                name: "envoy-codewire-public".into(),
                cluster_ip: Ipv4Addr::new(10, 44, 0, 43),
            })
        );
        values.remove(GATEWAY_SERVICE);
        let error = gateway_service_from(get(&values)).unwrap_err().to_string();
        assert!(error.contains(GATEWAY_SERVICE), "{error}");
        assert_eq!(gateway_service_from(get(&HashMap::new())).unwrap(), None);
    }

    #[test]
    fn off_renders_no_broker_mode_and_reads_nothing_else() {
        assert_eq!(read(&HashMap::new()).unwrap(), None);
        // A malformed value beside the switch off is never read.
        assert_eq!(
            read(&HashMap::from([(SWITCH, "false"), (CLUSTER_DNS_IP, "::1")])).unwrap(),
            None
        );
    }

    /// #6070: with the switch off, the broker settings are read exactly as
    /// with it on once every one is set, and not at all while any is missing,
    /// whatever the others hold.
    #[test]
    fn off_reads_the_broker_settings_only_when_every_one_is_set() {
        let mut off = on();
        off.insert(SWITCH, "false");
        off.insert(GATEWAY_SERVICE, "envoy-codewire-public");
        let gateway = |values: &HashMap<&'static str, &'static str>| {
            let values = values.clone();
            gateway_service_from(move |key: &str| values.get(key).map(|v| (*v).to_owned()))
        };
        assert_eq!(read(&off).unwrap(), read(&on()).unwrap());
        assert!(read(&off).unwrap().is_some());
        assert!(gateway(&off).unwrap().is_some());
        for key in REQUIRED_WHEN_ON {
            let mut partial = off.clone();
            partial.remove(key);
            if key != CLUSTER_DNS_IP {
                partial.insert(CLUSTER_DNS_IP, "fd00::a");
            }
            assert_eq!(read(&partial).unwrap(), None, "{key}");
            assert_eq!(gateway(&partial).unwrap(), None, "{key}");
        }
        // Every one set and one malformed fails startup by name, as on.
        let mut malformed = off.clone();
        malformed.insert(CLUSTER_DNS_IP, "fd00::a");
        let error = read(&malformed).unwrap_err().to_string();
        assert!(error.contains(CLUSTER_DNS_IP), "{error}");
        // The settings a deployment has with the switch off and the fence
        // revision and cluster DNS address not set start with none read.
        let mut gateway_only = off.clone();
        gateway_only.remove(FENCE_REVISION);
        gateway_only.remove(CLUSTER_DNS_IP);
        let started = startup_from(
            |key| gateway_only.get(key).map(|v| (*v).to_owned()),
            DERP_HOST,
        )
        .unwrap();
        assert_eq!(started.template, None);
        assert_eq!(started.gateway, None);
        assert!(!started.settings.enabled);
    }

    #[test]
    fn on_renders_every_address_by_its_literal() {
        assert_eq!(
            read(&on()).unwrap(),
            Some(HostedEgressTemplate {
                stream_addr: "10.44.0.89:8089".into(),
                binding_addr: "10.44.0.87:8087".into(),
                fence_revision: "2".into(),
                gateway: GatewayPeer {
                    namespace: "gateway-proxies".into(),
                    gateway_name: "public".into(),
                    gateway_namespace: "gateway".into(),
                    port: 10443,
                },
                derp_tls_port: 8443,
                gateway_addr: "10.44.0.43:443".into(),
                derp_addr: "derp.codewire-dev.sh=10.44.0.84:8443".into(),
                cluster_dns_ip: "10.44.0.10".into(),
            })
        );
    }

    #[test]
    fn a_missing_or_malformed_setting_fails_startup_by_name() {
        for key in [
            GATEWAY_NAMESPACE,
            GATEWAY_NAME,
            GATEWAY_OWNER_NAMESPACE,
            GATEWAY_PORT,
            GATEWAY_CLUSTER_IP,
            FENCE_REVISION,
            CLUSTER_DNS_IP,
        ] {
            let mut values = on();
            values.remove(key);
            let error = read(&values).unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
        for (key, bad) in [
            // IPv4 literals only: no IPv6, no name, no port.
            (CLUSTER_DNS_IP, "fd00::a"),
            (CLUSTER_DNS_IP, "kube-dns.kube-system"),
            (CLUSTER_DNS_IP, "10.44.0.10:53"),
            (GATEWAY_CLUSTER_IP, "gateway.public"),
            (GATEWAY_CLUSTER_IP, "fd00::43"),
            (FENCE_REVISION, "two"),
            (GATEWAY_PORT, "0"),
            ("CODEWIRE_EGRESS_SERVICE_HOST", "codewire-egress"),
            ("CODEWIRE_EGRESS_SERVICE_PORT_STREAM", "stream"),
        ] {
            let mut values = on();
            values.insert(key, bad);
            let error = read(&values).unwrap_err().to_string();
            assert!(error.contains(key), "{key}={bad}: {error}");
        }
        let half = {
            let mut values = on();
            values.remove("CODEWIRE_DERP_SERVICE_PORT_HTTPS");
            values
        };
        assert!(
            read(&half)
                .unwrap_err()
                .to_string()
                .contains("must come together")
        );
        assert!(
            template_from(|key| on().get(key).map(|v| (*v).to_owned()), "")
                .unwrap_err()
                .to_string()
                .contains("DERP_HOST")
        );
    }

    #[test]
    fn the_required_list_is_exactly_what_startup_refuses_to_go_without() {
        // Every ConfigMap key a deployment with hosted egress on sets; the
        // Service links come from Kubernetes, not the ConfigMap.
        let mut full = on();
        full.insert(GATEWAY_SERVICE, "envoy-codewire-public");
        let starts = |values: &HashMap<&str, &str>| {
            startup_from(|key| values.get(key).map(|v| (*v).to_owned()), DERP_HOST).is_ok()
        };
        assert!(starts(&full));
        let required: std::collections::BTreeSet<&str> = full
            .keys()
            .copied()
            .filter(|key| {
                *key != SWITCH && !key.contains("_SERVICE_HOST") && !key.contains("_SERVICE_PORT_")
            })
            .filter(|key| {
                let mut values = full.clone();
                values.remove(key);
                !starts(&values)
            })
            .collect();
        assert_eq!(
            required,
            REQUIRED_WHEN_ON.into_iter().collect(),
            "REQUIRED_WHEN_ON must name every key startup requires, and only those"
        );
    }

    #[test]
    fn an_unlinked_service_leaves_its_address_empty_and_the_render_refuses_it() {
        for (host, port, service) in [
            (
                "CODEWIRE_EGRESS_SERVICE_HOST",
                "CODEWIRE_EGRESS_SERVICE_PORT_STREAM",
                "codewire-egress",
            ),
            (
                "CODEWIRE_ORCHESTRATION_WORKSPACE_BINDING_SERVICE_HOST",
                "CODEWIRE_ORCHESTRATION_WORKSPACE_BINDING_SERVICE_PORT_WORKSPACE_BIND",
                "codewire-orchestration-workspace-binding",
            ),
            (
                "CODEWIRE_DERP_SERVICE_HOST",
                "CODEWIRE_DERP_SERVICE_PORT_HTTPS",
                "codewire-derp",
            ),
        ] {
            let mut values = on();
            values.remove(host);
            values.remove(port);
            let egress = read(&values).unwrap().unwrap();
            let opts = crate::sandbox::template::TemplateOpts {
                runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
                hosted_egress: Some(egress),
                ..Default::default()
            };
            let error = opts.validate_hosted_egress().unwrap_err().to_string();
            assert!(error.contains(service), "{service}: {error}");
        }
    }

    #[test]
    fn off_by_default_and_on_with_no_platform_allow() {
        assert_eq!(
            EgressSettings::from_values(None, None, None).unwrap(),
            EgressSettings::default()
        );
        for empty in [None, Some(""), Some(" , ")] {
            assert_eq!(
                EgressSettings::from_values(Some("true"), empty, None).unwrap(),
                EgressSettings {
                    enabled: true,
                    interception: false,
                },
                "{empty:?}"
            );
        }
        assert!(EgressSettings::from_values(Some("maybe"), None, None).is_err());
    }

    #[test]
    fn a_platform_allow_stops_startup_while_nothing_enforces_it() {
        for named in [
            "control.example.com:443",
            " , derp.example.com:443",
            "no-port",
        ] {
            assert!(
                EgressSettings::from_values(Some("true"), Some(named), None).is_err(),
                "{named}"
            );
        }
    }

    #[test]
    fn interception_is_off_by_default_and_on_only_with_hosted_egress() {
        assert!(
            !EgressSettings::from_values(Some("true"), None, None)
                .unwrap()
                .interception
        );
        assert!(
            EgressSettings::from_values(Some("true"), None, Some("true"))
                .unwrap()
                .interception
        );
        assert!(EgressSettings::from_values(None, None, Some("true")).is_err());
        assert!(EgressSettings::from_values(Some("false"), None, Some("true")).is_err());
        assert!(EgressSettings::from_values(Some("true"), None, Some("maybe")).is_err());
    }

    #[test]
    fn the_list_is_not_read_while_hosted_egress_is_off() {
        assert_eq!(
            EgressSettings::from_values(Some("false"), Some("control.example.com:443"), None)
                .unwrap(),
            EgressSettings::default()
        );
    }
}
