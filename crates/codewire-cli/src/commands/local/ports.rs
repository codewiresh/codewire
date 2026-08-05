//! Lima port-forward planning and canonical local port mappings.

use super::*;

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LimaPortForwardEdit {
    #[serde(rename = "guestPort")]
    pub(crate) guest_port: i32,
    #[serde(rename = "hostPort")]
    pub(crate) host_port: i32,
    pub(crate) proto: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalPortPublishResult {
    pub(crate) added: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LimaPortForwardPlan {
    pub(crate) updated_ports: Vec<config::LocalPortConfig>,
    pub(crate) forwards: Vec<LimaPortForwardEdit>,
    pub(crate) added: usize,
}

pub(crate) fn publish_local_ports(
    instance: &mut config::LocalInstanceConfig,
    publish: &[String],
) -> anyhow::Result<LocalPortPublishResult> {
    match trimmed_required(&instance.backend, "local backend")? {
        "lima" => {
            let result = add_lima_port_forwards(instance, publish)?;
            instance.ports = result.updated_ports;
            Ok(LocalPortPublishResult {
                added: result.added,
            })
        }
        _ => anyhow::bail!(
            "interactive 'cw env --local ports' forwarding is only available for Lima; use backend-native port mapping for docker"
        ),
    }
}

pub(crate) fn add_lima_port_forwards(
    instance: &config::LocalInstanceConfig,
    publish: &[String],
) -> anyhow::Result<LimaPortForwardPlan> {
    let plan = plan_lima_port_forwards(instance, publish)?;
    if !plan.forwards.is_empty() {
        lima_add_port_forwards(instance, &plan.forwards)?;
    }
    Ok(plan)
}

pub(crate) fn plan_lima_port_forwards(
    instance: &config::LocalInstanceConfig,
    publish: &[String],
) -> anyhow::Result<LimaPortForwardPlan> {
    let mut existing_by_host: HashMap<i32, config::LocalPortConfig> =
        HashMap::with_capacity(instance.ports.len());
    let mut updated_ports = Vec::with_capacity(instance.ports.len() + publish.len());
    for port in &instance.ports {
        let canonical = canonical_local_port(port);
        let host_port = canonical.effective_host_port();
        let guest_port = canonical.effective_guest_port();
        if host_port <= 0 || guest_port <= 0 {
            continue;
        }
        if let Some(existing) = existing_by_host.get(&host_port)
            && existing.effective_guest_port() != guest_port
        {
            anyhow::bail!(
                "Lima instance {:?} has conflicting host port {} mapped to guest ports {} and {}",
                instance.name,
                host_port,
                existing.effective_guest_port(),
                guest_port
            );
        }
        existing_by_host.insert(host_port, canonical.clone());
        updated_ports.push(canonical);
    }

    let mut forwards = Vec::with_capacity(publish.len());
    let mut added = 0;
    for spec in publish {
        let port = parse_published_port_spec(spec)?;
        let host_port = port.effective_host_port();
        let guest_port = port.effective_guest_port();
        if let Some(existing) = existing_by_host.get(&host_port) {
            if existing.effective_guest_port() != guest_port {
                anyhow::bail!(
                    "host port {} is already forwarded to guest port {}",
                    host_port,
                    existing.effective_guest_port()
                );
            }
            continue;
        }
        existing_by_host.insert(host_port, port.clone());
        updated_ports.push(port);
        forwards.push(LimaPortForwardEdit {
            guest_port,
            host_port,
            proto: "tcp".to_string(),
        });
        added += 1;
    }

    Ok(LimaPortForwardPlan {
        updated_ports,
        forwards,
        added,
    })
}

pub(crate) fn parse_published_port_spec(spec: &str) -> anyhow::Result<config::LocalPortConfig> {
    let spec = spec.trim();
    let Some((host, guest)) = spec.split_once(':') else {
        anyhow::bail!(
            "invalid port spec {:?} (use host:guest format, e.g. 8080:3000)",
            spec
        );
    };
    if guest.contains(':') {
        anyhow::bail!(
            "invalid port spec {:?} (use host:guest format, e.g. 8080:3000)",
            spec
        );
    }
    let host_port = host.trim().parse::<i32>().ok().filter(|port| *port > 0);
    let guest_port = guest.trim().parse::<i32>().ok().filter(|port| *port > 0);
    let (Some(host_port), Some(guest_port)) = (host_port, guest_port) else {
        anyhow::bail!(
            "invalid port spec {:?} (use host:guest format, e.g. 8080:3000)",
            spec
        );
    };
    if guest_port == i32::from(LOCAL_DAEMON_RUNTIME_PORT) {
        anyhow::bail!(
            "guest port {LOCAL_DAEMON_RUNTIME_PORT} is reserved for the managed environment daemon"
        );
    }
    Ok(canonical_local_port(&config::LocalPortConfig {
        host_port,
        guest_port,
        ..config::LocalPortConfig::default()
    }))
}

pub(crate) fn canonical_local_port(port: &config::LocalPortConfig) -> config::LocalPortConfig {
    let host_port = port.effective_host_port();
    let guest_port = port.effective_guest_port();
    let mut out = config::LocalPortConfig {
        label: port.label.clone(),
        ..config::LocalPortConfig::default()
    };
    if host_port <= 0 || guest_port <= 0 {
        return out;
    }
    if host_port == guest_port {
        out.port = guest_port;
    } else {
        out.host_port = host_port;
        out.guest_port = guest_port;
    }
    out
}

pub(crate) fn lima_add_port_forwards(
    instance: &config::LocalInstanceConfig,
    forwards: &[LimaPortForwardEdit],
) -> anyhow::Result<()> {
    if forwards.is_empty() {
        return Ok(());
    }
    let spec = lima_add_port_forwards_command_spec(instance, forwards)?;
    run_local_command_combined(&spec).map(|_| ())
}

pub(crate) fn lima_add_port_forwards_command_spec(
    instance: &config::LocalInstanceConfig,
    forwards: &[LimaPortForwardEdit],
) -> anyhow::Result<LocalRuntimeCommand> {
    let name = local_lima_instance_name(instance)?;
    if forwards.is_empty() {
        anyhow::bail!("no Lima port forwards specified");
    }
    let payload = serde_json::to_string(forwards).context("marshal Lima port forwards")?;
    let set_expr = format!(".portForwards = (.portForwards // []) + {payload}");
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "edit".to_string(),
            "--tty=false".to_string(),
            name.to_string(),
            "--set".to_string(),
            set_expr,
        ],
    })
}

pub(crate) fn local_mount_entry(mount: &config::LocalMountConfig) -> Option<LocalMountEntry> {
    if mount.source.trim().is_empty() {
        return None;
    }
    Some(LocalMountEntry {
        source: mount.source.clone(),
        target: mount.target.clone(),
        readonly: mount.readonly.unwrap_or(false),
    })
}
