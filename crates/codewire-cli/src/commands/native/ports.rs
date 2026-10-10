//! `cw env port` for local environments: publish or withdraw a guest port on
//! the host's 127.0.0.1 while the VM runs. A stopped environment records the
//! change and publishes it at its next start.

use super::*;

pub(crate) async fn handle_native_environment_port(
    name: &str,
    command: EnvPortCommand,
) -> anyhow::Result<()> {
    let mut client = native_client().await?;
    match command {
        EnvPortCommand::Add(args) => {
            anyhow::ensure!(
                args.label.is_none() && args.access.is_none(),
                "--label and --access apply to platform preview ports; a local port is published on 127.0.0.1 only"
            );
            let guest_port = parse_local_port(&args.port)?;
            let host_port = args.host_port.unwrap_or(guest_port);
            let environment = client
                .update_host_ports(
                    name,
                    vec![v1::HostPortBinding {
                        host_port: u32::from(host_port),
                        guest_port: u32::from(guest_port),
                    }],
                    Vec::new(),
                )
                .await
                .map_err(native_status)?;
            let summary = if environment.state == v1::EnvironmentState::Running as i32 {
                format!("Published http://127.0.0.1:{host_port} -> {name}:{guest_port}")
            } else {
                format!(
                    "Recorded 127.0.0.1:{host_port} -> {name}:{guest_port}; it is published when {name} starts"
                )
            };
            print_native_ports(&environment, args.output, Some(&summary))
        }
        EnvPortCommand::List(args) => {
            let environment = client.get(name).await.map_err(native_status)?;
            print_native_ports(&environment, args.output, None)
        }
        EnvPortCommand::Rm(args) => {
            let host_port = parse_local_port(&args.port)?;
            let environment = client
                .update_host_ports(name, Vec::new(), vec![u32::from(host_port)])
                .await
                .map_err(native_status)?;
            let summary = format!("Withdrew 127.0.0.1:{host_port} from {name}");
            print_native_ports(&environment, args.output, Some(&summary))
        }
    }
}

fn parse_local_port(value: &str) -> anyhow::Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow::anyhow!("a port is a number from 1 to 65535"))
}

fn native_port_views(environment: &v1::Environment) -> Vec<NativeHostPortView> {
    environment
        .host_ports
        .iter()
        .map(|binding| NativeHostPortView {
            listen: format!("127.0.0.1:{}", binding.host_port),
            guest_port: binding.guest_port,
        })
        .collect()
}

fn print_native_ports(
    environment: &v1::Environment,
    output: OutputFormat,
    summary: Option<&str>,
) -> anyhow::Result<()> {
    let ports = native_port_views(environment);
    if matches!(output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&ports)?);
        return Ok(());
    }
    print!(
        "{}",
        format_native_ports(&environment.name, &ports, summary)
    );
    Ok(())
}

fn format_native_ports(name: &str, ports: &[NativeHostPortView], summary: Option<&str>) -> String {
    let mut output = String::new();
    if let Some(summary) = summary {
        output.push_str(summary);
        output.push('\n');
    }
    if ports.is_empty() {
        if summary.is_none() {
            output.push_str(&format!("{name} publishes no host ports\n"));
        }
        return output;
    }
    if summary.is_some() {
        output.push_str(&format!("{name} publishes:\n"));
    }
    for port in ports {
        output.push_str(&format!("  {} -> {}\n", port.listen, port.guest_port));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ports_parse_and_render_without_preview_urls() {
        assert_eq!(parse_local_port(" 47321 ").unwrap(), 47_321);
        for invalid in ["0", "65536", "web", ""] {
            assert!(parse_local_port(invalid).is_err(), "{invalid}");
        }
        let ports = [NativeHostPortView {
            listen: "127.0.0.1:18080".to_owned(),
            guest_port: 3_000,
        }];
        assert_eq!(
            format_native_ports("web", &ports, None),
            "  127.0.0.1:18080 -> 3000\n"
        );
        assert_eq!(
            format_native_ports("web", &[], None),
            "web publishes no host ports\n"
        );
        assert_eq!(
            format_native_ports("web", &[], Some("Withdrew 127.0.0.1:18080 from web")),
            "Withdrew 127.0.0.1:18080 from web\n"
        );
        assert_eq!(
            format_native_ports("web", &ports, Some("Published")),
            "Published\nweb publishes:\n  127.0.0.1:18080 -> 3000\n"
        );
    }
}
