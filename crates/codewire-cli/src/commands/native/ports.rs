//! `cw ports` for local environments: list, publish or withdraw a guest port
//! on the host's 127.0.0.1. Listing never starts the VM; publishing needs it
//! running; withdrawing works either way.

use codewire_local_vmm::guest_loopback::GuestLoopbackError;

use super::*;

pub(crate) async fn handle_native_environment_port(
    name: &str,
    operation: PortOperation,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let mut client = native_client().await?;
    match operation {
        PortOperation::List => {
            let environment = client.get(name).await.map_err(native_status)?;
            let mut https = https_report(&mut client, name, output_is_text(output)).await?;
            if !https.urls.is_empty() && environment.state != v1::EnvironmentState::Running as i32 {
                https.notes.push(format!(
                    "{name} is not running; its HTTPS URLs answer once it starts."
                ));
            }
            print_native_ports(&environment, &https, output, None)
        }
        PortOperation::Publish {
            port: guest_port,
            host_port,
            label,
            access,
        } => {
            anyhow::ensure!(
                label.is_none() && access.is_none(),
                "--label and --access apply to cloud preview ports; a local port is published on 127.0.0.1 only"
            );
            let environment = client.get(name).await.map_err(native_status)?;
            anyhow::ensure!(
                environment.state == v1::EnvironmentState::Running as i32,
                "{name} is not running; start it with `cw start {name}`, then publish the port"
            );
            let host_port = host_port.unwrap_or(guest_port);
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
            let mut summary =
                format!("Published http://127.0.0.1:{host_port} -> {name}:{guest_port}");
            if let Some(note) = listening_note(&mut client, name, guest_port).await {
                summary.push('\n');
                summary.push_str(&note);
            }
            let https = https_report(&mut client, name, output_is_text(output)).await?;
            print_native_ports(&environment, &https, output, Some(&summary))
        }
        PortOperation::Unpublish {
            port: guest_port,
            host_port,
            label,
        } => {
            anyhow::ensure!(
                label.is_none(),
                "--label applies to cloud preview ports; choose a local binding with --host-port"
            );
            let environment = client.get(name).await.map_err(native_status)?;
            let host_port = unpublished_host_port(&environment, guest_port, host_port)?;
            let environment = client
                .update_host_ports(name, Vec::new(), vec![u32::from(host_port)])
                .await
                .map_err(native_status)?;
            let summary = format!("Withdrew 127.0.0.1:{host_port} -> {name}:{guest_port}");
            let https = https_report(&mut client, name, output_is_text(output)).await?;
            print_native_ports(&environment, &https, output, Some(&summary))
        }
    }
}

/// What a connection to a newly published port will meet, when that is not a
/// server: one probe through the same daemon path the host port uses (#4347).
/// Nothing is said when the daemon cannot be reached, such as while the VM
/// is still booting.
async fn listening_note(
    client: &mut NativeSupervisorClient,
    name: &str,
    guest_port: u16,
) -> Option<String> {
    let access = client.daemon_access(name).await.ok()?;
    match codewire_local_vmm::guest_loopback::probe_guest_loopback(access, guest_port).await {
        Ok(()) | Err(GuestLoopbackError::DaemonUnreachable) => None,
        Err(GuestLoopbackError::NothingListens(_)) => Some(format!(
            "Nothing in {name} listens on 127.0.0.1:{guest_port} yet; connections are refused until a server listens there."
        )),
        Err(GuestLoopbackError::Refused(reason)) => Some(format!(
            "Connections to {name}:{guest_port} are refused: {reason}"
        )),
    }
}

/// The host port of the one binding of `guest_port`; `--host-port` chooses
/// among several and must name one of them.
fn unpublished_host_port(
    environment: &v1::Environment,
    guest_port: u16,
    host_port: Option<u16>,
) -> anyhow::Result<u16> {
    let name = &environment.name;
    let bindings: Vec<u16> = environment
        .host_ports
        .iter()
        .filter(|binding| binding.guest_port == u32::from(guest_port))
        .filter_map(|binding| u16::try_from(binding.host_port).ok())
        .filter(|bound| host_port.is_none_or(|host_port| *bound == host_port))
        .collect();
    match (bindings.as_slice(), host_port) {
        ([one], _) => Ok(*one),
        ([], Some(host_port)) => anyhow::bail!(
            "{name} does not publish guest port {guest_port} on 127.0.0.1:{host_port}"
        ),
        ([], None) => anyhow::bail!("{name} does not publish guest port {guest_port}"),
        (several, _) => anyhow::bail!(
            "{name} publishes guest port {guest_port} on several host ports ({}); choose one with --host-port",
            several
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
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

fn output_is_text(output: OutputFormat) -> bool {
    !matches!(output, OutputFormat::Json)
}

/// One entry of `cw ports --output json`: a host port, or a labelled port's
/// HTTPS URL.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum NativePortEntry<'a> {
    HostPort(&'a NativeHostPortView),
    Https(&'a NativeHttpsView),
}

fn print_native_ports(
    environment: &v1::Environment,
    https: &HttpsReport,
    output: OutputFormat,
    summary: Option<&str>,
) -> anyhow::Result<()> {
    let ports = native_port_views(environment);
    if matches!(output, OutputFormat::Json) {
        let entries: Vec<NativePortEntry<'_>> = ports
            .iter()
            .map(NativePortEntry::HostPort)
            .chain(https.urls.iter().map(NativePortEntry::Https))
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    print!(
        "{}",
        format_native_ports(&environment.name, &ports, https, summary)
    );
    Ok(())
}

fn format_native_ports(
    name: &str,
    ports: &[NativeHostPortView],
    https: &HttpsReport,
    summary: Option<&str>,
) -> String {
    let mut output = String::new();
    if let Some(summary) = summary {
        output.push_str(summary);
        output.push('\n');
    }
    if ports.is_empty() && https.urls.is_empty() {
        if summary.is_none() {
            output.push_str(&format!("{name} publishes no host ports\n"));
        }
    } else {
        if summary.is_some() {
            output.push_str(&format!("{name} publishes:\n"));
        }
        for port in ports {
            output.push_str(&format!("  {} -> {}\n", port.listen, port.guest_port));
        }
        for view in &https.urls {
            output.push_str(&format!(
                "  {} -> {} ({})\n",
                view.url, view.guest_port, view.label
            ));
        }
    }
    for note in &https.notes {
        output.push_str(note);
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpublish_selects_one_binding_by_guest_port() {
        let binding = |host_port, guest_port| v1::HostPortBinding {
            host_port,
            guest_port,
        };
        let environment = v1::Environment {
            name: "web".into(),
            host_ports: vec![binding(3000, 3000), binding(8080, 80), binding(8081, 80)],
            ..Default::default()
        };
        assert_eq!(
            unpublished_host_port(&environment, 3000, None).unwrap(),
            3000
        );
        assert_eq!(
            unpublished_host_port(&environment, 80, Some(8081)).unwrap(),
            8081
        );
        let ambiguous = unpublished_host_port(&environment, 80, None).unwrap_err();
        assert_eq!(
            ambiguous.to_string(),
            "web publishes guest port 80 on several host ports (8080, 8081); choose one with --host-port"
        );
        assert_eq!(
            unpublished_host_port(&environment, 80, Some(9000))
                .unwrap_err()
                .to_string(),
            "web does not publish guest port 80 on 127.0.0.1:9000"
        );
        assert_eq!(
            unpublished_host_port(&environment, 22, None)
                .unwrap_err()
                .to_string(),
            "web does not publish guest port 22"
        );
    }

    #[test]
    fn local_ports_render_without_preview_urls() {
        let ports = [NativeHostPortView {
            listen: "127.0.0.1:18080".to_owned(),
            guest_port: 3_000,
        }];
        let none = HttpsReport::default();
        assert_eq!(
            format_native_ports("web", &ports, &none, None),
            "  127.0.0.1:18080 -> 3000\n"
        );
        assert_eq!(
            format_native_ports("web", &[], &none, None),
            "web publishes no host ports\n"
        );
        assert_eq!(
            format_native_ports("web", &[], &none, Some("Withdrew 127.0.0.1:18080 from web")),
            "Withdrew 127.0.0.1:18080 from web\n"
        );
        assert_eq!(
            format_native_ports("web", &ports, &none, Some("Published")),
            "Published\nweb publishes:\n  127.0.0.1:18080 -> 3000\n"
        );
    }

    #[test]
    fn labelled_ports_list_their_https_urls_and_notes() {
        let https = HttpsReport {
            urls: vec![NativeHttpsView {
                url: "https://web-shop.cw.localhost".to_owned(),
                guest_port: 3_000,
                label: "web".to_owned(),
            }],
            notes: vec!["A note.".to_owned()],
        };
        assert_eq!(
            format_native_ports("shop", &[], &https, None),
            "  https://web-shop.cw.localhost -> 3000 (web)\nA note.\n"
        );
        let ports = [NativeHostPortView {
            listen: "127.0.0.1:18080".to_owned(),
            guest_port: 3_000,
        }];
        let entries: Vec<_> = ports
            .iter()
            .map(NativePortEntry::HostPort)
            .chain(https.urls.iter().map(NativePortEntry::Https))
            .collect();
        assert_eq!(
            serde_json::to_value(&entries).unwrap(),
            serde_json::json!([
                {"listen": "127.0.0.1:18080", "guest_port": 3000},
                {"url": "https://web-shop.cw.localhost", "guest_port": 3000, "label": "web"},
            ])
        );
    }
}
