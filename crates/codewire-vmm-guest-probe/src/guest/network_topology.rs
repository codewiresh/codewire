//! The guest network namespace's topology check: exactly loopback and the
//! trusted TUN, by its name, routed only through the TUN's gateway.

use super::*;

pub(super) fn verify_isolated_tun(
    interface: &str,
    net_dev: &Path,
    route: &Path,
    ipv6_route: &Path,
) -> Result<()> {
    // An inherited sysfs mount remains associated with the network namespace
    // in which it was mounted. /proc/net is process-namespace aware, so use
    // its bounded interface table to inspect this agent's actual namespace.
    let devices = fs::read_to_string(net_dev)
        .with_context(|| format!("read guest network interfaces {}", net_dev.display()))?;
    let mut lines = devices.lines();
    ensure!(
        lines.next().is_some() && lines.next().is_some(),
        "guest network interface table is malformed"
    );
    let mut interfaces = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let (interface, counters) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("guest network interface table is malformed"))?;
        let interface = interface.trim();
        let counters = counters.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(
            !interface.is_empty()
                && counters.len() == 16
                && counters
                    .iter()
                    .all(|value| !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit())),
            "guest network interface table is malformed"
        );
        interfaces.push(interface);
    }
    interfaces.sort();
    ensure!(
        interfaces.as_slice() == [interface, "lo"],
        "guest network namespace does not contain exactly loopback and the trusted TUN"
    );

    let routes = fs::read_to_string(route)
        .with_context(|| format!("read guest route table {}", route.display()))?;
    let mut default_route = false;
    for line in routes
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(fields.len() >= 8, "guest route table is malformed");
        ensure!(
            fields[0] == "lo" || fields[0] == interface,
            "guest has a route through an unexpected interface"
        );
        if fields[1] == "00000000" {
            ensure!(
                fields[0] == interface
                    && fields[2].eq_ignore_ascii_case("010200C0")
                    && fields[7] == "00000000",
                "guest default route is not bound to the trusted TUN gateway"
            );
            default_route = true;
        }
    }
    ensure!(default_route, "guest trusted TUN default route is absent");

    match fs::read_to_string(ipv6_route) {
        Ok(routes) => {
            for line in routes.lines().filter(|line| !line.trim().is_empty()) {
                let interface = line
                    .split_ascii_whitespace()
                    .next_back()
                    .ok_or_else(|| anyhow::anyhow!("guest IPv6 route table is malformed"))?;
                ensure!(
                    interface == "lo",
                    "guest TUN unexpectedly has an IPv6 route"
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A kernel with IPv6 disabled has no IPv6 route surface.
        }
        Err(error) => return Err(error).context("read guest IPv6 route table"),
    }
    Ok(())
}
