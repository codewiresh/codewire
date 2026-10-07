//! The environment's exposed application ports, which a bound daemon serves
//! on its tailnet address (#2460). Orchestration states the full set in each
//! access grant and pushes every change through `SetAppPorts`; the latest
//! set replaces the previous one.

use std::collections::BTreeSet;

use tokio::sync::watch;

/// A set larger than this is refused.
pub const MAX_APP_PORTS: usize = 256;

/// A validated set of ports, 1-65535.
pub type AppPorts = BTreeSet<u16>;

/// The daemon's current set: written by access grants and pushes, read by
/// the tailnet listener.
pub type AppPortsSender = watch::Sender<AppPorts>;

/// A set the daemon refused. Value-blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("app ports must be 1-65535, without duplicates, at most {MAX_APP_PORTS}")]
pub struct InvalidAppPorts;

/// Validate a set stated on the wire: every port 1-65535, no duplicates and
/// at most [`MAX_APP_PORTS`].
pub fn app_ports(ports: &[i32]) -> Result<AppPorts, InvalidAppPorts> {
    if ports.len() > MAX_APP_PORTS {
        return Err(InvalidAppPorts);
    }
    let mut set = AppPorts::new();
    for port in ports {
        let port = u16::try_from(*port)
            .ok()
            .filter(|port| *port > 0)
            .ok_or(InvalidAppPorts)?;
        if !set.insert(port) {
            return Err(InvalidAppPorts);
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_distinct_ports_in_range_are_accepted() {
        assert_eq!(
            app_ports(&[5173, 3000]).unwrap(),
            AppPorts::from([3000, 5173])
        );
        assert_eq!(app_ports(&[]).unwrap(), AppPorts::new());
        for refused in [
            vec![0],
            vec![-1],
            vec![65_536],
            vec![3000, 3000],
            (1..=257).collect::<Vec<i32>>(),
        ] {
            assert_eq!(app_ports(&refused), Err(InvalidAppPorts), "{refused:?}");
        }
        assert_eq!(
            app_ports(&(1..=256).collect::<Vec<i32>>()).unwrap().len(),
            MAX_APP_PORTS
        );
    }
}
