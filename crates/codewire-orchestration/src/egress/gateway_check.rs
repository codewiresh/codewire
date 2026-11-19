//! The public gateway's address, held to its Service (#4000; cw-security,
//! 2026-11-19 on #4000).
//!
//! A broker-mode Sandbox reaches the control plane, its coordinator and Mesh
//! at the gateway Service's ClusterIP, which deploy pins and configures as
//! `CODEWIRE_HOSTED_EGRESS_GATEWAY_CLUSTER_IP`. If the two ever part, the
//! configured address can be given to another Service, which those Sandboxes
//! would then reach. So orchestration reads the Service by name (a Role with
//! `get` on that one Service and nothing else) at startup and every
//! [`CHECK_EVERY`], and refuses every broker-mode render unless its last read
//! is younger than [`FRESH_FOR`] and found the configured address. A refusal
//! names the Service and both addresses, is logged, and is counted by reason
//! in `codewire_egress_gateway_check_refused_total`, which an alert reads.
//!
//! Deploy holds the same equality on every delivery; this is the half that
//! stops a running orchestration from rendering against a moved gateway.

use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::Service;
use kube::Api;
use prometheus::{IntCounterVec, Opts, register_int_counter_vec};

/// How often the Service is read again.
pub const CHECK_EVERY: Duration = Duration::from_secs(30);
/// How old the last read may be when a broker-mode render asks.
pub const FRESH_FOR: Duration = Duration::from_secs(60);

/// The gateway Service and the address deployment configured for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayService {
    pub namespace: String,
    pub name: String,
    pub cluster_ip: Ipv4Addr,
}

/// What one read of the Service found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    Matches,
    Differs { actual: String },
    Unreadable { error: String },
}

struct Last {
    reading: Reading,
    at: Instant,
}

static SERVICE: OnceLock<GatewayService> = OnceLock::new();
static LAST: Mutex<Option<Last>> = Mutex::new(None);
static REFUSED: OnceLock<IntCounterVec> = OnceLock::new();

fn refused_metric() -> &'static IntCounterVec {
    REFUSED.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_egress_gateway_check_refused_total",
                "Broker-mode renders refused because the gateway Service was not found at its configured address, by reason."
            ),
            &["reason"]
        )
        .expect("gateway check metric registration must be unique")
    })
}

/// Whether a broker-mode render may go ahead now.
pub fn verified() -> anyhow::Result<()> {
    let Some(service) = SERVICE.get() else {
        refused_metric().with_label_values(&["not_started"]).inc();
        anyhow::bail!("hosted egress is on but the gateway Service is not being checked");
    };
    let last = LAST.lock().expect("gateway check state");
    let result = verdict(
        service,
        last.as_ref().map(|last| (&last.reading, last.at.elapsed())),
    );
    if let Err((reason, error)) = &result {
        refused_metric().with_label_values(&[reason]).inc();
        tracing::warn!(reason, %error, "broker-mode render refused: the gateway is not at its configured address");
    }
    result.map_err(|(_, error)| error)
}

/// The decision for `service` given its last read and that read's age.
fn verdict(
    service: &GatewayService,
    last: Option<(&Reading, Duration)>,
) -> Result<(), (&'static str, anyhow::Error)> {
    let named = format!("Service {}/{}", service.namespace, service.name);
    let configured = service.cluster_ip;
    match last {
        None => Err((
            "not_read",
            anyhow::anyhow!(
                "{named} has not been read yet; the configured gateway address is {configured}"
            ),
        )),
        Some((_, age)) if age > FRESH_FOR => Err((
            "stale",
            anyhow::anyhow!(
                "{named} was last read {}s ago; the configured gateway address is {configured}",
                age.as_secs()
            ),
        )),
        Some((Reading::Matches, _)) => Ok(()),
        Some((Reading::Differs { actual }, _)) => Err((
            "differs",
            anyhow::anyhow!(
                "{named} has ClusterIP {actual}, not the configured gateway address {configured}"
            ),
        )),
        Some((Reading::Unreadable { error }, _)) => Err((
            "unreadable",
            anyhow::anyhow!(
                "{named} could not be read ({error}); the configured gateway address is {configured}"
            ),
        )),
    }
}

/// What the Service holds now, compared with the configured address.
async fn read(client: &kube::Client, service: &GatewayService) -> Reading {
    let services: Api<Service> = Api::namespaced(client.clone(), &service.namespace);
    match services.get(&service.name).await {
        Ok(found) => {
            let actual = found
                .spec
                .and_then(|spec| spec.cluster_ip)
                .unwrap_or_default();
            if actual == service.cluster_ip.to_string() {
                Reading::Matches
            } else {
                Reading::Differs { actual }
            }
        }
        Err(error) => Reading::Unreadable {
            error: error.to_string(),
        },
    }
}

fn store(reading: Reading) {
    let mut last = LAST.lock().expect("gateway check state");
    let changed = last.as_ref().is_none_or(|last| last.reading != reading);
    if changed {
        match &reading {
            Reading::Matches => tracing::info!("the gateway Service is at its configured address"),
            other => tracing::warn!(
                ?other,
                "the gateway Service is not at its configured address"
            ),
        }
    }
    *last = Some(Last {
        reading,
        at: Instant::now(),
    });
}

/// Read `service` once now, then every [`CHECK_EVERY`] for the life of the
/// process. Called once, at startup, while hosted egress is on.
pub async fn start(client: kube::Client, service: GatewayService) -> anyhow::Result<()> {
    anyhow::ensure!(
        SERVICE.set(service.clone()).is_ok(),
        "the gateway check started twice"
    );
    store(read(&client, &service).await);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            store(read(&client, &service).await);
        }
    });
    Ok(())
}

/// For tests that render broker-mode templates: a gateway found at its
/// configured address just now.
#[cfg(test)]
pub(crate) fn assume_verified() {
    let _ = SERVICE.set(GatewayService {
        namespace: "envoy-gateway-system".into(),
        name: "envoy-codewire-public".into(),
        cluster_ip: Ipv4Addr::new(10, 44, 0, 43),
    });
    *LAST.lock().expect("gateway check state") = Some(Last {
        reading: Reading::Matches,
        at: Instant::now(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> GatewayService {
        GatewayService {
            namespace: "envoy-gateway-system".into(),
            name: "envoy-codewire-public".into(),
            cluster_ip: Ipv4Addr::new(10, 44, 45, 129),
        }
    }

    fn refusal(last: Option<(&Reading, Duration)>) -> (&'static str, String) {
        let (reason, error) = verdict(&service(), last).unwrap_err();
        (reason, error.to_string())
    }

    #[test]
    fn a_fresh_matching_read_lets_broker_mode_render() {
        assert!(
            verdict(
                &service(),
                Some((&Reading::Matches, Duration::from_secs(59)))
            )
            .is_ok()
        );
    }

    #[test]
    fn a_moved_gateway_refuses_naming_the_service_and_both_addresses() {
        let moved = Reading::Differs {
            actual: "10.44.12.7".into(),
        };
        let (reason, error) = refusal(Some((&moved, Duration::ZERO)));
        assert_eq!(reason, "differs");
        for named in [
            "envoy-gateway-system/envoy-codewire-public",
            "10.44.12.7",
            "10.44.45.129",
        ] {
            assert!(error.contains(named), "{named}: {error}");
        }
    }

    #[test]
    fn an_unreadable_unread_or_stale_gateway_refuses() {
        let unreadable = Reading::Unreadable {
            error: "services \"envoy-codewire-public\" is forbidden".into(),
        };
        let (reason, error) = refusal(Some((&unreadable, Duration::ZERO)));
        assert_eq!(reason, "unreadable");
        assert!(
            error.contains("forbidden") && error.contains("10.44.45.129"),
            "{error}"
        );
        assert_eq!(refusal(None).0, "not_read");
        // A match older than the window is no longer evidence.
        assert_eq!(
            refusal(Some((
                &Reading::Matches,
                FRESH_FOR + Duration::from_secs(1)
            )))
            .0,
            "stale"
        );
    }
}
