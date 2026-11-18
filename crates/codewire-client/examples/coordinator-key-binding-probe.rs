//! Announces one node key to a deployment's coordinator as a CLI client and
//! reports whether the coordinator kept the session (codewire#3542).
//!
//! The coordinator binds a node key to the principal and environment that
//! first announced it, for seven days (`docs/dev/DERP-STUN.md`, "Coordinator
//! sessions and node keys"). The NATS accounts window carries those bindings
//! across a switch, and this probe shows the live coordinator enforces a
//! carried binding: bind a key in one environment before the window, then
//! after it require that announcing the key in another environment is refused
//! and that announcing it again in the first is accepted, as a takeover.
//!
//! Environment:
//! - `PROBE_SERVER`: the platform URL, such as `https://codewire-dev.sh`;
//! - `CODEWIRE_API_KEY`: the signed-in user's API key, read only from here;
//! - `PROBE_ORG`, `PROBE_ENVIRONMENT`: the organization and environment IDs;
//! - `PROBE_NODE_KEY`: the node public key as 64 hex digits, or `new` to
//!   announce a fresh one (it is printed, as public keys are);
//! - `PROBE_HOLD_SECONDS`: how long a kept session must stay up (default 20);
//! - `PROBE_DERP_REGION`: the node's preferred DERP region (default 1). It
//!   must not be 0: the wire form omits a zero region, and the coordinator
//!   then refuses the node as invalid.
//!
//! It prints one result line and exits 0 when the session stayed up, 3 when
//! the coordinator ended it. A client hears no acknowledgement of its node,
//! so a session that stayed up is read with the coordinator's log: no
//! `coordinator Connect node decode failed` and no `coordinator node key
//! refused` for it, and the bindings stream written at the announcement.

use std::time::Duration;

use anyhow::{Context as _, bail};
use codewire_client::{
    ClientConfig, CodewireClient, CoordinatorHandlers, PrimaryCoordinateIdentity,
    StaticTokenProvider,
};
use codewire_tailnet::node::{DiscoPublic, Node, NodePublic, prefix_from_uuid};
use rand::RngCore as _;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = required_env("PROBE_SERVER")?;
    let api_key = required_env("CODEWIRE_API_KEY")?;
    let org_id = required_env("PROBE_ORG")?;
    let environment_id: Uuid = required_env("PROBE_ENVIRONMENT")?
        .parse()
        .context("PROBE_ENVIRONMENT is not a UUID")?;
    let key = match required_env("PROBE_NODE_KEY")?.as_str() {
        "new" => {
            let mut raw = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            raw
        }
        hex => parse_key(hex)?,
    };
    let derp_region: i32 = std::env::var("PROBE_DERP_REGION")
        .ok()
        .map(|region| region.parse())
        .transpose()
        .context("PROBE_DERP_REGION is not a number")?
        .unwrap_or(1);
    if derp_region == 0 {
        bail!("PROBE_DERP_REGION must not be 0");
    }
    let hold = Duration::from_secs(
        std::env::var("PROBE_HOLD_SECONDS")
            .ok()
            .map(|seconds| seconds.parse())
            .transpose()
            .context("PROBE_HOLD_SECONDS is not a number")?
            .unwrap_or(20),
    );

    let client = CodewireClient::with_http(
        ClientConfig::new(&server)?.with_user_agent("codewire-coordinator-key-binding-probe/1")?,
        StaticTokenProvider::new(api_key)?,
        reqwest::Client::new(),
    )?;
    let mut session = client
        .connect_primary_coordinator(PrimaryCoordinateIdentity::client(&org_id, environment_id))
        .await
        .context("open the coordinator session")?;

    let node_id = Uuid::new_v4();
    let mut disco = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut disco);
    session
        .update_node(&Node {
            id: node_id,
            as_of: chrono::Utc::now(),
            key: NodePublic::from_raw(key),
            disco_key: DiscoPublic::from_raw(disco),
            preferred_derp: derp_region,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&node_id)],
        })
        .await
        .context("announce the node")?;

    let key_hex = to_hex(&key);
    let handlers = CoordinatorHandlers {
        on_peers: |_: &[Node]| {},
        on_derp_map: |_: &serde_json::Value| {},
    };
    match tokio::time::timeout(hold, session.run(handlers)).await {
        Err(_) => {
            println!(
                "up: node key {key_hex} in environment {environment_id}: the session was up {}s after the announcement; confirm in the coordinator log that the node was taken (no node decode failure, no refusal)",
                hold.as_secs()
            );
            Ok(())
        }
        Ok(ended) => {
            let reason = match ended {
                Ok(()) => "the coordinator closed the stream".to_owned(),
                Err(error) => format!("{error} (refusal: {})", error.is_refusal()),
            };
            println!("ended: node key {key_hex} in environment {environment_id}: {reason}");
            std::process::exit(3);
        }
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn parse_key(hex: &str) -> anyhow::Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("PROBE_NODE_KEY must be 64 hex digits or `new`");
    }
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)?;
    }
    Ok(key)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
