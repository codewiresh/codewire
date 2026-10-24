//! Connect to a DERP relay with a fresh, unregistered node key and report
//! whether the relay admits it (#2844).
//!
//! ```sh
//! cargo run -p codewire-derp --example derp_probe -- derp.example.com:443
//! ```
//!
//! Prints `admitted` when the relay sends ServerInfo, or `refused` when it
//! closes the connection first, and exits 0 or 1 accordingly. A relay that
//! verifies clients refuses this probe within its handshake budget.

use std::time::{Duration, Instant};

use codewire_tailnet::derp::{self, NodePrivate, ReceivedMessage};
use rand::rngs::OsRng;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .ok_or("usage: derp_probe <host:port>")?;
    let host = target
        .rsplit_once(':')
        .map(|(host, _)| host)
        .ok_or("usage: derp_probe <host:port>")?
        .to_string();
    let private = NodePrivate::generate(&mut OsRng);
    let started = Instant::now();
    let mut client = derp::connect_tls(
        &target,
        &host,
        derp::webpki_tls_config(),
        private,
        &mut OsRng,
    )
    .await?;
    let outcome = tokio::time::timeout(Duration::from_secs(30), client.recv()).await;
    let elapsed = started.elapsed().as_secs_f64();
    match outcome {
        Ok(Ok(ReceivedMessage::ServerInfo)) => {
            println!("admitted after {elapsed:.1}s");
            Ok(())
        }
        Ok(Ok(other)) => {
            println!("admitted after {elapsed:.1}s (first frame {other:?})");
            Ok(())
        }
        Ok(Err(error)) => {
            println!("refused after {elapsed:.1}s: {error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("no answer after {elapsed:.1}s");
            std::process::exit(2);
        }
    }
}
