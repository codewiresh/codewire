//! The network agent's move to a restored boot's identity (#3046 R4).

use anyhow::{Context as _, Result};
use codewire_network_session::NetworkKey;

use super::checkpoint;

/// Move to the identity in the seed the runner wrote for the restored boot,
/// then acknowledge to PID 1. A failure leaves the old key, so the restored
/// boot's worker is refused; PID 1 times out and the VM never thaws.
pub(super) fn rekey(vm_id: &mut uuid::Uuid, generation: &mut u64, key: &mut NetworkKey) {
    match moved() {
        Ok(rekeyed) => (*vm_id, *generation, *key) = rekeyed,
        Err(error) => eprintln!("codewire guest: network re-key failed: {error:#}"),
    }
}

fn moved() -> Result<(uuid::Uuid, u64, NetworkKey)> {
    let seed = checkpoint::read_seed_direct()?;
    let rekeyed = NetworkKey::derive(seed.auth_token(), seed.vm_id(), seed.generation())
        .context("derive the restored network key")?;
    checkpoint::acknowledge_rekey(checkpoint::NETWORK_REKEY, &seed, false)?;
    Ok((seed.vm_id(), seed.generation(), rekeyed))
}
