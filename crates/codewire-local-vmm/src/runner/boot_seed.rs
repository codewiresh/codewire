//! The seed a boot's guest reads first, built from the runner's request.

use codewire_vmm_guest_probe::{EgressCaCertificate, Seed, SeedPlaceholders, Sha256Value};
use rand::{RngCore as _, rngs::OsRng};

use super::{CreateVmRequest, RunnerError};
use crate::cw_runtime::AdmittedCwRuntimeDisk;

/// The seed for one boot: the request's bindings and this boot's daemon
/// token, never a host path or credential.
pub(super) fn boot_seed(
    request: &CreateVmRequest,
    token: &str,
    direct_shares_sha256: Option<Sha256Value>,
    docker_data_disk: bool,
    cw_runtime_disk: Option<&AdmittedCwRuntimeDisk>,
    egress_ca: Option<EgressCaCertificate>,
    placeholders: SeedPlaceholders,
) -> Result<Seed, RunnerError> {
    let seed = Seed::new_with_all_bindings(
        request.vm_id,
        request.generation,
        request.daemon_vsock_port,
        token.to_string(),
        request.setup,
        direct_shares_sha256,
        request.skill_snapshot_sha256,
    )?;
    let seed = if docker_data_disk {
        seed.with_docker_data_disk()
    } else {
        seed
    };
    let seed = match request.environment_projection_sha256 {
        Some(selection) => seed.with_environment_projection_sha256(selection),
        None => seed,
    };
    let seed = seed.with_managed_credential_clients(request.managed_credential_clients);
    let seed = match cw_runtime_disk {
        Some(disk) => seed.with_cw_runtime_catalog_sha256(digest(&disk.generation)?),
        None => seed,
    };
    // The runner admitted the request's image disk before building this.
    let seed = if request.image_disk.is_some() {
        seed.with_image_disk()
    } else {
        seed
    };
    let seed = match request.cw_runtime_moved_from_generation.as_deref() {
        Some(generation) => seed.with_cw_runtime_moved_from_sha256(digest(generation)?)?,
        None => seed,
    };
    let seed = match egress_ca {
        Some(certificate) => seed.with_egress_ca(certificate),
        None => seed,
    };
    // Placeholders ride only beside the CA (#3999).
    let seed = seed.with_credential_placeholders(placeholders)?;
    Ok(seed)
}

fn digest(generation: &str) -> Result<Sha256Value, RunnerError> {
    Sha256Value::parse_hex(generation).map_err(|_| RunnerError::InvalidRequest)
}

pub(super) fn generate_auth_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut token, "{byte:02x}");
    }
    token
}
