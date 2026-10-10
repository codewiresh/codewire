//! Verifies a signed cw release delivery with the verifier compiled into cw.
//!
//! The release job runs this after GnuPG signs and before anything is
//! published. cw's verifier is deliberately narrower than GnuPG, so a
//! signature GnuPG accepts but every cw would refuse must never become an
//! immutable release. It checks exactly the signatures cw checks: the stable
//! channel pointer, the release manifest and SHA256SUMS.
//!
//! Usage: verify-release-signatures PUBLIC_KEY FINGERPRINT DIST

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use codewire_cw_release::openpgp::ReleaseKey;
use codewire_cw_release::release::{ChannelEnvelope, MAX_JSON_BYTES, MAX_SIGNATURE_BYTES};

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(format!("{} is empty or exceeds its bound", path.display()));
    }
    Ok(bytes)
}

fn verify(key: &ReleaseKey, dist: &Path) -> Result<(), String> {
    let delivery = dist.join("delivery");
    let channel = ChannelEnvelope::decode(&read(
        &delivery.join("channels/stable.json"),
        MAX_JSON_BYTES,
    )?)
    .map_err(|error| format!("stable channel: {error}"))?;
    let pointer = channel
        .pointer
        .signing_bytes()
        .map_err(|error| format!("stable channel: {error}"))?;
    key.verify(&pointer, channel.signature.as_bytes())
        .map_err(|error| format!("stable channel: {error}"))?;
    for (data, signature) in [
        (
            delivery.join("release.json"),
            delivery.join("release.json.asc"),
        ),
        (dist.join("SHA256SUMS"), dist.join("SHA256SUMS.asc")),
    ] {
        key.verify(
            &read(&data, MAX_JSON_BYTES)?,
            &read(&signature, MAX_SIGNATURE_BYTES)?,
        )
        .map_err(|error| format!("{}: {error}", signature.display()))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let [key, fingerprint, dist] = arguments.as_slice() else {
        eprintln!("usage: verify-release-signatures PUBLIC_KEY FINGERPRINT DIST");
        return ExitCode::from(2);
    };
    let result = read(Path::new(key), 16 * 1024).and_then(|armored| {
        let fingerprint = fingerprint.to_str().ok_or("fingerprint is not UTF-8")?;
        let key = ReleaseKey::import(&armored, fingerprint).map_err(|error| error.to_string())?;
        verify(&key, &PathBuf::from(dist))
    });
    match result {
        Ok(()) => {
            println!("cw-release: built-in verifier admitted channel, manifest and SHA256SUMS");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cw-release: built-in verifier refused the delivery: {error}");
            ExitCode::FAILURE
        }
    }
}
