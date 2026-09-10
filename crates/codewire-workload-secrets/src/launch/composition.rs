//! One current bundle format. Public framing is only a bounded container:
//! context, recipient, role, expected count and composition digest are inside
//! every sealed part. A relay neither opens material nor authenticates roles.

use crypto_box::PublicKey;

use crate::{ProjectionCompositionPlan, composition_plan::composition_winning_keys_digest};

use super::*;

const BUNDLE_MAGIC: &[u8; 8] = b"CWENVB02";
const FRAGMENT_MAGIC: &[u8; 8] = b"CWENVF02";
const MAGIC: &[u8; 8] = b"CWENV\0\0\x02";
const CONTEXT_BYTES: usize = 16 + 8 + 32 + 8;
const BINDING_BYTES: usize = MAGIC.len() + CONTEXT_BYTES + 32;
const GROUP_END: usize = BINDING_BYTES + 1 + 1 + 32;
const HEADER_BYTES: usize = GROUP_END + 32;
const SEAL_OVERHEAD: usize = 48;
const CIPHER_OVERHEAD: usize = HEADER_BYTES + SEAL_OVERHEAD;
const MIN_CIPHER_BYTES: usize = CIPHER_OVERHEAD + 4;
const MAX_CIPHER_BYTES: usize = CIPHER_OVERHEAD + MAX_ENVIRONMENT_PROJECTION_BYTES;
const BUNDLE_HEADER_BYTES: usize = BUNDLE_MAGIC.len() + 1;
const FRAGMENT_HEADER_BYTES: usize = FRAGMENT_MAGIC.len() + 4;
const SINGLE_ROLE: u8 = 2;

/// The maximum complete one-launch bundle: aggregate values plus two sealed
/// headers, two length frames, and the second fragment's entry-count word.
/// This bounds ciphertext before allocation or decryption at every consumer.
pub const MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES: usize =
    BUNDLE_HEADER_BYTES + 2 * (4 + CIPHER_OVERHEAD) + MAX_ENVIRONMENT_PROJECTION_BYTES + 4;

/// Fixed mixed-projection contributor, never an arbitrary caller-chosen index.
/// The authenticated producer/transport establishes authority for this role;
/// public-key encryption alone cannot authenticate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectionContributor {
    Local,
    Platform,
}

impl ProjectionContributor {
    fn wire_role(self) -> u8 {
        match self {
            Self::Local => 0,
            Self::Platform => 1,
        }
    }
}

/// Encrypt an all-or-nothing single-source projection for one authenticated
/// launch. Single output is a complete bundle and cannot be used as a mixed
/// fragment. Encryption does not grant access or prove sender identity.
pub fn seal_environment_projection(
    projection: EnvironmentProjection,
    context: &ProjectionContext,
    recipient: [u8; 32],
    now_unix_ms: u64,
) -> Result<Vec<u8>, ProjectionError> {
    let ciphertext = seal_part(
        projection,
        context,
        recipient,
        None,
        [0; 32],
        [0; 32],
        now_unix_ms,
    )?;
    encode_bundle(&[&ciphertext])
}

/// Seal one producer's already-authorized, disjoint winning values. Both
/// contributors must use the same canonical winner plan and original launch
/// context/recipient. Each producer must independently check its inventory/plan
/// before this call; the digest is consistency, not authority. Actual names must
/// equal this contributor's entire winning set, including an empty winning set.
/// The returned opaque fragment is not itself a launchable bundle.
pub fn seal_environment_projection_fragment(
    projection: EnvironmentProjection,
    context: &ProjectionContext,
    recipient: [u8; 32],
    contributor: ProjectionContributor,
    plan: &ProjectionCompositionPlan,
    now_unix_ms: u64,
) -> Result<Vec<u8>, ProjectionError> {
    plan.validate_context(context, recipient)?;
    if !projection
        .entries
        .keys()
        .eq(plan.winning_keys(contributor).iter())
    {
        return Err(ProjectionError::InvalidValues);
    }
    let ciphertext = seal_part(
        projection,
        context,
        recipient,
        Some(contributor),
        plan.digest(),
        plan.winning_keys_digest(),
        now_unix_ms,
    )?;
    let mut bytes = Vec::with_capacity(FRAGMENT_HEADER_BYTES + ciphertext.len());
    bytes.extend_from_slice(FRAGMENT_MAGIC);
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}

/// Assemble exactly Local then Platform without opening either fragment.
/// Framing and aggregate ciphertext lengths are checked before allocation.
/// Encrypted role/count/group/context/recipient and disjoint values are checked
/// together only by the consuming launcher. Ordinary single bundles are denied.
pub fn compose_environment_projection(
    local_fragment: &[u8],
    platform_fragment: &[u8],
) -> Result<Vec<u8>, ProjectionError> {
    let local = decode_fragment(local_fragment)?;
    let platform = decode_fragment(platform_fragment)?;
    encode_bundle(&[local, platform])
}

fn seal_part(
    projection: EnvironmentProjection,
    context: &ProjectionContext,
    recipient: [u8; 32],
    contributor: Option<ProjectionContributor>,
    composition_sha256: [u8; 32],
    winning_keys_sha256: [u8; 32],
    now_unix_ms: u64,
) -> Result<Vec<u8>, ProjectionError> {
    context.validate_at(now_unix_ms)?;
    validate_projection_recipient(recipient)?;
    if contributor.is_some() == (composition_sha256 == [0; 32])
        || contributor.is_some() == (winning_keys_sha256 == [0; 32])
    {
        return Err(ProjectionError::InvalidEnvelope);
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + projection.encoded_len));
    plaintext.extend_from_slice(MAGIC);
    context.encode(&mut plaintext);
    plaintext.extend_from_slice(&recipient);
    plaintext.push(contributor.map_or(SINGLE_ROLE, ProjectionContributor::wire_role));
    plaintext.push(if contributor.is_some() { 2 } else { 1 });
    plaintext.extend_from_slice(&composition_sha256);
    plaintext.extend_from_slice(&winning_keys_sha256);
    projection.encode(&mut plaintext);
    PublicKey::from(recipient)
        .seal(&mut OsRng, &plaintext)
        .map_err(|_| ProjectionError::InvalidEnvelope)
}

fn valid_cipher_length(length: usize) -> Result<(), ProjectionError> {
    if !(MIN_CIPHER_BYTES..=MAX_CIPHER_BYTES).contains(&length) {
        return Err(ProjectionError::InvalidEnvelope);
    }
    Ok(())
}

fn take_envelope<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], ProjectionError> {
    take(bytes, count).map_err(|_| ProjectionError::InvalidEnvelope)
}

fn take_cipher<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], ProjectionError> {
    let length = read_u32(bytes).map_err(|_| ProjectionError::InvalidEnvelope)? as usize;
    valid_cipher_length(length)?;
    take_envelope(bytes, length)
}

fn decode_fragment(mut bytes: &[u8]) -> Result<&[u8], ProjectionError> {
    if bytes.len() > FRAGMENT_HEADER_BYTES + MAX_CIPHER_BYTES
        || take_envelope(&mut bytes, FRAGMENT_MAGIC.len())? != FRAGMENT_MAGIC
    {
        return Err(ProjectionError::InvalidEnvelope);
    }
    let ciphertext = take_cipher(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(ProjectionError::InvalidEnvelope);
    }
    Ok(ciphertext)
}

/// Length validation is independent of ciphertext contents, with fixed at-most
/// two-part storage. No attacker-controlled length is used for allocation.
fn bundle_length(parts: &[&[u8]]) -> Result<usize, ProjectionError> {
    if !(1..=2).contains(&parts.len()) {
        return Err(ProjectionError::InvalidEnvelope);
    }
    let mut encoded_values = 0_usize;
    let mut length = BUNDLE_HEADER_BYTES;
    for part in parts {
        valid_cipher_length(part.len())?;
        encoded_values = encoded_values
            .checked_add(part.len() - CIPHER_OVERHEAD)
            .ok_or(ProjectionError::InvalidEnvelope)?;
        length = length
            .checked_add(4 + part.len())
            .ok_or(ProjectionError::InvalidEnvelope)?;
    }
    if encoded_values > MAX_ENVIRONMENT_PROJECTION_BYTES + 4 * (parts.len() - 1)
        || length > MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES
    {
        return Err(ProjectionError::InvalidEnvelope);
    }
    Ok(length)
}

fn encode_bundle(parts: &[&[u8]]) -> Result<Vec<u8>, ProjectionError> {
    let length = bundle_length(parts)?;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(BUNDLE_MAGIC);
    bytes.push(parts.len() as u8);
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    Ok(bytes)
}

fn decode_bundle(mut bytes: &[u8]) -> Result<([&[u8]; 2], usize), ProjectionError> {
    if bytes.len() > MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES
        || take_envelope(&mut bytes, BUNDLE_MAGIC.len())? != BUNDLE_MAGIC
    {
        return Err(ProjectionError::InvalidEnvelope);
    }
    let count = usize::from(take_envelope(&mut bytes, 1)?[0]);
    if !(1..=2).contains(&count) {
        return Err(ProjectionError::InvalidEnvelope);
    }
    let mut parts: [&[u8]; 2] = [&[]; 2];
    for part in &mut parts[..count] {
        *part = take_cipher(&mut bytes)?;
    }
    if !bytes.is_empty() {
        return Err(ProjectionError::InvalidEnvelope);
    }
    bundle_length(&parts[..count])?;
    Ok((parts, count))
}

pub(super) fn open_bundle(
    recipient: ProjectionRecipient,
    ciphertext: &[u8],
    expected: &ProjectionContext,
    now_unix_ms: u64,
) -> Result<EnvironmentProjection, ProjectionError> {
    expected.validate_at(now_unix_ms)?;
    let (parts, count) = decode_bundle(ciphertext)?;
    let mut expected_binding = Vec::with_capacity(BINDING_BYTES);
    expected_binding.extend_from_slice(MAGIC);
    expected.encode(&mut expected_binding);
    expected_binding.extend_from_slice(&recipient.public_key());
    let mut group = None;
    let mut winning_keys = None;
    let mut projections = Vec::with_capacity(count);
    for (index, part) in parts[..count].iter().enumerate() {
        let plaintext = Zeroizing::new(
            recipient
                .0
                .unseal(part)
                .map_err(|_| ProjectionError::InvalidEnvelope)?,
        );
        if plaintext.len() < HEADER_BYTES + 4 || !plaintext.starts_with(&expected_binding) {
            return Err(ProjectionError::InvalidEnvelope);
        }
        let role = plaintext[BINDING_BYTES];
        let expected_role = if count == 1 { SINGLE_ROLE } else { index as u8 };
        let digest: [u8; 32] = plaintext[BINDING_BYTES + 2..GROUP_END]
            .try_into()
            .map_err(|_| ProjectionError::InvalidEnvelope)?;
        let winners_digest: [u8; 32] = plaintext[GROUP_END..HEADER_BYTES]
            .try_into()
            .map_err(|_| ProjectionError::InvalidEnvelope)?;
        if role != expected_role
            || usize::from(plaintext[BINDING_BYTES + 1]) != count
            || (count == 1) != (digest == [0; 32])
            || (count == 1) != (winners_digest == [0; 32])
            || group.is_some_and(|previous| previous != digest)
            || winning_keys.is_some_and(|previous| previous != winners_digest)
        {
            return Err(ProjectionError::InvalidEnvelope);
        }
        group = Some(digest);
        winning_keys = Some(winners_digest);
        projections.push(EnvironmentProjection::decode(&plaintext[HEADER_BYTES..])?);
    }
    if count == 2 {
        let local = projections[0].entries.keys().cloned().collect();
        let platform = projections[1].entries.keys().cloned().collect();
        if winning_keys != Some(composition_winning_keys_digest(&local, &platform)) {
            return Err(ProjectionError::InvalidEnvelope);
        }
    }
    // from_entries rejects overlapping names and validates the aggregate count
    // and bytes. Previously decoded plaintext values remain zeroizing owners on
    // every failure, including failure to open a later part.
    EnvironmentProjection::from_entries(projections.into_iter().flat_map(|part| part.entries))
}

#[cfg(test)]
mod tests;
