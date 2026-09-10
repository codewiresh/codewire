//! One selected-key worker per signing operation; no key cache or new owner.

use codewire_gateway_proto::codewire::bridge::v1;
use codewire_gateway_proto::ssh::{SshOperation, agent};
use codewire_protected_store::ssh_material::SshAgentMaterial;

use super::*;

/// Sign once and await exact child/staging drain before **every** return after
/// worker admission. The caller is an authority-owned task, not a disposable
/// RPC waiter: it must retain this future, original lease and its operation
/// permit through completion, then revalidate that lease before releasing the
/// signature. This helper neither authorizes a grant nor reads a store.
///
/// Cancellation covers startup and signing but cannot select away from drain.
/// The existing owner retains worker ownership if the caller nevertheless
/// drops the future; dropping is not evidence that cleanup was observed.
pub async fn sign_once<C>(
    owner: &SshAgentOwner,
    material: SshAgentMaterial,
    request: v1::CredentialSshSignRequest,
    deadline: Instant,
    cancellation: C,
) -> Result<Vec<u8>, SshAgentError>
where
    C: Future<Output = ()> + Send,
{
    let expected = material.public_key().key_blob().to_vec();
    if request.public_key_blob != expected {
        return Err(SshAgentError::Denied);
    }
    let payload = Zeroizing::new(
        agent::encode_request(&v1::credential_ssh_request::Operation::Sign(request))
            .map_err(|_| SshAgentError::Denied)?,
    );
    tokio::pin!(cancellation);
    // Poll a durable caller cancellation before spawning any process. The
    // ready branch is local and owns no material/worker lifecycle authority.
    tokio::select! {
        biased;
        _ = &mut cancellation => return Err(SshAgentError::Cancelled),
        _ = std::future::ready(()) => {}
    }
    let now = Instant::now();
    if deadline <= now || deadline > now + codewire_gateway_proto::ssh::MAX_DEADLINE {
        return Err(SshAgentError::Expired);
    }
    let (key, passphrase) = material.into_parts();
    let pending = owner.start(key, passphrase, deadline)?;
    let drain = pending.drain_handle();
    let result = tokio::select! {
        biased;
        _ = &mut cancellation => Err(SshAgentError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(SshAgentError::Expired),
        result = async {
            let selected = pending.ready().await?;
            if selected.public_identity().key_blob() != expected {
                return Err(SshAgentError::InvalidKey);
            }
            if deadline <= Instant::now() {
                return Err(SshAgentError::Expired);
            }
            // The existing parser is the exact-key and algorithm guard. The
            // generic codec below only extracts its already-validated reply.
            let reply = selected.request(&payload).await?;
            match agent::decode_response(&reply, SshOperation::Sign)
                .map_err(|_| SshAgentError::Failed)?
            {
                v1::credential_ssh_response::Result::Signature(signature) => Ok(signature.signature_blob),
                _ => Err(SshAgentError::Failed),
            }
        } => result,
    };
    // Deliberately outside select: no signature and no cancellation outcome
    // may be published until this exact worker's terminal cleanup is known.
    // Cleanup failure dominates all other outcomes and latches owner failure.
    drain.cancel_and_drain().await?;
    let signature = result?;
    if deadline <= Instant::now() {
        return Err(SshAgentError::Expired);
    }
    tokio::select! {
        biased;
        _ = &mut cancellation => Err(SshAgentError::Cancelled),
        _ = std::future::ready(()) => Ok(signature),
    }
}
