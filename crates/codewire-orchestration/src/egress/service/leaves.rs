//! `EgressService.SignInterceptionLeaves` (#4001, N3b): cw-egress's front
//! door gets its leaves through the credential relay epoch running for its
//! Pod's binding on this process.
//!
//! The Pod, its binding and its interception decision are checked by the
//! caller (`sign_interception_leaves`). The epoch asks the credential service
//! with its own credentials and handle, none of which reach this module, so
//! the service signs only for that binding's hosts and only until that
//! epoch's end. The relay is leader-gated, so a Pod whose epoch runs on
//! another process, or not yet, is answered UNAVAILABLE; cw-egress retries,
//! and the front door's hosts fail closed until it has leaves.

use std::time::Duration;

use codewire_proto::codewire::internal::v1::{InterceptionLeaf, SignInterceptionLeavesResponse};
use connectrpc::ConnectError;
use tokio::sync::oneshot;
use tonic::{Code, Status};
use uuid::Uuid;

use super::{EgressServiceState, GuestPod, denied};
use crate::front_door::{BindingKey, EpochRequest, Sign};
use crate::workspace_binding::store::LiveBinding;

/// How long an ask waits for its epoch. The epoch answers one ask at a time
/// and bounds each by its broker admission timeout, so this covers a join
/// ahead of it and the signing itself.
const SIGN_WAIT: Duration = Duration::from_secs(15);

impl EgressServiceState {
    /// The leaves for `leaf_public_key`, signed through the binding's
    /// current epoch.
    pub(super) async fn sign_leaves(
        &self,
        guest: &GuestPod,
        binding: &LiveBinding,
        leaf_public_key: Vec<u8>,
    ) -> Result<SignInterceptionLeavesResponse, ConnectError> {
        let Some(front_doors) = &self.front_doors else {
            return Err(no_epoch());
        };
        let key = BindingKey {
            environment_id: Uuid::parse_str(&binding.environment_id).map_err(|_| denied())?,
            pod_uid: guest.uid.clone(),
            generation: u64::try_from(binding.operation_generation).map_err(|_| denied())?,
        };
        let (_, epoch) = front_doors.current(&key).ok_or_else(no_epoch)?;
        let (reply, signed) = oneshot::channel();
        epoch
            .send(EpochRequest::Sign(Sign {
                leaf_public_key,
                reply,
            }))
            .await
            .map_err(|_| no_epoch())?;
        let signed = tokio::time::timeout(SIGN_WAIT, signed)
            .await
            .map_err(|_| no_epoch())?
            .map_err(|_| no_epoch())?
            .map_err(|status| answer(&status))?;
        Ok(SignInterceptionLeavesResponse {
            leaves: signed
                .leaves
                .into_iter()
                .map(|leaf| InterceptionLeaf {
                    certificate_der: leaf.certificate_der,
                    ..Default::default()
                })
                .collect(),
            renew_at_unix: signed.renew_at_unix,
            ..Default::default()
        })
    }
}

fn no_epoch() -> ConnectError {
    ConnectError::unavailable("no credential relay epoch can sign for this Pod")
}

/// The epoch's answer for cw-egress, by code only.
fn answer(status: &Status) -> ConnectError {
    match status.code() {
        Code::PermissionDenied => denied(),
        Code::InvalidArgument => {
            ConnectError::invalid_argument("the front door's key cannot be signed")
        }
        _ => no_epoch(),
    }
}
