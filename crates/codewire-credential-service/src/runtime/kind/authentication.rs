//! Kind-only successful bridge-authentication evidence.
//!
//! The production authenticator remains the sole identity authority. This
//! wrapper calls it first, then records bounded public fixture coordinates and
//! whether the exact presented workspace token changed since that
//! environment's last success. Each environment is compared only with itself,
//! so another stage's Sandbox authenticating in between cannot hide a rotation
//! or invent one (#2972).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tonic::metadata::MetadataMap;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::TARGET;
use crate::KubernetesPlatformBridgeAuthenticator;
use crate::authority::{KubernetesPlatformRuntimeAuthority, WORKSPACE_AUTHORIZATION};

const MAX_TOKEN_BYTES: usize = 16 * 1024;

pub(super) struct KindBridgeAuthenticator {
    inner: KubernetesPlatformBridgeAuthenticator,
    evidence: Mutex<EvidenceState>,
}

impl KindBridgeAuthenticator {
    pub(super) fn new(inner: KubernetesPlatformBridgeAuthenticator) -> Self {
        Self {
            inner,
            evidence: Mutex::new(EvidenceState::default()),
        }
    }
}

#[async_trait]
impl PlatformBridgeAuthenticator for KindBridgeAuthenticator {
    type Authority = KubernetesPlatformRuntimeAuthority;

    async fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<std::sync::Arc<Self::Authority>, PlatformBridgeAuthenticationError> {
        // Authentication and all authoritative Pod/database checks happen
        // unchanged before fixture metadata is inspected or any event exists.
        let authority = self.inner.authenticate(metadata).await?;
        let tokens = PresentedTokens::from_metadata(metadata)?;
        let scope = &authority.initial.scope;
        let generation = u64::try_from(scope.generation)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or(PlatformBridgeAuthenticationError::Unavailable)?;
        let mut evidence = self
            .evidence
            .lock()
            .map_err(|_| PlatformBridgeAuthenticationError::Unavailable)?;
        let (auth_sequence, workspace_token_changed) = evidence.record(
            &scope.environment_id,
            generation,
            &tokens.workspace_pod_uid,
            &tokens.relay_pod_uid,
            tokens.workspace_sha256,
        )?;
        tracing::info!(
            target: TARGET,
            event = "bridge_authenticated",
            environment_id = scope.environment_id.as_str(),
            generation,
            workspace_pod_uid = tokens.workspace_pod_uid.as_str(),
            relay_pod_uid = tokens.relay_pod_uid.as_str(),
            auth_sequence,
            workspace_token_changed,
            "bridge_authenticated"
        );
        drop(evidence);
        Ok(authority)
    }
}

#[derive(Default)]
struct EvidenceState {
    auth_sequence: u64,
    /// Each environment's last successful authentication.
    previous: HashMap<String, PreviousAuthentication>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreviousAuthentication {
    generation: u64,
    workspace_pod_uid: String,
    relay_pod_uid: String,
    workspace_sha256: [u8; 32],
}

impl EvidenceState {
    fn record(
        &mut self,
        environment_id: &str,
        generation: u64,
        workspace_pod_uid: &str,
        relay_pod_uid: &str,
        workspace_sha256: [u8; 32],
    ) -> Result<(u64, bool), PlatformBridgeAuthenticationError> {
        let auth_sequence = self
            .auth_sequence
            .checked_add(1)
            .ok_or(PlatformBridgeAuthenticationError::Unavailable)?;
        let changed = self.previous.get(environment_id).is_some_and(|previous| {
            previous.generation == generation
                && previous.workspace_pod_uid == workspace_pod_uid
                && previous.relay_pod_uid == relay_pod_uid
                && previous.workspace_sha256 != workspace_sha256
        });
        self.auth_sequence = auth_sequence;
        self.previous.insert(
            environment_id.to_owned(),
            PreviousAuthentication {
                generation,
                workspace_pod_uid: workspace_pod_uid.to_owned(),
                relay_pod_uid: relay_pod_uid.to_owned(),
                workspace_sha256,
            },
        );
        Ok((auth_sequence, changed))
    }
}

struct PresentedTokens {
    relay_pod_uid: String,
    workspace_pod_uid: String,
    workspace_sha256: [u8; 32],
}

impl PresentedTokens {
    fn from_metadata(metadata: &MetadataMap) -> Result<Self, PlatformBridgeAuthenticationError> {
        let relay = only_relay_authorization(metadata)?;
        let workspace = only_workspace_authorization(metadata)?;
        let relay_token = bearer(&relay)?;
        let workspace_token = bearer(&workspace)?;
        Ok(Self {
            relay_pod_uid: projected_pod_uid(relay_token)?,
            workspace_pod_uid: projected_pod_uid(workspace_token)?,
            workspace_sha256: Sha256::digest(workspace_token).into(),
        })
    }
}

fn only_relay_authorization(
    metadata: &MetadataMap,
) -> Result<Zeroizing<Vec<u8>>, PlatformBridgeAuthenticationError> {
    let mut values = metadata.get_all("authorization").iter();
    match (values.next(), values.next()) {
        (Some(value), None) => Ok(Zeroizing::new(value.as_encoded_bytes().to_vec())),
        _ => Err(PlatformBridgeAuthenticationError::Unavailable),
    }
}

fn only_workspace_authorization(
    metadata: &MetadataMap,
) -> Result<Zeroizing<Vec<u8>>, PlatformBridgeAuthenticationError> {
    let mut values = metadata.get_all_bin(WORKSPACE_AUTHORIZATION).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_bytes()
            .map(|value| Zeroizing::new(value.to_vec()))
            .map_err(|_| PlatformBridgeAuthenticationError::Unavailable),
        _ => Err(PlatformBridgeAuthenticationError::Unavailable),
    }
}

fn bearer(value: &[u8]) -> Result<&[u8], PlatformBridgeAuthenticationError> {
    value
        .strip_prefix(b"Bearer ")
        .filter(|token| !token.is_empty() && token.len() <= MAX_TOKEN_BYTES)
        .ok_or(PlatformBridgeAuthenticationError::Unavailable)
}

#[derive(Deserialize)]
struct ProjectedClaims {
    #[serde(rename = "kubernetes.io")]
    kubernetes: KubernetesClaims,
}

#[derive(Deserialize)]
struct KubernetesClaims {
    pod: PodClaims,
}

#[derive(Deserialize)]
struct PodClaims {
    uid: String,
}

fn projected_pod_uid(token: &[u8]) -> Result<String, PlatformBridgeAuthenticationError> {
    let mut parts = token.split(|byte| *byte == b'.');
    let header = parts.next().filter(|part| !part.is_empty());
    let payload = parts.next().filter(|part| !part.is_empty());
    let signature = parts.next().filter(|part| !part.is_empty());
    if header.is_none() || signature.is_none() || parts.next().is_some() {
        return Err(PlatformBridgeAuthenticationError::Unavailable);
    }
    let payload = payload.ok_or(PlatformBridgeAuthenticationError::Unavailable)?;
    let mut decoded = Zeroizing::new(Vec::with_capacity(payload.len()));
    URL_SAFE_NO_PAD
        .decode_vec(payload, &mut decoded)
        .map_err(|_| PlatformBridgeAuthenticationError::Unavailable)?;
    let claims: ProjectedClaims = serde_json::from_slice(&decoded)
        .map_err(|_| PlatformBridgeAuthenticationError::Unavailable)?;
    let uid = Uuid::parse_str(&claims.kubernetes.pod.uid)
        .ok()
        .filter(|uid| !uid.is_nil() && uid.to_string() == claims.kubernetes.pod.uid)
        .ok_or(PlatformBridgeAuthenticationError::Unavailable)?;
    Ok(uid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    const RELAY_UID: &str = "0d63a03b-d1e8-4ca9-9dd3-46c20afc513e";
    const WORKSPACE_UID: &str = "64c23db1-5362-407a-a02a-710b99684cb2";
    const OTHER_WORKSPACE_UID: &str = "a79588a6-6ca7-4d3d-ae50-4e822ce192b4";

    fn token(uid: &str, suffix: &str) -> String {
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "kubernetes.io":{"pod":{"uid":uid}},
                "synthetic":suffix,
            }))
            .unwrap(),
        );
        format!("e30.{payload}.synthetic-signature")
    }

    fn metadata(workspace_suffix: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            format!("Bearer {}", token(RELAY_UID, "relay"))
                .parse()
                .unwrap(),
        );
        let workspace = format!("Bearer {}", token(WORKSPACE_UID, workspace_suffix));
        metadata.insert_bin(
            WORKSPACE_AUTHORIZATION,
            MetadataValue::from_bytes(workspace.as_bytes()),
        );
        metadata
    }

    fn record(
        state: &mut EvidenceState,
        environment_id: &str,
        generation: u64,
        digest: [u8; 32],
    ) -> Result<(u64, bool), PlatformBridgeAuthenticationError> {
        state.record(environment_id, generation, WORKSPACE_UID, RELAY_UID, digest)
    }

    #[test]
    fn evidence_retains_only_hash_and_marks_exact_workspace_token_changes() {
        let first = PresentedTokens::from_metadata(&metadata("old")).unwrap();
        let same = PresentedTokens::from_metadata(&metadata("old")).unwrap();
        let changed = PresentedTokens::from_metadata(&metadata("new")).unwrap();
        assert_eq!(first.relay_pod_uid, RELAY_UID);
        assert_eq!(first.workspace_pod_uid, WORKSPACE_UID);
        assert_eq!(first.workspace_sha256, same.workspace_sha256);
        assert_ne!(first.workspace_sha256, changed.workspace_sha256);

        let mut state = EvidenceState::default();
        assert_eq!(
            record(&mut state, "environment-a", 7, first.workspace_sha256).unwrap(),
            (1, false)
        );
        assert_eq!(
            record(&mut state, "environment-a", 7, same.workspace_sha256).unwrap(),
            (2, false)
        );
        assert_eq!(
            record(&mut state, "environment-a", 7, changed.workspace_sha256,).unwrap(),
            (3, true)
        );
        assert_eq!(state.auth_sequence, 3);
        assert_eq!(
            state.previous["environment-a"].workspace_sha256,
            changed.workspace_sha256
        );
    }

    #[test]
    fn another_environment_in_between_neither_hides_nor_invents_a_change() {
        // #2972: the Claude stages' Sandboxes authenticate while the native
        // stage idles for its rotation. Each environment compares only with
        // its own previous authentication.
        let old = PresentedTokens::from_metadata(&metadata("old")).unwrap();
        let changed = PresentedTokens::from_metadata(&metadata("new")).unwrap();
        let mut state = EvidenceState::default();
        assert_eq!(
            record(&mut state, "environment-a", 7, old.workspace_sha256).unwrap(),
            (1, false)
        );
        assert_eq!(
            record(&mut state, "environment-b", 3, changed.workspace_sha256).unwrap(),
            (2, false)
        );
        assert_eq!(
            record(&mut state, "environment-a", 7, changed.workspace_sha256).unwrap(),
            (3, true)
        );
        assert_eq!(
            record(&mut state, "environment-b", 3, changed.workspace_sha256).unwrap(),
            (4, false)
        );
        assert_eq!(
            record(&mut state, "environment-a", 7, changed.workspace_sha256).unwrap(),
            (5, false)
        );
        assert_eq!(
            record(&mut state, "environment-b", 3, old.workspace_sha256).unwrap(),
            (6, true)
        );
    }

    #[test]
    fn changed_flag_is_scoped_to_exact_identity_and_sequence_overflow_is_closed() {
        let old = PresentedTokens::from_metadata(&metadata("old")).unwrap();
        let changed = PresentedTokens::from_metadata(&metadata("new")).unwrap();
        let mut state = EvidenceState::default();
        record(&mut state, "environment-a", 7, old.workspace_sha256).unwrap();
        assert_eq!(
            record(&mut state, "environment-b", 7, changed.workspace_sha256,).unwrap(),
            (2, false)
        );
        assert_eq!(
            record(&mut state, "environment-b", 8, old.workspace_sha256).unwrap(),
            (3, false)
        );
        assert_eq!(
            state
                .record(
                    "environment-b",
                    8,
                    OTHER_WORKSPACE_UID,
                    RELAY_UID,
                    changed.workspace_sha256,
                )
                .unwrap(),
            (4, false)
        );

        state.auth_sequence = u64::MAX;
        let previous = state.previous.clone();
        assert!(record(&mut state, "environment-b", 8, changed.workspace_sha256,).is_err());
        assert_eq!(state.auth_sequence, u64::MAX);
        assert_eq!(state.previous, previous);
    }

    #[test]
    fn evidence_parser_rejects_noncanonical_or_ambiguous_identity_metadata() {
        let mut duplicate = metadata("old");
        let repeated = duplicate.get("authorization").unwrap().clone();
        duplicate.append("authorization", repeated);
        assert!(PresentedTokens::from_metadata(&duplicate).is_err());

        let mut noncanonical = metadata("old");
        let workspace = format!("Bearer {}", token(&WORKSPACE_UID.to_uppercase(), "old"));
        noncanonical.insert_bin(
            WORKSPACE_AUTHORIZATION,
            MetadataValue::from_bytes(workspace.as_bytes()),
        );
        assert!(PresentedTokens::from_metadata(&noncanonical).is_err());

        let mut malformed = metadata("old");
        malformed.insert_bin(
            WORKSPACE_AUTHORIZATION,
            MetadataValue::from_bytes(b"Bearer not-a-jwt"),
        );
        assert!(PresentedTokens::from_metadata(&malformed).is_err());
    }
}
