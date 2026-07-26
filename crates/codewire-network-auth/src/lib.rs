use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub const NETWORK_AUTH_NAMESPACE: &str = "mesh.networkauth";
pub const NETWORK_AUTH_ISSUER_KEY: &str = "issuer.current";

pub const RUNTIME_TOKEN_PREFIX: &str = "cwrt1";
pub const SENDER_TOKEN_PREFIX: &str = "cwsd1";
pub const OBSERVER_TOKEN_PREFIX: &str = "cwog1";
pub const ALGORITHM_ED25519: &str = "Ed25519";
pub const SUBJECT_KIND_CLIENT: &str = "client";
pub const SUBJECT_KIND_NODE: &str = "node";
pub const RUNTIME_KIND: &str = "runtime";
pub const SENDER_DELEGATION_KIND: &str = "sender";
pub const OBSERVER_DELEGATION_KIND: &str = "observer";

pub const DEFAULT_BUNDLE_VALIDITY: Duration = Duration::minutes(15);
pub const DEFAULT_RUNTIME_TTL: Duration = Duration::minutes(5);
pub const DEFAULT_SENDER_TTL: Duration = Duration::minutes(2);
pub const DEFAULT_OBSERVER_TTL: Duration = Duration::minutes(10);
pub const MAX_CLOCK_SKEW: Duration = Duration::seconds(30);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKey {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierBundle {
    pub network_id: String,
    pub issuer: String,
    pub keys: Vec<VerifierKey>,
    pub version: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeClaims {
    pub kind: String,
    pub network_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub issuer: String,
    #[serde(rename = "kid")]
    pub key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerState {
    pub network_id: String,
    pub issuer: String,
    pub key_id: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCredentialResponse {
    pub credential: String,
    pub network_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderDelegationClaims {
    pub kind: String,
    pub network_id: String,
    pub source_node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_session_id: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_session_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_groups: Vec<String>,
    pub verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience_node: String,
    pub issuer: String,
    #[serde(rename = "kid")]
    pub key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderDelegationResponse {
    pub delegation: String,
    pub network_id: String,
    pub source_node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_session_id: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_session_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_groups: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience_node: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderDelegationInput {
    pub source_node: String,
    pub from_session_id: Option<u32>,
    pub from_session_name: String,
    pub source_groups: Vec<String>,
    pub verbs: Vec<String>,
    pub audience_node: String,
    pub ttl: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverDelegationClaims {
    pub kind: String,
    pub network_id: String,
    pub target_node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    pub verbs: Vec<String>,
    pub audience_subject_kind: String,
    pub audience_subject_id: String,
    pub issuer: String,
    #[serde(rename = "kid")]
    pub key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverDelegationResponse {
    pub delegation: String,
    pub grant_id: String,
    pub network_id: String,
    pub target_node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    pub verbs: Vec<String>,
    pub audience_subject_kind: String,
    pub audience_subject_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience_display: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverDelegationInput {
    pub target_node: String,
    pub session_id: Option<u32>,
    pub session_name: String,
    pub verbs: Vec<String>,
    pub audience_subject_kind: String,
    pub audience_subject_id: String,
    pub ttl: Duration,
}

pub fn resolve_network_id(raw: &str) -> String {
    raw.trim().to_string()
}

pub fn new_issuer_state(network_id: &str) -> IssuerState {
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let now = Utc::now();
    let network_id = resolve_network_id(network_id);
    IssuerState {
        network_id: network_id.clone(),
        issuer: format!("mesh:{network_id}"),
        key_id: random_id("kid_"),
        private_key: URL_SAFE_NO_PAD.encode(signing_key.to_keypair_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
        created_at: now,
        version: 1,
    }
}

impl IssuerState {
    pub fn bundle(&self, now: DateTime<Utc>, validity: Duration) -> VerifierBundle {
        let validity = if validity <= Duration::zero() {
            DEFAULT_BUNDLE_VALIDITY
        } else {
            validity
        };
        VerifierBundle {
            network_id: resolve_network_id(&self.network_id),
            issuer: self.issuer.clone(),
            keys: vec![VerifierKey {
                key_id: self.key_id.clone(),
                algorithm: ALGORITHM_ED25519.to_string(),
                public_key: self.public_key.clone(),
            }],
            version: self.version,
            expires_at: now + validity,
        }
    }
}

pub fn sign_runtime_credential(
    state: &IssuerState,
    subject_kind: &str,
    subject_id: &str,
    now: DateTime<Utc>,
    ttl: Duration,
) -> Result<(String, RuntimeClaims), String> {
    if subject_kind.trim().is_empty() {
        return Err("subject kind is required".to_string());
    }
    if subject_id.trim().is_empty() {
        return Err("subject id is required".to_string());
    }
    validate_state_issuer(state, "runtime token")?;
    let ttl = if ttl <= Duration::zero() {
        DEFAULT_RUNTIME_TTL
    } else {
        ttl
    };
    let signing_key = signing_key_from_state(state)?;
    let claims = RuntimeClaims {
        kind: RUNTIME_KIND.to_string(),
        network_id: resolve_network_id(&state.network_id),
        subject_kind: subject_kind.to_string(),
        subject_id: subject_id.to_string(),
        issuer: state.issuer.clone(),
        key_id: state.key_id.clone(),
        issued_at: now,
        expires_at: now + ttl,
        jti: random_id("rt_"),
    };
    let payload =
        serde_json::to_vec(&claims).map_err(|err| format!("marshalling runtime claims: {err}"))?;
    let signature = signing_key.sign(&payload);
    let token = token(RUNTIME_TOKEN_PREFIX, &payload, &signature.to_bytes());
    Ok((token, claims))
}

pub fn verify_runtime_credential(
    token: &str,
    bundle: &VerifierBundle,
    now: DateTime<Utc>,
) -> Result<RuntimeClaims, String> {
    let (claims, payload, signature) = parse_runtime_credential(token)?;
    if claims.kind != RUNTIME_KIND {
        return Err(format!("unexpected runtime token kind {:?}", claims.kind));
    }
    if claims.network_id != resolve_network_id(&bundle.network_id) {
        return Err(format!(
            "runtime token network_id = {:?}, want {:?}",
            claims.network_id,
            resolve_network_id(&bundle.network_id)
        ));
    }
    validate_bundle_issuer(bundle, "runtime token")?;
    validate_issuer(&claims.issuer, &bundle.issuer, "runtime token")?;
    validate_times(
        now,
        bundle.expires_at,
        claims.issued_at,
        claims.expires_at,
        "runtime token",
    )?;
    verify_signature(
        bundle,
        &claims.key_id,
        &payload,
        &signature,
        "runtime token",
    )?;
    Ok(claims)
}

pub fn parse_runtime_credential(token: &str) -> Result<(RuntimeClaims, Vec<u8>, Vec<u8>), String> {
    let (payload, signature) = parse_token(token, RUNTIME_TOKEN_PREFIX, "runtime token")?;
    let claims = serde_json::from_slice(&payload)
        .map_err(|err| format!("parsing runtime token payload: {err}"))?;
    Ok((claims, payload, signature))
}

pub fn sign_sender_delegation(
    state: &IssuerState,
    now: DateTime<Utc>,
    input: SenderDelegationInput,
) -> Result<(String, SenderDelegationClaims), String> {
    if input.source_node.trim().is_empty() {
        return Err("source node is required".to_string());
    }
    if input.from_session_id.is_none() && input.from_session_name.trim().is_empty() {
        return Err("sender delegation requires session id or name".to_string());
    }
    if input.verbs.is_empty() {
        return Err("sender delegation requires at least one verb".to_string());
    }
    validate_state_issuer(state, "sender delegation")?;
    let ttl = if input.ttl <= Duration::zero() {
        DEFAULT_SENDER_TTL
    } else {
        input.ttl
    };
    let signing_key = signing_key_from_state(state)?;
    let claims = SenderDelegationClaims {
        kind: SENDER_DELEGATION_KIND.to_string(),
        network_id: resolve_network_id(&state.network_id),
        source_node: input.source_node.trim().to_string(),
        from_session_id: input.from_session_id,
        from_session_name: input.from_session_name.trim().to_string(),
        source_groups: input.source_groups,
        verbs: input.verbs,
        audience_node: input.audience_node.trim().to_string(),
        issuer: state.issuer.clone(),
        key_id: state.key_id.clone(),
        issued_at: now,
        expires_at: now + ttl,
        jti: random_id("sd_"),
    };
    let payload = serde_json::to_vec(&claims)
        .map_err(|err| format!("marshalling sender delegation claims: {err}"))?;
    let signature = signing_key.sign(&payload);
    let token = token(SENDER_TOKEN_PREFIX, &payload, &signature.to_bytes());
    Ok((token, claims))
}

pub fn verify_sender_delegation(
    token: &str,
    bundle: &VerifierBundle,
    now: DateTime<Utc>,
) -> Result<SenderDelegationClaims, String> {
    let (payload, signature) = parse_token(token, SENDER_TOKEN_PREFIX, "sender delegation")?;
    let claims: SenderDelegationClaims = serde_json::from_slice(&payload)
        .map_err(|err| format!("parsing sender delegation payload: {err}"))?;
    if claims.kind != SENDER_DELEGATION_KIND {
        return Err(format!(
            "unexpected sender delegation kind {:?}",
            claims.kind
        ));
    }
    if claims.network_id != resolve_network_id(&bundle.network_id) {
        return Err(format!(
            "sender delegation network_id = {:?}, want {:?}",
            claims.network_id,
            resolve_network_id(&bundle.network_id)
        ));
    }
    validate_bundle_issuer(bundle, "sender delegation")?;
    validate_issuer(&claims.issuer, &bundle.issuer, "sender delegation")?;
    validate_times(
        now,
        bundle.expires_at,
        claims.issued_at,
        claims.expires_at,
        "sender delegation",
    )?;
    verify_signature(
        bundle,
        &claims.key_id,
        &payload,
        &signature,
        "sender delegation",
    )?;
    Ok(claims)
}

pub fn sign_observer_delegation(
    state: &IssuerState,
    now: DateTime<Utc>,
    input: ObserverDelegationInput,
) -> Result<(String, ObserverDelegationClaims), String> {
    if input.target_node.trim().is_empty() {
        return Err("target node is required".to_string());
    }
    if input.session_id.is_none() && input.session_name.trim().is_empty() {
        return Err("observer delegation requires session id or name".to_string());
    }
    if input.verbs.is_empty() {
        return Err("observer delegation requires at least one verb".to_string());
    }
    if input.audience_subject_kind.trim().is_empty() {
        return Err("audience subject kind is required".to_string());
    }
    if input.audience_subject_id.trim().is_empty() {
        return Err("audience subject id is required".to_string());
    }
    validate_state_issuer(state, "observer delegation")?;
    let ttl = if input.ttl <= Duration::zero() {
        DEFAULT_OBSERVER_TTL
    } else {
        input.ttl
    };
    let signing_key = signing_key_from_state(state)?;
    let claims = ObserverDelegationClaims {
        kind: OBSERVER_DELEGATION_KIND.to_string(),
        network_id: resolve_network_id(&state.network_id),
        target_node: input.target_node.trim().to_string(),
        session_id: input.session_id,
        session_name: input.session_name.trim().to_string(),
        verbs: input.verbs,
        audience_subject_kind: input.audience_subject_kind.trim().to_string(),
        audience_subject_id: input.audience_subject_id.trim().to_string(),
        issuer: state.issuer.clone(),
        key_id: state.key_id.clone(),
        issued_at: now,
        expires_at: now + ttl,
        jti: random_id("og_"),
    };
    let payload = serde_json::to_vec(&claims)
        .map_err(|err| format!("marshalling observer delegation claims: {err}"))?;
    let signature = signing_key.sign(&payload);
    let token = token(OBSERVER_TOKEN_PREFIX, &payload, &signature.to_bytes());
    Ok((token, claims))
}

pub fn verify_observer_delegation(
    token: &str,
    bundle: &VerifierBundle,
    now: DateTime<Utc>,
) -> Result<ObserverDelegationClaims, String> {
    let (payload, signature) = parse_token(token, OBSERVER_TOKEN_PREFIX, "observer delegation")?;
    let claims: ObserverDelegationClaims = serde_json::from_slice(&payload)
        .map_err(|err| format!("parsing observer delegation payload: {err}"))?;
    if claims.kind != OBSERVER_DELEGATION_KIND {
        return Err(format!(
            "unexpected observer delegation kind {:?}",
            claims.kind
        ));
    }
    if claims.network_id != resolve_network_id(&bundle.network_id) {
        return Err(format!(
            "observer delegation network_id = {:?}, want {:?}",
            claims.network_id,
            resolve_network_id(&bundle.network_id)
        ));
    }
    validate_bundle_issuer(bundle, "observer delegation")?;
    validate_issuer(&claims.issuer, &bundle.issuer, "observer delegation")?;
    validate_times(
        now,
        bundle.expires_at,
        claims.issued_at,
        claims.expires_at,
        "observer delegation",
    )?;
    verify_signature(
        bundle,
        &claims.key_id,
        &payload,
        &signature,
        "observer delegation",
    )?;
    Ok(claims)
}

fn signing_key_from_state(state: &IssuerState) -> Result<SigningKey, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(state.private_key.as_bytes())
        .map_err(|err| format!("decoding private key: {err}"))?;
    match raw.len() {
        32 => {
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| "invalid private key length".to_string())?;
            Ok(SigningKey::from_bytes(&bytes))
        }
        64 => {
            let bytes: [u8; 64] = raw
                .as_slice()
                .try_into()
                .map_err(|_| "invalid private key length".to_string())?;
            SigningKey::from_keypair_bytes(&bytes)
                .map_err(|err| format!("decoding private key: {err}"))
        }
        _ => Err("invalid private key length".to_string()),
    }
}

fn parse_token(token: &str, prefix: &str, label: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != prefix {
        return Err(format!("invalid {label} format"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|err| format!("decoding {label} payload: {err}"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|err| format!("decoding {label} signature: {err}"))?;
    Ok((payload, signature))
}

fn token(prefix: &str, payload: &[u8], signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        prefix,
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

fn validate_times(
    now: DateTime<Utc>,
    bundle_expires_at: DateTime<Utc>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    label: &str,
) -> Result<(), String> {
    if now > bundle_expires_at + MAX_CLOCK_SKEW {
        return Err("verifier bundle expired".to_string());
    }
    if now < issued_at - MAX_CLOCK_SKEW {
        return Err(format!("{label} issued in the future"));
    }
    if now > expires_at + MAX_CLOCK_SKEW {
        return Err(format!("{label} expired"));
    }
    Ok(())
}

fn validate_issuer(claims_issuer: &str, bundle_issuer: &str, label: &str) -> Result<(), String> {
    if claims_issuer != bundle_issuer {
        return Err(format!(
            "{label} issuer = {claims_issuer:?}, want {bundle_issuer:?}"
        ));
    }
    Ok(())
}

fn expected_issuer(network_id: &str) -> String {
    format!("mesh:{}", resolve_network_id(network_id))
}

fn validate_state_issuer(state: &IssuerState, label: &str) -> Result<(), String> {
    let want = expected_issuer(&state.network_id);
    if state.issuer != want {
        return Err(format!(
            "{label} issuer state = {:?}, want {want:?}",
            state.issuer
        ));
    }
    Ok(())
}

fn validate_bundle_issuer(bundle: &VerifierBundle, label: &str) -> Result<(), String> {
    let want = expected_issuer(&bundle.network_id);
    if bundle.issuer != want {
        return Err(format!(
            "{label} verifier bundle issuer = {:?}, want {want:?}",
            bundle.issuer
        ));
    }
    Ok(())
}

fn verify_signature(
    bundle: &VerifierBundle,
    key_id: &str,
    payload: &[u8],
    signature: &[u8],
    label: &str,
) -> Result<(), String> {
    let key = bundle
        .keys
        .iter()
        .find(|key| key.key_id == key_id)
        .ok_or_else(|| format!("no verifier key for kid {key_id:?}"))?;
    if key.algorithm != ALGORITHM_ED25519 {
        return Err(format!(
            "unsupported verifier algorithm {:?}",
            key.algorithm
        ));
    }
    let public_key = URL_SAFE_NO_PAD
        .decode(key.public_key.as_bytes())
        .map_err(|err| format!("decoding verifier public key: {err}"))?;
    let public_key: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| "invalid verifier public key length".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|err| format!("decoding verifier public key: {err}"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| format!("invalid {label} signature length"))?;
    let signature = Signature::from_bytes(&signature);
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| format!("invalid {label} signature"))
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_runtime_credential() {
        let state = new_issuer_state("project-alpha");
        assert_eq!(state.issuer, "mesh:project-alpha");
        let now = Utc::now();
        let (token, claims) = sign_runtime_credential(
            &state,
            SUBJECT_KIND_CLIENT,
            "github:1234",
            now,
            Duration::minutes(1),
        )
        .unwrap();

        let bundle = state.bundle(now, Duration::hours(1));
        assert_eq!(bundle.issuer, "mesh:project-alpha");
        let verified = verify_runtime_credential(&token, &bundle, now).unwrap();

        assert_eq!(verified.subject_kind, SUBJECT_KIND_CLIENT);
        assert_eq!(verified.subject_id, "github:1234");
        assert_eq!(verified.issuer, "mesh:project-alpha");
        assert_eq!(verified.jti, claims.jti);
    }

    #[test]
    fn rejects_runtime_credential_with_old_relay_issuer() {
        let mut state = new_issuer_state("project-alpha");
        let now = Utc::now();
        let mut bundle = state.bundle(now, Duration::hours(1));
        state.issuer = "relay:project-alpha".to_string();
        let err = sign_runtime_credential(
            &state,
            SUBJECT_KIND_CLIENT,
            "github:1234",
            now,
            Duration::minutes(1),
        )
        .unwrap_err();
        assert!(err.contains("runtime token issuer state"));
        assert!(err.contains("relay:project-alpha"));
        assert!(err.contains("mesh:project-alpha"));

        let state = new_issuer_state("project-alpha");
        let (token, _) = sign_runtime_credential(
            &state,
            SUBJECT_KIND_CLIENT,
            "github:1234",
            now,
            Duration::minutes(1),
        )
        .unwrap();
        bundle.issuer = "relay:project-alpha".to_string();
        let err = verify_runtime_credential(&token, &bundle, now).unwrap_err();
        assert!(err.contains("runtime token verifier bundle issuer"));
        assert!(err.contains("relay:project-alpha"));
        assert!(err.contains("mesh:project-alpha"));
    }

    #[test]
    fn signs_and_verifies_sender_delegation() {
        let state = new_issuer_state("project-alpha");
        let now = Utc::now();
        let (token, claims) = sign_sender_delegation(
            &state,
            now,
            SenderDelegationInput {
                source_node: "dev-1".to_string(),
                from_session_id: Some(17),
                from_session_name: "planner".to_string(),
                source_groups: vec!["mesh".to_string()],
                verbs: vec!["msg".to_string(), "request".to_string()],
                audience_node: "dev-2".to_string(),
                ttl: Duration::minutes(1),
            },
        )
        .unwrap();

        let bundle = state.bundle(now, Duration::hours(1));
        let verified = verify_sender_delegation(&token, &bundle, now).unwrap();

        assert_eq!(verified.source_node, "dev-1");
        assert_eq!(verified.from_session_name, "planner");
        assert_eq!(verified.source_groups, vec!["mesh"]);
        assert_eq!(verified.issuer, "mesh:project-alpha");
        assert_eq!(verified.jti, claims.jti);
    }

    #[test]
    fn signs_and_verifies_observer_delegation() {
        let state = new_issuer_state("project-alpha");
        let now = Utc::now();
        let (token, claims) = sign_observer_delegation(
            &state,
            now,
            ObserverDelegationInput {
                target_node: "dev-2".to_string(),
                session_id: Some(29),
                session_name: "builder".to_string(),
                verbs: vec!["msg.read".to_string(), "msg.listen".to_string()],
                audience_subject_kind: SUBJECT_KIND_CLIENT.to_string(),
                audience_subject_id: "github:1234".to_string(),
                ttl: Duration::minutes(1),
            },
        )
        .unwrap();

        let bundle = state.bundle(now, Duration::hours(1));
        let verified = verify_observer_delegation(&token, &bundle, now).unwrap();

        assert_eq!(verified.target_node, "dev-2");
        assert_eq!(verified.audience_subject_id, "github:1234");
        assert_eq!(verified.issuer, "mesh:project-alpha");
        assert_eq!(verified.jti, claims.jti);
    }
}
