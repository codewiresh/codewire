//! The sealed `codewire_oauth_state` cookie of a sign-in round trip. The start
//! writes nothing, so what the callback needs rides in the browser, encrypted
//! and authenticated under a key only the IdP holds (#4166). The rules are in
//! docs/dev/AUTH-POLICY.md, "Sign-in with GitHub or Google".
//!
//! A sealed value is base64url of `version || nonce || ciphertext`, AES-256-GCM
//! with the associated data [`associated_data`]. The plaintext is the state's
//! SHA-256, the expiry (Unix seconds, big-endian `i64`), then the verifier,
//! the nonce, the auth request id and the return path, each a big-endian `u16`
//! length and its UTF-8 bytes, where an empty value is an absent one.

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit as _, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{Provider, ReturnTarget, clean_auth_request_id, safe_return_to, same_secret};

/// The HKDF label the sealing key is derived under, and the purpose the
/// associated data names. Nothing else uses it.
const PURPOSE: &[u8] = b"codewire-idp-oauth-state-v1";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const STATE_HASH_LEN: usize = 32;

/// The key sign-in state cookies are sealed under, derived from the IdP's
/// session secret.
#[derive(Clone)]
pub struct StateCookieKey(Aes256Gcm);

/// The session secret was empty.
#[derive(Debug, thiserror::Error)]
#[error("the session secret for OAuth state cookies is not set")]
pub struct EmptySessionSecret;

impl StateCookieKey {
    pub fn derive(session_secret: &str) -> Result<Self, EmptySessionSecret> {
        if session_secret.is_empty() {
            return Err(EmptySessionSecret);
        }
        let key = hkdf_sha256(&[], session_secret.as_bytes(), PURPOSE);
        Ok(Self(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(
            key.as_slice(),
        ))))
    }
}

/// HKDF-SHA256 (RFC 5869) with one block of output, the 32 bytes an AES-256
/// key needs. HMAC pads its key with zeros, so an empty salt is the RFC's
/// default salt of 32 zero bytes.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract =
        <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    extract.update(ikm);
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(extract.finalize().into_bytes().into());
    let mut expand =
        <Hmac<Sha256> as Mac>::new_from_slice(prk.as_slice()).expect("HMAC accepts any key length");
    expand.update(info);
    expand.update(&[1]);
    Zeroizing::new(expand.finalize().into_bytes().into())
}

/// Binds a sealed value to its purpose, its format and its provider, so a
/// cookie sealed for one provider fails authentication on the other's
/// callback.
fn associated_data(provider: Provider) -> Vec<u8> {
    let mut aad = PURPOSE.to_vec();
    aad.push(0);
    aad.push(VERSION);
    aad.extend_from_slice(provider.as_str().as_bytes());
    aad
}

/// What a sign-in start hands its callback.
pub(super) struct SignInStart {
    state_hash: [u8; STATE_HASH_LEN],
    /// Unix seconds.
    expires_at: i64,
    pub(super) verifier: String,
    /// Present exactly for Google.
    pub(super) nonce: Option<String>,
    pub(super) target: ReturnTarget,
}

/// Why a state cookie was not accepted. Every reason refuses the callback
/// before the provider exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum Unsealed {
    #[error("not a sealed state")]
    Malformed,
    #[error("an unknown sealed state version")]
    Version,
    #[error("failed authentication")]
    Unauthentic,
    #[error("expired")]
    Expired,
    #[error("sealed for another state")]
    StateMismatch,
    #[error("a return target that is not allowed")]
    Target,
}

/// A field longer than its `u16` length allows.
#[derive(Debug, thiserror::Error)]
#[error("an OAuth state field is too long to seal")]
pub(super) struct SealFailed;

impl SignInStart {
    pub(super) fn new(
        raw_state: &str,
        verifier: String,
        nonce: Option<String>,
        target: ReturnTarget,
        expires_at: i64,
    ) -> Self {
        Self {
            state_hash: Sha256::digest(raw_state.as_bytes()).into(),
            expires_at,
            verifier,
            nonce,
            target,
        }
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SealFailed> {
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        out.extend_from_slice(&self.state_hash);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        for field in [
            Some(self.verifier.as_str()),
            self.nonce.as_deref(),
            self.target.auth_request_id.as_deref(),
            self.target.return_to.as_deref(),
        ] {
            let bytes = field.unwrap_or_default().as_bytes();
            let len = u16::try_from(bytes.len()).map_err(|_| SealFailed)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }

    fn decode(mut bytes: &[u8]) -> Option<Self> {
        let state_hash = *take(&mut bytes, STATE_HASH_LEN)?.first_chunk()?;
        let expires_at = i64::from_be_bytes(*take(&mut bytes, 8)?.first_chunk()?);
        let verifier = take_field(&mut bytes)??;
        let nonce = take_field(&mut bytes)?;
        let auth_request_id = take_field(&mut bytes)?;
        let return_to = take_field(&mut bytes)?;
        bytes.is_empty().then_some(Self {
            state_hash,
            expires_at,
            verifier,
            nonce,
            target: ReturnTarget {
                auth_request_id,
                return_to,
            },
        })
    }

    /// The target as the start would have accepted it.
    fn target_allowed(&self) -> bool {
        let ReturnTarget {
            auth_request_id,
            return_to,
        } = &self.target;
        auth_request_id
            .as_deref()
            .is_none_or(|id| clean_auth_request_id(id).is_some())
            && return_to
                .as_deref()
                .is_none_or(|path| safe_return_to(path).is_some())
    }
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (head, tail) = bytes.split_at_checked(len)?;
    *bytes = tail;
    Some(head)
}

/// One length-prefixed field: `None` when it is cut short or not UTF-8,
/// `Some(None)` when it is empty.
fn take_field(bytes: &mut &[u8]) -> Option<Option<String>> {
    let len = u16::from_be_bytes(*take(bytes, 2)?.first_chunk()?);
    let value = take(bytes, usize::from(len))?;
    if value.is_empty() {
        return Some(None);
    }
    String::from_utf8(value.to_vec()).ok().map(Some)
}

pub(super) fn seal(
    key: &StateCookieKey,
    provider: Provider,
    start: &SignInStart,
) -> Result<String, SealFailed> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let plaintext = start.encode()?;
    let sealed = key
        .0
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data(provider),
            },
        )
        .map_err(|_| SealFailed)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

/// Open the cookie on `provider`'s callback, whose `state` parameter is
/// `raw_state`, at `now` (Unix seconds).
pub(super) fn open(
    key: &StateCookieKey,
    provider: Provider,
    cookie: &str,
    raw_state: &str,
    now: i64,
) -> Result<SignInStart, Unsealed> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cookie)
        .map_err(|_| Unsealed::Malformed)?;
    let (&version, rest) = bytes.split_first().ok_or(Unsealed::Malformed)?;
    if version != VERSION {
        return Err(Unsealed::Version);
    }
    let (nonce, sealed) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(Unsealed::Malformed)?;
    let plaintext = Zeroizing::new(
        key.0
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &associated_data(provider),
                },
            )
            .map_err(|_| Unsealed::Unauthentic)?,
    );
    let start = SignInStart::decode(&plaintext).ok_or(Unsealed::Malformed)?;
    if start.nonce.is_some() != (provider == Provider::Google) {
        return Err(Unsealed::Malformed);
    }
    if start.expires_at <= now {
        return Err(Unsealed::Expired);
    }
    if raw_state.is_empty()
        || !same_secret(&Sha256::digest(raw_state.as_bytes()), &start.state_hash)
    {
        return Err(Unsealed::StateMismatch);
    }
    if !start.target_allowed() {
        return Err(Unsealed::Target);
    }
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn key() -> StateCookieKey {
        StateCookieKey::derive("synthetic-session-secret").unwrap()
    }

    fn start(target: ReturnTarget) -> SignInStart {
        SignInStart::new(
            "raw-state",
            "v".repeat(43),
            Some("google-nonce".into()),
            target,
            NOW + 600,
        )
    }

    fn sealed(target: ReturnTarget) -> String {
        seal(&key(), Provider::Google, &start(target)).unwrap()
    }

    fn reseal(cookie: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut bytes = URL_SAFE_NO_PAD.decode(cookie).unwrap();
        edit(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn hkdf_matches_rfc_5869() {
        fn hex(bytes: &[u8]) -> String {
            crate::auth_session::hex_lower(bytes)
        }
        // Test case 1: the first block of its 42-byte output.
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(
            hex(hkdf_sha256(&salt, &[0x0b; 22], &info).as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
        // Test case 3: no salt and no info.
        assert_eq!(
            hex(hkdf_sha256(&[], &[0x0b; 22], &[]).as_slice()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }

    #[test]
    fn a_sealed_start_opens_with_its_state_provider_and_key() {
        let target = ReturnTarget::sanitized("request-id", "/device?user_code=ABCD");
        let cookie = sealed(target.clone());
        assert!(!cookie.contains("raw-state") && !cookie.contains("google-nonce"));
        let opened = open(&key(), Provider::Google, &cookie, "raw-state", NOW).unwrap();
        assert_eq!(opened.verifier, "v".repeat(43));
        assert_eq!(opened.nonce.as_deref(), Some("google-nonce"));
        assert_eq!(opened.target, target);
        // Two seals of one start differ: each has its own nonce.
        assert_ne!(cookie, sealed(target));
    }

    #[test]
    fn every_other_cookie_is_refused() {
        let cookie = sealed(ReturnTarget::default());
        let refused = |cookie: &str, provider, state: &str, now| {
            open(&key(), provider, cookie, state, now).err()
        };
        let google = Provider::Google;

        let flipped = reseal(&cookie, |bytes| {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        });
        assert_eq!(
            refused(&flipped, google, "raw-state", NOW),
            Some(Unsealed::Unauthentic)
        );
        let version = reseal(&cookie, |bytes| bytes[0] = 2);
        assert_eq!(
            refused(&version, google, "raw-state", NOW),
            Some(Unsealed::Version)
        );
        assert_eq!(
            refused(&cookie, Provider::GitHub, "raw-state", NOW),
            Some(Unsealed::Unauthentic)
        );
        assert_eq!(
            refused(&cookie, google, "raw-state", NOW + 600),
            Some(Unsealed::Expired)
        );
        assert_eq!(
            refused(&cookie, google, "other-state", NOW),
            Some(Unsealed::StateMismatch)
        );
        assert_eq!(
            refused(&cookie, google, "", NOW),
            Some(Unsealed::StateMismatch)
        );
        assert_eq!(
            refused("not base64!", google, "raw-state", NOW),
            Some(Unsealed::Malformed)
        );
        assert_eq!(
            refused("", google, "raw-state", NOW),
            Some(Unsealed::Malformed)
        );

        // A rotated session secret ends the sign-ins in flight.
        let rotated = StateCookieKey::derive("another-session-secret").unwrap();
        assert_eq!(
            open(&rotated, google, &cookie, "raw-state", NOW).err(),
            Some(Unsealed::Unauthentic)
        );
        assert!(StateCookieKey::derive("").is_err());
    }

    #[test]
    fn a_sealed_target_is_checked_again_at_use() {
        for target in [
            ReturnTarget {
                auth_request_id: None,
                return_to: Some("//evil.example/".into()),
            },
            ReturnTarget {
                auth_request_id: Some("a\u{7}".into()),
                return_to: None,
            },
        ] {
            let cookie = sealed(target);
            assert_eq!(
                open(&key(), Provider::Google, &cookie, "raw-state", NOW).err(),
                Some(Unsealed::Target)
            );
        }
    }

    #[test]
    fn a_nonce_is_sealed_exactly_for_google() {
        let without = SignInStart::new(
            "raw-state",
            "v".repeat(43),
            None,
            ReturnTarget::default(),
            NOW + 600,
        );
        let cookie = seal(&key(), Provider::Google, &without).unwrap();
        assert_eq!(
            open(&key(), Provider::Google, &cookie, "raw-state", NOW).err(),
            Some(Unsealed::Malformed)
        );
        let with = start(ReturnTarget::default());
        let cookie = seal(&key(), Provider::GitHub, &with).unwrap();
        assert_eq!(
            open(&key(), Provider::GitHub, &cookie, "raw-state", NOW).err(),
            Some(Unsealed::Malformed)
        );
    }

    #[test]
    fn a_sealed_cookie_never_looks_like_a_links_raw_state() {
        // The callback reads a 64-hex cookie as a link's raw state, so even
        // the smallest sealed start must not be one.
        let smallest = SignInStart::new(
            "s",
            "v".repeat(43),
            None,
            ReturnTarget::sanitized("", ""),
            NOW + 600,
        );
        let cookie = seal(&key(), Provider::GitHub, &smallest).unwrap();
        assert!(cookie.len() > 64, "{}", cookie.len());
        assert!(!cookie.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn the_largest_target_fits_a_browser_cookie() {
        let target = ReturnTarget::sanitized(
            &"a".repeat(super::super::MAX_AUTH_REQUEST_ID_BYTES),
            &format!("/{}", "p".repeat(super::super::MAX_RETURN_TO_BYTES - 1)),
        );
        assert!(target.auth_request_id.is_some() && target.return_to.is_some());
        let cookie = sealed(target);
        // A browser bounds a cookie's name and value together.
        assert!(
            super::super::STATE_COOKIE.len() + 1 + cookie.len()
                <= super::super::MAX_STATE_COOKIE_BYTES,
            "{}",
            cookie.len()
        );
    }
}
