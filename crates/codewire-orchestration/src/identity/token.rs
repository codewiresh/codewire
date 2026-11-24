//! The sandbox identity token (docs/dev/SANDBOX-IDENTITY.md, "The token"): a
//! compact JWS, ES256, whose signing input is built here and signed by the
//! OpenBao transit key ([`super::transit`]).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::config::IssuerBase;
use super::keys::SigningKey;
use super::transit::JwsSignature;

/// No token lives longer than this, whatever a registration says.
pub(crate) const MAX_LIFETIME_SECONDS: i64 = 600;

/// `sandboxes.<deployment domain>`, the trust domain of every Sandbox's
/// SPIFFE ID. The deployment domain is the host of its public origin
/// (`FRONTEND_URL`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustDomain(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the deployment's public origin is not an https URL with a DNS host name")]
pub struct InvalidPublicOrigin;

impl TrustDomain {
    pub fn from_public_origin(origin: &str) -> Result<Self, InvalidPublicOrigin> {
        let url = Url::parse(origin).map_err(|_| InvalidPublicOrigin)?;
        match url.host() {
            Some(Host::Domain(host)) if url.scheme() == "https" && host.contains('.') => {
                Ok(Self(format!("sandboxes.{host}")))
            }
            _ => Err(InvalidPublicOrigin),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one Sandbox's token for one audience says, apart from its times and
/// `jti`. Two equal subjects make the same token but for those.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenSubject {
    iss: String,
    sub: String,
    aud: String,
    groups: Vec<String>,
    codewire: CodewireClaims,
    lifetime_seconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct CodewireClaims {
    org_id: String,
    sandbox_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment_name: Option<String>,
}

/// The facts a token is made from: the Sandbox's, read for this mint, and
/// its organization's registration of the audience.
pub(crate) struct SubjectFacts<'a> {
    pub(crate) issuer_base: &'a IssuerBase,
    pub(crate) trust_domain: &'a TrustDomain,
    pub(crate) org_id: &'a str,
    pub(crate) environment_id: &'a str,
    /// The creator's stable user ID.
    pub(crate) created_by: &'a str,
    pub(crate) environment_name: Option<&'a str>,
    /// The Sandbox's groups, bare.
    pub(crate) groups: &'a [String],
    /// The canonical audience.
    pub(crate) audience: &'a str,
    /// The groups the registration may see; `None` sees them all.
    pub(crate) visible_groups: Option<&'a [String]>,
    pub(crate) lifetime_seconds: i64,
    pub(crate) claim_created_by: bool,
    pub(crate) claim_environment_name: bool,
}

impl TokenSubject {
    pub(crate) fn new(facts: &SubjectFacts<'_>) -> Self {
        let org = facts.org_id;
        let mut visible: Vec<String> = facts
            .groups
            .iter()
            .filter(|group| group.as_str() != "all")
            .filter(|group| {
                facts
                    .visible_groups
                    .is_none_or(|visible| visible.contains(*group))
            })
            .map(|group| format!("{org}:{group}"))
            .collect();
        visible.sort();
        visible.dedup();
        let mut groups = Vec::with_capacity(visible.len() + 1);
        groups.push(format!("{org}:all"));
        groups.extend(visible);
        Self {
            iss: format!("{}/orgs/{org}", facts.issuer_base.as_str()),
            sub: format!(
                "spiffe://{}/org/{org}/sandbox/{}",
                facts.trust_domain.as_str(),
                facts.environment_id
            ),
            aud: facts.audience.to_owned(),
            groups,
            codewire: CodewireClaims {
                org_id: org.to_owned(),
                sandbox_id: facts.environment_id.to_owned(),
                created_by: facts.claim_created_by.then(|| facts.created_by.to_owned()),
                environment_name: facts
                    .environment_name
                    .filter(|_| facts.claim_environment_name)
                    .map(str::to_owned),
            },
            lifetime_seconds: facts.lifetime_seconds.clamp(1, MAX_LIFETIME_SECONDS),
        }
    }
}

/// The header, in the order it is serialized. Nothing else is ever in it:
/// verifiers take keys only from the issuer's JWKS.
#[derive(Serialize)]
struct Header {
    alg: &'static str,
    kid: String,
    typ: &'static str,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: &'a str,
    groups: &'a [String],
    #[serde(rename = "codewire.sh")]
    codewire: &'a CodewireClaims,
}

/// A token's JWS signing input, waiting for its signature.
pub(crate) struct UnsignedToken {
    signing_input: String,
    expires_at: i64,
}

impl UnsignedToken {
    /// The token for `subject`, issued at `issued_at` (Unix seconds) with
    /// `jti`, to be signed by `key`.
    pub(crate) fn new(subject: &TokenSubject, key: SigningKey, issued_at: i64, jti: &str) -> Self {
        let expires_at = issued_at.saturating_add(subject.lifetime_seconds);
        let header = Header {
            alg: "ES256",
            kid: key.kid(),
            typ: "JWT",
        };
        let claims = Claims {
            iss: &subject.iss,
            sub: &subject.sub,
            aud: &subject.aud,
            iat: issued_at,
            nbf: issued_at,
            exp: expires_at,
            jti,
            groups: &subject.groups,
            codewire: &subject.codewire,
        };
        Self {
            signing_input: format!("{}.{}", encode(&header), encode(&claims)),
            expires_at,
        }
    }

    pub(crate) fn signing_input(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    pub(crate) fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The compact JWS.
    pub(crate) fn signed(self, signature: &JwsSignature) -> Zeroizing<String> {
        Zeroizing::new(format!("{}.{}", self.signing_input, signature.as_str()))
    }
}

fn encode(value: &impl Serialize) -> String {
    // Serializing these plain structs of strings and integers can't fail.
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap_or_default())
}

/// A fresh `jti`: 128 random bits, base64url.
pub(crate) fn new_jti() -> std::io::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::identity::keys::tests::{at, key_read, key_set};
    use crate::identity::transit::tests::SIGNATURE;

    const ORG: &str = "0e3c5b7a-1f2d-4c3b-9a8e-7d6c5b4a3f2e";
    const SANDBOX: &str = "7b1f2e3d-4c5b-4a69-8877-665544332211";

    fn key(version: u32) -> SigningKey {
        let read = key_read(&[(version, "2026-11-01T00:00:00Z")], version, version);
        key_set(read)
            .unwrap()
            .signing_key(at("2026-11-14T00:00:00Z"))
            .unwrap()
    }

    fn facts<'a>(
        issuer: &'a IssuerBase,
        trust: &'a TrustDomain,
        groups: &'a [String],
    ) -> SubjectFacts<'a> {
        SubjectFacts {
            issuer_base: issuer,
            trust_domain: trust,
            org_id: ORG,
            environment_id: SANDBOX,
            created_by: "user_2b8f",
            environment_name: Some("app"),
            groups,
            audience: "https://k8s.walk.example",
            visible_groups: None,
            lifetime_seconds: 600,
            claim_created_by: false,
            claim_environment_name: false,
        }
    }

    fn decoded(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    /// The token's header and claims, decoded.
    fn parts(token: &str) -> (Value, Value, String) {
        let mut parts = token.split('.');
        let (header, claims, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        assert!(parts.next().is_none(), "a compact JWS has three parts");
        (decoded(header), decoded(claims), signature.to_owned())
    }

    fn signature() -> JwsSignature {
        crate::identity::transit::tests::signature()
    }

    #[test]
    fn the_token_carries_exactly_the_specified_claims() {
        let issuer = IssuerBase::parse("https://identity.codewire.example").unwrap();
        let trust = TrustDomain::from_public_origin("https://codewire.example").unwrap();
        let groups = ["data-readers".to_owned(), "builders".to_owned()];
        let subject = TokenSubject::new(&facts(&issuer, &trust, &groups));
        let unsigned =
            UnsignedToken::new(&subject, key(7), 1_794_600_000, "Rk0xMjM0NTY3ODkwYWJjZA");
        assert_eq!(unsigned.expires_at(), 1_794_600_600);
        let token = unsigned.signed(&signature());

        let (header, claims, signature) = parts(&token);
        assert_eq!(
            header,
            json!({"alg": "ES256", "kid": "sandbox-identity-7", "typ": "JWT"})
        );
        assert_eq!(
            claims,
            json!({
                "iss": format!("https://identity.codewire.example/orgs/{ORG}"),
                "sub": format!("spiffe://sandboxes.codewire.example/org/{ORG}/sandbox/{SANDBOX}"),
                "aud": "https://k8s.walk.example",
                "iat": 1_794_600_000, "nbf": 1_794_600_000, "exp": 1_794_600_600,
                "jti": "Rk0xMjM0NTY3ODkwYWJjZA",
                "groups": [format!("{ORG}:all"), format!("{ORG}:builders"), format!("{ORG}:data-readers")],
                "codewire.sh": {"org_id": ORG, "sandbox_id": SANDBOX},
            })
        );
        assert_eq!(signature, SIGNATURE);
    }

    #[test]
    fn the_header_never_names_where_a_key_comes_from() {
        let issuer = IssuerBase::parse("https://identity.codewire.example").unwrap();
        let trust = TrustDomain::from_public_origin("https://codewire.example").unwrap();
        let subject = TokenSubject::new(&facts(&issuer, &trust, &[]));
        let token = UnsignedToken::new(&subject, key(1), 1, "jti").signed(&signature());
        let (header, ..) = parts(&token);
        let names: Vec<_> = header.as_object().unwrap().keys().cloned().collect();
        assert_eq!(names, ["alg", "kid", "typ"]);
        for forbidden in ["jku", "x5u", "jwk", "x5c"] {
            assert!(header.get(forbidden).is_none(), "{forbidden}");
        }
    }

    #[test]
    fn a_registration_sees_only_its_groups_and_its_opted_in_claims() {
        let issuer = IssuerBase::parse("https://identity.codewire.example").unwrap();
        let trust = TrustDomain::from_public_origin("https://codewire.example").unwrap();
        let groups = [
            "data-readers".to_owned(),
            "builders".to_owned(),
            "all".to_owned(),
        ];
        let visible = ["data-readers".to_owned(), "deployers".to_owned()];
        let mut opted = facts(&issuer, &trust, &groups);
        opted.visible_groups = Some(&visible[..]);
        opted.claim_created_by = true;
        opted.claim_environment_name = true;
        opted.lifetime_seconds = 120;
        let subject = TokenSubject::new(&opted);
        let token = UnsignedToken::new(&subject, key(1), 1_000, "jti").signed(&signature());
        let (_, claims, _) = parts(&token);
        assert_eq!(
            claims["groups"],
            json!([format!("{ORG}:all"), format!("{ORG}:data-readers")])
        );
        assert_eq!(
            claims["codewire.sh"],
            json!({"org_id": ORG, "sandbox_id": SANDBOX, "created_by": "user_2b8f", "environment_name": "app"})
        );
        assert_eq!(claims["exp"], json!(1_120));

        // A Sandbox in no group carries only `<org>:all`; an unnamed one
        // never gets an empty name.
        let mut bare = facts(&issuer, &trust, &[]);
        bare.environment_name = None;
        bare.claim_environment_name = true;
        let token =
            UnsignedToken::new(&TokenSubject::new(&bare), key(1), 1, "j").signed(&signature());
        let (_, claims, _) = parts(&token);
        assert_eq!(claims["groups"], json!([format!("{ORG}:all")]));
        assert_eq!(
            claims["codewire.sh"],
            json!({"org_id": ORG, "sandbox_id": SANDBOX})
        );
    }

    #[test]
    fn no_token_outlives_ten_minutes() {
        let issuer = IssuerBase::parse("https://identity.codewire.example").unwrap();
        let trust = TrustDomain::from_public_origin("https://codewire.example").unwrap();
        let mut long = facts(&issuer, &trust, &[]);
        long.lifetime_seconds = 3_600;
        let subject = TokenSubject::new(&long);
        assert_eq!(
            UnsignedToken::new(&subject, key(1), 0, "j").expires_at(),
            600
        );
    }

    #[test]
    fn a_jti_is_128_random_bits() {
        let first = new_jti().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&first).unwrap().len(), 16);
        assert_ne!(first, new_jti().unwrap());
    }

    #[test]
    fn the_trust_domain_is_under_the_public_origins_host() {
        assert_eq!(
            TrustDomain::from_public_origin("https://codewire-dev.sh")
                .unwrap()
                .as_str(),
            "sandboxes.codewire-dev.sh"
        );
        for origin in [
            "http://codewire.example",
            "https://localhost",
            "https://10.0.0.1",
            "x",
        ] {
            assert!(TrustDomain::from_public_origin(origin).is_err(), "{origin}");
        }
    }
}
