//! End-to-end exercise of the device authorization grant (RFC 8628).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use codewire_oidc::jwks::{PublicJwk, SigningKey};
use codewire_oidc::{
    AccessGrant, ApplicationType, AuthCodeGrant, AuthMethod, AuthOutcome, AuthRequestId,
    AuthorizationStore, Client, ClientStore, DeviceAuthorization, DeviceAuthorizationStore,
    DeviceStatus, ErrorCode, GrantType, Issuer, KeyStore, Provider, ProviderConfig, RefreshGrant,
    RequestContext, ResponseType, Scopes, StoreResult, StoredAuthRequest, Subject, TokenStore,
    UserAuthenticator,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;

#[derive(Default, Clone)]
struct Mem(Arc<Mutex<Inner>>);
#[derive(Default)]
struct Inner {
    access: HashMap<String, AccessGrant>,
    refresh: HashMap<String, RefreshGrant>,
    devices: HashMap<String, DeviceAuthorization>, // keyed by device_code
}

#[async_trait::async_trait]
impl AuthorizationStore for Mem {
    async fn create(&self, _r: StoredAuthRequest) -> StoreResult<AuthRequestId> {
        Ok(AuthRequestId("x".into()))
    }
    async fn get(&self, _: &AuthRequestId) -> StoreResult<Option<StoredAuthRequest>> {
        Ok(None)
    }
    async fn update(&self, _: &StoredAuthRequest) -> StoreResult<()> {
        Ok(())
    }
    async fn delete(&self, _: &AuthRequestId) -> StoreResult<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl TokenStore for Mem {
    async fn store_code(&self, _: &str, _: AuthCodeGrant, _: u64) -> StoreResult<()> {
        Ok(())
    }
    async fn consume_code(&self, _: &str) -> StoreResult<Option<AuthCodeGrant>> {
        Ok(None)
    }
    async fn store_access(&self, t: &str, g: AccessGrant, _: u64) -> StoreResult<()> {
        self.0.lock().unwrap().access.insert(t.into(), g);
        Ok(())
    }
    async fn get_access(&self, t: &str) -> StoreResult<Option<AccessGrant>> {
        Ok(self.0.lock().unwrap().access.get(t).cloned())
    }
    async fn store_refresh(&self, t: &str, g: RefreshGrant, _: u64) -> StoreResult<()> {
        self.0.lock().unwrap().refresh.insert(t.into(), g);
        Ok(())
    }
    async fn consume_refresh(&self, t: &str) -> StoreResult<Option<RefreshGrant>> {
        Ok(self.0.lock().unwrap().refresh.remove(t))
    }
    async fn revoke(&self, _: &str) -> StoreResult<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl DeviceAuthorizationStore for Mem {
    async fn store_device(&self, auth: DeviceAuthorization, _: u64) -> StoreResult<()> {
        self.0
            .lock()
            .unwrap()
            .devices
            .insert(auth.device_code.clone(), auth);
        Ok(())
    }
    async fn get_by_user_code(&self, user_code: &str) -> StoreResult<Option<DeviceAuthorization>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .devices
            .values()
            .find(|d| d.user_code == user_code)
            .cloned())
    }
    async fn get_by_device_code(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>> {
        Ok(self.0.lock().unwrap().devices.get(device_code).cloned())
    }
    async fn consume_approved(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>> {
        let mut state = self.0.lock().unwrap();
        let approved = matches!(
            state.devices.get(device_code),
            Some(DeviceAuthorization {
                status: DeviceStatus::Approved { .. },
                ..
            })
        );
        Ok(approved
            .then(|| state.devices.remove(device_code))
            .flatten())
    }
    async fn update(&self, auth: &DeviceAuthorization) -> StoreResult<()> {
        self.0
            .lock()
            .unwrap()
            .devices
            .insert(auth.device_code.clone(), auth.clone());
        Ok(())
    }
    async fn delete(&self, device_code: &str) -> StoreResult<()> {
        self.0.lock().unwrap().devices.remove(device_code);
        Ok(())
    }
}

struct Clients {
    device: Client,
    no_device: Client,
}
#[async_trait::async_trait]
impl ClientStore for Clients {
    async fn get(&self, id: &str) -> StoreResult<Option<Client>> {
        Ok([&self.device, &self.no_device]
            .into_iter()
            .find(|c| c.id == id)
            .cloned())
    }
    async fn verify_secret(&self, _: &str, _: &str) -> StoreResult<bool> {
        Ok(false)
    }
}

struct Keys(SigningKey);
#[async_trait::async_trait]
impl KeyStore for Keys {
    async fn active_signer(&self) -> StoreResult<SigningKey> {
        Ok(self.0.clone())
    }
    async fn public_jwks(&self) -> StoreResult<Vec<PublicJwk>> {
        Ok(vec![PublicJwk {
            kid: self.0.kid.clone(),
            public_key: self.0.public_key.clone(),
        }])
    }
}

struct NoAuth;
#[async_trait::async_trait]
impl UserAuthenticator for NoAuth {
    async fn authenticate(
        &self,
        _: &RequestContext,
        _: &StoredAuthRequest,
    ) -> StoreResult<AuthOutcome> {
        Ok(AuthOutcome::NeedsLogin("https://idp.example/login".into()))
    }
}

fn dev_client(id: &str, grants: Vec<GrantType>) -> Client {
    Client {
        id: id.into(),
        name: id.into(),
        application_type: ApplicationType::Native,
        auth_method: AuthMethod::None,
        redirect_uris: vec![],
        post_logout_redirect_uris: vec![],
        grant_types: grants,
        response_types: vec![ResponseType::Code],
        scopes: Scopes::parse("openid profile groups offline_access"),
        skip_consent: true,
        access_token_lifetime_secs: 3600,
        id_token_lifetime_secs: 3600,
        refresh_token_lifetime_secs: Some(2_592_000),
        clock_skew_secs: 0,
        disabled: false,
    }
}

fn provider(with_device: bool) -> Provider {
    let mem = Mem::default();
    let signer = Ed25519SigningKey::from_bytes(&[5u8; 32]);
    let key = SigningKey {
        kid: "k1".into(),
        secret_key: signer.to_bytes().to_vec(),
        public_key: signer.verifying_key().to_bytes().to_vec(),
    };
    let clients = Clients {
        device: dev_client(
            "relay",
            vec![GrantType::AuthorizationCode, GrantType::DeviceCode],
        ),
        no_device: dev_client("plain", vec![GrantType::AuthorizationCode]),
    };
    let mut b = Provider::builder(ProviderConfig {
        issuer: Issuer("https://idp.example".into()),
        paths: Default::default(),
        scopes_supported: vec!["openid".into()],
    })
    .auth_requests(Arc::new(mem.clone()))
    .tokens(Arc::new(mem.clone()))
    .clients(Arc::new(clients))
    .keys(Arc::new(Keys(key)))
    .authenticator(Arc::new(NoAuth));
    if with_device {
        b = b.device_store(Arc::new(mem));
    }
    b.build().unwrap()
}

#[tokio::test]
async fn device_flow_happy_path() {
    let p = provider(true);
    // 1. Device starts the flow. (Like our relay: no refresh grant, so no
    //    offline_access — the device re-runs the flow rather than refreshing.)
    let auth = p
        .authorize_device("relay", None, Some("openid groups"))
        .await
        .unwrap();
    assert_eq!(auth.interval, 5);
    assert_eq!(auth.verification_uri, "https://idp.example/device");
    assert!(auth.verification_uri_complete.contains(&auth.user_code));
    assert!(auth.user_code.contains('-'));

    // 2. Polling before approval → authorization_pending.
    let err = p
        .exchange_device_code("relay", None, &auth.device_code)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::AuthorizationPending);

    // 3. The operator visits the verification UI; the host approves.
    let pending = p.lookup_user_code(&auth.user_code).await.unwrap().unwrap();
    assert_eq!(pending.client_id, "relay");
    p.approve_device(
        &auth.user_code,
        Subject("operator".into()),
        Some(1_700_000_000),
    )
    .await
    .unwrap();

    // 4. The device polls again → tokens.
    let tokens = p
        .exchange_device_code("relay", None, &auth.device_code)
        .await
        .unwrap();
    assert_eq!(tokens.token_type, "Bearer");
    assert!(tokens.id_token.is_some()); // openid was granted
    assert!(tokens.refresh_token.is_none()); // client lacks the refresh grant
    assert_eq!(tokens.scope, "openid groups");

    // 5. The device_code is single-use: a further poll is now expired/unknown.
    let err = p
        .exchange_device_code("relay", None, &auth.device_code)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpiredToken);
}

#[tokio::test]
async fn concurrent_device_redemption_mints_one_token_set() {
    let p = provider(true);
    let auth = p
        .authorize_device("relay", None, Some("openid"))
        .await
        .unwrap();
    p.approve_device(&auth.user_code, Subject("operator".into()), None)
        .await
        .unwrap();

    let (first, second) = tokio::join!(
        p.exchange_device_code("relay", None, &auth.device_code),
        p.exchange_device_code("relay", None, &auth.device_code),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let replay = first.err().or_else(|| second.err()).expect("one replay");
    assert_eq!(replay.code, ErrorCode::ExpiredToken);
}

#[tokio::test]
async fn device_flow_denied() {
    let p = provider(true);
    let auth = p
        .authorize_device("relay", None, Some("openid"))
        .await
        .unwrap();
    p.deny_device(&auth.user_code).await.unwrap();
    let err = p
        .exchange_device_code("relay", None, &auth.device_code)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::AccessDenied);
}

#[tokio::test]
async fn device_flow_unknown_code_is_expired() {
    let p = provider(true);
    let err = p
        .exchange_device_code("relay", None, "nope")
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpiredToken);
}

#[tokio::test]
async fn device_grant_rejected_for_client_without_it() {
    let p = provider(true);
    let err = p
        .authorize_device("plain", None, Some("openid"))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnauthorizedClient);
}

#[tokio::test]
async fn device_flow_disabled_without_store() {
    let p = provider(false);
    let err = p
        .authorize_device("relay", None, Some("openid"))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRequest);
    // ...and discovery does not advertise it.
    assert!(p.discovery().device_authorization_endpoint.is_none());
}

#[tokio::test]
async fn discovery_advertises_device_when_enabled() {
    let p = provider(true);
    let d = p.discovery();
    assert_eq!(
        d.device_authorization_endpoint.as_deref(),
        Some("https://idp.example/api/oauth/device_authorization")
    );
    assert!(
        d.grant_types_supported
            .iter()
            .any(|g| g == "urn:ietf:params:oauth:grant-type:device_code")
    );
}

#[tokio::test]
async fn approve_unknown_user_code_errors() {
    let p = provider(true);
    let err = p
        .approve_device("ZZZZ-ZZZZ", Subject("x".into()), None)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRequest);
}
