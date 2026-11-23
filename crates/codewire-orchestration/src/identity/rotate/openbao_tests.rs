//! The rotation job against a real OpenBao (#4662): a throwaway dev server
//! on loopback, the production [`TransitKeyClient`] logging in through a JWT
//! auth mount under the rotator's own policy, and one fresh transit mount per
//! case. A pinned key rotates; a key with any pinned setting drifted fails
//! with [`RotateError::Drift`] and is left exactly as it was.
//!
//! Run with `cargo test -p codewire-orchestration --lib
//! identity::rotate::openbao_tests -- --ignored`, with `bao` on PATH or
//! `CODEWIRE_TEST_BAO_BIN` naming it. The dev server keeps everything in
//! memory, its root token never leaves this process, and it is killed when
//! the test ends.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use codewire_protected_store::openbao_workload_identity::static_workload_identity;
use serde_json::{Value, json};
use url::Url;

use super::{RotateError, RotationOutcome, run};
use crate::identity::config::{TRANSIT_KEY_NAME, TransitKeyConfig};
use crate::identity::transit::TransitKeyClient;

const AUTH_MOUNT: &str = "harness-k8s";
const ROLE: &str = "sandbox-identity-rotator-harness";
const POLICY: &str = "sandbox-identity-rotator-harness";
const SUBJECT: &str = "system:serviceaccount:dev:codewire-sandbox-identity-rotator";
const KUBERNETES_AUDIENCE: &str = "https://kubernetes.default.svc";
const OPENBAO_AUDIENCE: &str = "https://openbao.harness.test";
const SIGNER_MOUNT: &str = "harness-jwt";
const SIGNER_KEY: &str = "service-account-issuer";
const STEP: Duration = Duration::from_secs(30);

/// The pinned settings each case breaks, one per fresh mount, as the JSON
/// value written to the key's config.
const DRIFTS: [(&str, &str, &str); 4] = [
    ("drift-auto-rotate", "auto_rotate_period", r#""24h""#),
    ("drift-exportable", "exportable", "true"),
    ("drift-plaintext-backup", "allow_plaintext_backup", "true"),
    ("drift-deletion", "deletion_allowed", "true"),
];
const CONTROL: &str = "drift-control";

/// A dev server killed on drop, so a failed assertion leaves nothing running.
struct DevServer {
    child: Child,
    address: Url,
    root_token: String,
    http: reqwest::Client,
    _home: tempfile::TempDir,
}

impl Drop for DevServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DevServer {
    async fn start() -> Self {
        let binary = std::env::var("CODEWIRE_TEST_BAO_BIN").unwrap_or_else(|_| "bao".to_owned());
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let home = tempfile::tempdir().unwrap();
        let root_token = uuid::Uuid::new_v4().to_string();
        // The token goes in the environment, which only this user can read,
        // never on the command line, and is not stored by the token helper.
        // PATH alone passes through, so `bao` on PATH is found.
        let child = Command::new(binary)
            .args([
                "server",
                "-dev",
                "-dev-no-store-token",
                &format!("-dev-listen-address=127.0.0.1:{port}"),
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home.path())
            .env("BAO_DEV_ROOT_TOKEN_ID", &root_token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the OpenBao dev server");
        let server = Self {
            child,
            address: Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
            root_token,
            http: reqwest::Client::builder().timeout(STEP).build().unwrap(),
            _home: home,
        };
        for _ in 0..120 {
            if let Ok(response) = server.http.get(server.url("sys/health")).send().await
                && response.status().is_success()
            {
                return server;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("the OpenBao dev server did not become healthy in 30 seconds");
    }

    fn url(&self, path: &str) -> Url {
        self.address.join(&format!("v1/{path}")).unwrap()
    }

    async fn root(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        let mut request = self
            .http
            .request(method, self.url(path))
            .header("X-Vault-Token", &self.root_token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        assert!(status.is_success(), "{path}: {status}");
        let bytes = response.bytes().await.unwrap();
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        }
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        self.root(reqwest::Method::POST, path, Some(body)).await
    }

    async fn read_key(&self, mount: &str) -> Value {
        self.root(
            reqwest::Method::GET,
            &format!("{mount}/keys/{TRANSIT_KEY_NAME}"),
            None,
        )
        .await["data"]
            .clone()
    }

    async fn cluster_id(&self) -> String {
        let health: Value = self
            .http
            .get(self.url("sys/health"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        health["cluster_id"].as_str().unwrap().to_owned()
    }

    /// A JWT auth mount standing in for Kubernetes auth: it trusts a key
    /// this server holds, and its role admits only the rotator's subject and
    /// OpenBao audience, with the rotator's policy.
    async fn configure_login(&self, mounts: &[&str]) {
        self.post(
            &format!("sys/mounts/{SIGNER_MOUNT}"),
            json!({"type": "transit"}),
        )
        .await;
        self.post(
            &format!("{SIGNER_MOUNT}/keys/{SIGNER_KEY}"),
            json!({"type": "ecdsa-p256"}),
        )
        .await;
        let signer = self
            .root(
                reqwest::Method::GET,
                &format!("{SIGNER_MOUNT}/keys/{SIGNER_KEY}"),
                None,
            )
            .await;
        let public_key = signer["data"]["keys"]["1"]["public_key"].as_str().unwrap();
        self.post(&format!("sys/auth/{AUTH_MOUNT}"), json!({"type": "jwt"}))
            .await;
        self.post(
            &format!("auth/{AUTH_MOUNT}/config"),
            json!({"jwt_validation_pubkeys": [public_key]}),
        )
        .await;
        self.post(
            &format!("sys/policies/acl/{POLICY}"),
            json!({"policy": rotator_policy(mounts)}),
        )
        .await;
        self.post(
            &format!("auth/{AUTH_MOUNT}/role/{ROLE}"),
            json!({
                "role_type": "jwt",
                "user_claim": "sub",
                "bound_subject": SUBJECT,
                "bound_audiences": [OPENBAO_AUDIENCE],
                "token_policies": [POLICY],
                "token_ttl": "5m",
            }),
        )
        .await;
    }

    /// A Pod-bound-style token with both audiences, signed ES256 by the
    /// server's own transit key, as a TokenRequest would return.
    async fn service_account_jwt(&self) -> String {
        let now = Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "typ": "JWT"}).to_string());
        let claims = URL_SAFE_NO_PAD.encode(
            json!({
                "sub": SUBJECT,
                "aud": [KUBERNETES_AUDIENCE, OPENBAO_AUDIENCE],
                "iat": now,
                "nbf": now,
                "exp": now + 600,
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        let signed = self
            .post(
                &format!("{SIGNER_MOUNT}/sign/{SIGNER_KEY}"),
                json!({
                    "input": STANDARD.encode(&signing_input),
                    "hash_algorithm": "sha2-256",
                    "marshaling_algorithm": "jws",
                }),
            )
            .await;
        let signature = signed["data"]["signature"].as_str().unwrap();
        let signature = signature.rsplit(':').next().unwrap();
        format!("{signing_input}.{signature}")
    }

    /// A fresh mount whose key has three versions, all created now. At
    /// `now + 31 days` a pinned key is due both to retire below 3 and to
    /// rotate, so a run that changed nothing changed nothing for a reason.
    async fn fresh_key(&self, mount: &str) {
        self.post(&format!("sys/mounts/{mount}"), json!({"type": "transit"}))
            .await;
        self.post(
            &format!("{mount}/keys/{TRANSIT_KEY_NAME}"),
            json!({"type": "ecdsa-p256"}),
        )
        .await;
        for _ in 0..2 {
            self.post(
                &format!("{mount}/keys/{TRANSIT_KEY_NAME}/rotate"),
                json!({}),
            )
            .await;
        }
    }

    fn rotator(&self, mount: &str, cluster_id: &str, jwt: &str) -> TransitKeyClient {
        TransitKeyClient::new(
            TransitKeyConfig {
                address: self.address.clone(),
                auth_mount: AUTH_MOUNT.to_owned(),
                role: ROLE.to_owned(),
                transit_mount: mount.to_owned(),
                expected_cluster_id: cluster_id.to_owned(),
            },
            static_workload_identity(jwt),
        )
        .unwrap()
    }
}

/// The rotator role's production grant, for each mount.
fn rotator_policy(mounts: &[&str]) -> String {
    mounts
        .iter()
        .map(|mount| {
            format!(
                r#"path "{mount}/keys/{key}" {{
  capabilities = ["read"]
}}
path "{mount}/keys/{key}/rotate" {{
  capabilities = ["update"]
}}
path "{mount}/keys/{key}/config" {{
  capabilities = ["update"]
  allowed_parameters = {{
    "min_decryption_version" = []
    "min_encryption_version" = []
  }}
}}
"#,
                key = TRANSIT_KEY_NAME,
            )
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires an OpenBao binary (bao on PATH or CODEWIRE_TEST_BAO_BIN)"]
async fn drifted_custody_on_a_real_openbao_fails_the_run_and_leaves_the_key_unchanged() {
    let server = DevServer::start().await;
    let mut mounts = vec![CONTROL];
    mounts.extend(DRIFTS.iter().map(|(mount, ..)| *mount));
    server.configure_login(&mounts).await;
    let cluster_id = server.cluster_id().await;
    let jwt = server.service_account_jwt().await;
    let due = Utc::now() + chrono::Duration::days(31);

    // The control: the same login and grant rotate a pinned key.
    server.fresh_key(CONTROL).await;
    let outcome = tokio::time::timeout(STEP, run(&server.rotator(CONTROL, &cluster_id, &jwt), due))
        .await
        .expect("the control run finishes in 30 seconds")
        .expect("the control run succeeds");
    assert_eq!(
        outcome,
        RotationOutcome {
            signing_version: Some(3),
            retired_below: Some(3),
            rotated: true,
        }
    );
    let after = server.read_key(CONTROL).await;
    assert_eq!(after["latest_version"], json!(4));
    assert_eq!(after["min_decryption_version"], json!(3));
    assert_eq!(after["min_encryption_version"], json!(3));
    println!("{CONTROL}: {outcome:?}");

    for (mount, setting, value) in DRIFTS {
        server.fresh_key(mount).await;
        let value: Value = serde_json::from_str(value).unwrap();
        server
            .post(
                &format!("{mount}/keys/{TRANSIT_KEY_NAME}/config"),
                json!({ setting: value }),
            )
            .await;
        let before = server.read_key(mount).await;
        assert_ne!(before[setting], json!(false), "{mount}: drift applied");
        assert_ne!(before[setting], json!(0), "{mount}: drift applied");
        let result =
            tokio::time::timeout(STEP, run(&server.rotator(mount, &cluster_id, &jwt), due))
                .await
                .unwrap_or_else(|_| panic!("{mount}: the run finishes in 30 seconds"));
        assert!(
            matches!(result, Err(RotateError::Drift)),
            "{mount}: {result:?}"
        );
        let after = server.read_key(mount).await;
        assert_eq!(before, after, "{mount}: the key is unchanged");
        println!(
            "{mount}: {setting}={} -> Drift; latest_version={} min_decryption_version={} \
             min_encryption_version={} unchanged",
            before[setting],
            after["latest_version"],
            after["min_decryption_version"],
            after["min_encryption_version"],
        );
    }
}
