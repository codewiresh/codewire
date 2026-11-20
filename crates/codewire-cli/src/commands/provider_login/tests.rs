//! The CLI's device logins against a scripted in-process provider. Real time:
//! each provider asks for the shortest poll interval, one second.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};

use super::*;

const SIGN_IN: SignInScreen<'static> = SignInScreen::local("Codex", "work");

#[derive(Default)]
struct Scripted(Mutex<VecDeque<Value>>, Mutex<Vec<String>>);

#[async_trait]
impl BrokerUpstreamTransport for Scripted {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (_, target, _, _) = request.into_parts();
        self.1.lock().unwrap().push(target.as_str().to_owned());
        let Some(answer) = self.0.lock().unwrap().pop_front() else {
            // An unanswered provider never completes the login.
            return std::future::pending().await;
        };
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move {
                Ok(serde_json::to_vec(&answer).unwrap().into())
            })),
        ))
    }
}

fn scripted(answers: impl IntoIterator<Item = Value>) -> Arc<Scripted> {
    Arc::new(Scripted(
        Mutex::new(answers.into_iter().collect()),
        Mutex::default(),
    ))
}

/// Codex's answers to a device login: the code, the approval, the tokens.
fn codex_answers() -> [Value; 3] {
    let encode = |value: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    };
    [
        json!({"device_auth_id":"synthetic","user_code":"ABCD-EFGH","interval":"1"}),
        json!({"authorization_code":"code","code_challenge":"challenge","code_verifier":"verifier"}),
        json!({
            "id_token": format!("{}.{}.sig", encode(json!({})), encode(json!({
                "email":"person@example.test",
                "https://api.openai.com/auth":{"chatgpt_account_id":"account"}}))),
            "access_token":"synthetic-access","refresh_token":"synthetic-refresh"}),
    ]
}

/// GitHub's answers to a device login before its installation listing.
fn github_answers() -> [Value; 3] {
    [
        json!({"device_code":"synthetic","user_code":"ABCD-EFGH","expires_in":900,"interval":1}),
        json!({"access_token":"ghu_synthetic_user_token","token_type":"bearer"}),
        json!({"id":7,"login":"octo-user"}),
    ]
}

fn github_app() -> GitHubDeviceLoginConfig {
    GitHubDeviceLoginConfig::new("Iv1.synthetic".into(), "codewire-synthetic".into()).unwrap()
}

#[tokio::test]
async fn codex_login_imports_the_issued_tokens_without_a_provider_cli() {
    let provider = scripted(codex_answers());
    let import = codex_device_login_with(
        SIGN_IN,
        provider.clone(),
        std::future::pending(),
        &Interrupt::default(),
    )
    .await
    .unwrap();
    assert_eq!(import.account_hint(), Some("person@example.test"));
    assert_eq!(
        provider.1.lock().unwrap().as_slice(),
        [
            "https://auth.openai.com/api/accounts/deviceauth/usercode",
            "https://auth.openai.com/api/accounts/deviceauth/token",
            "https://auth.openai.com/oauth/token",
        ]
    );
}

#[tokio::test]
async fn github_login_verifies_the_app_installation() {
    let provider = scripted(
        github_answers()
            .into_iter()
            .chain([json!({"installations":[{"id":41,"app_slug":"codewire-synthetic"}]})]),
    );
    let import = github_device_login_with(
        SIGN_IN,
        github_app(),
        provider,
        std::future::pending(),
        &Interrupt::default(),
    )
    .await
    .unwrap();
    assert_eq!(import.account_hint(), "octo-user");
}

#[tokio::test]
async fn cancelling_a_pending_login_changes_nothing() {
    let provider = scripted([]);
    let error =
        match codex_device_login_with(SIGN_IN, provider, async {}, &Interrupt::default()).await {
            Ok(_) => panic!("a cancelled login must not complete"),
            Err(error) => error,
        };
    assert_eq!(error.to_string(), CANCELLED);
}

/// Ctrl-C pressed as the login sends its request number `at`, counting from
/// zero, before the provider answers it.
struct PressAt {
    provider: Arc<Scripted>,
    at: usize,
    sent: std::sync::atomic::AtomicUsize,
    press: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl BrokerUpstreamTransport for PressAt {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == self.at {
            self.press.notify_one();
            // Long enough for a cancel that still raced this step to win.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        self.provider.execute(request).await
    }
}

fn press_at(
    provider: Arc<Scripted>,
    at: usize,
) -> (Arc<PressAt>, impl Future<Output = ()> + Send + 'static) {
    let press = Arc::new(tokio::sync::Notify::new());
    let cancel = {
        let press = press.clone();
        async move { press.notified().await }
    };
    let transport = PressAt {
        provider,
        at,
        sent: Default::default(),
        press,
    };
    (Arc::new(transport), cancel)
}

/// Once OpenAI approved, the code exchange may issue the sign-in, so a
/// Ctrl-C during it no longer drops what it returns (cw-network on #4991):
/// the login finishes and the connect revokes it.
#[tokio::test]
async fn a_ctrl_c_during_the_codex_exchange_returns_the_issued_sign_in() {
    let (provider, cancel) = press_at(scripted(codex_answers()), 2);
    let import = codex_device_login_with(SIGN_IN, provider, cancel, &Interrupt::default())
        .await
        .expect("the exchange runs to its end");
    assert_eq!(import.account_hint(), Some("person@example.test"));
}

/// GitHub issues the user token with the approval, so a Ctrl-C during the
/// checks after it returns the authorization for the connect to discard.
#[tokio::test]
async fn a_ctrl_c_during_the_github_checks_returns_the_issued_authorization() {
    let (provider, cancel) = press_at(
        scripted(
            github_answers()
                .into_iter()
                .chain([json!({"installations":[{"id":41,"app_slug":"codewire-synthetic"}]})]),
        ),
        2,
    );
    let import = github_device_login_with(
        SIGN_IN,
        github_app(),
        provider,
        cancel,
        &Interrupt::default(),
    )
    .await
    .expect("the checks run to their end");
    assert_eq!(import.account_hint(), "octo-user");
}

/// A check that fails after GitHub issued the token says so to the connect,
/// which tells the person what GitHub keeps; the error reads as before.
#[tokio::test]
async fn a_github_failure_after_the_approval_is_marked_issued() {
    let provider = scripted(
        github_answers()
            .into_iter()
            .chain([json!({"installations":[]})]),
    );
    let error = match github_device_login_with(
        SIGN_IN,
        github_app(),
        provider,
        std::future::pending(),
        &Interrupt::default(),
    )
    .await
    {
        Ok(_) => panic!("no installation must not complete the login"),
        Err(error) => error,
    };
    assert!(
        error.downcast_ref::<IssuedButNotSaved>().is_some(),
        "{error:#}"
    );
    // The cloud client says this same sentence for the service's
    // CREDENTIAL_GITHUB_INSTALLATION_REQUIRED, with the server's own App's
    // link; locally it is always the Codewire App's.
    assert_eq!(
        error.to_string(),
        "the Codewire GitHub App is not installed on any account this GitHub login can use; \
         install it, choose the accounts and repositories, then connect again: \
         https://github.com/apps/codewire-sh/installations/new",
        "{error:#}"
    );
    // A cancel before the approval issued nothing.
    let error = match github_device_login_with(
        SIGN_IN,
        github_app(),
        scripted([]),
        async {},
        &Interrupt::default(),
    )
    .await
    {
        Ok(_) => panic!("a cancelled login must not complete"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<IssuedButNotSaved>().is_none());
}

/// Records each request and answers 200 with an empty JSON object.
#[derive(Default)]
struct Recording(Mutex<Vec<(Method, String, Vec<u8>)>>);

#[async_trait]
impl BrokerUpstreamTransport for Recording {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, _, body) = request.into_parts();
        self.0
            .lock()
            .unwrap()
            .push((method, target.as_str().to_owned(), body));
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async { Ok(b"{}".to_vec().into()) })),
        ))
    }
}

/// The bundle a Codex login produces, as the connect holds it.
async fn codex_material() -> ProtectedValue {
    let (bundle, _) = codex_device_login_with(
        SIGN_IN,
        scripted(codex_answers()),
        std::future::pending(),
        &Interrupt::default(),
    )
    .await
    .unwrap()
    .into_parts();
    let mut bytes = bundle.into_bytes();
    ProtectedValue::new(std::mem::take(&mut *bytes)).unwrap()
}

#[tokio::test]
async fn discarding_a_codex_sign_in_asks_openai_once_to_revoke_its_refresh_token() {
    let openai = Arc::new(Recording::default());
    let upstream: Arc<dyn BrokerUpstreamTransport> = openai.clone();
    let answer = revoke_unsaved_codex_over(
        async move { Ok(upstream) },
        codex_material().await,
        UNSAVED_REVOCATION_BOUND,
    )
    .await;
    assert_eq!(answer, ProviderRevocation::Confirmed);
    let requests = openai.0.lock().unwrap();
    let [(method, target, body)] = requests.as_slice() else {
        panic!("{} requests", requests.len());
    };
    assert_eq!(method, Method::POST);
    assert_eq!(target, "https://auth.openai.com/api/accounts/oauth/revoke");
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
    for field in [
        ("token", "synthetic-refresh"),
        ("token_type_hint", "refresh_token"),
    ] {
        assert!(
            form.contains(&(field.0.to_owned(), field.1.to_owned())),
            "{field:?}"
        );
    }
}

/// The system resolver blocks its thread, so a lookup that hangs must not
/// hold the cancel past the bound, nor the exit after it: `cw`'s runtime is
/// dropped as the process ends (cw-network on #4991).
#[test]
fn a_blocking_lookup_is_unavailable_at_the_bound_and_does_not_hold_the_exit() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // The login that makes the material polls once, a second, before this.
    let material = runtime.block_on(codex_material());
    let openai = Arc::new(Recording::default());
    let upstream: Arc<dyn BrokerUpstreamTransport> = openai.clone();
    let started = std::time::Instant::now();
    let answer = runtime.block_on(revoke_unsaved_codex_over(
        async move {
            std::thread::sleep(std::time::Duration::from_secs(3));
            Ok(upstream)
        },
        material,
        std::time::Duration::from_millis(50),
    ));
    assert_eq!(
        answer,
        ProviderRevocation::Failed(RevocationFailure::Unavailable)
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    let exiting = std::time::Instant::now();
    drop(runtime);
    assert!(
        exiting.elapsed() < std::time::Duration::from_millis(500),
        "the runtime waited {:?} for the lookup",
        exiting.elapsed()
    );
    assert!(openai.0.lock().unwrap().is_empty());
}

/// The client accepts a server's install link only for a slug the broker
/// would accept as a configured App's (`docs/dev/SECRETS-AND-CREDENTIALS.md`):
/// the two rules live in crates that can't share code, so this pins them.
#[test]
fn the_client_install_link_rule_is_the_broker_app_slug_rule() {
    use codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig;
    let longest = "a".repeat(100);
    let overlong = "a".repeat(101);
    for slug in [
        "codewire-sh",
        "codewire-synthetic",
        "a",
        "0",
        "a-b-c",
        "a--b",
        longest.as_str(),
        overlong.as_str(),
        "",
        "-a",
        "a-",
        "-",
        "Codewire",
        "code_wire",
        "code.wire",
        "a/b",
        "a b",
        "a\n",
        "a\u{1b}[31m",
        "caf\u{e9}",
        "a%2Fb",
        "a?b",
        "a#b",
    ] {
        let broker = GitHubDeviceLoginConfig::new("Iv1.synthetic".into(), slug.into());
        let url = format!("https://github.com/apps/{slug}/installations/new");
        let client = codewire_client::GithubAppInstallUrl::parse(&url);
        assert_eq!(broker.is_ok(), client.is_some(), "{slug:?}");
        if let Ok(config) = broker {
            assert_eq!(client.unwrap().as_str(), config.install_url());
        }
    }
}
