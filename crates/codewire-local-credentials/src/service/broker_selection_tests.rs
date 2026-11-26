use super::*;

use codewire_access::{AccessProfileName, CredentialAuthKind, ProviderId};
use codewire_protected_store::EphemeralProtectedStore;
use codewire_protected_store::ssh_material::generate_ed25519;

use HttpProvider::{AnthropicApiKey, CodexOAuth, GitHubOAuth, OpenAiApiKey};

fn set(providers: &[HttpProvider]) -> BTreeSet<HttpProvider> {
    providers.iter().copied().collect()
}

/// #5615: only a set that grows, into what the pinned revision names, is
/// growth. A provider outside it is refused even when the set grows.
#[test]
fn providers_grow_only_into_what_the_pinned_revision_names() {
    let named = set(&[OpenAiApiKey, AnthropicApiKey]);
    let grew = |running: &[_], asked: &[_]| providers_grew(&set(running), &set(asked), &named);
    assert!(grew(&[OpenAiApiKey], &[OpenAiApiKey, AnthropicApiKey]));
    assert!(grew(&[], &[AnthropicApiKey]));
    // Equal, shrunk and swapped sets.
    assert!(!grew(&[OpenAiApiKey], &[OpenAiApiKey]));
    assert!(!grew(&[OpenAiApiKey, AnthropicApiKey], &[OpenAiApiKey]));
    assert!(!grew(&[OpenAiApiKey], &[AnthropicApiKey]));
    // A provider the revision doesn't name.
    assert!(!grew(&[OpenAiApiKey], &[OpenAiApiKey, CodexOAuth]));
    assert!(!grew(&[OpenAiApiKey], &[OpenAiApiKey, GitHubOAuth]));
}

/// Records what each launch was told, and never starts a child.
struct RefusedSpawns(Arc<std::sync::Mutex<Vec<LocalBrokerProcessConfig>>>);

impl LocalBrokerProcessSpawner for RefusedSpawns {
    fn runner_protocol(&self) -> u32 {
        crate::broker_process::TEST_RUNNER_PROTOCOL
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        _: &crate::ProviderLookup,
        _: std::os::unix::net::UnixStream,
        _: &crate::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, crate::LocalBrokerSpawnError> {
        self.0.lock().unwrap().push(config.clone());
        Err(crate::LocalBrokerSpawnError::InvalidConfiguration)
    }
}

/// An environment bound to a profile that selects an OpenAI key, an
/// Anthropic key and an SSH identity, all usable now, and a manager holding
/// one running broker for generation 7 that serves `running` alone: what its
/// start got while the rest was withheld.
struct Withheld {
    manager: BrokerProcessManager<EphemeralProtectedStore>,
    authority: Arc<LocalCredentialAuthority<EphemeralProtectedStore>>,
    binding: EnvironmentAccessBinding,
    config: LocalBrokerProcessConfig,
    ssh: CredentialId,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    launches: Arc<std::sync::Mutex<Vec<LocalBrokerProcessConfig>>>,
}

impl Withheld {
    async fn new(directory: &std::path::Path, running: &[HttpProvider]) -> Self {
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &directory.join("authority"),
                EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            )
            .unwrap(),
        );
        let key = |provider: &str| {
            authority
                .add_credential(
                    NewCredential {
                        provider: ProviderId::parse(provider).unwrap(),
                        authentication_kind: CredentialAuthKind::ApiKey,
                        display_name: provider.into(),
                        account_hint: None,
                        expires_at_unix: None,
                    },
                    ProtectedValue::from_slice(format!("synthetic-{provider}").as_bytes()).unwrap(),
                )
                .unwrap()
                .metadata
                .id
        };
        let openai = key("openai");
        let anthropic = key("anthropic");
        let ssh = authority
            .add_ssh_credential("ssh".into(), None, generate_ed25519().unwrap(), || Ok(()))
            .unwrap()
            .metadata
            .id;
        let profile = authority
            .create_profile(
                AccessProfileName::parse("work").unwrap(),
                BTreeMap::from([
                    (CapabilitySlot::openai(), openai),
                    (CapabilitySlot::anthropic(), anthropic),
                    (CapabilitySlot::parse("ssh").unwrap(), ssh.clone()),
                ]),
            )
            .unwrap()
            .profile;
        let id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        let binding = EnvironmentAccessBinding {
            environment_id: id.clone(),
            profile_id: profile.id,
            profile_revision: profile.revision,
        };
        authority
            .create_environment_access_binding(binding.clone())
            .unwrap();
        let launches = Arc::new(std::sync::Mutex::new(Vec::new()));
        let manager = BrokerProcessManager::new(
            Arc::clone(&authority),
            Some(Arc::new(RefusedSpawns(Arc::clone(&launches)))),
            Arc::new(BrokerLeaseAuditLog::default()),
            LocalSshOperationRuntime::new(None),
            None,
            Arc::new(crate::broker_log::BrokerLog::disabled()),
        );
        let config = LocalBrokerProcessConfig {
            environment_id: id.clone(),
            environment_generation: 7,
            environment_name: "synthetic".into(),
            runner_socket: directory.join(format!("{id}.sock")),
            http_providers: set(running),
            platform_delegated: false,
            network_policy_allows_github: true,
            network_policy_allowed_hosts: BTreeSet::new(),
        };
        let (shutdown, mut stopping) = watch::channel(false);
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&stopped);
        manager.entries.lock().await.insert(
            id,
            BrokerProcessEntry {
                generation: 7,
                config: config.clone(),
                projection: None,
                platform: None,
                local_profile: Some(binding.clone()),
                shutdown,
                state: watch::channel(BrokerProcessState::Running).1,
                task: tokio::spawn(async move {
                    let _ = stopping.changed().await;
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                }),
                drain_failed: false,
            },
        );
        Self {
            manager,
            authority,
            binding,
            config,
            ssh,
            stopped,
            launches,
        }
    }

    fn request(&self) -> BrokerEnsureRequest {
        BrokerEnsureRequest {
            environment_id: self.config.environment_id.clone(),
            environment_generation: 7,
            environment_name: self.config.environment_name.clone(),
            runner_socket: self.config.runner_socket.clone(),
            projection: None,
            platform: None,
            local_profile: Some(self.binding.clone()),
            network_policy_allows_github: true,
            network_policy_allowed_hosts: BTreeSet::new(),
            boot_secrets: Default::default(),
        }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn launches(&self) -> Vec<LocalBrokerProcessConfig> {
        self.launches.lock().unwrap().clone()
    }

    /// The running broker is the one the fixture started, untouched.
    async fn untouched(&self) {
        assert!(!self.stopped());
        assert!(self.launches().is_empty());
        assert_eq!(
            self.manager.entries.lock().await[&self.config.environment_id].config,
            self.config
        );
    }

    async fn end(self) {
        let id = self.config.environment_id.clone();
        self.manager.stop(&id, Some(7)).await.unwrap();
    }
}

fn refused(error: Status) {
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "broker selection changed within an active environment generation"
    );
}

/// #5615: the Anthropic key was withheld at start and is usable again. The
/// next ensure stops the broker that serves OpenAI alone before it launches
/// one that serves both, with no new generation. That launch fails here, so
/// none serves afterwards: a failed replacement leaves nothing running.
#[tokio::test(start_paused = true)]
async fn a_reconnected_credential_replaces_the_running_broker_with_one_that_serves_it() {
    let directory = tempfile::tempdir().unwrap();
    let withheld = Withheld::new(directory.path(), &[OpenAiApiKey]).await;

    let replaced = withheld.manager.ensure(withheld.request()).await.unwrap();
    assert!(!replaced.running);
    assert!(withheld.stopped());
    let told = withheld.launches();
    assert!(
        !told.is_empty()
            && told
                .iter()
                .all(|config| config.http_providers == set(&[OpenAiApiKey, AnthropicApiKey])),
        "{told:?}"
    );
    withheld.end().await;
}

/// A running broker that serves a provider the grants no longer derive is
/// kept: a smaller set is no growth, and the withheld one is refused at its
/// lease.
#[tokio::test(start_paused = true)]
async fn a_set_that_shrinks_is_refused_and_keeps_the_running_broker() {
    let directory = tempfile::tempdir().unwrap();
    let withheld = Withheld::new(
        directory.path(),
        &[OpenAiApiKey, AnthropicApiKey, CodexOAuth],
    )
    .await;
    refused(
        withheld
            .manager
            .ensure(withheld.request())
            .await
            .unwrap_err(),
    );
    withheld.untouched().await;
    withheld.end().await;
}

/// A set that swaps a provider for another is refused too.
#[tokio::test(start_paused = true)]
async fn a_set_that_swaps_a_provider_is_refused_and_keeps_the_running_broker() {
    let directory = tempfile::tempdir().unwrap();
    let withheld = Withheld::new(directory.path(), &[OpenAiApiKey, CodexOAuth]).await;
    refused(
        withheld
            .manager
            .ensure(withheld.request())
            .await
            .unwrap_err(),
    );
    withheld.untouched().await;
    withheld.end().await;
}

/// Growth with any other part of the selection changed is still refused.
#[tokio::test(start_paused = true)]
async fn a_grown_set_with_another_change_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let withheld = Withheld::new(directory.path(), &[OpenAiApiKey]).await;
    let mut renamed = withheld.request();
    renamed.environment_name = "renamed".into();
    refused(withheld.manager.ensure(renamed).await.unwrap_err());
    withheld.untouched().await;
    withheld.end().await;
}

/// An SSH identity is never one of the broker's providers: the authority's
/// own SSH runtime decides each signature from the credential as it is then.
/// Revoking it changes nothing an ensure compares, so the running broker is
/// kept. (An SSH identity isn't reconnected by rotation, which refuses it; a
/// new one is enrolled.)
#[tokio::test(start_paused = true)]
async fn an_ssh_identitys_state_never_changes_the_running_broker() {
    let directory = tempfile::tempdir().unwrap();
    let withheld = Withheld::new(directory.path(), &[OpenAiApiKey, AnthropicApiKey]).await;
    assert!(
        withheld
            .manager
            .ensure(withheld.request())
            .await
            .unwrap()
            .running
    );
    withheld.authority.revoke_credential(&withheld.ssh).unwrap();
    assert!(
        withheld
            .manager
            .ensure(withheld.request())
            .await
            .unwrap()
            .running
    );
    withheld.untouched().await;
    withheld.end().await;
}
