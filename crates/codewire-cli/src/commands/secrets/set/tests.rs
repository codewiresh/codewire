//! A set against a store that records its calls: the switch refuses every
//! binding flag before anything is asked or sent, and a change that needs no
//! value reads none.

use clap::Parser as _;
use codewire_access::{StoredBinding, StoredPresentation};

use super::*;
use crate::commands::SecretsCommand;
use crate::secret_client::SecretBindingView;
use crate::{Cli, Command};

#[derive(Default)]
struct Recorded {
    secret: Option<SecretMetadata>,
    calls: Vec<&'static str>,
    writes: Vec<(Option<Vec<u8>>, BindingWrite)>,
}

impl KeyStore for Recorded {
    fn command(&self) -> String {
        "cw secrets --cloud --project=myapp".to_owned()
    }

    fn place(&self) -> String {
        " in project myapp".to_owned()
    }

    fn plain_set_line(&self, key: &str) -> String {
        format!("Secret {key} set in project \"myapp\".")
    }

    async fn find(&mut self, _key: &str) -> anyhow::Result<Option<SecretMetadata>> {
        self.calls.push("find");
        Ok(self.secret.clone())
    }

    async fn require_bindings(&mut self) -> anyhow::Result<()> {
        self.calls.push("require_bindings");
        Ok(())
    }

    async fn write(
        &mut self,
        _key: &str,
        value: Option<Zeroizing<Vec<u8>>>,
        binding: &BindingWrite,
    ) -> anyhow::Result<Option<SecretMetadata>> {
        self.calls.push("write");
        self.writes
            .push((value.map(|value| value.to_vec()), binding.clone()));
        Ok(None)
    }
}

fn set_args(words: &[&str], host_bound: bool) -> ScopedSecretKeyArgs {
    let mut argv = vec!["cw", "secrets", "--cloud", "--project=myapp", "set", "KEY"];
    argv.extend(words);
    let Command::Secrets(args) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected secrets");
    };
    let SecretsCommand::Set(mut set) = args.command else {
        panic!("expected set");
    };
    set.host_bound = host_bound;
    set
}

fn bound(hosts: &[&str]) -> SecretMetadata {
    SecretMetadata {
        key: "KEY".to_owned(),
        binding: Some(SecretBindingView::new(
            &StoredBinding {
                hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
                presentation: StoredPresentation::Header {
                    headers: vec!["Authorization".into()],
                    scheme: Some("Bearer".into()),
                },
                prefix: Some("ft_".into()),
                preset: None,
            },
            1,
        )),
        ..Default::default()
    }
}

const EVERY_FLAG: [&[&str]; 10] = [
    &["--host", "api.fancy.com"],
    &["--remove-host", "api.fancy.com"],
    &["--header", "X-Api-Key"],
    &["--scheme", "none"],
    &["--prefix", ""],
    &["--basic"],
    &["--username", "git"],
    &["--basic-user"],
    &["--preset", "stripe"],
    &["--plain"],
];

#[tokio::test]
async fn while_host_bound_secrets_are_off_every_binding_flag_is_refused_before_any_call() {
    for flag in EVERY_FLAG {
        let mut store = Recorded::default();
        let error = set_key(&mut store, &set_args(flag, false))
            .await
            .unwrap_err();
        assert_eq!(
            crate::error_report::render(
                &error,
                crate::output::Style::new(false, crate::output::Charset::Unicode)
            ),
            "✗ Sending a secret only to its hosts isn't available yet\n",
            "{flag:?}"
        );
        assert!(store.calls.is_empty(), "{flag:?}: {:?}", store.calls);
    }
}

#[tokio::test]
async fn removing_a_host_sends_the_whole_binding_and_no_value() {
    let mut store = Recorded {
        secret: Some(bound(&["api.fancy.com", "api.old.example"])),
        ..Default::default()
    };
    set_key(
        &mut store,
        &set_args(&["--remove-host", "api.old.example"], true),
    )
    .await
    .unwrap();
    assert_eq!(store.calls, ["find", "require_bindings", "write"]);
    let (value, binding) = &store.writes[0];
    assert_eq!(value, &None);
    let BindingWrite::Bind(binding) = binding else {
        panic!("expected a binding, got {binding:?}");
    };
    assert_eq!(binding.hosts, ["api.fancy.com"]);
    assert_eq!(binding.prefix.as_deref(), Some("ft_"));
}

#[tokio::test]
async fn clearing_the_prefix_reads_no_value() {
    let mut store = Recorded {
        secret: Some(bound(&["api.fancy.com"])),
        ..Default::default()
    };
    set_key(&mut store, &set_args(&["--prefix", ""], true))
        .await
        .unwrap();
    let (value, BindingWrite::Bind(binding)) = &store.writes[0] else {
        panic!("expected a binding");
    };
    assert_eq!(value, &None);
    assert_eq!(binding.prefix, None);
}

#[tokio::test]
async fn a_refused_binding_is_refused_before_the_store_is_written() {
    let mut store = Recorded {
        secret: Some(bound(&["api.fancy.com"])),
        ..Default::default()
    };
    let error = set_key(
        &mut store,
        &set_args(&["--remove-host", "api.fancy.com"], true),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("is KEY's only host"),
        "{error:#}"
    );
    assert_eq!(store.calls, ["find"]);
}

#[test]
fn a_store_refusal_reads_in_the_cli_words() {
    let flags = SecretBindingArgs {
        hosts: vec!["api.other.example".into()],
        ..Default::default()
    };
    let answered = |reason: &str, message: &str| {
        anyhow::Error::from(crate::reworded::answered_for_tests(
            connectrpc::ConnectError::invalid_argument(message),
            reason,
        ))
        .context("set secret")
    };
    let plain = crate::output::Style::new(false, crate::output::Charset::Unicode);
    let required = refused_write(
        answered(
            "secret_value_required",
            "adding a host needs the secret's value again",
        ),
        "FANCY_TOKEN",
        &ValueNeed::Again(Reentry::AddHost),
        "cw secrets --cloud --project=myapp",
        &flags,
    );
    assert_eq!(
        crate::error_report::render(&required, plain),
        "✗ Adding a host to FANCY_TOKEN needs its value again\n\
         → pass the value on stdin: cw secrets --cloud --project=myapp set FANCY_TOKEN --host api.other.example < FILE\n"
    );
    let reserved = refused_write(
        answered(
            "bound_host_reserved",
            "registry.example can't be bound: Codewire serves it itself",
        ),
        "FANCY_TOKEN",
        &ValueNeed::Again(Reentry::Bind),
        "cw secrets --cloud --project=myapp",
        &flags,
    );
    assert_eq!(
        crate::error_report::render(&reserved, plain),
        format!(
            "✗ registry.example can't be bound: Codewire serves it itself\ntrace {}\n",
            crate::reworded::TRACE_FOR_TESTS
        )
    );
    // Anything else is left as it was.
    let other = refused_write(
        answered("something_else", "no"),
        "FANCY_TOKEN",
        &ValueNeed::New,
        "cw secrets --cloud --project=myapp",
        &flags,
    );
    assert!(other.to_string().contains("set secret"));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn the_local_authority_refusals_read_in_the_same_words() {
    let status = |reason: &'static str, message: &str| {
        let mut status = tonic::Status::invalid_argument(message.to_owned());
        status.metadata_mut().insert(
            codewire_local_credentials::STORE_REFUSAL_KEY,
            tonic::metadata::MetadataValue::from_static(reason),
        );
        anyhow::Error::new(status).context("set local user secret")
    };
    let flags = SecretBindingArgs {
        plain: true,
        ..Default::default()
    };
    let plain = crate::output::Style::new(false, crate::output::Charset::Unicode);
    let required = refused_write(
        status("secret_value_required", "making a secret plain needs it"),
        "KEY",
        &ValueNeed::Again(Reentry::Plain),
        "cw secrets --local --user",
        &flags,
    );
    assert_eq!(
        crate::error_report::render(&required, plain),
        "✗ Making KEY plain needs its value again\n\
         → pass the value on stdin: cw secrets --local --user set KEY --plain < FILE\n"
    );
    let off = refused_write(
        status("LOCAL_HOST_BOUND_SECRETS_UNAVAILABLE", "off"),
        "KEY",
        &ValueNeed::New,
        "cw secrets --local --user",
        &flags,
    );
    assert_eq!(
        crate::error_report::render(&off, plain),
        "✗ Sending a secret only to its hosts isn't available yet\n"
    );
}
