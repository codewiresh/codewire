use std::time::Duration;

use super::*;

/// A store that records which steps ran. Synthetic metadata only.
#[derive(Default)]
struct Fake {
    records: Vec<FakeRecord>,
    press_ctrl_c_while_approving: bool,
    not_ready: Option<&'static str>,
    readiness_checks: usize,
    approvals: usize,
    discarded: usize,
    published: Vec<Option<String>>,
}

#[derive(Clone)]
struct FakeRecord {
    name: String,
    provider: &'static str,
}

fn record(name: &str, provider: &'static str) -> FakeRecord {
    FakeRecord {
        name: name.into(),
        provider,
    }
}

impl ConnectStore for Fake {
    const PLACEMENT: &'static str = "local";
    type Record = FakeRecord;
    type Approval = ();

    async fn named(
        &mut self,
        provider: CredentialConnectProviderArg,
        name: &str,
    ) -> anyhow::Result<Option<FakeRecord>> {
        let found = self
            .records
            .iter()
            .find(|record| record.name.eq_ignore_ascii_case(name))
            .cloned();
        if let Some(found) = &found {
            anyhow::ensure!(
                found.provider == provider_id(provider),
                "different provider"
            );
        }
        Ok(found)
    }

    async fn connections(
        &mut self,
        provider: CredentialConnectProviderArg,
    ) -> anyhow::Result<Vec<FakeRecord>> {
        Ok(self
            .records
            .iter()
            .filter(|record| record.provider == provider_id(provider))
            .cloned()
            .collect())
    }

    fn display_name(record: &FakeRecord) -> &str {
        &record.name
    }

    fn describe(record: &FakeRecord) -> anyhow::Result<Reconnecting> {
        Ok(Reconnecting {
            name: record.name.clone(),
            status: "active",
        })
    }

    async fn ready(&mut self, _: CredentialConnectProviderArg, _: &str) -> anyhow::Result<()> {
        self.readiness_checks += 1;
        match self.not_ready {
            Some(refusal) => anyhow::bail!(refusal),
            None => Ok(()),
        }
    }

    async fn approve(
        &mut self,
        _: &ConnectTarget<FakeRecord>,
        interrupt: &mut Interrupt,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.readiness_checks > 0,
            "approved before the store was checked"
        );
        self.approvals += 1;
        if self.press_ctrl_c_while_approving {
            press(interrupt);
        }
        Ok(())
    }

    async fn discard(&mut self, _: CredentialConnectProviderArg, (): ()) -> Option<String> {
        self.discarded += 1;
        None
    }

    async fn publish(
        &mut self,
        target: ConnectTarget<FakeRecord>,
        (): (),
        _: &mut Interrupt,
        _: &mut CredentialExecution,
    ) -> anyhow::Result<()> {
        self.published
            .push(target.existing.map(|existing| existing.name));
        Ok(())
    }
}

/// The state a Ctrl-C leaves behind, without a real signal.
fn press(interrupt: &mut Interrupt) {
    interrupt.pressed_in_test = true;
}

fn args(provider: CredentialConnectProviderArg, name: &str, yes: bool) -> CredentialConnectArgs {
    CredentialConnectArgs {
        credential_type: None,
        provider: Some(provider),
        name: Some(name.into()),
        yes,
        output: crate::commands::OutputFormat::Text,
        expires_at: None,
        key_file: None,
        account_hint: None,
        guided: false,
    }
}

async fn run(
    store: &mut Fake,
    args: CredentialConnectArgs,
    is_terminal: bool,
    prompt: impl FnOnce(&str) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let mut execution = CredentialExecution::Unchanged;
    connect_with(store, args, &mut execution, is_terminal, prompt).await
}

fn no_prompt(_: &str) -> anyhow::Result<bool> {
    panic!("this connect must not ask")
}

#[tokio::test]
async fn a_second_github_connection_under_another_name_is_refused_before_the_provider() {
    for yes in [false, true] {
        let mut store = Fake {
            records: vec![record("work", "github")],
            ..Fake::default()
        };
        let error = run(
            &mut store,
            args(CredentialConnectProviderArg::Github, "other", yes),
            true,
            no_prompt,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "GitHub is already connected as work; run `cw credentials --local connect github --name work --yes` to reconnect it"
        );
        assert_eq!(store.approvals, 0);
        assert!(store.published.is_empty());
    }
    // The command in the sentence runs as printed.
    let mut store = Fake {
        records: vec![record("my work", "github")],
        ..Fake::default()
    };
    let error = run(
        &mut store,
        args(CredentialConnectProviderArg::Github, "other", true),
        true,
        no_prompt,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("run `cw credentials --local connect github --name 'my work' --yes`"),
        "{error}"
    );
}

#[tokio::test]
async fn the_same_github_name_reconnects_only_after_confirmation() {
    let mut store = Fake {
        records: vec![record("work", "github")],
        ..Fake::default()
    };
    run(
        &mut store,
        args(CredentialConnectProviderArg::Github, "WORK", true),
        false,
        no_prompt,
    )
    .await
    .unwrap();
    assert_eq!(store.approvals, 1);
    assert_eq!(store.published, [Some("work".to_owned())]);
    let error = run(
        &mut store,
        args(CredentialConnectProviderArg::Github, "work", false),
        false,
        no_prompt,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("--yes"), "{error}");
    assert_eq!(store.approvals, 1);
}

#[tokio::test]
async fn only_github_is_one_connection_per_user() {
    let mut store = Fake {
        records: vec![record("first", "openai")],
        ..Fake::default()
    };
    run(
        &mut store,
        args(CredentialConnectProviderArg::Codex, "second", false),
        false,
        no_prompt,
    )
    .await
    .unwrap();
    assert_eq!(store.published, [None]);
    let mut store = Fake {
        records: vec![record("one", "github"), record("two", "github")],
        ..Fake::default()
    };
    let error = run(
        &mut store,
        args(CredentialConnectProviderArg::Github, "one", true),
        true,
        no_prompt,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("more than one local GitHub connection exists"),
        "{error}"
    );
    assert_eq!(store.approvals, 0);
}

/// A store that can't save now stops a connect, new or a reconnect, with its
/// own sentence before any provider step, and saves nothing (#4826).
#[tokio::test]
async fn a_store_that_cannot_save_stops_the_connect_before_the_provider_step() {
    for existing in [false, true] {
        let mut store = Fake {
            records: if existing {
                vec![record("work", "anthropic")]
            } else {
                Vec::new()
            },
            not_ready: Some("the local credential store can't save a Claude sign-in now"),
            ..Fake::default()
        };
        let error = run(
            &mut store,
            args(CredentialConnectProviderArg::Claude, "work", true),
            false,
            no_prompt,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the local credential store can't save a Claude sign-in now"
        );
        assert_eq!(store.readiness_checks, 1);
        assert_eq!(store.approvals, 0);
        assert!(store.published.is_empty());
    }
}

#[tokio::test]
async fn a_ctrl_c_after_the_provider_answers_saves_nothing() {
    for existing in [false, true] {
        let mut store = Fake {
            records: if existing {
                vec![record("work", "openai")]
            } else {
                Vec::new()
            },
            press_ctrl_c_while_approving: true,
            ..Fake::default()
        };
        let error = run(
            &mut store,
            args(CredentialConnectProviderArg::Codex, "work", true),
            false,
            no_prompt,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "canceled; no credential was changed");
        assert_eq!(store.approvals, 1);
        // What the provider approved is discarded, never saved (#4904).
        assert_eq!(store.discarded, 1);
        assert!(store.published.is_empty());
    }
}

#[test]
fn a_discarded_sign_in_says_what_its_provider_still_holds() {
    use CredentialConnectProviderArg::{Claude, Codex, Github};
    assert_eq!(
        discarded_sign_in(Codex, Some(ProviderRevocation::Confirmed)).unwrap(),
        "OpenAI revoked the Codex sign-in you approved."
    );
    assert_eq!(
        discarded_sign_in(
            Codex,
            Some(ProviderRevocation::Failed(RevocationFailure::Refused(400)))
        )
        .unwrap(),
        "OpenAI didn't confirm revoking the Codex sign-in you approved: OpenAI refused the request (HTTP 400). It may stay valid until it expires; you can sign out of all ChatGPT devices in ChatGPT under Settings → Security."
    );
    assert!(discarded_sign_in(Codex, None).is_none());
    assert!(
        discarded_sign_in(Github, None)
            .unwrap()
            .contains("https://github.com/settings/apps/authorizations")
    );
    assert!(
        discarded_sign_in(Claude, None)
            .unwrap()
            .contains("expires on its own")
    );
}

#[tokio::test]
async fn new_oauth_name_needs_no_replacement_confirmation() {
    let mut store = Fake {
        records: vec![record("work-openai", "openai")],
        ..Fake::default()
    };
    run(
        &mut store,
        args(CredentialConnectProviderArg::Github, "new-name", false),
        false,
        |_| panic!("new enrollment must not prompt for replacement"),
    )
    .await
    .unwrap();
    assert_eq!(store.published, [None]);
}

#[tokio::test]
async fn a_declined_reconnect_changes_nothing() {
    for guided in [false, true] {
        let mut store = Fake {
            records: vec![record("work", "anthropic")],
            ..Fake::default()
        };
        let mut connect = args(CredentialConnectProviderArg::Claude, "work", false);
        connect.guided = guided;
        let result = run(&mut store, connect, true, |_| Ok(false)).await;
        // A guided connect reports the cancellation to its caller.
        assert_eq!(result.is_err(), guided);
        if let Err(error) = result {
            assert_eq!(error.to_string(), CANCELED);
        }
        assert_eq!(store.approvals, 0);
        assert!(store.published.is_empty());
    }
}

#[test]
fn oauth_reconnect_requires_yes_or_a_positive_terminal_confirmation() {
    let record = Reconnecting {
        name: "work-openai".into(),
        status: "revoked",
    };
    let codex = CredentialConnectProviderArg::Codex;
    let error = confirm_reconnect_with("local", codex, &record, false, false, |_| {
        panic!("noninteractive reconnect must not read stdin");
    })
    .unwrap_err();
    assert!(error.to_string().contains("--yes"));
    assert!(
        confirm_reconnect_with("local", codex, &record, true, false, |_| {
            panic!("--yes must not read stdin");
        })
        .unwrap()
    );
    for answer in [false, true] {
        assert_eq!(
            confirm_reconnect_with("local", codex, &record, false, true, |message| {
                assert_eq!(
                    message,
                    "Reconnect Codex \"work-openai\" (revoked) on this computer? It stays in its profiles and becomes active; its expiry is kept."
                );
                Ok(answer)
            })
            .unwrap(),
            answer
        );
    }
    assert!(
        confirm_reconnect_with("local", codex, &record, false, true, |_| {
            Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "synthetic EOF").into())
        })
        .is_err()
    );
}

#[test]
fn both_placements_ask_the_same_reconnect_question() {
    let record = Reconnecting {
        name: "work".into(),
        status: "active",
    };
    let asked = |placement| {
        let mut asked = String::new();
        confirm_reconnect_with(
            placement,
            CredentialConnectProviderArg::Github,
            &record,
            false,
            true,
            |message| {
                asked = message.to_owned();
                Ok(true)
            },
        )
        .unwrap();
        asked
    };
    // No ID or revision, and an active status goes unsaid; only the place
    // differs between the placements.
    assert_eq!(
        asked("cloud"),
        "Reconnect GitHub \"work\" in your Codewire account? It stays in its profiles and becomes active; its expiry is kept."
    );
    assert_eq!(
        asked("local"),
        asked("cloud").replacen("in your Codewire account", "on this computer", 1)
    );
    let refusal = |placement| {
        confirm_reconnect_with(
            placement,
            CredentialConnectProviderArg::Github,
            &record,
            false,
            false,
            no_prompt,
        )
        .unwrap_err()
        .to_string()
    };
    assert_eq!(
        refusal("cloud"),
        "the GitHub credential \"work\" is already connected in your Codewire account; pass --yes to reconnect it without a terminal"
    );
    assert_eq!(
        refusal("local"),
        refusal("cloud").replacen("in your Codewire account", "on this computer", 1)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_ctrl_c_while_nothing_waits_for_it_is_still_seen() {
    // SIGINT reaches the whole test process, so this runs alone in a child of
    // this binary, where no other test's SIGINT listener can see it (#3231).
    const ISOLATED: &str = "CODEWIRE_TEST_SIGINT_ISOLATED";
    const NAME: &str = "commands::credential_input::connect::tests::a_ctrl_c_while_nothing_waits_for_it_is_still_seen";
    if std::env::var_os(ISOLATED).is_none() {
        let output = crate::process::command(std::env::current_exe().unwrap(), &[])
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(ISOLATED, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "isolated SIGINT test failed: {}\n{stdout}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // A listener of our own keeps every SIGINT below from reaching the
    // default handler, whatever the order of registration.
    let _listener =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
    let interrupt = Interrupt::default();
    assert!(!interrupt.was_pressed());
    interrupt.listen();
    assert!(!interrupt.was_pressed());
    let pid = std::process::id().to_string();
    // Nothing awaits the interrupt while the signal arrives, as between a
    // provider's answer and the save. The bound only turns a hang into a
    // failure.
    tokio::time::timeout(Duration::from_secs(120), async {
        while !interrupt.was_pressed() {
            crate::process::command("kill", &[])
                .args(["-INT", &pid])
                .status()
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the press is remembered");
    tokio::time::timeout(Duration::from_secs(120), interrupt.pressed())
        .await
        .expect("a remembered press ends the next wait at once");
}

/// A token's reconnect says its year restarts; every other says the expiry
/// is kept (#4945).
#[test]
fn a_token_reconnect_says_its_year_restarts() {
    let record = Reconnecting {
        name: "claude".into(),
        status: "active",
    };
    let mut asked = String::new();
    confirm_reconnect_with(
        "local",
        CredentialConnectProviderArg::ClaudeToken,
        &record,
        false,
        true,
        |message| {
            asked = message.to_owned();
            Ok(true)
        },
    )
    .unwrap();
    assert_eq!(
        asked,
        "Reconnect Claude (token) \"claude\" on this computer? It stays in its profiles and becomes active; its one-year expiry restarts."
    );
}

/// The alias's line and `rotate`'s refusal both give the exact command that
/// connects or replaces the token, placement and name included.
#[test]
fn the_token_commands_name_their_placement_and_name() {
    let plain = crate::output::Style::new(false, crate::output::Charset::Unicode);
    assert_eq!(
        claude_token_command_line("cloud", "work", plain),
        "→ cw credentials --cloud connect claude-token --name work"
    );
    let refusal = claude_token_rotate_refusal("local", "work");
    let step = refusal
        .downcast_ref::<crate::error_report::NextStep>()
        .map(ToString::to_string);
    assert_eq!(
        step.as_deref(),
        Some("cw credentials --local connect claude-token --name work")
    );
    assert!(format!("{refusal:#}").contains("not with rotate"));
}
