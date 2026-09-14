use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command as StdCommand;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

// Run the actual fixture entrypoint inside a separately signalled executable.
// Public paths are test-only harness inputs, never production fixture switches.
#[test]
#[ignore = "invoked only as the exact isolated fixture subprocess"]
fn fixture_process() {
    let options = Options {
        public_key: std::env::var_os("CHECKOUT_TEST_PUBLIC_KEY").unwrap().into(),
        output: std::env::var_os("CHECKOUT_TEST_OUTPUT").unwrap().into(),
        lifetime: Duration::from_secs(120),
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(serve(options))
        .unwrap();
}

fn synthetic_key(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    let mut command = StdCommand::new("/usr/bin/ssh-keygen");
    let output = command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic test key generation failed"
    );
    path
}

struct Fixture {
    root: tempfile::TempDir,
    output: PathBuf,
    key: PathBuf,
    child: OwnedChild,
    ready: serde_json::Value,
}

impl Fixture {
    async fn start() -> Self {
        let root = tempfile::Builder::new()
            .prefix("cw-checkout-fixture-")
            .tempdir()
            .unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = synthetic_key(root.path(), "selected");
        let output = root.path().join("target");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", root.path())
            .env("CHECKOUT_TEST_PUBLIC_KEY", key.with_extension("pub"))
            .env("CHECKOUT_TEST_OUTPUT", &output)
            .args([
                "--exact",
                "linux::tests::fixture_process",
                "--ignored",
                "--test-threads=1",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let child = OwnedChild::spawn(&mut command).unwrap();
        let ready = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if let Ok(bytes) = fs::read(output.join("ready.json")) {
                    break serde_json::from_slice(&bytes).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture executable readiness");
        Self {
            root,
            output,
            key,
            child,
            ready,
        }
    }

    fn ssh_command(&self, key: &Path) -> Command {
        let hosts = self.root.path().join("known_hosts");
        fs::write(
            &hosts,
            format!("{}\n", self.ready["known_hosts"][0].as_str().unwrap()),
        )
        .unwrap();
        let url = url::Url::parse(self.ready["url"].as_str().unwrap()).unwrap();
        let mut command = Command::new("/usr/bin/ssh");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", self.root.path())
            .args([
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ConnectTimeout=5",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", hosts.display()))
            .arg("-i")
            .arg(key)
            .arg("-p")
            .arg(url.port().unwrap().to_string())
            .arg("synthetic@127.0.0.1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        command
    }

    fn counts(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.output.join("counter.json")).unwrap()).unwrap()
    }

    async fn terminate(&mut self) {
        let pid = self.child.group.unwrap();
        // SAFETY: this is the exact live, unreaped fixture child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        tokio::time::timeout(TEST_TIMEOUT, self.child.exited())
            .await
            .unwrap()
            .unwrap();
        let status = self.child.finish().await.unwrap();
        assert!(
            status.success(),
            "fixture must finish successful signal cleanup"
        );
        let finished: serde_json::Value =
            serde_json::from_slice(&fs::read(self.output.join("finish.json")).unwrap()).unwrap();
        assert_eq!(finished["drained"], true);
        for entry in fs::read_dir(&self.output).unwrap() {
            let entry = entry.unwrap();
            assert!(matches!(
                entry.file_name().to_str(),
                Some("ready.json" | "counter.json" | "finish.json")
            ));
            assert_eq!(entry.metadata().unwrap().mode() & 0o777, 0o600);
        }
        let url = url::Url::parse(self.ready["url"].as_str().unwrap()).unwrap();
        // Rebind the released listener instead of making an outgoing probe to
        // a closed port, which host filtering may silently drop for minutes.
        drop(
            TcpListener::bind(("127.0.0.1", url.port().unwrap()))
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn stock_git_authenticates_selected_key_and_checks_out_exact_content() {
    let mut fixture = Fixture::start().await;
    let hosts = fixture.root.path().join("known_hosts");
    fs::write(
        &hosts,
        format!("{}\n", fixture.ready["known_hosts"][0].as_str().unwrap()),
    )
    .unwrap();
    // Paths come exclusively from tempfile's fixed alphanumeric pattern.
    let ssh = format!(
        "/usr/bin/ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile='{}' -i '{}'",
        hosts.display(),
        fixture.key.display()
    );
    let mut command = git_command(fixture.root.path());
    command
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_SSH_VARIANT", "ssh")
        .args([
            "clone",
            "--quiet",
            fixture.ready["url"].as_str().unwrap(),
            "clone",
        ]);
    let output = tokio::time::timeout(TEST_TIMEOUT, command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "stock Git selected-key clone failed"
    );
    assert_eq!(fixture.counts()["authenticated"], 1);
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("clone/proof.txt")).unwrap(),
        format!("{CONTENT}\n")
    );
    let revision = run_git(
        fixture.root.path(),
        &["-C", "clone", "rev-parse", "HEAD"],
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(revision).unwrap().trim(),
        fixture.ready["revision"].as_str().unwrap()
    );
    fixture.terminate().await;
}

#[tokio::test]
async fn unknown_key_and_unsupported_command_fail_closed() {
    let mut fixture = Fixture::start().await;
    let wrong = synthetic_key(fixture.root.path(), "unselected");
    let mut command = fixture.ssh_command(&wrong);
    command.arg("git-upload-pack '/repository.git'");
    let output = tokio::time::timeout(TEST_TIMEOUT, command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Permission denied (publickey)")
    );
    assert_eq!(fixture.counts()["authenticated"], 0);
    assert!(fixture.counts()["denied"].as_u64().unwrap() > 0);
    let mut command = fixture.ssh_command(&fixture.key);
    command.arg("touch should-never-exist");
    let output = tokio::time::timeout(TEST_TIMEOUT, command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fixture.counts()["authenticated"], 1);
    assert_eq!(fixture.counts()["unsupported_commands"], 1);
    assert!(!fixture.output.join("should-never-exist").exists());
    fixture.terminate().await;
}

#[tokio::test]
async fn termination_drains_active_upload_pack() {
    let mut fixture = Fixture::start().await;
    let mut command = fixture.ssh_command(&fixture.key);
    command.arg("git-upload-pack '/repository.git'");
    let mut ssh = OwnedChild::spawn(&mut command).unwrap();
    let mut output = ssh.child.stdout.take().unwrap();
    let mut advertisement = [0u8; 4];
    tokio::time::timeout(TEST_TIMEOUT, output.read_exact(&mut advertisement))
        .await
        .unwrap()
        .unwrap();
    assert!(advertisement.iter().all(u8::is_ascii_hexdigit));
    fixture.terminate().await;
    tokio::time::timeout(TEST_TIMEOUT, ssh.exited())
        .await
        .unwrap()
        .unwrap();
    assert!(!ssh.finish().await.unwrap().success());
}

#[tokio::test]
async fn cancellation_closes_an_unfinished_transport_without_waiting_for_peer() {
    let (stream, _unfinished_peer) = tokio::io::duplex(128);
    let stop = CancellationToken::new();
    let mut stream = StopStream {
        stream,
        stopped: Box::pin(stop.clone().cancelled_owned()),
        received: 0,
        sent: 0,
    };
    let reader = tokio::spawn(async move {
        let mut byte = [0];
        stream.read(&mut byte).await.unwrap()
    });
    tokio::task::yield_now().await;
    stop.cancel();
    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, reader)
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn process_cleanup_kills_a_term_resistant_child_and_descendant() {
    let root = tempfile::tempdir().unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(root.path())
        .args([
            "-c",
            "trap '' TERM; /bin/sleep 300 & printf '%s\\n' \"$!\"; wait",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    let mut owned = OwnedChild::spawn(&mut command).unwrap();
    let mut stdout = owned.child.stdout.take().unwrap();
    let mut line = Vec::new();
    loop {
        let byte = tokio::time::timeout(TEST_TIMEOUT, stdout.read_u8())
            .await
            .unwrap()
            .unwrap();
        if byte == b'\n' {
            break;
        }
        line.push(byte);
    }
    let descendant: u32 = String::from_utf8(line).unwrap().parse().unwrap();
    let process = format!("/proc/{descendant}/stat");
    let prior = fs::read_to_string(&process).unwrap();
    let started = prior
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    assert!(!owned.finish().await.unwrap().success());
    tokio::time::timeout(TEST_TIMEOUT, bounded_bytes(stdout))
        .await
        .unwrap()
        .unwrap();
    // An init-owned zombie is already dead; neither it nor PID reuse authorizes
    // another signal. The owned pipe EOF also proves no live inheritor remains.
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            let Ok(stat) = fs::read_to_string(&process) else {
                break;
            };
            let fields: Vec<_> = stat
                .rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .collect();
            if fields[0] == "Z" || fields[19] != started {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("killed exact descendant must reach terminal state");
}

#[tokio::test]
async fn repository_preparation_cancellation_drains_its_running_git_child() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().to_owned();
    let stop = CancellationToken::new();
    let child_stop = stop.clone();
    let preparation = tokio::spawn(async move {
        // Test-only fixed Git alias stalls after proving process admission. The
        // executable accepts no aliases or caller-selected Git commands.
        run_git(
            &directory,
            &[
                "-c",
                "alias.stall=!printf ready >stalled; trap '' TERM; /bin/sleep 300",
                "stall",
            ],
            &child_stop,
        )
        .await
    });
    tokio::time::timeout(TEST_TIMEOUT, async {
        while !root.path().join("stalled").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    stop.cancel();
    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, preparation)
            .await
            .unwrap()
            .unwrap(),
        Err("repository preparation cancelled")
    );
}

#[test]
fn input_contract_rejects_extra_authority_and_existing_output() {
    let arguments = [
        "--public-key-file",
        "/public",
        "--output-dir",
        "/output",
        "--listen-host",
        "0.0.0.0",
    ];
    assert!(Options::parse(arguments.into_iter().map(Into::into)).is_err());
    let arguments = [
        "--public-key-file",
        "/public",
        "--output-dir",
        "/output",
        "--timeout-seconds",
        "1801",
    ];
    assert!(Options::parse(arguments.into_iter().map(Into::into)).is_err());
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = root.path().join("output");
    create_output(&output).unwrap();
    assert!(create_output(&output).is_err());
    let invalid = root.path().join("public");
    fs::write(&invalid, "ssh-ed25519 not-a-key\nssh-ed25519 second-key\n").unwrap();
    assert!(read_selected_public_key(&invalid).is_err());
}
