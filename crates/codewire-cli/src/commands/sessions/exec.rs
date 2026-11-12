//! `cw exec`: run a command once, as `ssh HOST COMMAND` does.
//!
//! No session is made. In a local VM the command runs over the environment
//! daemon's `ExecService.Run` stream: output streams back, stdin is passed
//! through and closed explicitly, and when the stream goes away the daemon
//! ends the command's process group. A cloud environment's public edge
//! carries only its session streams full duplex, so there the command runs
//! over the environment's tailnet, the way `cw shell` reaches it, as an SSH
//! exec that ends with its channel. A trusted host is this machine as you,
//! and its daemon admits only durable sessions, so there the command runs
//! here, in the environment's folder.

use super::*;
use codewire_proto::codewire::v1::{
    RunRequest, RunResize, RunResponse, RunStart, run_request, run_response,
};

/// `cw exec [--in ENV] COMMAND...`: exits with the command's status.
pub(crate) async fn handle_exec_command(globals: &Globals, args: ExecArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.command.is_empty(),
        "`cw exec` needs a command: `cw exec --in ENV COMMAND`"
    );
    let env = parse_env_overrides(&args.env)?;
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let code = match target {
        #[cfg(unix)]
        EnvironmentSessionTarget::Host { environment, .. } => {
            exec_on_host(&environment.path, &args, env).await?
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        EnvironmentSessionTarget::NativeLocal { environment_id, .. } => {
            let client = super::native_environment_data_client(&environment_id).await?;
            let stream = client.run(run_start(&args, env)?).await?;
            drive(LocalStream(stream), args.tty).await?
        }
        EnvironmentSessionTarget::Platform {
            org_id,
            environment_id,
            client,
            ..
        } => {
            let tailnet = codewire_client::tailnet_session::EnvironmentTailnet::connect(
                &client,
                &org_id,
                &environment_id,
            )
            .await
            .context("reach the environment over its tailnet")?;
            tailnet
                .wait_for_direct(codewire_client::hosted_shell::TAILNET_DIRECT_WAIT)
                .await
                .ok();
            let start = run_start(&args, Default::default())?;
            let tty = args
                .tty
                .then_some((start.term.as_str(), start.columns, start.rows));
            let channel = tailnet.exec(&ssh_line(&args, &env), tty).await?;
            let code = drive(
                SshStream {
                    channel,
                    tty: args.tty,
                },
                args.tty,
            )
            .await;
            // However the run ended, end the connection while this process
            // can still send: an interrupted command ends with it.
            tailnet.close(std::time::Duration::from_secs(5)).await;
            code?
        }
    };
    exit_with(code)
}

/// Ends `cw` with the command's status once its output is written.
fn exit_with(code: i32) -> anyhow::Result<()> {
    use std::io::Write as _;
    if code == 0 {
        return Ok(());
    }
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

fn run_start(
    args: &ExecArgs,
    env: std::collections::BTreeMap<String, String>,
) -> anyhow::Result<RunStart> {
    let mut start = RunStart {
        command: args.command.clone(),
        working_dir: args.workdir.clone().unwrap_or_default(),
        env: env.into_iter().collect(),
        allocate_tty: args.tty,
        ..Default::default()
    };
    if args.tty {
        let (columns, rows) = crate::terminal_attach::terminal_size().unwrap_or((80, 24));
        start.term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
        start.columns = u32::from(columns);
        start.rows = u32::from(rows);
    }
    Ok(start)
}

/// One `ExecService.Run` stream, however it is reached.
trait RunStream {
    async fn send(&self, request: RunRequest) -> anyhow::Result<()>;
    async fn next_output(&mut self) -> anyhow::Result<Option<RunResponse>>;
}

/// The command line for a cloud environment's SSH exec. `sh -c` changes to
/// the working directory and runs the command with its variables; every
/// word is quoted, so the daemon's `SHELL -c LINE` and its word-split form
/// read it the same way.
fn ssh_line(args: &ExecArgs, env: &std::collections::BTreeMap<String, String>) -> String {
    const SCRIPT: &str = r#"d=$1; shift; if [ -n "$d" ]; then cd "$d" || exit 126; fi; exec "$@""#;
    let mut words = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        SCRIPT.to_owned(),
        "cw".to_owned(),
        args.workdir.clone().unwrap_or_default(),
    ];
    if !env.is_empty() {
        words.push("env".to_owned());
        words.extend(env.iter().map(|(key, value)| format!("{key}={value}")));
    }
    words.extend(args.command.iter().cloned());
    words
        .iter()
        .map(|word| format!("'{}'", word.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// An SSH exec channel over the environment's tailnet, as a run. With a
/// terminal the end of this side's input is not sent, as `ssh -t` does not
/// send it: the terminal owns the command's input.
struct SshStream {
    channel: codewire_client::tailnet_session::InteractiveShell,
    tty: bool,
}

impl RunStream for SshStream {
    async fn send(&self, request: RunRequest) -> anyhow::Result<()> {
        let input = &self.channel.input;
        match request.input {
            Some(run_request::Input::Stdin(bytes)) => input.write(&bytes).await,
            Some(run_request::Input::CloseStdin(_)) if !self.tty => input.close().await,
            Some(run_request::Input::Resize(size)) => input.resize(size.columns, size.rows).await,
            _ => Ok(()),
        }
    }

    async fn next_output(&mut self) -> anyhow::Result<Option<RunResponse>> {
        use codewire_client::tailnet_session::ShellEvent;
        Ok(self.channel.output.next().await.map(|event| RunResponse {
            event: Some(match event {
                ShellEvent::Stdout(bytes) => run_response::Event::Stdout(bytes),
                ShellEvent::Stderr(bytes) => run_response::Event::Stderr(bytes),
                ShellEvent::Exit(code) => run_response::Event::ExitCode(code as i32),
            }),
            ..Default::default()
        }))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct LocalStream(codewire_local_vmm::public_client::NativeRunStream);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RunStream for LocalStream {
    async fn send(&self, request: RunRequest) -> anyhow::Result<()> {
        Ok(self.0.send(request).await?)
    }

    async fn next_output(&mut self) -> anyhow::Result<Option<RunResponse>> {
        Ok(self.0.next_output().await?)
    }
}

fn request(input: run_request::Input) -> RunRequest {
    RunRequest {
        input: Some(input),
        ..Default::default()
    }
}

/// Carries this terminal through one run and returns its exit status.
/// Without `-t`, Ctrl-C ends the run here and the daemon ends the command;
/// with `-t` the terminal is raw and Ctrl-C reaches the command.
async fn drive(mut stream: impl RunStream, tty: bool) -> anyhow::Result<i32> {
    use std::io::Write as _;
    let tty = tty && std::io::stdin().is_terminal();
    let _raw = tty
        .then(RawModeGuard::enable)
        .transpose()
        .context("enabling raw mode")?;
    let mut stdin = crate::terminal_attach::terminal_input().await;
    let mut buffer = [0_u8; 8192];
    let mut stdin_open = true;
    let mut window = crate::terminal_attach::WindowSizeWatch::new(tty);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    loop {
        tokio::select! {
            read = stdin.read(&mut buffer), if stdin_open => match read {
                Ok(0) | Err(_) => {
                    stdin_open = false;
                    stream
                        .send(request(run_request::Input::CloseStdin(Box::default())))
                        .await?;
                }
                Ok(read) => {
                    stream
                        .send(request(run_request::Input::Stdin(buffer[..read].to_vec())))
                        .await?;
                }
            },
            Some((columns, rows)) = window.changed(), if tty => {
                stream
                    .send(request(run_request::Input::Resize(Box::new(RunResize {
                        columns: u32::from(columns),
                        rows: u32::from(rows),
                        ..Default::default()
                    }))))
                    .await?;
            }
            _ = &mut interrupt, if !tty => return Ok(130),
            output = stream.next_output() => match output?.and_then(|output| output.event) {
                Some(run_response::Event::Stdout(bytes)) => {
                    let mut stdout = std::io::stdout();
                    stdout.write_all(&bytes)?;
                    stdout.flush()?;
                }
                Some(run_response::Event::Stderr(bytes)) => {
                    let mut stderr = std::io::stderr();
                    stderr.write_all(&bytes)?;
                    stderr.flush()?;
                }
                Some(run_response::Event::ExitCode(code)) => return Ok(code),
                None => anyhow::bail!(
                    "the connection to the environment ended before the command did; its outcome is unknown"
                ),
            },
        }
    }
}

/// A trusted host's command, run here as you in the environment's folder:
/// a relative `-w` is inside it. The terminal stays with the command, so
/// Ctrl-C reaches it and `cw` reports how it ended.
#[cfg(unix)]
async fn exec_on_host(
    folder: &std::path::Path,
    args: &ExecArgs,
    env: std::collections::BTreeMap<String, String>,
) -> anyhow::Result<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    let dir = match args.workdir.as_deref() {
        Some(workdir) => folder.join(workdir),
        None => folder.to_owned(),
    };
    let mut child = tokio::process::Command::new(&args.command[0])
        .args(&args.command[1..])
        .current_dir(&dir)
        .envs(env)
        .spawn()
        .with_context(|| format!("run {} in {}", args.command[0], dir.display()))?;
    // Ctrl-C is the command's to handle; cw only waits for how it ends.
    let interrupts = tokio::spawn(async { while tokio::signal::ctrl_c().await.is_ok() {} });
    let status = child.wait().await;
    interrupts.abort();
    let status = status.context("wait for the command")?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_args(words: &[&str]) -> ExecArgs {
        let args = words.iter().map(Into::into).collect();
        let args = crate::command_line::separate_command(args).expect("separated");
        let crate::Command::Exec(args) = crate::Cli::try_parse_from(args).expect("parsed").command
        else {
            panic!("not cw exec");
        };
        args
    }

    fn line(text: &str) -> Vec<&str> {
        text.split(' ').collect()
    }

    #[test]
    fn exec_takes_its_options_then_a_bare_command() {
        let args = exec_args(&line(
            "cw exec --in app -w src -e A=1 -t make -j8 -- --in x",
        ));
        assert_eq!(args.environment.as_deref(), Some("app"));
        assert_eq!(args.workdir.as_deref(), Some("src"));
        assert_eq!(args.env, ["A=1"]);
        assert!(args.tty);
        assert_eq!(
            args.command,
            ["make", "-j8", "--", "--in", "x"].map(String::from)
        );
        // Without --, an option of cw's after the command is refused.
        let refused = crate::command_line::separate_command(
            line("cw exec npm test --in app")
                .into_iter()
                .map(Into::into)
                .collect(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refused.starts_with("`--in` goes before the command: `cw exec --in app npm test`"),
            "{refused}"
        );
    }

    #[test]
    fn a_run_start_carries_the_command_and_a_terminal_only_with_tty() {
        let args = exec_args(&line("cw exec -w src -e A=1 env"));
        let env = parse_env_overrides(&args.env).unwrap();
        let start = run_start(&args, env).unwrap();
        assert_eq!(start.command, ["env"]);
        assert_eq!(start.working_dir, "src");
        assert_eq!(start.env.get("A").map(String::as_str), Some("1"));
        assert!(!start.allocate_tty);
        assert_eq!((start.columns, start.rows), (0, 0));
        let tty = run_start(&exec_args(&line("cw exec -t htop")), Default::default()).unwrap();
        assert!(tty.allocate_tty);
        assert!(tty.columns > 0 && tty.rows > 0);
    }

    /// A cloud environment's daemon runs the line as `SHELL -c LINE`; every
    /// word is single-quoted, so a word-split reading of it is the same.
    #[cfg(unix)]
    #[test]
    fn a_cloud_line_runs_the_command_in_its_folder_with_its_variables() {
        let folder = tempfile::tempdir().unwrap();
        let args = exec_args(&[
            "cw",
            "exec",
            "-w",
            &folder.path().to_string_lossy(),
            "-e",
            "K=it's",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$K\" \"$(pwd)\" \"$1\"",
            "x",
            "a b",
        ]);
        let env = parse_env_overrides(&args.env).unwrap();
        let line = ssh_line(&args, &env);
        assert!(line.starts_with("'sh' '-c' "), "{line}");
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&line)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "it's|{}|a b",
                folder.path().canonicalize().unwrap().display()
            )
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_host_command_runs_in_its_folder_and_reports_how_it_ended() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::create_dir(folder.path().join("sub")).unwrap();
        let code = |words: &[&str]| {
            let args = exec_args(words);
            let env = parse_env_overrides(&args.env).unwrap();
            let folder = folder.path().to_owned();
            async move { exec_on_host(&folder, &args, env).await.unwrap() }
        };
        assert_eq!(code(&["cw", "exec", "true"]).await, 0);
        assert_eq!(code(&["cw", "exec", "sh", "-c", "exit 3"]).await, 3);
        assert_eq!(
            code(&[
                "cw",
                "exec",
                "-w",
                "sub",
                "-e",
                "CODE=7",
                "sh",
                "-c",
                "test \"${PWD##*/}\" = sub && test \"$CODE\" = 7",
            ])
            .await,
            0
        );
        assert_eq!(
            code(&["cw", "exec", "sh", "-c", "kill -TERM $$"]).await,
            128 + 15
        );
        let missing = exec_on_host(
            folder.path(),
            &exec_args(&["cw", "exec", "no-such-command-here"]),
            Default::default(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            missing.starts_with("run no-such-command-here in "),
            "{missing}"
        );
    }
}
