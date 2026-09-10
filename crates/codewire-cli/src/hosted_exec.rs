//! Fixed-purpose Kubernetes exec adapter for the already-authenticated daemon.
//!
//! This path deliberately does not load ordinary CLI configuration, choose an
//! endpoint, forward the inherited environment, or resolve application values.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write as _;

use clap::{Args, Parser, Subcommand};
use codewire_daemon::HOSTED_EXEC_AMBIGUOUS_EXIT_CODE;
use codewire_daemon::client::{SessionClient, v1};
use codewire_daemon::config::DAEMON_AUTH_TOKEN_ENV;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_stream::{Stream, StreamExt};
use tonic::metadata::{Ascii, MetadataValue};
use zeroize::Zeroizing;

const DAEMON_ENDPOINT: &str = "http://127.0.0.1:7777";
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_ARGUMENTS: usize = 1024;
const FAILURE_DIAGNOSTIC: &str = "hosted exec failed";

#[derive(Parser)]
#[command(
    name = "cw",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
struct HostedExecCli {
    #[command(subcommand)]
    command: HostedExecCommand,
}

#[derive(Subcommand)]
enum HostedExecCommand {
    #[command(
        name = "__hosted-exec",
        hide = true,
        disable_help_flag = true,
        disable_version_flag = true
    )]
    Exec(HostedExecArgs),
}

// Do not derive Debug: arguments and ordinary overrides are not diagnostics.
#[derive(Args)]
struct HostedExecArgs {
    #[arg(long = "work-dir")]
    working_dir: Option<String>,
    #[arg(long = "env", value_name = "KEY=VALUE")]
    environment: Vec<String>,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

/// A deliberately content-free failure. The outer lifecycle owner must recycle
/// the exact Pod when the command's terminal status cannot be certified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedExecFailure;

/// Execute the hidden, fixed-loopback lifecycle adapter before normal CLI setup.
/// Only a clean daemon terminal stream certifies an ordinary child exit status.
/// The reserved status also covers failures to parse, authenticate, or emit
/// output; neither arguments nor RPC error text are printed as diagnostics.
pub fn run_hosted_exec_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match run(args) {
        Ok(code) => code,
        Err(HostedExecFailure) => {
            let _ = writeln!(std::io::stderr().lock(), "{FAILURE_DIAGNOSTIC}");
            HOSTED_EXEC_AMBIGUOUS_EXIT_CODE
        }
    }
}

fn run<I, T>(args: I) -> Result<i32, HostedExecFailure>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let request = parse_request(args)?;
    let token = read_daemon_token(|name| std::env::var(name).map_err(|_| HostedExecFailure))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| HostedExecFailure)?;
    runtime.block_on(async move {
        let client = SessionClient::connect(DAEMON_ENDPOINT, token.as_str())
            .await
            .map_err(|_| HostedExecFailure)?;
        drop(token);
        let stream = client
            .exec_transient(request)
            .await
            .map_err(|_| HostedExecFailure)?;
        relay_output(stream, &mut tokio::io::stdout(), &mut tokio::io::stderr()).await
    })
}

fn parse_request<I, T>(args: I) -> Result<v1::ExecStartRequest, HostedExecFailure>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let HostedExecCommand::Exec(args) = HostedExecCli::try_parse_from(args)
        .map_err(|_| HostedExecFailure)?
        .command;
    if args.working_dir.as_ref().is_some_and(String::is_empty)
        || args.command.first().is_none_or(String::is_empty)
        || args.command.len() > MAX_COMMAND_ARGUMENTS
        || args.environment.len() > codewire_project::MAX_ENVIRONMENT_VALUES
    {
        return Err(HostedExecFailure);
    }
    let working_dir = args.working_dir.unwrap_or_default();
    let mut bytes = 0_usize;
    for value in std::iter::once(&working_dir)
        .chain(&args.command)
        .chain(&args.environment)
    {
        bytes = bytes
            .checked_add(value.len())
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(HostedExecFailure)?;
        if bytes > MAX_INPUT_BYTES || value.contains('\0') {
            return Err(HostedExecFailure);
        }
    }
    let mut names = BTreeSet::new();
    for entry in &args.environment {
        let (name, _) = entry.split_once('=').ok_or(HostedExecFailure)?;
        if !codewire_project::is_valid_environment_key(name)
            || name == DAEMON_AUTH_TOKEN_ENV
            || !names.insert(name)
        {
            return Err(HostedExecFailure);
        }
    }
    Ok(v1::ExecStartRequest {
        command: args.command,
        working_dir,
        env: args.environment,
    })
}

fn read_daemon_token(
    read: impl FnOnce(&str) -> Result<String, HostedExecFailure>,
) -> Result<Zeroizing<String>, HostedExecFailure> {
    let token = Zeroizing::new(read(DAEMON_AUTH_TOKEN_ENV)?);
    // SessionClient trims its general-purpose inputs. This fixed-purpose path
    // requires canonical metadata instead of silently repairing the capability.
    if token.is_empty() || !token.is_ascii() || token.trim() != token.as_str() {
        return Err(HostedExecFailure);
    }
    MetadataValue::<Ascii>::try_from(token.as_str()).map_err(|_| HostedExecFailure)?;
    Ok(token)
}

async fn relay_output<S, O, E>(
    mut stream: S,
    stdout: &mut O,
    stderr: &mut E,
) -> Result<i32, HostedExecFailure>
where
    S: Stream<Item = Result<v1::ExecMessage, tonic::Status>> + Unpin,
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut exit_code = None;
    while let Some(message) = stream.next().await {
        let message = message.map_err(|_| HostedExecFailure)?;
        if exit_code.is_some() {
            // Exit must be terminal, including with respect to gRPC trailers.
            return Err(HostedExecFailure);
        }
        match message.payload {
            Some(v1::exec_message::Payload::Stdout(bytes)) => {
                stdout
                    .write_all(&bytes)
                    .await
                    .map_err(|_| HostedExecFailure)?;
                stdout.flush().await.map_err(|_| HostedExecFailure)?;
            }
            Some(v1::exec_message::Payload::Stderr(bytes)) => {
                stderr
                    .write_all(&bytes)
                    .await
                    .map_err(|_| HostedExecFailure)?;
                stderr.flush().await.map_err(|_| HostedExecFailure)?;
            }
            Some(v1::exec_message::Payload::Exit(status)) if (0..=255).contains(&status.code) => {
                exit_code = Some(status.code);
            }
            // Error is daemon failure text, not a child output frame. Never
            // print it or accept a subsequent exit as a successful transport.
            _ => return Err(HostedExecFailure),
        }
    }
    let code = exit_code.ok_or(HostedExecFailure)?;
    stdout.flush().await.map_err(|_| HostedExecFailure)?;
    stderr.flush().await.map_err(|_| HostedExecFailure)?;
    Ok(code)
}

#[cfg(test)]
mod tests;
