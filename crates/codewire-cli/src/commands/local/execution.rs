//! Process execution and safe command rendering for local runtimes.

use super::*;

pub(crate) fn run_local_command_combined(spec: &LocalRuntimeCommand) -> anyhow::Result<String> {
    let output = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .output()
        .with_context(|| format!("run {}", spec.program))?;
    if !output.status.success() {
        let combined = combined_output(&output.stdout, &output.stderr);
        anyhow::bail!(
            "{} {} failed with exit code {}\n{}",
            spec.program,
            display_local_runtime_args(&spec.args),
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    Ok(combined_output(&output.stdout, &output.stderr))
}

pub(crate) fn run_local_command_with_stdin(
    spec: &LocalRuntimeCommand,
    stdin: &str,
) -> anyhow::Result<String> {
    let mut child = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {}", spec.program))?;
    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin
            .write_all(stdin.as_bytes())
            .with_context(|| format!("write stdin for {}", spec.program))?;
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("wait for {}", spec.program))?;
    if !output.status.success() {
        let combined = combined_output(&output.stdout, &output.stderr);
        anyhow::bail!(
            "{} {} failed with exit code {}\n{}",
            spec.program,
            display_local_runtime_args(&spec.args),
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    Ok(combined_output(&output.stdout, &output.stderr))
}

pub(crate) fn display_local_runtime_args(args: &[String]) -> String {
    let mut redact_environment_value = false;
    args.iter()
        .map(|arg| {
            let rendered = if redact_environment_value {
                arg.split_once('=')
                    .map(|(key, _)| format!("{key}=<redacted>"))
                    .unwrap_or_else(|| arg.clone())
            } else {
                arg.strip_prefix(&format!("{DAEMON_AUTH_TOKEN_ENV}="))
                    .map(|_| format!("{DAEMON_AUTH_TOKEN_ENV}=<redacted>"))
                    .unwrap_or_else(|| arg.clone())
            };
            redact_environment_value = matches!(arg.as_str(), "--env" | "-e");
            rendered
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn combined_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(stdout));
    combined.push_str(&String::from_utf8_lossy(stderr));
    combined
}
